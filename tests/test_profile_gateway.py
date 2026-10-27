from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from autocve.analysis import profile as profile_mod
from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace, save_credential
from autocve.llm.gateway import BudgetExceeded, LlmGateway, budget_status
from autocve.models import Advisory, CredentialStatus, LlmUsage, Provider
from autocve.security.keyvault import KeyVault
from tests.anthropic_fakes import FakeAnthropic
from tests.fakes import FakeValidator
from tests.osv_fixtures import advisory

PROFILE = {
    "summary_ko": "템플릿 컴파일 시 코드가 실행될 수 있습니다.",
    "vulnerable_symbols": ["lodash.template", "_.template"],
    "requires_specific_api": True,
    "trigger_conditions": "untrusted options.sourceURL",
    "preconditions": [],
    "attack_vector": "network",
    "fixed_versions": ["4.17.21"],
}


@pytest.fixture
def env(session_factory, settings):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    fake = FakeAnthropic()
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        yield session, workspace, vault, fake


def with_key(session, workspace, vault):
    save_credential(
        session, vault, workspace, Provider.ANTHROPIC, "sk-ant-test-key-1", FakeValidator()
    )


def stored_advisory(session, record):
    upsert_advisory(session, record)
    session.commit()
    return session.get(Advisory, record["id"])


def test_profile_extracted_once_and_cached(env):
    session, workspace, vault, fake = env
    with_key(session, workspace, vault)
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    adv = stored_advisory(session, advisory("GHSA-1", "lodash", "4.17.21"))
    fake.reply_json(PROFILE, input_tokens=1200, output_tokens=150)

    first = profile_mod.get_profile(session, gateway, workspace, adv, "lodash")
    assert first.profile["vulnerable_symbols"] == ["lodash.template", "_.template"]
    assert not first.incomplete

    request = fake.requests[0]
    assert request["model"] == "claude-haiku-5-5"
    assert request["output_config"]["format"]["type"] == "json_schema"
    assert request["output_config"]["effort"] == "low"
    assert request["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "GHSA-1" in request["messages"][0]["content"]

    second = profile_mod.get_profile(session, gateway, workspace, adv, "lodash")
    assert second.id == first.id
    assert len(fake.requests) == 1  # 캐시를 썼다

    usage = session.scalar(select(LlmUsage))
    assert (usage.stage, usage.input_tokens, usage.output_tokens) == ("profile", 1200, 150)
    assert usage.cost_usd == Decimal("0.000195")


def test_malicious_package_skips_claude(env):
    session, workspace, vault, fake = env
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    adv = stored_advisory(session, advisory("MAL-2026-1", "evil-pkg", None))
    result = profile_mod.get_profile(session, gateway, workspace, adv, "evil-pkg")
    assert result.profile["malicious_package"]
    assert fake.requests == []


def test_profile_without_key_is_retried_later(env):
    session, workspace, vault, fake = env
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    adv = stored_advisory(session, advisory("GHSA-1", "lodash", "4.17.21"))

    skipped = profile_mod.get_profile(session, gateway, workspace, adv, "lodash")
    assert skipped.incomplete and skipped.profile["retry"]

    with_key(session, workspace, vault)
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    fake.reply_json(PROFILE)
    retried = profile_mod.get_profile(session, gateway, workspace, adv, "lodash")
    assert retried.id == skipped.id
    assert not retried.incomplete
    assert "retry" not in retried.profile


def test_refusal_gives_incomplete_profile(env):
    session, workspace, vault, fake = env
    with_key(session, workspace, vault)
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    adv = stored_advisory(session, advisory("GHSA-1", "lodash", "4.17.21"))
    fake.reply_text("", stop_reason="refusal")
    result = profile_mod.get_profile(session, gateway, workspace, adv, "lodash")
    assert result.incomplete
    assert result.profile["vulnerable_symbols"] == []


def test_budget_blocks_calls(env):
    session, workspace, vault, fake = env
    with_key(session, workspace, vault)
    workspace.monthly_budget_usd = Decimal("0.0001")
    session.commit()
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    fake.reply_json(PROFILE, input_tokens=10_000, output_tokens=1_000)
    gateway.create(stage="profile", model="claude-haiku-5-5", max_tokens=10, messages=[])
    assert budget_status(session, workspace).ratio >= 1.0
    with pytest.raises(BudgetExceeded):
        gateway.create(stage="profile", model="claude-haiku-5-5", max_tokens=10, messages=[])


def test_fix_diff_drops_test_files_and_oversized():
    diff = (
        "diff --git a/lib/template.js b/lib/template.js\n+fixed\n"
        "diff --git a/test/template.test.js b/test/template.test.js\n+test only\n"
    )
    assert profile_mod.filter_diff(diff) == "diff --git a/lib/template.js b/lib/template.js\n+fixed"

    commit = "https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a"
    record = SimpleNamespace(
        references=[{"type": "FIX", "url": commit}, {"type": "WEB", "url": "https://example.com/b"}]
    )
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text=diff)

    text, too_large = profile_mod.fetch_fix_diff(
        httpx.Client(transport=httpx.MockTransport(handler)), record
    )
    assert calls == [f"{commit}.diff"]
    assert "test only" not in text and not too_large

    oversized = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, text="diff --git a/x b/x\n" + "+" * 40_000)
        )
    )
    assert profile_mod.fetch_fix_diff(oversized, record) == (None, True)


def test_invalid_key_is_not_available(env):
    session, workspace, vault, fake = env
    with_key(session, workspace, vault)
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    assert gateway.available()
    from autocve.credentials.service import get_credential

    get_credential(session, workspace, Provider.ANTHROPIC).status = CredentialStatus.INVALID
    session.commit()
    assert not gateway.available()

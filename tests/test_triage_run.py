import pytest
from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace
from autocve.ecosystems import purl
from autocve.llm.gateway import LlmGateway
from autocve.models import (
    CodeFile,
    Component,
    Finding,
    FindingStatus,
    LlmUsage,
    Project,
    TriageResult,
    Verdict,
)
from autocve.security.keyvault import KeyVault, generate_master_key
from autocve.triage.models import Judgement, TriageError
from autocve.triage.policy import PolicyConfig
from autocve.triage.run import triage_findings
from tests.anthropic_fakes import FakeAnthropic
from tests.osv_fixtures import advisory

NO_RISK = Judgement(
    {"not_affected": 0.96, "possibly_affected": 0.03, "likely_affected": 0.01},
    {"no_llm": 0.9, "haiku": 0.1, "sonnet": 0.0, "opus": 0.0},
    0.96,
    provider="typesafe",
    model_version="jev-1.14.0",
    input_tokens=500,
)
RISKY = Judgement(
    {"not_affected": 0.05, "possibly_affected": 0.15, "likely_affected": 0.8},
    {"no_llm": 0.0, "haiku": 0.2, "sonnet": 0.7, "opus": 0.1},
    0.8,
    provider="typesafe",
    model_version="jev-1.14.0",
    input_tokens=700,
)


class FakeJev:
    provider = "typesafe"

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def judge(self, inp, *, include_snippets=True):
        self.calls.append((inp, include_snippets))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def setup(session_factory, settings, tmp_path):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        project = Project(workspace_id=workspace.id, name="app", repo_url="https://github.com/o/a")
        session.add(project)
        session.commit()
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        yield session, project, vault, checkout


def add_finding(session, project, name, version, record, *, scope="prod", direct=True):
    upsert_advisory(session, record)
    component = Component(
        project_id=project.id,
        locator=f"node_modules/{name}",
        purl=purl("npm", name, version),
        ecosystem="npm",
        name=name,
        version=version,
        direct=direct,
        scope=scope,
        manifest_path="package-lock.json",
    )
    session.add(component)
    session.flush()
    finding = Finding(project_id=project.id, component_id=component.id, advisory_id=record["id"])
    session.add(finding)
    session.commit()
    return finding


def run(session, project, vault, settings, checkout, jev, **kwargs):
    workspace = get_or_create_default_workspace(session)
    gateway = LlmGateway(session, workspace, vault, FakeAnthropic().factory)
    return triage_findings(
        session,
        project,
        vault=vault,
        settings=settings,
        checkout=checkout,
        gateway=gateway,
        jev=jev,
        config=kwargs.pop("config", PolicyConfig(audit_percent=0)),
        **kwargs,
    )


def result_for(session, finding):
    return session.scalar(select(TriageResult).where(TriageResult.finding_id == finding.id))


def test_auto_close_and_analyze_routes(setup, settings):
    session, project, vault, checkout = setup
    quiet = add_finding(session, project, "qs", "6.5.0", advisory("GHSA-q", "qs", "6.5.3"))
    loud = add_finding(
        session, project, "lodash", "4.17.11", advisory("GHSA-l", "lodash", "4.17.12")
    )
    jev = FakeJev(NO_RISK, RISKY)

    summary = run(session, project, vault, settings, checkout, jev)

    assert summary.triaged == 2 and summary.jev_calls == 2
    session.refresh(quiet)
    session.refresh(loud)
    assert (quiet.status, quiet.verdict) == (FindingStatus.TRIAGED, Verdict.NOT_AFFECTED)
    assert result_for(session, quiet).action == "auto_close"
    assert (loud.status, loud.verdict) == (FindingStatus.TRIAGED, None)
    loud_result = result_for(session, loud)
    assert (loud_result.action, loud_result.route) == ("analyze", "sonnet")
    assert loud_result.model_version == "jev-1.14.0"

    usage = session.scalars(select(LlmUsage).where(LlmUsage.stage == "jev")).all()
    assert [u.input_tokens for u in usage] == [500, 700]


def test_jev_failure_falls_back_to_rules(setup, settings):
    session, project, vault, checkout = setup
    finding = add_finding(session, project, "qs", "6.5.0", advisory("GHSA-q", "qs", "6.5.3"))
    summary = run(session, project, vault, settings, checkout, FakeJev(TriageError("down")))
    result = result_for(session, finding)
    assert summary.degraded == 1
    assert result.degraded and result.provider == "rules"
    assert result.action == "analyze"  # 규칙은 자동 종결하지 않는다


def test_evidence_uses_index_and_checkout(setup, settings):
    session, project, vault, checkout = setup
    finding = add_finding(
        session, project, "lodash", "4.17.11", advisory("GHSA-l", "lodash", "4.17.12")
    )
    (checkout / "src").mkdir()
    (checkout / "src" / "render.js").write_text(
        "const _ = require('lodash');\nconst t = _.template(input);\n"
    )
    session.add_all(
        [
            CodeFile(
                project_id=project.id, path="src/render.js", sha256="a" * 64, imports=["lodash"]
            ),
            CodeFile(
                project_id=project.id,
                path="test/a.test.js",
                sha256="b" * 64,
                imports=["lodash"],
                is_test=True,
            ),
        ]
    )
    session.commit()
    # 프로파일 없이도 import 증거는 남는다. 심볼 검색은 프로파일이 있어야 한다.
    jev = FakeJev(RISKY)
    run(session, project, vault, settings, checkout, jev)
    inp, include_snippets = jev.calls[0]
    assert inp.evidence.prod_import_files == ["src/render.js"]
    assert inp.evidence.test_import_files == ["test/a.test.js"]
    assert include_snippets
    assert result_for(session, finding).evidence["prod_import_count"] == 1


def test_same_input_reuses_previous_judgement(setup, settings):
    session, project, vault, checkout = setup
    first = add_finding(session, project, "qs", "6.5.0", advisory("GHSA-q", "qs", "6.5.3"))
    run(session, project, vault, settings, checkout, FakeJev(RISKY))

    # 같은 패키지·버전·취약점이 다른 위치에 또 있으면 JEV를 다시 부르지 않는다.
    component = Component(
        project_id=project.id,
        locator="node_modules/x/node_modules/qs",
        purl=purl("npm", "qs", "6.5.0"),
        ecosystem="npm",
        name="qs",
        version="6.5.0",
        direct=True,
        scope="prod",
        manifest_path="package-lock.json",
    )
    session.add(component)
    session.flush()
    second = Finding(project_id=project.id, component_id=component.id, advisory_id="GHSA-q")
    session.add(second)
    session.commit()

    jev = FakeJev()
    summary = run(session, project, vault, settings, checkout, jev)
    assert jev.calls == [] and summary.cache_hits == 1
    assert result_for(session, second).provider == "cache"
    assert result_for(session, second).route == result_for(session, first).route


def test_withdrawn_and_malicious_and_dev(setup, settings):
    session, project, vault, checkout = setup
    withdrawn = add_finding(
        session,
        project,
        "a",
        "1.0.0",
        advisory("GHSA-w", "a", "2.0.0", withdrawn="2026-02-01T00:00:00Z"),
    )
    malicious = add_finding(session, project, "evil", "1.0.0", advisory("MAL-2026-1", "evil", None))
    dev = add_finding(
        session, project, "jest", "1.0.0", advisory("GHSA-d", "jest", "2.0.0"), scope="dev"
    )
    jev = FakeJev()
    run(session, project, vault, settings, checkout, jev)

    assert jev.calls == []
    session.refresh(withdrawn)
    session.refresh(malicious)
    session.refresh(dev)
    assert withdrawn.status == FindingStatus.RESOLVED
    assert (malicious.verdict, result_for(session, malicious).action) == (
        Verdict.AFFECTED,
        "malicious",
    )
    assert result_for(session, dev).action == "dev_only"


def test_snippet_opt_out_is_passed_to_jev(setup, settings):
    session, project, vault, checkout = setup
    project.jev_snippets = False
    session.commit()
    add_finding(session, project, "qs", "6.5.0", advisory("GHSA-q", "qs", "6.5.3"))
    jev = FakeJev(RISKY)
    run(session, project, vault, settings, checkout, jev)
    assert jev.calls[0][1] is False


def test_unreadable_keys_do_not_stop_triage(setup, settings):
    from autocve.credentials.service import save_credential
    from autocve.models import Provider
    from tests.fakes import FakeValidator

    session, project, vault, checkout = setup
    workspace = get_or_create_default_workspace(session)
    for provider, key in (
        (Provider.ANTHROPIC, "sk-ant-x-12345678"),
        (Provider.OPENROUTER, "sk-or-v1-12345678"),
    ):
        save_credential(session, vault, workspace, provider, key, FakeValidator())
    finding = add_finding(session, project, "qs", "6.5.0", advisory("GHSA-q", "qs", "6.5.3"))

    other_vault = KeyVault.from_b64(generate_master_key())  # 마스터 키가 바뀐 상황
    summary = triage_findings(
        session, project, vault=other_vault, settings=settings, checkout=checkout
    )
    assert summary.triaged == 1
    assert result_for(session, finding).provider == "rules"

import json
from types import SimpleNamespace

import httpx
import pytest

from autocve.triage.evidence import Evidence, Snippet, import_names
from autocve.triage.inputs import MAX_STATE_CHARS, TriageInput
from autocve.triage.models import (
    EXPOSURE,
    ROUTE,
    Judgement,
    RuleTriage,
    SystemOneTriage,
    TriageError,
    parse_systemone_response,
)
from autocve.triage.policy import Action, PolicyConfig, decide, is_audit_sample


def make_input(**overrides) -> TriageInput:
    values = {
        "finding_id": 1,
        "advisory_id": "GHSA-1",
        "summary": "Prototype pollution",
        "package": "pkg:npm/lodash@4.17.11",
        "direct": True,
        "scope": "prod",
        "cvss": 7.5,
        "epss": 0.01,
        "in_kev": False,
        "attack_vector": "N",
        "malicious": False,
        "profile": {"vulnerable_symbols": ["_.template"], "requires_specific_api": True},
        "evidence": Evidence(prod_import_files=["a.js"], checkout_available=True),
    }
    values.update(overrides)
    return TriageInput(**values)


def test_import_names_for_pypi_and_npm():
    assert "yaml" in import_names(SimpleNamespace(ecosystem="PyPI", name="pyyaml"))
    assert "dateutil" in import_names(SimpleNamespace(ecosystem="PyPI", name="python-dateutil"))
    assert "typing_extensions" in import_names(
        SimpleNamespace(ecosystem="PyPI", name="typing-extensions")
    )
    assert import_names(SimpleNamespace(ecosystem="npm", name="@scope/Pkg")) == {"@scope/pkg"}


def test_state_is_bounded_and_drops_snippets_first():
    big = [Snippet("a.js", i, "template", "x" * 7000) for i in range(3)]
    inp = make_input(evidence=Evidence(prod_import_files=["a.js"], snippets=big))
    state = inp.render_state()
    assert len(state) <= MAX_STATE_CHARS
    assert "[evidence]" in state
    assert "a.js:0" in state and "a.js:2" not in state
    assert "--- " not in inp.render_state(snippets=0)


JEV_RESPONSE = {
    "model": "jev-1.14.0",
    "answers": {
        EXPOSURE: {
            "type": "choice",
            "choice": "not_affected",
            "confidence": 0.93,
            "probabilities": {
                "not_affected": 0.93,
                "possibly_affected": 0.05,
                "likely_affected": 0.02,
            },
        },
        ROUTE: {
            "type": "choice",
            "choice": "no_llm",
            "probabilities": {"no_llm": 0.8, "haiku": 0.15, "sonnet": 0.04, "opus": 0.01},
        },
    },
    "usage": {"input_tokens": 812},
}


def test_systemone_request_and_parse():
    seen = []

    def handler(request):
        seen.append(
            (str(request.url), request.headers["authorization"], json.loads(request.content))
        )
        return httpx.Response(200, json=JEV_RESPONSE)

    jev = SystemOneTriage(
        "openrouter",
        "https://openrouter.test/api/v1",
        "sk-or-v1-key",
        "typesafe/jev-1.14",
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    judgement = jev.judge(make_input())
    url, auth, body = seen[0]
    assert url == "https://openrouter.test/api/v1/systemone"
    assert auth == "Bearer sk-or-v1-key"
    assert body["model"] == "typesafe/jev-1.14"
    assert set(body["questions"]) == {EXPOSURE, ROUTE}
    assert body["questions"][EXPOSURE]["type"] == "choice"
    assert "[evidence]" in body["state"]
    assert judgement.exposure == "not_affected" and judgement.route == "no_llm"
    assert judgement.confidence == pytest.approx(0.93)
    assert (judgement.model_version, judgement.input_tokens) == ("jev-1.14.0", 812)


def test_parse_tolerates_missing_confidence_and_results_key():
    data = {
        "results": {
            k: {"probabilities": v["probabilities"]} for k, v in JEV_RESPONSE["answers"].items()
        }
    }
    exposure, route, confidence = parse_systemone_response(data)
    assert confidence == pytest.approx(0.93)
    assert route["no_llm"] == pytest.approx(0.8)


@pytest.mark.parametrize("payload", [{}, {"answers": {EXPOSURE: {"probabilities": {}}}}])
def test_parse_rejects_incomplete_responses(payload):
    with pytest.raises(TriageError):
        parse_systemone_response(payload)


def test_systemone_http_error_raises_triage_error():
    jev = SystemOneTriage(
        "typesafe",
        "https://t.test/v1",
        "k",
        "jev",
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))),
    )
    with pytest.raises(TriageError):
        jev.judge(make_input())


def test_rules_never_choose_no_llm():
    rules = RuleTriage()
    cases = [
        make_input(evidence=Evidence()),  # import 없음, 직접 의존성
        make_input(direct=False, evidence=Evidence()),
        make_input(evidence=Evidence(prod_import_files=["a.js"], checkout_available=True)),
        make_input(evidence=Evidence(prod_import_files=["a.js"], call_site_count=5)),
        make_input(profile={}),
    ]
    for inp in cases:
        judgement = rules.judge(inp)
        assert judgement.route != "no_llm"
        assert abs(sum(judgement.exposure_probs.values()) - 1) < 1e-9
    assert rules.judge(cases[3]).exposure == "likely_affected"
    assert rules.judge(cases[3]).route == "sonnet"


def judgement(exposure: dict, route: dict, confidence=0.9) -> Judgement:
    return Judgement(exposure, route, confidence, provider="typesafe")


CLEAR_NO = judgement(
    {"not_affected": 0.95, "possibly_affected": 0.04, "likely_affected": 0.01},
    {"no_llm": 0.9, "haiku": 0.1, "sonnet": 0, "opus": 0},
)
LIKELY_OPUS = judgement(
    {"not_affected": 0.05, "possibly_affected": 0.15, "likely_affected": 0.8},
    {"no_llm": 0, "haiku": 0.1, "sonnet": 0.2, "opus": 0.7},
)
CONFIG = PolicyConfig(audit_percent=0)


def test_auto_close_when_confident_and_not_severe():
    assert decide(make_input(), CLEAR_NO, 0.0, CONFIG).action == Action.AUTO_CLOSE


def test_severe_findings_are_never_auto_closed():
    for inp in (make_input(in_kev=True), make_input(cvss=9.8)):
        decision = decide(inp, CLEAR_NO, 0.0, CONFIG)
        assert decision.action == Action.ANALYZE
        assert decision.route == "sonnet"


def test_audit_sample_goes_to_haiku():
    finding_id = next(i for i in range(1000) if is_audit_sample(i, 5))
    decision = decide(make_input(finding_id=finding_id), CLEAR_NO, 0.0, PolicyConfig())
    assert (decision.action, decision.route, decision.audit) == (Action.AUTO_CLOSE, "haiku", True)
    assert is_audit_sample(finding_id, 5)  # 같은 Finding은 항상 같은 결과


def test_rule_confidence_does_not_bump_tier():
    rules = RuleTriage().judge(make_input(direct=False, evidence=Evidence()))
    assert rules.confidence < 0.6
    assert decide(make_input(), rules, 0.0, CONFIG).route == "haiku"


def test_low_confidence_bumps_tier():
    low = judgement(
        {"not_affected": 0.3, "possibly_affected": 0.4, "likely_affected": 0.3},
        {"no_llm": 0, "haiku": 0.6, "sonnet": 0.3, "opus": 0.1},
        confidence=0.4,
    )
    assert decide(make_input(), low, 0.0, CONFIG).route == "sonnet"


def test_budget_rules():
    assert decide(make_input(), LIKELY_OPUS, 0.85, CONFIG).route == "sonnet"
    assert decide(make_input(), LIKELY_OPUS, 0.5, CONFIG).route == "opus"
    assert decide(make_input(), LIKELY_OPUS, 1.0, CONFIG).action == Action.BUDGET
    # 자동 종결은 예산과 무관하게 가능하다 (Claude를 쓰지 않으므로).
    assert decide(make_input(), CLEAR_NO, 1.0, CONFIG).action == Action.AUTO_CLOSE


def test_malicious_and_dev_short_circuit():
    assert decide(make_input(malicious=True), LIKELY_OPUS, 0, CONFIG).action == Action.MALICIOUS
    assert decide(make_input(scope="dev"), LIKELY_OPUS, 0, CONFIG).action == Action.DEV_ONLY
    keep_dev = PolicyConfig(skip_dev=False, audit_percent=0)
    assert decide(make_input(scope="dev"), LIKELY_OPUS, 0, keep_dev).action == Action.ANALYZE

import pytest
from sqlalchemy import select

from autocve.analysis import deep, light
from autocve.analysis import run as analysis_run
from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace, save_credential
from autocve.ecosystems import purl
from autocve.llm.gateway import LlmGateway
from autocve.models import (
    Analysis,
    AnalysisBatch,
    Component,
    Finding,
    FindingStatus,
    LlmUsage,
    Project,
    Provider,
    TriageResult,
)
from autocve.security.keyvault import KeyVault
from tests.anthropic_fakes import BATCH_ID, FakeAnthropic
from tests.fakes import FakeValidator
from tests.osv_fixtures import advisory

AFFECTED = {
    "verdict": "affected",
    "confidence": 0.85,
    "rationale": "src/render.js에서 사용자 입력이 _.template로 전달됩니다.",
    "evidence": [{"path": "src/render.js", "line": 2, "note": "_.template(input)"}],
    "data_flow": ["req.body.tpl", "_.template"],
}
NOT_AFFECTED = {**AFFECTED, "verdict": "not_affected", "data_flow": []}
UNCERTAIN = {**AFFECTED, "verdict": "uncertain", "data_flow": []}


@pytest.fixture
def env(session_factory, settings, tmp_path):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    fake = FakeAnthropic()
    checkout = tmp_path / "repo"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src" / "render.js").write_text(
        "const _ = require('lodash');\nmodule.exports = (input) => _.template(input);\n"
    )
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        save_credential(
            session, vault, workspace, Provider.ANTHROPIC, "sk-ant-test-12345678", FakeValidator()
        )
        project = Project(workspace_id=workspace.id, name="a", repo_url="https://github.com/o/a")
        session.add(project)
        session.commit()
        gateway = LlmGateway(session, workspace, vault, fake.factory)
        yield session, project, vault, fake, gateway, checkout


def add_triaged(
    session, project, name="lodash", route="haiku", *, audit=False, severe=False, key="k"
):
    record = advisory(f"GHSA-{name}", name, "9.9.9")
    upsert_advisory(session, record)
    component = Component(
        project_id=project.id,
        locator=f"node_modules/{name}",
        purl=purl("npm", name, "1.0.0"),
        ecosystem="npm",
        name=name,
        version="1.0.0",
        direct=True,
        scope="prod",
        manifest_path="package-lock.json",
    )
    session.add(component)
    session.flush()
    finding = Finding(
        project_id=project.id,
        component_id=component.id,
        advisory_id=record["id"],
        status=FindingStatus.TRIAGED,
    )
    session.add(finding)
    session.flush()
    session.add(
        TriageResult(
            finding_id=finding.id,
            provider="typesafe",
            action="auto_close" if audit else "analyze",
            route=route,
            audit=audit,
            evidence={
                "prod_import_count": 1,
                "prod_import_files": ["src/render.js"],
                "severe": severe,
            },
            cache_key=f"{key}-{name}",
        )
    )
    session.commit()
    return finding


def analyze(session, project, vault, gateway, checkout, **kwargs):
    return analysis_run.analyze_findings(
        session, project, vault=vault, checkout=checkout, gateway=gateway, **kwargs
    )


def test_light_analysis_sets_verdict_and_score(env):
    session, project, vault, fake, gateway, checkout = env
    finding = add_triaged(session, project)
    fake.reply_json(AFFECTED)

    summary = analyze(session, project, vault, gateway, checkout)

    assert summary.analyzed == 1
    session.refresh(finding)
    assert (finding.status, finding.verdict) == (FindingStatus.ANALYZED, "affected")
    assert finding.grade is not None and finding.risk_factors["reachability"] == 1.0
    request = fake.requests[0]
    assert request["model"] == "claude-haiku-5-5"
    assert request["output_config"]["format"]["schema"]["required"][0] == "verdict"
    assert "GHSA-lodash" in request["messages"][0]["content"]
    saved = session.scalar(select(Analysis))
    assert saved.rationale.startswith("src/render.js")
    assert {"data_flow": "_.template"} in saved.evidence


def test_uncertain_escalates_once_to_deep_analysis(env):
    session, project, vault, fake, gateway, checkout = env
    finding = add_triaged(session, project)
    fake.reply_json(UNCERTAIN)  # Haiku
    fake.reply_tool_use("search_code", {"pattern": r"_\.template\(", "path_prefix": ""})
    fake.reply_json(AFFECTED, model="claude-sonnet-5-5")

    summary = analyze(session, project, vault, gateway, checkout)

    assert summary.escalated == 1
    session.refresh(finding)
    assert finding.verdict == "affected"
    sonnet_first, sonnet_final = fake.requests[1], fake.requests[2]
    assert sonnet_first["model"] == "claude-sonnet-5-5"
    assert sonnet_first["fallbacks"] == "default"
    assert {t["name"] for t in sonnet_first["tools"]} == {"read_file", "search_code", "list_dir"}
    assert all(t["strict"] for t in sonnet_first["tools"])
    assert "server-side-fallback-2026-07-01" in fake.headers[1]["anthropic-beta"]
    # 도구 결과가 다음 요청에 실려 간다.
    tool_result = sonnet_final["messages"][-1]["content"][0]
    assert tool_result["type"] == "tool_result"
    assert "src/render.js:2" in tool_result["content"]
    stages = [u.stage for u in session.scalars(select(LlmUsage).order_by(LlmUsage.id))]
    assert stages == ["haiku", "sonnet", "sonnet"]


def test_haiku_refusal_retries_on_sonnet(env):
    session, project, vault, fake, gateway, checkout = env
    finding = add_triaged(session, project)
    fake.reply_text("", stop_reason="refusal")
    fake.reply_json(NOT_AFFECTED, model="claude-sonnet-5-5")
    analyze(session, project, vault, gateway, checkout)
    session.refresh(finding)
    assert finding.verdict == "not_affected"


def test_refusal_on_deep_analysis_marks_finding(env):
    session, project, vault, fake, gateway, checkout = env
    finding = add_triaged(session, project, route="sonnet")
    fake.reply_text("", stop_reason="refusal", model="claude-sonnet-5-5")
    summary = analyze(session, project, vault, gateway, checkout)
    session.refresh(finding)
    assert summary.refused == 1
    assert finding.status == FindingStatus.ANALYSIS_REFUSED


def test_same_input_reuses_previous_analysis(env):
    session, project, vault, fake, gateway, checkout = env
    add_triaged(session, project, name="lodash")
    fake.reply_json(AFFECTED)
    analyze(session, project, vault, gateway, checkout)

    second = add_triaged(session, project, name="lodash2", key="k")
    # 다른 Finding이지만 판별 캐시 키가 같으면 분석도 재사용한다.
    session.scalar(
        select(TriageResult).where(TriageResult.finding_id == second.id)
    ).cache_key = "k-lodash"
    session.commit()
    summary = analyze(session, project, vault, gateway, checkout)
    assert summary.cache_hits == 1
    assert len(fake.requests) == 1


def test_budget_exhausted_marks_unanalyzed(env):
    session, project, vault, fake, gateway, checkout = env
    workspace = gateway.workspace
    workspace.monthly_budget_usd = 0.000001
    session.add(
        LlmUsage(
            workspace_id=workspace.id, provider="anthropic", model="x", stage="haiku", cost_usd=1
        )
    )
    session.commit()
    finding = add_triaged(session, project)
    summary = analyze(session, project, vault, gateway, checkout)
    session.refresh(finding)
    assert summary.budget_stopped == 1
    assert finding.status == FindingStatus.UNANALYZED
    assert fake.requests == []


def test_audit_mismatch_raises_auto_close_threshold(env, monkeypatch):
    session, project, vault, fake, gateway, checkout = env
    monkeypatch.setattr(analysis_run, "AUDIT_MIN_SAMPLES", 1)
    finding = add_triaged(session, project, audit=True)
    fake.reply_json(AFFECTED)
    summary = analyze(session, project, vault, gateway, checkout)
    session.refresh(finding)
    assert summary.audit_mismatches == 1
    assert finding.verdict == "affected"  # 자동 종결이 틀렸으므로 되살린다
    assert gateway.workspace.model_settings["auto_close_threshold"] == 0.92


def test_many_light_analyses_go_to_batch_api(env):
    session, project, vault, fake, gateway, checkout = env
    findings = [add_triaged(session, project, name=f"pkg{i}") for i in range(3)]
    urgent = add_triaged(session, project, name="urgent", severe=True)
    fake.reply_json(AFFECTED)  # 긴급 건은 실시간으로 분석한다

    summary = analyze(session, project, vault, gateway, checkout, batch_threshold=3)

    assert summary.batched == 3
    assert len(fake.batch_requests) == 3
    assert fake.batch_requests[0]["params"]["model"] == "claude-haiku-5-5"
    session.refresh(urgent)
    assert urgent.verdict == "affected"
    for finding in findings:
        session.refresh(finding)
        assert finding.status == FindingStatus.ANALYZING

    # 아직 끝나지 않았으면 아무것도 바꾸지 않는다.
    workspace = gateway.workspace
    assert analysis_run.collect_batches(session, workspace, vault, gateway)["collected"] == 0

    fake.batch_status = "ended"
    fake.batch_succeeds(f"finding-{findings[0].id}", NOT_AFFECTED, input_tokens=10_000)
    fake.batch_succeeds(f"finding-{findings[1].id}", UNCERTAIN)
    fake.batch_errors(f"finding-{findings[2].id}")
    result = analysis_run.collect_batches(session, workspace, vault, gateway)

    assert result["collected"] == 2
    assert result["projects_to_analyze"] == [project.id]
    statuses = []
    for finding in findings:
        session.refresh(finding)
        statuses.append((finding.status, finding.verdict))
    assert statuses == [
        (FindingStatus.ANALYZED, "not_affected"),
        (FindingStatus.TRIAGED, None),  # Sonnet으로 올려 다시 분석
        (FindingStatus.TRIAGED, None),  # 실패 → 다음에 실시간으로
    ]
    latest = session.scalar(
        select(TriageResult)
        .where(TriageResult.finding_id == findings[1].id)
        .order_by(TriageResult.id.desc())
    )
    assert latest.route == "sonnet"
    batch_usage = session.scalar(select(LlmUsage).where(LlmUsage.batch.is_(True)))
    # 10,000 × $0.10 + 200 × $0.50, 50% 할인
    assert float(batch_usage.cost_usd) == pytest.approx(0.00055)
    assert session.scalar(select(AnalysisBatch)).status == "ended"
    assert BATCH_ID


def test_repo_tools_stay_inside_checkout(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("import yaml\nyaml.load(data)\n")
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "i.js").write_text("yaml.load")
    (tmp_path / "secret.txt").write_text("top secret")
    tools = deep.RepoTools(root)

    assert tools.run("read_file", {"path": "../secret.txt", "start_line": 1, "end_line": 5})[1]
    assert tools.run("read_file", {"path": "/etc/passwd", "start_line": 1, "end_line": 5})[1]
    output, error = tools.run("read_file", {"path": "src/a.py", "start_line": 2, "end_line": 9})
    assert not error and "2: yaml.load(data)" in output and "1: import" not in output
    output, _ = tools.run("search_code", {"pattern": r"yaml\.load", "path_prefix": ""})
    assert output == "src/a.py:2: yaml.load(data)"
    assert tools.run("search_code", {"pattern": "(", "path_prefix": ""})[1]
    output, _ = tools.run("list_dir", {"path": ""})
    assert output == "src/"
    assert tools.run("nope", {})[1]


def test_light_outcome_parsing():
    class Message:
        stop_reason = "end_turn"
        content = [type("B", (), {"type": "text", "text": "not json"})()]

    assert light.outcome_from_message(Message()).verdict == "error"


def test_collect_batches_survives_missing_key(env):
    from autocve.credentials.service import delete_credential

    session, project, vault, fake, gateway, checkout = env
    session.add(AnalysisBatch(workspace_id=gateway.workspace.id, batch_id=BATCH_ID, model="m"))
    session.commit()
    delete_credential(session, gateway.workspace, Provider.ANTHROPIC)
    fresh = LlmGateway(session, gateway.workspace, vault, fake.factory)
    assert analysis_run.collect_batches(session, gateway.workspace, vault, fresh)["collected"] == 0

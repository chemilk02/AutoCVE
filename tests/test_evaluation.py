import json
import subprocess
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace, save_credential
from autocve.ecosystems import purl
from autocve.evaluation import calibrate, dataset, experiment, metrics, report
from autocve.evaluation.dataset import Case, DatasetError
from autocve.feedback import apply_feedback
from autocve.llm.gateway import LlmGateway
from autocve.models import (
    Advisory,
    Analysis,
    Component,
    FeedbackAction,
    Finding,
    FindingStatus,
    LlmUsage,
    Project,
    Provider,
    TriageResult,
)
from autocve.security.keyvault import KeyVault
from tests.anthropic_fakes import FakeAnthropic
from tests.fakes import FakeValidator
from tests.osv_fixtures import advisory

REPO = "https://github.com/acme/web"


@pytest.fixture
def env(session_factory, settings):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        project = Project(workspace_id=workspace.id, name="web", repo_url=REPO)
        session.add(project)
        session.commit()
        yield session, workspace, project, vault


def add(
    session,
    project,
    name,
    *,
    verdict=None,
    ecosystem="npm",
    aliases=None,
    status=FindingStatus.ANALYZED,
):
    record = advisory(f"GHSA-{name}", name, "9.9.9", ecosystem=ecosystem, aliases=aliases or [])
    upsert_advisory(session, record)
    component = Component(
        project_id=project.id,
        locator=name,
        purl=purl(ecosystem, name, "1.0.0"),
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        direct=True,
        scope="prod",
        manifest_path="m",
    )
    session.add(component)
    session.flush()
    finding = Finding(
        project_id=project.id,
        component_id=component.id,
        advisory_id=record["id"],
        verdict=verdict,
        status=status,
    )
    session.add(finding)
    session.commit()
    return finding


def test_dataset_load_and_validation(tmp_path):
    path = tmp_path / "cases.json"
    cases = [Case(REPO, "GHSA-1", "lodash", "affected", "note")]
    path.write_text(dataset.dump(cases))
    assert dataset.load(path) == cases

    path.write_text(
        json.dumps(
            {"cases": [{"repo_url": REPO, "advisory_id": "x", "package": "p", "expected": "maybe"}]}
        )
    )
    with pytest.raises(DatasetError, match="expected"):
        dataset.load(path)
    path.write_text(json.dumps({"cases": [{"repo_url": REPO}]}))
    with pytest.raises(DatasetError, match="advisory_id"):
        dataset.load(path)


def test_resolve_by_alias_and_normalized_name(env):
    session, _, project, _ = env
    finding = add(session, project, "pyyaml", ecosystem="PyPI", aliases=["CVE-2020-1747"])
    assert dataset.resolve(session, Case(REPO, "CVE-2020-1747", "PyYAML", "affected")) == [finding]
    assert dataset.resolve(session, Case(REPO, "GHSA-pyyaml", "pyyaml", "affected")) == [finding]
    assert (
        dataset.resolve(
            session, Case("https://github.com/other/x", "GHSA-pyyaml", "pyyaml", "affected")
        )
        == []
    )


def test_feedback_becomes_dataset_and_accuracy(env):
    session, workspace, project, _ = env
    tp = add(session, project, "a", verdict="affected")
    fn = add(session, project, "b", verdict="not_affected")
    fp = add(session, project, "c", verdict="affected")
    tn = add(session, project, "d", verdict="not_affected")
    add(session, project, "e", verdict="uncertain")
    session.add(TriageResult(finding_id=fn.id, provider="typesafe", action="auto_close"))
    session.commit()
    apply_feedback(session, tp, FeedbackAction.CONFIRM)
    apply_feedback(
        session, fn, FeedbackAction.FIXED
    )  # 시스템은 영향 없음이라 했지만 실제로는 고쳐야 했음
    apply_feedback(session, fp, FeedbackAction.NOT_AFFECTED, "내부 전용")
    apply_feedback(session, tn, FeedbackAction.NOT_AFFECTED, "미사용")

    cases = dataset.from_feedback(session, workspace)
    assert {(c.package, c.expected) for c in cases} == {
        ("a", "affected"),
        ("b", "affected"),
        ("c", "not_affected"),
        ("d", "not_affected"),
    }
    acc = metrics.current_accuracy(session, cases)
    # 사용자 처리 후가 아니라 처리 직전의 시스템 판정으로 채점한다.
    assert (acc.true_positive, acc.false_negative, acc.false_positive, acc.true_negative) == (
        1,
        1,
        1,
        1,
    )
    assert acc.false_negative_rate == 0.5
    assert acc.auto_closed_affected == 1
    assert "놓친 비율" in report.accuracy_section("t", acc)


def test_success_metrics(env):
    session, workspace, project, _ = env
    now = datetime.now(UTC)
    findings = [add(session, project, f"p{i}", verdict="affected") for i in range(4)]
    actions = ["auto_close", "dev_only", "analyze", "analyze"]
    for finding, action in zip(findings, actions, strict=True):
        session.add(
            TriageResult(
                finding_id=finding.id,
                provider="typesafe",
                action=action,
                route="opus" if action == "analyze" else None,
            )
        )
    session.add(
        Analysis(
            finding_id=findings[2].id, model="claude-opus-5-5", verdict="affected", cache_key=""
        )
    )
    session.add(
        LlmUsage(
            workspace_id=workspace.id,
            provider="anthropic",
            model="m",
            stage="opus",
            cost_usd=Decimal("0.4"),
        )
    )
    session.add(
        LlmUsage(
            workspace_id=workspace.id,
            provider="anthropic",
            model="m",
            stage="eval",
            cost_usd=Decimal("9"),
        )
    )
    # OSV 반영 30분 뒤 알림
    project.created_at = now - timedelta(days=1)
    findings[2].notified_at = now
    session.commit()
    session.get(Advisory, findings[2].advisory_id).modified = now - timedelta(minutes=30)
    session.commit()

    by_key = {m.key: m for m in metrics.success_metrics(session, workspace)}
    assert by_key["no_llm_rate"].value == 0.5 and by_key["no_llm_rate"].passed is False
    assert by_key["opus_rate"].value == 0.25
    assert by_key["cost_per_finding"].value == pytest.approx(0.1)  # eval 비용은 빼고 0.4 / 4
    assert by_key["notify_lag_p90"].value == pytest.approx(0.5, abs=0.01)
    assert by_key["notify_lag_p90"].passed is True
    table = report.metrics_table(list(by_key.values()))
    assert "| Claude 호출 없이 종결된 후보 비율 | 50.0% | 60% 이상 | 미달 |" in table


def test_calibration_recommends_largest_safe_threshold():
    data = []
    # 확률이 높을수록 실제로 영향 없음인 경우가 많도록 만든다.
    for i in range(30):
        p = 0.80 + i * 0.0066
        expected = "affected" if i < 6 else "not_affected"
        data.append(calibrate.Sample(p, True, False, expected))
    data.append(calibrate.Sample(0.99, True, True, "affected"))  # severe는 자동 종결 대상이 아니다
    result = calibrate.calibrate(data)
    assert result.recommended is not None
    chosen = next(p for p in result.points if p.threshold == result.recommended)
    assert chosen.error_rate <= 0.05
    looser = [p for p in result.points if p.threshold < result.recommended]
    assert all(p.error_rate is None or p.error_rate > 0.05 for p in looser)


def test_calibration_needs_enough_samples():
    result = calibrate.calibrate([calibrate.Sample(0.95, True, False, "not_affected")] * 5)
    assert result.recommended is None and "최소 20건" in result.reason
    bad = calibrate.calibrate([calibrate.Sample(0.995, True, False, "affected")] * 25)
    assert bad.recommended == 0.99


def test_calibration_samples_and_apply(env):
    session, workspace, project, _ = env
    finding = add(session, project, "a", verdict="not_affected")
    session.add(
        TriageResult(
            finding_id=finding.id,
            provider="rules",
            action="analyze",
            exposure_probs={"not_affected": 0.9},
        )
    )
    session.add(
        TriageResult(
            finding_id=finding.id,
            provider="openrouter",
            action="auto_close",
            exposure_probs={"not_affected": 0.93},
            route_probs={"no_llm": 0.8, "haiku": 0.2},
            evidence={"severe": False},
        )
    )
    session.commit()
    (sample,) = calibrate.samples(session, [Case(REPO, "GHSA-a", "a", "not_affected")])
    assert (sample.not_affected, sample.route_no_llm, sample.severe) == (0.93, True, False)
    calibrate.apply(session, workspace, 0.95)
    assert workspace.model_settings["auto_close_threshold"] == 0.95


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_experiment_current_and_opus_low(env, settings, tmp_path):
    session, workspace, project, vault = env
    repo = tmp_path / "src"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "index.js").write_text("require('a')\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")
    project.repo_url = str(repo)
    session.commit()
    finding = add(session, project, "a", verdict="not_affected")
    session.add(
        LlmUsage(
            workspace_id=workspace.id,
            provider="anthropic",
            model="m",
            stage="haiku",
            finding_id=finding.id,
            cost_usd=Decimal("0.001"),
        )
    )
    session.commit()
    cases = [Case(str(repo), "GHSA-a", "a", "affected")]

    current = experiment.run_current(session, cases)
    assert current.accuracy.false_negative == 1
    assert current.cost_usd == Decimal("0.001")

    save_credential(
        session, vault, workspace, Provider.ANTHROPIC, "sk-ant-x-12345678", FakeValidator()
    )
    fake = FakeAnthropic()
    fake.reply_json(
        {
            "verdict": "affected",
            "confidence": 0.8,
            "rationale": "r",
            "evidence": [],
            "data_flow": [],
        },
        model="claude-opus-5-5",
        input_tokens=10_000,
        output_tokens=500,
    )
    gateway = LlmGateway(session, workspace, vault, fake.factory)
    opus = experiment.run_opus_low(
        session, cases, workspace, vault, settings, gateway=gateway, allow_local=True
    )
    assert opus.accuracy.true_positive == 1
    assert fake.requests[0]["model"] == "claude-opus-5-5"
    assert fake.requests[0]["output_config"]["effort"] == "low"
    eval_usage = session.scalar(select(LlmUsage).where(LlmUsage.stage == "eval"))
    assert opus.cost_usd == eval_usage.cost_usd == Decimal("0.050000")  # 10K × $4 + 500 × $20
    assert "opus_low" in report.experiment_section([current, opus])
    assert experiment.estimate_cost(session, cases) == (1, Decimal("0.50"))


def test_cli_eval(settings, monkeypatch, capsys, session_factory):
    from autocve import cli, config

    monkeypatch.setenv("AUTOCVE_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("AUTOCVE_MASTER_KEY", settings.master_key.get_secret_value())
    config.get_settings.cache_clear()
    try:
        assert cli.main(["eval", "report"]) == 0
        assert "## 성공 지표" in capsys.readouterr().out
        assert cli.main(["eval", "export-feedback"]) == 0
        assert json.loads(capsys.readouterr().out) == {"cases": []}
        assert cli.main(["eval", "experiment", "--strategy", "opus_low"]) == 1
        assert "--yes" in capsys.readouterr().err
        assert cli.main(["eval", "calibrate", "--apply"]) == 1
    finally:
        config.get_settings.cache_clear()


def test_evaluation_page(client):
    page = client.get("/evaluation")
    assert page.status_code == 200
    assert "성공 지표" in page.text and "아직 처리한 Finding이 없습니다" in page.text


def test_opus_rate_not_judged_without_analyses(env):
    session, workspace, project, _ = env
    finding = add(session, project, "a")
    session.add(
        TriageResult(finding_id=finding.id, provider="rules", action="analyze", route="haiku")
    )
    session.commit()
    opus = next(m for m in metrics.success_metrics(session, workspace) if m.key == "opus_rate")
    assert (opus.value, opus.passed, opus.detail) == (None, None, "Claude 분석 기록 없음")

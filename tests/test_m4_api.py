import pytest
from sqlalchemy import select

from autocve.models import Feedback, Finding, FindingStatus, LlmUsage, Project, TriageResult
from autocve.notify.channels import NotifyError
from tests.test_projects_api import test_detail_shows_findings_with_signals as seed_finding


@pytest.fixture
def finding_id(client, session_factory):
    seed_finding(client, session_factory)
    with session_factory() as session:
        return session.scalar(select(Finding.id))


def test_finding_detail_page(client, session_factory, finding_id):
    with session_factory() as session:
        finding = session.get(Finding, finding_id)
        finding.risk_score, finding.grade = 52.7, "high"
        finding.risk_factors = {
            "severity": 0.75,
            "cvss": 7.5,
            "exploit": 1.0,
            "epss": 0.03,
            "in_kev": True,
            "reachability": 0.6,
            "verdict": None,
            "exposure": 1.0,
            "malicious": False,
        }
        session.add(
            TriageResult(
                finding_id=finding_id,
                provider="rules",
                action="analyze",
                route="haiku",
                evidence={
                    "prod_import_count": 1,
                    "test_import_count": 0,
                    "symbols_searched": ["template"],
                    "call_site_count": 1,
                    "snippets": [
                        {"path": "a.js", "line": 3, "symbol": "template", "code": "_.template(x)"}
                    ],
                },
            )
        )
        session.commit()
    page = client.get(f"/findings/{finding_id}").text
    assert "High 53" in page
    assert "CISA KEV 등재" in page
    assert "_.template(x)" in page
    assert "분석 대기 → Haiku" in page
    assert client.get("/findings/999").status_code == 404


def test_feedback_actions(client, session_factory, finding_id):
    response = client.post(f"/findings/{finding_id}/feedback", data={"action": "not_affected"})
    assert response.status_code == 400
    assert "사유" in response.text

    client.post(
        f"/findings/{finding_id}/feedback",
        data={"action": "not_affected", "reason": "관리자 전용 도구에서만 사용"},
    )
    with session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert (finding.status, finding.verdict) == (FindingStatus.DISMISSED, "not_affected")
        assert finding.grade == "info"  # 다시 계산됨
        feedback = session.scalar(select(Feedback))
        assert feedback.system_verdict is None and feedback.reason.startswith("관리자")

    client.post(f"/findings/{finding_id}/feedback", data={"action": "reopen"})
    client.post(f"/findings/{finding_id}/feedback", data={"action": "confirm"})
    with session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert (finding.status, finding.verdict) == (FindingStatus.ANALYZED, "affected")

    client.post(f"/findings/{finding_id}/feedback", data={"action": "fixed"})
    with session_factory() as session:
        assert session.get(Finding, finding_id).status == FindingStatus.RESOLVED
        assert session.query(Feedback).count() == 4
    assert client.post(f"/findings/{finding_id}/feedback", data={"action": "x"}).status_code == 422


def test_slack_webhook_format_is_checked():
    from autocve.credentials.validators import validate_slack_webhook
    from autocve.models import CredentialStatus

    assert validate_slack_webhook("https://evil.example/x").status == CredentialStatus.INVALID
    assert validate_slack_webhook("https://hooks.slack.com/services/T/B/X").status == "valid"


def test_notification_settings(client, session_factory):
    page = client.get("/settings/notifications")
    assert page.status_code == 200 and "SMTP가 설정되지 않아" in page.text

    bad = client.post("/settings/notifications", data={"email_to": "not-an-email"})
    assert bad.status_code == 400

    ok = client.post(
        "/settings/notifications",
        data={"immediate_grade": "critical", "email_to": "a@x.com, b@y.org", "digest": "on"},
    )
    assert ok.status_code == 200
    with session_factory() as session:
        from autocve.models import Workspace

        settings = session.scalar(select(Workspace)).notification_settings
    assert settings == {
        "immediate_grade": "critical",
        "email_to": ["a@x.com", "b@y.org"],
        "digest": True,
    }


def test_test_notification_uses_channel_factory(settings, validators, queue):
    from fastapi.testclient import TestClient

    from autocve.api.app import create_app

    class Channel:
        def __init__(self, name, fail=False):
            self.name, self.fail, self.sent = name, fail, []

        def send(self, message):
            if self.fail:
                raise NotifyError("HTTP 404")
            self.sent.append(message)

    channels = [Channel("slack")]
    app = create_app(settings, validators, queue, channel_factory=lambda *a: channels)
    with TestClient(app) as client:
        response = client.post("/settings/notifications/test")
        assert response.status_code == 200 and "테스트 알림을 보냈습니다" in response.text
        assert channels[0].sent[0].subject == "[AutoCVE] 알림 테스트"
        channels.append(Channel("email", fail=True))
        failed = client.post("/settings/notifications/test")
        assert failed.status_code == 502 and "email: HTTP 404" in failed.text
        channels.clear()
        assert client.post("/settings/notifications/test").status_code == 400


def test_usage_page(client, session_factory, finding_id):
    with session_factory() as session:
        project = session.scalar(select(Project))
        session.add_all(
            [
                LlmUsage(
                    workspace_id=project.workspace_id,
                    provider="typesafe",
                    model="jev",
                    stage="jev",
                    input_tokens=800,
                    cost_usd=0.00003,
                ),
                LlmUsage(
                    workspace_id=project.workspace_id,
                    provider="anthropic",
                    model="claude-haiku-5-5",
                    stage="haiku",
                    input_tokens=1000,
                    cache_read_input_tokens=3000,
                    cost_usd=0.0005,
                ),
                TriageResult(finding_id=finding_id, provider="typesafe", action="auto_close"),
            ]
        )
        session.commit()
    page = client.get("/usage").text
    assert "$0.0005" in page
    assert "100%" in page  # 판별 1건 중 1건이 Claude 없이 종결
    assert "75%" in page  # 캐시 적중 3000 / 4000
    assert "JEV 판별" in page and "Haiku 분석" in page

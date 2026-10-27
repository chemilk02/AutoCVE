import json
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace, save_credential
from autocve.ecosystems import purl
from autocve.models import (
    Component,
    Finding,
    FindingStatus,
    NotificationLog,
    Project,
    Provider,
    TriageResult,
)
from autocve.notify import service
from autocve.notify.channels import EmailChannel, NotifyError, SlackChannel, SmtpConfig
from autocve.notify.messages import MAX_ITEMS, Item, Message
from autocve.security.keyvault import KeyVault
from tests.fakes import FakeValidator
from tests.osv_fixtures import advisory


class RecordingChannel:
    name = "fake"

    def __init__(self, fail=False):
        self.sent: list[Message] = []
        self.fail = fail

    def send(self, message):
        if self.fail:
            raise NotifyError("down")
        self.sent.append(message)


def item(i=0, **overrides):
    values = {
        "grade": "high",
        "score": 52.7,
        "project": "web",
        "package": "lodash@4.17.11",
        "advisory_id": f"GHSA-{i}",
        "summary": "Prototype <b>pollution</b>",
        "verdict": "affected",
        "rationale": "render.js에서 사용",
        "url": f"http://app/findings/{i}",
    }
    values.update(overrides)
    return Item(**values)


def test_slack_channel_posts_escaped_blocks():
    seen = []

    def handler(request):
        seen.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200, text="ok")

    channel = SlackChannel(
        "https://hooks.slack.com/services/T/B/X",
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    channel.send(Message("subject", "intro", [item()]))
    url, payload = seen[0]
    assert url == "https://hooks.slack.com/services/T/B/X"
    assert payload["text"] == "subject"
    body = payload["blocks"][1]["text"]["text"]
    assert "&lt;b&gt;" in body and "<b>" not in body
    assert "<http://app/findings/0|" in body


def test_slack_rejects_non_slack_url_and_reports_errors():
    with pytest.raises(NotifyError):
        SlackChannel("https://evil.example/hook")
    failing = SlackChannel(
        "https://hooks.slack.com/x",
        httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(404, text="no_service"))
        ),
    )
    with pytest.raises(NotifyError, match="404"):
        failing.send(Message("s", "i"))


def test_email_channel_uses_starttls_and_login():
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def send_message(self, message):
            calls.append(("send", message["To"], message["Subject"], message.get_content()))

    config = SmtpConfig("smtp.test", 587, "user", "pw", "autocve@test")
    EmailChannel(config, ["a@x.com", "b@x.com"], smtp_factory=FakeSMTP).send(
        Message("제목", "intro", [item()])
    )
    assert calls[0] == ("connect", "smtp.test", 587)
    assert ("starttls",) in calls and ("login", "user", "pw") in calls
    _, to, subject, body = calls[-1]
    assert to == "a@x.com, b@x.com" and subject == "제목"
    assert "GHSA-0" in body and "render.js에서 사용" in body


def test_message_caps_item_count():
    message = Message("s", "i", [item(i) for i in range(MAX_ITEMS + 5)])
    assert "외 5건" in message.plain_text()
    assert len(message.slack_blocks()) == MAX_ITEMS + 2


@pytest.fixture
def env(session_factory, settings):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        project = Project(workspace_id=workspace.id, name="web", repo_url="https://github.com/o/w")
        session.add(project)
        session.commit()
        yield session, workspace, project, vault


def make_finding(
    session, project, name, *, grade, status=FindingStatus.ANALYZED, verdict="affected", action=None
):
    upsert_advisory(session, advisory(f"GHSA-{name}", name, "9.9.9"))
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
        advisory_id=f"GHSA-{name}",
        status=status,
        verdict=verdict,
        grade=grade,
        risk_score={"critical": 90, "high": 50, "medium": 30, "low": 10, "info": 1}[grade],
    )
    session.add(finding)
    session.flush()
    if action:
        session.add(TriageResult(finding_id=finding.id, provider="rules", action=action))
    session.commit()
    return finding


def with_anthropic_key(session, workspace, vault):
    save_credential(
        session, vault, workspace, Provider.ANTHROPIC, "sk-ant-x-12345678", FakeValidator()
    )


def test_immediate_alert_selection(env, settings):
    session, workspace, project, vault = env
    with_anthropic_key(session, workspace, vault)
    critical = make_finding(session, project, "a", grade="critical")
    high = make_finding(session, project, "b", grade="high")
    make_finding(session, project, "c", grade="medium")
    make_finding(session, project, "d", grade="high", verdict="not_affected")
    make_finding(session, project, "e", grade="high", status=FindingStatus.TRIAGED, verdict=None)
    make_finding(session, project, "f", grade="high", status=FindingStatus.DISMISSED)
    malicious = make_finding(
        session, project, "g", grade="critical", status=FindingStatus.TRIAGED, action="malicious"
    )
    channel = RecordingChannel()

    sent = service.notify_immediate(session, workspace, vault, settings, channels=[channel])

    assert sent == 3
    (message,) = channel.sent
    assert [i.advisory_id for i in message.items] == ["GHSA-a", "GHSA-g", "GHSA-b"]
    for finding in (critical, high, malicious):
        session.refresh(finding)
        assert finding.notified_at is not None
    assert critical.status == FindingStatus.NOTIFIED
    assert malicious.status == FindingStatus.TRIAGED  # 분석 대상이 아니므로 상태는 그대로
    assert session.scalar(select(NotificationLog)).ok

    # 이미 알린 것은 다시 보내지 않는다. 등급이 올라가면 다시 보낸다.
    assert service.notify_immediate(session, workspace, vault, settings, channels=[channel]) == 0
    high.grade = "critical"
    session.commit()
    assert service.notify_immediate(session, workspace, vault, settings, channels=[channel]) == 1


def test_pending_analysis_waits_unless_no_claude_key(env, settings):
    session, workspace, project, vault = env
    make_finding(session, project, "a", grade="high", status=FindingStatus.TRIAGED, verdict=None)
    channel = RecordingChannel()
    # Claude 키가 없으면 분석이 영영 안 되므로 판별 결과로 알린다.
    assert service.notify_immediate(session, workspace, vault, settings, channels=[channel]) == 1


def test_critical_only_threshold(env, settings):
    session, workspace, project, vault = env
    workspace.notification_settings = {"immediate_grade": "critical"}
    session.commit()
    make_finding(session, project, "a", grade="high")
    assert (
        service.notify_immediate(session, workspace, vault, settings, channels=[RecordingChannel()])
        == 0
    )


def test_failed_delivery_keeps_findings_pending(env, settings):
    session, workspace, project, vault = env
    finding = make_finding(session, project, "a", grade="critical")
    assert (
        service.notify_immediate(
            session, workspace, vault, settings, channels=[RecordingChannel(fail=True)]
        )
        == 0
    )
    session.refresh(finding)
    assert finding.notified_at is None
    log = session.scalar(select(NotificationLog))
    assert not log.ok and log.error == "down"


def test_digest_covers_lower_grades_once(env, settings):
    session, workspace, project, vault = env
    make_finding(session, project, "a", grade="medium")
    make_finding(
        session,
        project,
        "b",
        grade="low",
        status=FindingStatus.TRIAGED,
        verdict=None,
        action="dev_only",
    )
    make_finding(session, project, "c", grade="info")
    make_finding(session, project, "d", grade="high")
    channel = RecordingChannel()
    with_anthropic_key(session, workspace, vault)

    assert service.send_digest(session, workspace, vault, settings, channels=[channel]) == 2
    assert {i.advisory_id for i in channel.sent[0].items} == {"GHSA-a", "GHSA-b"}
    assert service.send_digest(session, workspace, vault, settings, channels=[channel]) == 0

    workspace.notification_settings = {"digest": False}
    session.commit()
    make_finding(session, project, "e", grade="medium")
    assert service.send_digest(session, workspace, vault, settings, channels=[channel]) == 0


def test_channels_from_settings(env, settings):
    session, workspace, project, vault = env
    assert service.channels_for(session, workspace, vault, settings) == []
    save_credential(
        session,
        vault,
        workspace,
        Provider.SLACK,
        "https://hooks.slack.com/services/T/B/X",
        FakeValidator(),
    )
    workspace.notification_settings = {"email_to": ["a@x.com"]}
    session.commit()
    configured = settings.model_copy(update={"smtp_host": "smtp.test", "smtp_from": "a@test"})
    names = [c.name for c in service.channels_for(session, workspace, vault, configured)]
    assert names == ["slack", "email"]
    assert datetime.now(UTC)

"""알림 대상 선정과 전송 (§F9).

- 즉시 알림: 설정한 등급(기본 High) 이상. 이미 알린 Finding도 등급이 올라가면 다시 알린다.
- 일일 요약: 즉시 알림 기준 아래(Medium, Low) 중 아직 알리지 않은 것.
- 분석 대기 중인 후보는 결과가 나올 때까지 기다린다. Claude 키가 없으면 판별 결과로 알린다.
- 영향 없음으로 판정되었거나 사용자가 닫은 Finding은 알리지 않는다.
"""

import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.config import Settings
from autocve.credentials.service import CredentialError, load_secret
from autocve.llm.gateway import LlmGateway
from autocve.models import (
    Advisory,
    Analysis,
    Component,
    Finding,
    FindingStatus,
    NotificationLog,
    Project,
    Provider,
    TriageResult,
    Verdict,
    Workspace,
)
from autocve.notify.channels import (
    Channel,
    EmailChannel,
    NotifyError,
    SlackChannel,
    SmtpConfig,
)
from autocve.notify.messages import Item, Message
from autocve.security.keyvault import KeyVault
from autocve.triage.policy import Action

logger = logging.getLogger(__name__)

GRADE_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_IMMEDIATE_GRADE = "high"
DIGEST_MIN_GRADE = "low"

# 결과가 나온 상태. TRIAGED·ANALYZING은 분석을 기다린다.
SETTLED = {
    FindingStatus.ANALYZED,
    FindingStatus.NOTIFIED,
    FindingStatus.UNANALYZED,
    FindingStatus.ANALYSIS_REFUSED,
}


def channels_for(
    session: Session,
    workspace: Workspace,
    vault: KeyVault,
    settings: Settings,
    http: httpx.Client | None = None,
) -> list[Channel]:
    channels: list[Channel] = []
    try:
        webhook = load_secret(session, vault, workspace, Provider.SLACK)
    except CredentialError as e:
        logger.warning("Slack 웹훅을 읽을 수 없습니다: %s", e)
        webhook = None
    if webhook:
        try:
            channels.append(SlackChannel(webhook, http))
        except NotifyError as e:
            logger.warning("%s", e)
    recipients = (workspace.notification_settings or {}).get("email_to") or []
    if settings.smtp_host and settings.smtp_from and recipients:
        channels.append(
            EmailChannel(
                SmtpConfig(
                    host=settings.smtp_host,
                    port=settings.smtp_port,
                    username=settings.smtp_username,
                    password=settings.smtp_password.get_secret_value()
                    if settings.smtp_password
                    else None,
                    sender=settings.smtp_from,
                    starttls=settings.smtp_starttls,
                ),
                recipients,
            )
        )
    return channels


def _items(session: Session, rows, settings: Settings) -> list[Item]:
    items = []
    for finding, component, advisory, project in rows:
        analysis = session.scalar(
            select(Analysis).where(Analysis.finding_id == finding.id).order_by(Analysis.id.desc())
        )
        items.append(
            Item(
                grade=finding.grade or "info",
                score=finding.risk_score or 0.0,
                project=project.name,
                package=f"{component.name}@{component.version}",
                advisory_id=advisory.id,
                summary=(advisory.summary or "")[:300],
                verdict=finding.verdict,
                rationale=(analysis.rationale if analysis else "")[:500],
                url=f"{settings.public_url.rstrip('/')}/findings/{finding.id}",
            )
        )
    return items


def _candidates(session: Session, workspace: Workspace, vault: KeyVault):
    statuses = set(SETTLED)
    if not LlmGateway(session, workspace, vault).available():
        statuses.add(FindingStatus.TRIAGED)
    rows = session.execute(
        select(Finding, Component, Advisory, Project)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Project, Project.id == Finding.project_id)
        .where(
            Project.workspace_id == workspace.id,
            Finding.grade.is_not(None),
            (Finding.verdict.is_(None)) | (Finding.verdict != Verdict.NOT_AFFECTED),
        )
        .order_by(Finding.risk_score.desc())
    ).all()
    return [r for r in rows if r[0].status in statuses or _settled_at_triage(session, r[0])]


def _settled_at_triage(session: Session, finding: Finding) -> bool:
    """악성 패키지, dev 전용처럼 판별 단계에서 끝나 분석을 기다리지 않는 Finding."""
    if finding.status != FindingStatus.TRIAGED:
        return False
    triage = session.scalar(
        select(TriageResult)
        .where(TriageResult.finding_id == finding.id)
        .order_by(TriageResult.id.desc())
    )
    return triage is not None and triage.action in (Action.MALICIOUS, Action.DEV_ONLY)


def _send(
    session: Session,
    workspace: Workspace,
    channels: list[Channel],
    message: Message,
    kind: str,
    finding_ids: list[int],
) -> bool:
    delivered = False
    for channel in channels:
        try:
            channel.send(message)
            delivered = True
            error = None
        except NotifyError as e:
            error = str(e)[:500]
            logger.warning("%s 알림 실패: %s", channel.name, error)
        session.add(
            NotificationLog(
                workspace_id=workspace.id,
                channel=channel.name,
                kind=kind,
                finding_ids=finding_ids,
                ok=error is None,
                error=error,
            )
        )
    session.commit()
    return delivered


def _mark(session: Session, findings: list[Finding]) -> None:
    now = datetime.now(UTC)
    for finding in findings:
        finding.notified_at = now
        finding.notified_grade = finding.grade
        if finding.status == FindingStatus.ANALYZED:
            finding.status = FindingStatus.NOTIFIED
    session.commit()


def notify_immediate(
    session: Session,
    workspace: Workspace,
    vault: KeyVault,
    settings: Settings,
    *,
    channels: list[Channel] | None = None,
) -> int:
    threshold = (workspace.notification_settings or {}).get(
        "immediate_grade", DEFAULT_IMMEDIATE_GRADE
    )
    minimum = GRADE_ORDER.get(threshold, GRADE_ORDER[DEFAULT_IMMEDIATE_GRADE])
    rows = [
        r
        for r in _candidates(session, workspace, vault)
        if GRADE_ORDER.get(r[0].grade, 0) >= minimum
        and (
            r[0].notified_grade is None
            or GRADE_ORDER.get(r[0].grade, 0) > GRADE_ORDER.get(r[0].notified_grade, 0)
        )
    ]
    if not rows:
        return 0
    channels = (
        channels if channels is not None else channels_for(session, workspace, vault, settings)
    )
    if not channels:
        return 0
    items = _items(session, rows, settings)
    top = items[0]
    message = Message(
        subject=f"[AutoCVE] 위험 취약점 {len(items)}건: {top.package} {top.advisory_id}",
        intro=f"*즉시 확인이 필요한 취약점 {len(items)}건*",
        items=items,
        footer=f"설정: {settings.public_url.rstrip('/')}/settings/notifications",
    )
    findings = [r[0] for r in rows]
    if _send(session, workspace, channels, message, "immediate", [f.id for f in findings]):
        _mark(session, findings)
        return len(findings)
    return 0


def send_digest(
    session: Session,
    workspace: Workspace,
    vault: KeyVault,
    settings: Settings,
    *,
    channels: list[Channel] | None = None,
) -> int:
    config = workspace.notification_settings or {}
    if config.get("digest") is False:
        return 0
    threshold = GRADE_ORDER.get(config.get("immediate_grade", DEFAULT_IMMEDIATE_GRADE), 3)
    rows = [
        r
        for r in _candidates(session, workspace, vault)
        if r[0].notified_at is None
        and GRADE_ORDER[DIGEST_MIN_GRADE] <= GRADE_ORDER.get(r[0].grade, 0) < threshold
    ]
    if not rows:
        return 0
    channels = (
        channels if channels is not None else channels_for(session, workspace, vault, settings)
    )
    if not channels:
        return 0
    items = _items(session, rows, settings)
    message = Message(
        subject=f"[AutoCVE] 일일 요약: 새 취약점 {len(items)}건",
        intro=f"*지난 요약 이후 새로 확인된 취약점 {len(items)}건*",
        items=items,
        footer=f"전체 목록: {settings.public_url.rstrip('/')}/projects",
    )
    findings = [r[0] for r in rows]
    if _send(session, workspace, channels, message, "digest", [f.id for f in findings]):
        _mark(session, findings)
        return len(findings)
    return 0


def send_test(session: Session, workspace: Workspace, channels: list[Channel]) -> dict[str, str]:
    message = Message(
        subject="[AutoCVE] 알림 테스트",
        intro="AutoCVE 알림 설정이 정상입니다.",
    )
    results = {}
    for channel in channels:
        try:
            channel.send(message)
            results[channel.name] = "ok"
        except NotifyError as e:
            results[channel.name] = str(e)
    session.add_all(
        NotificationLog(
            workspace_id=workspace.id,
            channel=name,
            kind="test",
            finding_ids=[],
            ok=result == "ok",
            error=None if result == "ok" else result[:500],
        )
        for name, result in results.items()
    )
    session.commit()
    return results

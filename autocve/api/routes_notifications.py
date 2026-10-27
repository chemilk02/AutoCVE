import re
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.api.deps import AppState, get_session, get_state, templates
from autocve.credentials import service
from autocve.credentials.service import CredentialError
from autocve.envsync import env_locks
from autocve.models import CredentialStatus, NotificationLog, Provider
from autocve.notify.service import send_test

router = APIRouter()

_EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
IMMEDIATE_GRADES = {"critical": "Critical만", "high": "High 이상"}


def _render(
    request: Request,
    session: Session,
    state: AppState,
    notice: tuple[str, str] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    workspace = service.get_or_create_default_workspace(session)
    logs = session.scalars(
        select(NotificationLog)
        .where(NotificationLog.workspace_id == workspace.id)
        .order_by(NotificationLog.id.desc())
        .limit(10)
    ).all()
    return templates.TemplateResponse(
        request,
        "settings_notifications.html",
        {
            "workspace": workspace,
            "config": workspace.notification_settings or {},
            "slack": service.get_credential(session, workspace, Provider.SLACK),
            "smtp_ready": bool(state.settings.smtp_host and state.settings.smtp_from),
            "grades": IMMEDIATE_GRADES,
            "locks": env_locks(state.settings),
            "logs": logs,
            "notice": notice,
        },
        status_code=status_code,
    )


@router.get("/settings/notifications", response_class=HTMLResponse)
def show(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    return _render(request, session, state)


@router.post("/settings/notifications", response_class=HTMLResponse)
def save(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
    immediate_grade: Annotated[str, Form()] = "high",
    email_to: Annotated[str, Form()] = "",
    digest: Annotated[str | None, Form()] = None,
    slack_webhook: Annotated[str, Form()] = "",
):
    workspace = service.get_or_create_default_workspace(session)
    locks = env_locks(state.settings)
    config = dict(workspace.notification_settings or {})
    # .env로 관리하는 항목은 폼 값을 무시하고 현재 값을 유지한다.
    if locks.notify_email:
        recipients = config.get("email_to") or []
    else:
        recipients = [e.strip() for e in re.split(r"[,\s;]+", email_to) if e.strip()]
    if locks.notify_grade:
        immediate_grade = config.get("immediate_grade", "high")
    digest_on = config.get("digest", True) if locks.notify_digest else digest == "on"
    bad = [e for e in recipients if not _EMAIL.match(e)]
    if bad or immediate_grade not in IMMEDIATE_GRADES or len(recipients) > 20:
        message = f"이메일 주소를 확인하세요: {', '.join(bad)}" if bad else "입력값을 확인하세요"
        return _render(request, session, state, ("error", message), 400)
    if slack_webhook.strip() and Provider.SLACK in locks.providers:
        message = "Slack Webhook은 .env의 AUTOCVE_SLACK_WEBHOOK_URL로 관리합니다"
        return _render(request, session, state, ("error", message), 409)
    if slack_webhook.strip():
        result = service.save_credential(
            session,
            state.vault,
            workspace,
            Provider.SLACK,
            slack_webhook,
            state.validators[Provider.SLACK],
        )
        if result.status == CredentialStatus.INVALID:
            return _render(request, session, state, ("error", result.message), 400)
    workspace.notification_settings = {
        "immediate_grade": immediate_grade,
        "email_to": recipients,
        "digest": digest_on,
    }
    session.commit()
    return _render(request, session, state, ("success", "알림 설정을 저장했습니다"))


@router.post("/settings/notifications/slack/delete", response_class=HTMLResponse)
def delete_slack(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    if Provider.SLACK in env_locks(state.settings).providers:
        message = "Slack Webhook은 .env의 AUTOCVE_SLACK_WEBHOOK_URL로 관리합니다"
        return _render(request, session, state, ("error", message), 409)
    workspace = service.get_or_create_default_workspace(session)
    service.delete_credential(session, workspace, Provider.SLACK)
    return _render(request, session, state, ("success", "Slack Webhook을 삭제했습니다"))


@router.post("/settings/notifications/test", response_class=HTMLResponse)
def test(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    workspace = service.get_or_create_default_workspace(session)
    try:
        channels = state.channel_factory(session, workspace, state.vault, state.settings)
    except CredentialError as e:
        return _render(request, session, state, ("error", str(e)), 400)
    if not channels:
        return _render(
            request, session, state, ("error", "설정된 알림 채널이 없습니다"), status_code=400
        )
    results = send_test(session, workspace, channels)
    failed = {k: v for k, v in results.items() if v != "ok"}
    if failed:
        detail = "; ".join(f"{k}: {v}" for k, v in failed.items())
        return _render(request, session, state, ("error", f"전송 실패 - {detail}"), 502)
    return _render(
        request, session, state, ("success", f"테스트 알림을 보냈습니다 ({', '.join(results)})")
    )

from decimal import Decimal, InvalidOperation
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from autocve.api.deps import AppState, get_session, get_state, templates
from autocve.credentials import service
from autocve.credentials.service import CredentialError
from autocve.credentials.validators import ValidationResult
from autocve.llm.gateway import budget_status
from autocve.models import JEV_PROVIDERS, CredentialStatus, JevProvider, Provider

router = APIRouter()

PROVIDER_LABELS = {
    Provider.ANTHROPIC: "Anthropic",
    Provider.TYPESAFE: "TypeSafe (JEV 직접)",
    Provider.OPENROUTER: "OpenRouter (JEV 경유)",
    Provider.GITHUB: "GitHub",
    Provider.SLACK: "Slack Webhook",
}
NOTICE_LEVELS = {
    CredentialStatus.VALID: "success",
    CredentialStatus.UNVERIFIED: "warning",
    CredentialStatus.INVALID: "error",
}


def _render(
    request: Request,
    session: Session,
    notice: tuple[str, str] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    workspace = service.get_or_create_default_workspace(session)
    credentials = {p: service.get_credential(session, workspace, p) for p in Provider}
    return templates.TemplateResponse(
        request,
        "settings_keys.html",
        {
            "workspace": workspace,
            "budget": budget_status(session, workspace),
            "credentials": credentials,
            "labels": PROVIDER_LABELS,
            "jev_providers": JEV_PROVIDERS,
            "notice": notice,
        },
        status_code=status_code,
    )


def _notice(provider: Provider, action: str, result: ValidationResult) -> tuple[str, str]:
    label = PROVIDER_LABELS[provider]
    return NOTICE_LEVELS[result.status], f"{label} 키 {action}: {result.message}"


@router.get("/settings/keys", response_class=HTMLResponse)
def show_keys(request: Request, session: Annotated[Session, Depends(get_session)]):
    return _render(request, session)


@router.post("/settings/keys/{provider}", response_class=HTMLResponse)
def save_key(
    request: Request,
    provider: Provider,
    api_key: Annotated[str, Form()],
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    workspace = service.get_or_create_default_workspace(session)
    try:
        result = service.save_credential(
            session, state.vault, workspace, provider, api_key, state.validators[provider]
        )
    except CredentialError as e:
        return _render(request, session, ("error", str(e)), status_code=400)
    action = "저장 안 함" if result.status == CredentialStatus.INVALID else "저장"
    status_code = 400 if result.status == CredentialStatus.INVALID else 200
    return _render(request, session, _notice(provider, action, result), status_code)


@router.post("/settings/keys/{provider}/revalidate", response_class=HTMLResponse)
def revalidate_key(
    request: Request,
    provider: Provider,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    workspace = service.get_or_create_default_workspace(session)
    try:
        result = service.revalidate_credential(
            session, state.vault, workspace, provider, state.validators[provider]
        )
    except CredentialError as e:
        return _render(request, session, ("error", str(e)), status_code=400)
    return _render(request, session, _notice(provider, "재검증", result))


@router.post("/settings/keys/{provider}/delete", response_class=HTMLResponse)
def delete_key(
    request: Request,
    provider: Provider,
    session: Annotated[Session, Depends(get_session)],
):
    workspace = service.get_or_create_default_workspace(session)
    service.delete_credential(session, workspace, provider)
    return _render(request, session, ("success", f"{PROVIDER_LABELS[provider]} 키를 삭제했습니다"))


@router.post("/settings/jev-provider", response_class=HTMLResponse)
def choose_jev_provider(
    request: Request,
    provider: Annotated[JevProvider, Form()],
    session: Annotated[Session, Depends(get_session)],
):
    workspace = service.get_or_create_default_workspace(session)
    try:
        service.set_jev_provider(session, workspace, provider)
    except CredentialError as e:
        return _render(request, session, ("error", str(e)), status_code=400)
    return _render(request, session, ("success", "JEV 제공자를 변경했습니다"))


@router.post("/settings/budget", response_class=HTMLResponse)
def update_budget(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    monthly_budget_usd: Annotated[str, Form()] = "",
):
    workspace = service.get_or_create_default_workspace(session)
    value = monthly_budget_usd.strip()
    if not value:
        workspace.monthly_budget_usd = None
    else:
        try:
            amount = Decimal(value)
        except InvalidOperation:
            amount = Decimal(-1)
        if amount <= 0 or amount > Decimal("100000"):
            return _render(
                request, session, ("error", "예산은 0보다 큰 금액(USD)으로 입력하세요"), 400
            )
        workspace.monthly_budget_usd = amount.quantize(Decimal("0.01"))
    session.commit()
    return _render(request, session, ("success", "월 예산을 저장했습니다"))

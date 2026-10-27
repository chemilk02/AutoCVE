from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from autocve import usage
from autocve.api.deps import get_session, templates
from autocve.credentials import service

router = APIRouter()

STAGE_LABELS = {
    "profile": "취약점 프로파일",
    "jev": "JEV 판별",
    "haiku": "Haiku 분석",
    "sonnet": "Sonnet 분석",
    "opus": "Opus 분석",
}
SOURCE_LABELS = {
    "typesafe": "JEV (TypeSafe)",
    "openrouter": "JEV (OpenRouter)",
    "rules": "규칙",
    "cache": "캐시 재사용",
    "analysis": "분석 단계 재판별",
}


@router.get("/usage", response_class=HTMLResponse)
def show_usage(request: Request, session: Annotated[Session, Depends(get_session)]):
    workspace = service.get_or_create_default_workspace(session)
    return templates.TemplateResponse(
        request,
        "usage.html",
        {
            "stats": usage.collect(session, workspace),
            "stage_labels": STAGE_LABELS,
            "source_labels": SOURCE_LABELS,
        },
    )

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.api.deps import get_session, templates
from autocve.api.routes_projects import EXPOSURES, describe_triage
from autocve.feedback import FeedbackError, apply_feedback
from autocve.models import (
    Advisory,
    Analysis,
    Component,
    Feedback,
    FeedbackAction,
    Finding,
    Project,
    TriageResult,
)
from autocve.notify.messages import VERDICT_LABELS
from autocve.scoring.risk import GRADE_LABELS

router = APIRouter()

FEEDBACK_LABELS = {
    FeedbackAction.CONFIRM: "영향 있음 확인",
    FeedbackAction.NOT_AFFECTED: "해당 없음",
    FeedbackAction.FIXED: "수정 완료",
    FeedbackAction.REOPEN: "다시 열기",
}
STATUS_LABELS = {
    "new": "판별 대기",
    "triaged": "판별 완료",
    "analyzing": "분석 중",
    "analyzed": "분석 완료",
    "notified": "알림 보냄",
    "resolved": "해소됨",
    "dismissed": "해당 없음으로 닫음",
    "unanalyzed": "예산 소진으로 분석 보류",
    "analysis_refused": "분석 거부됨",
}


def _render(
    request: Request,
    session: Session,
    finding: Finding,
    notice: tuple[str, str] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    component = session.get(Component, finding.component_id)
    advisory = session.get(Advisory, finding.advisory_id)
    project = session.get(Project, finding.project_id)
    triages = session.scalars(
        select(TriageResult)
        .where(TriageResult.finding_id == finding.id)
        .order_by(TriageResult.id.desc())
    ).all()
    analyses = session.scalars(
        select(Analysis).where(Analysis.finding_id == finding.id).order_by(Analysis.id.desc())
    ).all()
    feedback = session.scalars(
        select(Feedback).where(Feedback.finding_id == finding.id).order_by(Feedback.id.desc())
    ).all()
    latest = triages[0] if triages else None
    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "finding": finding,
            "component": component,
            "advisory": advisory,
            "project": project,
            "exposures": EXPOSURES,
            "triages": [(t, describe_triage(t)) for t in triages],
            "snippets": (latest.evidence or {}).get("snippets", []) if latest else [],
            "evidence": (latest.evidence or {}) if latest else {},
            "analyses": analyses,
            "feedback": feedback,
            "grade_label": GRADE_LABELS.get(finding.grade or ""),
            "verdict_labels": VERDICT_LABELS,
            "status_labels": STATUS_LABELS,
            "feedback_labels": FEEDBACK_LABELS,
            "notice": notice,
        },
        status_code=status_code,
    )


def _get(session: Session, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding이 없습니다")
    return finding


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def show_finding(
    request: Request, finding_id: int, session: Annotated[Session, Depends(get_session)]
):
    return _render(request, session, _get(session, finding_id))


@router.post("/findings/{finding_id}/feedback", response_class=HTMLResponse)
def post_feedback(
    request: Request,
    finding_id: int,
    action: Annotated[FeedbackAction, Form()],
    session: Annotated[Session, Depends(get_session)],
    reason: Annotated[str, Form()] = "",
):
    finding = _get(session, finding_id)
    try:
        apply_feedback(session, finding, action, reason)
    except FeedbackError as e:
        return _render(request, session, finding, ("error", str(e)), status_code=400)
    return RedirectResponse(f"/findings/{finding.id}", status_code=303)

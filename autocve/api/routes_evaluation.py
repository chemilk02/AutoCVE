from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from autocve.api.deps import get_session, templates
from autocve.credentials import service
from autocve.evaluation import calibrate, dataset, metrics
from autocve.evaluation.report import format_metric

router = APIRouter()


@router.get("/evaluation", response_class=HTMLResponse)
def show_evaluation(request: Request, session: Annotated[Session, Depends(get_session)]):
    """사용자 처리 기록을 정답으로 삼아 지표와 정확도, 임계값 보정 결과를 보여준다."""
    workspace = service.get_or_create_default_workspace(session)
    cases = dataset.from_feedback(session, workspace)
    current = (workspace.model_settings or {}).get("auto_close_threshold")
    return templates.TemplateResponse(
        request,
        "evaluation.html",
        {
            "metrics": [(m, format_metric(m)) for m in metrics.success_metrics(session, workspace)],
            "accuracy": metrics.current_accuracy(session, cases),
            "calibration": calibrate.calibrate(calibrate.samples(session, cases)),
            "current_threshold": current if current is not None else 0.90,
        },
    )

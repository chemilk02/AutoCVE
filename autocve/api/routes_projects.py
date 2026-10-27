from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.api.deps import AppState, get_session, get_state, templates
from autocve.credentials import service
from autocve.inventory.repo import RepoError, validate_repo_url
from autocve.matcher.matcher import OPEN_STATUSES
from autocve.models import (
    Advisory,
    Analysis,
    Component,
    ExploitSignal,
    Finding,
    Project,
    TriageResult,
)
from autocve.scoring.risk import GRADE_LABELS

router = APIRouter()

EXPOSURES = {
    "internet": "prod, 인터넷 노출",
    "internal": "prod, 내부망",
    "dev": "개발 전용",
}


ROUTE_LABELS = {"haiku": "Haiku", "sonnet": "Sonnet", "opus": "Opus"}
ACTION_LABELS = {
    "auto_close": "자동 종결",
    "analyze": "분석 대기",
    "malicious": "악성 패키지",
    "dev_only": "dev 전용, 분석 생략",
    "budget_exhausted": "예산 소진, 분석 보류",
    "withdrawn": "취약점 철회",
    "version_mismatch": "영향 버전 아님",
}
EXPOSURE_LABELS = {
    "not_affected": "영향 없음",
    "possibly_affected": "영향 가능",
    "likely_affected": "영향 가능성 높음",
}


def describe_triage(result: TriageResult | None) -> dict | None:
    if result is None:
        return None
    exposure = None
    if result.exposure_probs:
        top = max(result.exposure_probs, key=result.exposure_probs.get)
        exposure = EXPOSURE_LABELS.get(top, top)
        if result.provider != "rules":
            # 규칙 기반 값은 확률이 아니므로 퍼센트로 보여주지 않는다.
            exposure += f" {result.exposure_probs[top]:.0%}"
    action = ACTION_LABELS.get(result.action, result.action)
    if result.route:
        action += f" → {ROUTE_LABELS.get(result.route, result.route)}"
    if result.audit:
        action += " (감사 표본)"
    source = {"typesafe": "JEV", "openrouter": "JEV", "cache": "캐시", "rules": "규칙"}.get(
        result.provider, result.provider
    )
    return {
        "action": action,
        "exposure": exposure,
        "source": source + (" (JEV 실패로 대체)" if result.degraded else ""),
        "reasons": result.reasons or [],
        "closed": result.action in ("auto_close", "withdrawn", "version_mismatch"),
    }


@router.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse("/projects", status_code=303)


def _render_list(
    request: Request,
    session: Session,
    notice: tuple[str, str] | None = None,
    status_code: int = 200,
    form: dict | None = None,
) -> HTMLResponse:
    workspace = service.get_or_create_default_workspace(session)
    projects = session.scalars(
        select(Project).where(Project.workspace_id == workspace.id).order_by(Project.name)
    ).all()
    component_counts = dict(
        session.execute(
            select(Component.project_id, func.count()).group_by(Component.project_id)
        ).all()
    )
    finding_counts = dict(
        session.execute(
            select(Finding.project_id, func.count())
            .where(Finding.status.in_(list(OPEN_STATUSES)))
            .group_by(Finding.project_id)
        ).all()
    )
    return templates.TemplateResponse(
        request,
        "projects.html",
        {
            "projects": projects,
            "component_counts": component_counts,
            "finding_counts": finding_counts,
            "exposures": EXPOSURES,
            "notice": notice,
            "form": form or {},
        },
        status_code=status_code,
    )


@router.get("/projects", response_class=HTMLResponse)
def list_projects(request: Request, session: Annotated[Session, Depends(get_session)]):
    return _render_list(request, session)


@router.post("/projects", response_class=HTMLResponse)
async def create_project(
    request: Request,
    name: Annotated[str, Form()],
    repo_url: Annotated[str, Form()],
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
    exposure: Annotated[str, Form()] = "internet",
    default_branch: Annotated[str, Form()] = "",
):
    form = {"name": name, "repo_url": repo_url, "exposure": exposure, "branch": default_branch}
    try:
        url = validate_repo_url(repo_url)
    except RepoError as e:
        return _render_list(request, session, ("error", str(e)), 400, form)
    if exposure not in EXPOSURES or not name.strip():
        return _render_list(request, session, ("error", "입력값을 확인하세요"), 400, form)
    workspace = service.get_or_create_default_workspace(session)
    duplicate = session.scalar(
        select(Project).where(Project.workspace_id == workspace.id, Project.repo_url == url)
    )
    if duplicate is not None:
        return _render_list(request, session, ("error", "이미 등록된 저장소입니다"), 400, form)
    project = Project(
        workspace_id=workspace.id,
        name=name.strip(),
        repo_url=url,
        default_branch=default_branch.strip() or None,
        exposure=exposure,
    )
    session.add(project)
    session.commit()
    await state.queue.enqueue("scan_project", project.id)
    return RedirectResponse(f"/projects/{project.id}?queued=1", status_code=303)


def _get_project(session: Session, project_id: int) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="프로젝트가 없습니다")
    return project


def _render_detail(
    request: Request, session: Session, project: Project, notice: tuple[str, str] | None = None
) -> HTMLResponse:
    components = session.scalars(select(Component).where(Component.project_id == project.id)).all()
    rows = session.execute(
        select(Finding, Component, Advisory)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .where(Finding.project_id == project.id)
        .order_by(Finding.risk_score.desc().nulls_last(), Component.name, Advisory.id)
    ).all()
    cves = {a for _, _, adv in rows for a in [adv.id, *(adv.aliases or [])] if a.startswith("CVE-")}
    signals = {
        s.cve_id: s
        for s in session.scalars(select(ExploitSignal).where(ExploitSignal.cve_id.in_(cves)))
    }
    latest_triage: dict[int, TriageResult] = {}
    finding_ids = [f.id for f, _, _ in rows]
    for i in range(0, len(finding_ids), 500):
        for result in session.scalars(
            select(TriageResult)
            .where(TriageResult.finding_id.in_(finding_ids[i : i + 500]))
            .order_by(TriageResult.id)
        ):
            latest_triage[result.finding_id] = result
    latest_analysis: dict[int, Analysis] = {}
    for i in range(0, len(finding_ids), 500):
        for analysis in session.scalars(
            select(Analysis)
            .where(Analysis.finding_id.in_(finding_ids[i : i + 500]))
            .order_by(Analysis.id)
        ):
            latest_analysis[analysis.finding_id] = analysis
    findings = []
    for finding, component, advisory in rows:
        advisory_cves = [a for a in [advisory.id, *(advisory.aliases or [])] if a in signals]
        epss = max((signals[c].epss or 0 for c in advisory_cves), default=None)
        in_kev = any(signals[c].in_kev for c in advisory_cves)
        findings.append(
            {
                "finding": finding,
                "component": component,
                "advisory": advisory,
                "epss": epss,
                "in_kev": in_kev,
                "malicious": advisory.id.startswith("MAL-"),
                "triage": describe_triage(latest_triage.get(finding.id)),
                "analysis": latest_analysis.get(finding.id),
                "grade_label": GRADE_LABELS.get(finding.grade or "", None),
            }
        )
    grades = Counter(f["finding"].grade for f in findings if f["finding"].status in OPEN_STATUSES)
    summary = {
        "grades": [(GRADE_LABELS[g], g, grades.get(g, 0)) for g in GRADE_LABELS],
        "total": len(components),
        "by_ecosystem": Counter(c.ecosystem for c in components),
        "direct": sum(c.direct for c in components),
        "dev": sum(c.scope == "dev" for c in components),
    }
    return templates.TemplateResponse(
        request,
        "project_detail.html",
        {
            "project": project,
            "summary": summary,
            "findings": findings,
            "open_statuses": OPEN_STATUSES,
            "exposures": EXPOSURES,
            "notice": notice,
        },
    )


@router.get("/projects/{project_id}", response_class=HTMLResponse)
def show_project(
    request: Request,
    project_id: int,
    session: Annotated[Session, Depends(get_session)],
    queued: int = 0,
):
    project = _get_project(session, project_id)
    notice = ("success", "스캔을 예약했습니다. 잠시 후 새로고침하세요.") if queued else None
    return _render_detail(request, session, project, notice)


@router.post("/projects/{project_id}/scan", response_class=HTMLResponse)
async def rescan_project(
    project_id: int,
    session: Annotated[Session, Depends(get_session)],
    state: Annotated[AppState, Depends(get_state)],
):
    project = _get_project(session, project_id)
    await state.queue.enqueue("scan_project", project.id)
    return RedirectResponse(f"/projects/{project.id}?queued=1", status_code=303)


@router.post("/projects/{project_id}/settings")
def update_project_settings(
    project_id: int,
    session: Annotated[Session, Depends(get_session)],
    exposure: Annotated[str, Form()],
    jev_snippets: Annotated[str | None, Form()] = None,
):
    project = _get_project(session, project_id)
    if exposure not in EXPOSURES:
        raise HTTPException(status_code=400, detail="노출 범위 값이 올바르지 않습니다")
    project.exposure = exposure
    project.jev_snippets = jev_snippets == "on"
    session.commit()
    return RedirectResponse(f"/projects/{project.id}", status_code=303)


@router.post("/projects/{project_id}/delete")
def delete_project(project_id: int, session: Annotated[Session, Depends(get_session)]):
    project = _get_project(session, project_id)
    session.delete(project)
    session.commit()
    return RedirectResponse("/projects", status_code=303)

"""수집 → 매칭을 잇는 작업 단위. 워커와 CLI가 같은 함수를 쓴다."""

import logging
from dataclasses import dataclass, field

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.analysis.run import analyze_findings, collect_batches
from autocve.collector import exploit, osv
from autocve.config import Settings
from autocve.credentials.service import load_secret
from autocve.ecosystems import SUPPORTED
from autocve.inventory.scan import checked_out, log_scan, scan_checkout
from autocve.matcher.matcher import MatchResult, match_advisories, match_components
from autocve.models import Component, Project, Provider, Workspace
from autocve.notify.service import notify_immediate, send_digest
from autocve.scoring.risk import score_findings
from autocve.security.keyvault import KeyVault
from autocve.triage.run import TriageSummary, triage_findings

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = httpx.Timeout(60.0, connect=15.0)


def http_client() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True)


@dataclass
class FeedSyncSummary:
    changed_advisories: int = 0
    bootstrapped: list[str] = field(default_factory=list)
    new_findings: int = 0
    resolved_findings: int = 0
    # 새 Finding이 생겨 판별이 필요한 프로젝트
    projects_to_triage: list[int] = field(default_factory=list)


def _merge(summary: FeedSyncSummary, result: MatchResult) -> None:
    summary.new_findings += len(result.created)
    summary.resolved_findings += len(result.resolved)
    projects = set(summary.projects_to_triage) | {f.project_id for f in result.created}
    summary.projects_to_triage = sorted(projects)


def sync_feeds(
    session: Session, http: httpx.Client, settings: Settings, ecosystems=SUPPORTED
) -> FeedSyncSummary:
    client = osv.OsvClient(http, settings.osv_base_url)
    summary = FeedSyncSummary()
    for ecosystem in ecosystems:
        result = osv.sync_ecosystem(session, client, ecosystem)
        if result.bootstrapped:
            summary.bootstrapped.append(ecosystem)
            components = session.scalars(
                select(Component).where(Component.ecosystem == ecosystem)
            ).all()
            _merge(summary, match_components(session, components))
        elif result.changed_ids:
            summary.changed_advisories += len(result.changed_ids)
            _merge(summary, match_advisories(session, result.changed_ids))
    return summary


def sync_exploit_signals(session: Session, http: httpx.Client, settings: Settings) -> dict:
    """EPSS와 KEV를 따로 갱신한다. 한쪽이 실패해도 다른 쪽은 진행한다."""
    status: dict[str, str] = {}
    for name, run in (
        ("epss", lambda: exploit.sync_epss(session, http, settings.epss_url).updated),
        ("kev", lambda: exploit.sync_kev(session, http, settings.kev_url)),
    ):
        try:
            status[name] = f"ok ({run()}건)"
        except httpx.HTTPError as e:
            session.rollback()
            logger.warning("%s 수집 실패: %s", name, e)
            status[name] = f"실패: {type(e).__name__}"
    # 악용 신호가 바뀌면 Claude 호출 없이 위험도만 다시 계산한다.
    status["rescored"] = str(score_findings(session))
    return status


@dataclass
class ProjectScanSummary:
    project_id: int
    commit: str | None
    components: int
    changed_components: int
    new_findings: int
    resolved_findings: int
    manifest_errors: list[str]
    triage: dict
    analysis: dict


def _triage_dict(summary: TriageSummary) -> dict:
    return {**summary.__dict__, "actions": dict(summary.actions)}


def _github_token(session: Session, project: Project, vault: KeyVault) -> str | None:
    workspace = session.get(Workspace, project.workspace_id)
    return load_secret(session, vault, workspace, Provider.GITHUB)


def scan_and_match(
    session: Session,
    project: Project,
    vault: KeyVault,
    settings: Settings,
    *,
    http: httpx.Client | None = None,
    allow_local: bool = False,
    triage_kwargs: dict | None = None,
    analysis_kwargs: dict | None = None,
) -> ProjectScanSummary:
    """clone → 스캔 → 매칭 → 판별.

    판별은 clone한 코드에서 증거를 모으므로 같은 checkout 안에서 한다.
    """
    token = _github_token(session, project, vault)
    with checked_out(
        session, project, token=token, workdir=settings.scan_workdir, allow_local=allow_local
    ) as (root, commit):
        result = scan_checkout(session, project, root, commit)
        log_scan(project, result)
        matched = match_components(session, result.changed_components)
        triage = triage_findings(
            session,
            project,
            vault=vault,
            settings=settings,
            checkout=root,
            http=http,
            **(triage_kwargs or {}),
        )
        analysis = analyze_findings(
            session, project, vault=vault, checkout=root, **(analysis_kwargs or {})
        )
    return ProjectScanSummary(
        project_id=project.id,
        commit=result.commit,
        components=result.total_components,
        changed_components=len(result.changed_components),
        new_findings=len(matched.created),
        resolved_findings=len(matched.resolved),
        manifest_errors=result.manifest_errors,
        triage=_triage_dict(triage),
        analysis=analysis.as_dict(),
    )


def triage_project(
    session: Session,
    project: Project,
    vault: KeyVault,
    settings: Settings,
    *,
    http: httpx.Client | None = None,
    allow_local: bool = False,
    triage_kwargs: dict | None = None,
    analysis_kwargs: dict | None = None,
) -> dict:
    """판별 대기·분석 대기 Finding을 처리한다. 증거 수집과 심층 분석을 위해 다시 clone한다."""
    token = _github_token(session, project, vault)
    with checked_out(
        session, project, token=token, workdir=settings.scan_workdir, allow_local=allow_local
    ) as (root, _):
        summary = triage_findings(
            session,
            project,
            vault=vault,
            settings=settings,
            checkout=root,
            http=http,
            **(triage_kwargs or {}),
        )
        analysis = analyze_findings(
            session, project, vault=vault, checkout=root, **(analysis_kwargs or {})
        )
    return {"triage": _triage_dict(summary), "analysis": analysis.as_dict()}


def collect_analysis_batches(session: Session, vault: KeyVault) -> dict:
    results = {}
    for workspace in session.scalars(select(Workspace)):
        results[workspace.id] = collect_batches(session, workspace, vault)
    return results


def notify_all(
    session: Session, vault: KeyVault, settings: Settings, *, digest: bool = False
) -> dict:
    """모든 워크스페이스에 즉시 알림(또는 일일 요약)을 보낸다.

    알림 실패가 수집·분석 작업을 막지 않도록 예외는 기록만 한다.
    """
    sent = {}
    for workspace in session.scalars(select(Workspace)):
        try:
            if digest:
                sent[workspace.id] = send_digest(session, workspace, vault, settings)
            else:
                sent[workspace.id] = notify_immediate(session, workspace, vault, settings)
        except Exception:  # noqa: BLE001 - 알림은 부가 기능이라 실패를 기록만 한다
            logger.exception("워크스페이스 %s 알림 실패", workspace.id)
            session.rollback()
    return sent

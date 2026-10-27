"""수집 → 매칭을 잇는 작업 단위. 워커와 CLI가 같은 함수를 쓴다."""

import logging
from dataclasses import dataclass, field

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.collector import exploit, osv
from autocve.config import Settings
from autocve.credentials.service import load_secret
from autocve.ecosystems import SUPPORTED
from autocve.inventory.scan import scan_project
from autocve.matcher.matcher import MatchResult, match_advisories, match_components
from autocve.models import Component, Project, Provider, Workspace
from autocve.security.keyvault import KeyVault

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


def _merge(summary: FeedSyncSummary, result: MatchResult) -> None:
    summary.new_findings += len(result.created)
    summary.resolved_findings += len(result.resolved)


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


def scan_and_match(
    session: Session,
    project: Project,
    vault: KeyVault,
    settings: Settings,
    *,
    allow_local: bool = False,
) -> ProjectScanSummary:
    workspace = session.get(Workspace, project.workspace_id)
    token = load_secret(session, vault, workspace, Provider.GITHUB)
    result = scan_project(
        session, project, token=token, workdir=settings.scan_workdir, allow_local=allow_local
    )
    matched = match_components(session, result.changed_components)
    return ProjectScanSummary(
        project_id=project.id,
        commit=result.commit,
        components=result.total_components,
        changed_components=len(result.changed_components),
        new_findings=len(matched.created),
        resolved_findings=len(matched.resolved),
        manifest_errors=result.manifest_errors,
    )

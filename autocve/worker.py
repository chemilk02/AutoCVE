"""arq 워커.

실행: arq autocve.worker.WorkerSettings

작업은 동기 코드(SQLAlchemy, httpx, git)라서 스레드에서 돌린다.
"""

import asyncio
import logging

from arq import cron
from arq.connections import RedisSettings
from sqlalchemy import select

from autocve import pipeline
from autocve.config import get_settings
from autocve.db import make_engine, make_session_factory
from autocve.inventory.repo import RepoError
from autocve.models import Project
from autocve.security.keyvault import KeyVault
from autocve.security.redaction import install_log_redaction

logger = logging.getLogger(__name__)


async def startup(ctx: dict) -> None:
    install_log_redaction()
    settings = get_settings()
    ctx["settings"] = settings
    ctx["session_factory"] = make_session_factory(make_engine(settings.database_url))
    ctx["vault"] = KeyVault.from_b64(settings.master_key.get_secret_value())


def _sync_feeds(ctx: dict) -> dict:
    with ctx["session_factory"]() as session, pipeline.http_client() as http:
        summary = pipeline.sync_feeds(session, http, ctx["settings"])
    return summary.__dict__


def _sync_exploits(ctx: dict) -> dict:
    with ctx["session_factory"]() as session, pipeline.http_client() as http:
        return pipeline.sync_exploit_signals(session, http, ctx["settings"])


def _scan(ctx: dict, project_id: int) -> dict:
    with ctx["session_factory"]() as session:
        project = session.get(Project, project_id)
        if project is None:
            return {"error": "프로젝트가 없습니다"}
        try:
            return pipeline.scan_and_match(session, project, ctx["vault"], ctx["settings"]).__dict__
        except RepoError as e:
            return {"error": str(e)}


async def _exclusive(ctx: dict, name: str, func) -> dict:
    """같은 수집 작업이 겹쳐 돌지 않게 한다 (최초 적재가 다음 cron 주기보다 길 수 있다)."""
    lock = f"autocve:lock:{name}"
    if not await ctx["redis"].set(lock, "1", nx=True, ex=WorkerSettings.job_timeout):
        logger.info("%s 이미 실행 중이라 건너뜀", name)
        return {"skipped": True}
    try:
        return await asyncio.to_thread(func, ctx)
    finally:
        await ctx["redis"].delete(lock)


async def sync_feeds(ctx: dict) -> dict:
    return await _exclusive(ctx, "sync_feeds", _sync_feeds)


async def sync_exploits(ctx: dict) -> dict:
    return await _exclusive(ctx, "sync_exploits", _sync_exploits)


async def scan_project(ctx: dict, project_id: int) -> dict:
    return await asyncio.to_thread(_scan, ctx, project_id)


async def scan_all_projects(ctx: dict) -> int:
    with ctx["session_factory"]() as session:
        ids = list(session.scalars(select(Project.id)))
    for project_id in ids:
        await ctx["redis"].enqueue_job("scan_project", project_id)
    return len(ids)


class WorkerSettings:
    functions = [sync_feeds, sync_exploits, scan_project, scan_all_projects]
    cron_jobs = [
        cron(sync_feeds, minute=7, run_at_startup=True),  # 매시 7분
        cron(sync_exploits, hour=6, minute=17, run_at_startup=True),  # 매일 06:17 UTC
        cron(scan_all_projects, hour=3, minute=23),  # 매일 03:23 UTC
    ]
    on_startup = startup
    # 최초 OSV 적재(npm 수백 MB)는 오래 걸린다.
    job_timeout = 3 * 60 * 60
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)

"""arq 워커. M0에서는 큐 연결 확인용 heartbeat만 있다.

실행: arq autocve.worker.WorkerSettings
"""

import logging

from arq import cron
from arq.connections import RedisSettings

from autocve.config import get_settings
from autocve.security.redaction import install_log_redaction

logger = logging.getLogger(__name__)


async def startup(ctx: dict) -> None:
    install_log_redaction()


async def heartbeat(ctx: dict) -> None:
    logger.info("worker heartbeat")


class WorkerSettings:
    functions = [heartbeat]
    cron_jobs = [cron(heartbeat, minute={0, 15, 30, 45})]
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)

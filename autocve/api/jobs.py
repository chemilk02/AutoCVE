from typing import Protocol

from arq import ArqRedis, create_pool
from arq.connections import RedisSettings


class JobQueue(Protocol):
    async def enqueue(self, name: str, *args) -> None: ...

    async def close(self) -> None: ...


class ArqQueue:
    """Redis가 늦게 뜨더라도 웹 앱은 시작되도록, 첫 사용 시점에 연결한다."""

    def __init__(self, redis_url: str):
        self._settings = RedisSettings.from_dsn(redis_url)
        self._pool: ArqRedis | None = None

    async def enqueue(self, name: str, *args) -> None:
        if self._pool is None:
            self._pool = await create_pool(self._settings)
        await self._pool.enqueue_job(name, *args)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.aclose()

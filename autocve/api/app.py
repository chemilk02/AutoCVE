import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from autocve.api import routes_settings
from autocve.api.deps import AppState
from autocve.api.security import AccessControlMiddleware
from autocve.config import Settings, get_settings
from autocve.credentials.service import get_or_create_default_workspace
from autocve.credentials.validators import Validator, default_validators
from autocve.db import make_engine, make_session_factory
from autocve.models import Provider
from autocve.security.keyvault import KeyVault
from autocve.security.redaction import install_log_redaction

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def create_app(
    settings: Settings | None = None,
    validators: dict[Provider, Validator] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level)
    install_log_redaction()

    engine = make_engine(settings.database_url)
    state = AppState(
        settings=settings,
        session_factory=make_session_factory(engine),
        vault=KeyVault.from_b64(settings.master_key.get_secret_value()),
        validators=validators or default_validators(settings),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # uvicorn이 붙인 핸들러까지 가리도록 시작 시점에 한 번 더 적용한다.
        install_log_redaction()
        with state.session_factory() as session:
            get_or_create_default_workspace(session)
        yield
        engine.dispose()

    app = FastAPI(title="AutoCVE", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.autocve = state
    password = settings.admin_password.get_secret_value() if settings.admin_password else None
    app.add_middleware(AccessControlMiddleware, admin_password=password)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    app.include_router(routes_settings.router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        with state.session_factory() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok"}

    return app

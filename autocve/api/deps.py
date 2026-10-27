from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, sessionmaker

from autocve.api.jobs import JobQueue
from autocve.config import Settings
from autocve.credentials.validators import Validator
from autocve.models import Provider
from autocve.security.keyvault import KeyVault

templates = Jinja2Templates(directory=Path(__file__).resolve().parent.parent / "web" / "templates")


@dataclass
class AppState:
    settings: Settings
    session_factory: sessionmaker[Session]
    vault: KeyVault
    validators: dict[Provider, Validator]
    queue: JobQueue


def get_state(request: Request) -> AppState:
    return request.app.state.autocve


def get_session(request: Request) -> Iterator[Session]:
    with get_state(request).session_factory() as session:
        yield session

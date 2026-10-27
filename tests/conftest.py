import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from autocve.api.app import create_app
from autocve.config import Settings
from autocve.models import Base, Provider
from autocve.security.keyvault import generate_master_key
from tests.fakes import FakeQueue, FakeValidator


@pytest.fixture
def settings(tmp_path) -> Settings:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    return Settings(database_url=url, master_key=generate_master_key(), admin_password=None)


@pytest.fixture
def validators() -> dict[Provider, FakeValidator]:
    return {p: FakeValidator() for p in Provider}


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
def session_factory(settings):
    from autocve.db import make_engine, make_session_factory

    engine = make_engine(settings.database_url)
    yield make_session_factory(engine)
    engine.dispose()


@pytest.fixture
def client(settings, validators, queue):
    with TestClient(create_app(settings, validators, queue)) as c:
        yield c

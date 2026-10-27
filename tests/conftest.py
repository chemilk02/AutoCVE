from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from autocve.api.app import create_app
from autocve.config import Settings
from autocve.credentials.validators import ValidationResult
from autocve.models import Base, CredentialStatus, Provider
from autocve.security.keyvault import generate_master_key


@dataclass
class FakeValidator:
    """제공자별로 돌려줄 결과를 바꿀 수 있고, 받은 키를 기록한다."""

    status: CredentialStatus = CredentialStatus.VALID
    seen: list[str] = field(default_factory=list)

    def __call__(self, key: str) -> ValidationResult:
        self.seen.append(key)
        return ValidationResult(self.status, f"fake {self.status}")


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
def client(settings, validators):
    with TestClient(create_app(settings, validators)) as c:
        yield c

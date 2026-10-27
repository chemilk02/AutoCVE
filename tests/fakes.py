from dataclasses import dataclass, field

from autocve.credentials.validators import ValidationResult
from autocve.models import CredentialStatus


@dataclass
class FakeValidator:
    """제공자별로 돌려줄 결과를 바꿀 수 있고, 받은 키를 기록한다."""

    status: CredentialStatus = CredentialStatus.VALID
    seen: list[str] = field(default_factory=list)

    def __call__(self, key: str) -> ValidationResult:
        self.seen.append(key)
        return ValidationResult(self.status, f"fake {self.status}")


class FakeQueue:
    def __init__(self):
        self.jobs: list[tuple] = []

    async def enqueue(self, name: str, *args) -> None:
        self.jobs.append((name, *args))

    async def close(self) -> None:
        pass

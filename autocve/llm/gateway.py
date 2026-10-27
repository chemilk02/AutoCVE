"""사용자 키로 Claude를 호출하고 호출마다 사용량과 비용을 기록한다.

월 예산을 넘으면 호출을 막는다.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import anthropic
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.credentials.service import get_credential, load_secret
from autocve.llm.pricing import cost_usd
from autocve.models import CredentialStatus, LlmUsage, Provider, Workspace
from autocve.security.keyvault import KeyVault

logger = logging.getLogger(__name__)

ClientFactory = Callable[[str], anthropic.Anthropic]


class BudgetExceeded(Exception):
    pass


class LlmUnavailable(Exception):
    pass


def default_client(api_key: str) -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=300.0)


@dataclass(frozen=True)
class BudgetStatus:
    used_usd: Decimal
    limit_usd: Decimal | None

    @property
    def ratio(self) -> float:
        if not self.limit_usd:
            return 0.0
        return float(self.used_usd / self.limit_usd)


def month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def budget_status(session: Session, workspace: Workspace) -> BudgetStatus:
    used = session.scalar(
        select(func.coalesce(func.sum(LlmUsage.cost_usd), 0)).where(
            LlmUsage.workspace_id == workspace.id, LlmUsage.created_at >= month_start()
        )
    )
    return BudgetStatus(Decimal(str(used or 0)), workspace.monthly_budget_usd)


def record_usage(
    session: Session,
    workspace: Workspace,
    *,
    provider: str,
    model: str,
    stage: str,
    finding_id: int | None = None,
    batch: bool = False,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
    cost: Decimal | None = None,
) -> LlmUsage:
    usage = LlmUsage(
        workspace_id=workspace.id,
        provider=provider,
        model=model,
        stage=stage,
        finding_id=finding_id,
        batch=batch,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_creation_input_tokens=cache_creation_input_tokens,
        cache_read_input_tokens=cache_read_input_tokens,
        cost_usd=cost
        if cost is not None
        else cost_usd(
            provider,
            model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_creation_input_tokens=cache_creation_input_tokens,
            cache_read_input_tokens=cache_read_input_tokens,
        ),
    )
    session.add(usage)
    # 이후 단계가 실패해도 비용 기록은 남아야 하므로 바로 커밋한다.
    session.commit()
    return usage


class LlmGateway:
    def __init__(
        self,
        session: Session,
        workspace: Workspace,
        vault: KeyVault,
        client_factory: ClientFactory = default_client,
    ):
        self._session = session
        self._workspace = workspace
        self._vault = vault
        self._factory = client_factory
        self._client: anthropic.Anthropic | None = None

    def available(self) -> bool:
        credential = get_credential(self._session, self._workspace, Provider.ANTHROPIC)
        return credential is not None and credential.status != CredentialStatus.INVALID

    def budget(self) -> BudgetStatus:
        return budget_status(self._session, self._workspace)

    def _get_client(self) -> anthropic.Anthropic:
        if self._client is None:
            key = load_secret(self._session, self._vault, self._workspace, Provider.ANTHROPIC)
            if key is None:
                raise LlmUnavailable("Anthropic 키가 없습니다")
            self._client = self._factory(key)
        return self._client

    def create(
        self, *, stage: str, finding_id: int | None = None, beta: bool = False, **params: Any
    ):
        """messages.create를 호출하고 사용량을 기록한다. 예산이 소진되었으면 BudgetExceeded."""
        if self.budget().ratio >= 1.0:
            raise BudgetExceeded("월 예산을 모두 사용했습니다")
        client = self._get_client()
        messages = client.beta.messages if beta else client.messages
        response = messages.create(**params)
        usage = response.usage
        record_usage(
            self._session,
            self._workspace,
            provider="anthropic",
            model=params["model"],
            stage=stage,
            finding_id=finding_id,
            input_tokens=usage.input_tokens or 0,
            output_tokens=usage.output_tokens or 0,
            cache_creation_input_tokens=usage.cache_creation_input_tokens or 0,
            cache_read_input_tokens=usage.cache_read_input_tokens or 0,
        )
        return response

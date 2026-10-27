"""경량 분석을 Batch API로 보낸다 (50% 할인, 보통 1시간 안에 끝남).

긴급하지 않은 후보(새 저장소 초기 스캔 등)가 많을 때 쓴다. KEV, CVSS 9 이상은 실시간으로 분석한다.
결과는 워커가 주기적으로 확인해 반영한다.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

import anthropic
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.analysis import light
from autocve.credentials.service import CredentialError
from autocve.llm.gateway import LlmGateway, LlmUnavailable, record_usage
from autocve.llm.pricing import BATCH_DISCOUNT, cost_usd
from autocve.models import AnalysisBatch, Finding, FindingStatus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BatchItem:
    finding_id: int
    context: str
    cache_key: str


def submit(session: Session, gateway: LlmGateway, items: list[BatchItem]) -> AnalysisBatch:
    client = gateway.client()
    requests = [
        {"custom_id": f"finding-{item.finding_id}", "params": light.request_params(item.context)}
        for item in items
    ]
    created = client.messages.batches.create(requests=requests)
    batch = AnalysisBatch(
        workspace_id=gateway.workspace.id,
        batch_id=created.id,
        model=light.MODEL,
        requests={
            f"finding-{item.finding_id}": {
                "finding_id": item.finding_id,
                "cache_key": item.cache_key,
            }
            for item in items
        },
    )
    session.add(batch)
    for item in items:
        finding = session.get(Finding, item.finding_id)
        finding.status = FindingStatus.ANALYZING
    session.commit()
    logger.info("경량 분석 %d건을 배치 %s로 보냈습니다", len(items), created.id)
    return batch


def collect(session: Session, gateway: LlmGateway, batch: AnalysisBatch, apply) -> int | None:
    """끝난 배치의 결과를 반영한다. 아직 진행 중이면 None.

    `apply(finding, outcome, cache_key)`는 분석 결과를 Finding에 반영하는 함수다.
    실패·만료된 요청은 Finding을 `triaged`로 되돌려 다음 분석 때 실시간으로 다시 시도한다.
    """
    client = gateway.client()
    status = client.messages.batches.retrieve(batch.batch_id)
    if status.processing_status != "ended":
        return None
    applied = 0
    for result in client.messages.batches.results(batch.batch_id):
        meta = (batch.requests or {}).get(result.custom_id)
        if meta is None:
            continue
        finding = session.get(Finding, meta["finding_id"])
        if finding is None:
            continue
        if result.result.type != "succeeded":
            finding.status = FindingStatus.TRIAGED
            continue
        message = result.result.message
        usage = message.usage
        tokens = {
            "input_tokens": usage.input_tokens or 0,
            "output_tokens": usage.output_tokens or 0,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens or 0,
            "cache_read_input_tokens": usage.cache_read_input_tokens or 0,
        }
        record_usage(
            session,
            gateway.workspace,
            provider="anthropic",
            model=message.model or batch.model,
            stage="haiku",
            finding_id=finding.id,
            batch=True,
            cost=cost_usd("anthropic", message.model or batch.model, **tokens) * BATCH_DISCOUNT,
            **tokens,
        )
        apply(finding, light.outcome_from_message(message), meta["cache_key"])
        applied += 1
    batch.status = "ended"
    batch.ended_at = datetime.now(UTC)
    session.commit()
    return applied


def pending_batches(session: Session, workspace_id: int) -> list[AnalysisBatch]:
    return session.scalars(
        select(AnalysisBatch).where(
            AnalysisBatch.workspace_id == workspace_id, AnalysisBatch.status == "in_progress"
        )
    ).all()


def safe_collect(session: Session, gateway: LlmGateway, batch: AnalysisBatch, apply) -> int | None:
    try:
        return collect(session, gateway, batch, apply)
    except (anthropic.APIError, LlmUnavailable, CredentialError) as e:
        logger.warning("배치 %s 확인 실패: %s", batch.batch_id, type(e).__name__)
        session.rollback()
        return None

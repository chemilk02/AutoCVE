"""경량 분석: Haiku 단일 호출, 증거 스니펫만 보고 구조화 출력을 받는다."""

import logging

import anthropic

from autocve.analysis.common import (
    ANALYSIS_SCHEMA,
    MODELS,
    SYSTEM_PROMPT,
    AnalysisOutcome,
    parse_outcome,
)
from autocve.llm.gateway import LlmGateway

logger = logging.getLogger(__name__)

MODEL = MODELS["haiku"]
# Haiku 5.5는 기본으로 생각(thinking)을 하고, 그 토큰도 max_tokens에 포함된다.
MAX_TOKENS = 4000


def request_params(context: str) -> dict:
    """실시간 호출과 Batch API가 같은 요청을 쓰도록 분리했다."""
    return {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": context}],
        "output_config": {
            "effort": "low",
            "format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA},
        },
    }


def outcome_from_message(message) -> AnalysisOutcome:
    if message.stop_reason == "refusal":
        return AnalysisOutcome("refused", MODEL, rationale="모델이 분석을 거부했습니다")
    text = next((b.text for b in message.content if b.type == "text"), "")
    outcome = parse_outcome(text, MODEL)
    if message.stop_reason == "max_tokens" and outcome.verdict == "error":
        outcome.rationale = "출력 한도에 걸려 결과가 잘렸습니다"
    return outcome


def analyze(gateway: LlmGateway, context: str, finding_id: int) -> AnalysisOutcome:
    try:
        message = gateway.create(stage="haiku", finding_id=finding_id, **request_params(context))
    except anthropic.APIError as e:
        logger.warning("경량 분석 실패 (finding %s): %s", finding_id, type(e).__name__)
        return AnalysisOutcome("error", MODEL, rationale=f"API 오류: {type(e).__name__}")
    return outcome_from_message(message)

"""라우팅 정책 (§4.4): 판별 확률과 안전 규칙으로 최종 행동을 정한다."""

import hashlib
from dataclasses import dataclass, field

from autocve.triage.inputs import TriageInput
from autocve.triage.models import Judgement

TIERS = ("haiku", "sonnet", "opus")


class Action:
    AUTO_CLOSE = "auto_close"  # Claude 없이 not_affected로 종결
    ANALYZE = "analyze"  # route 모델로 분석
    MALICIOUS = "malicious"  # 악성 패키지: 분석 없이 영향 있음
    DEV_ONLY = "dev_only"  # dev 의존성만 해당: 분석 생략
    BUDGET = "budget_exhausted"  # 예산 소진으로 분석 보류


@dataclass(frozen=True)
class PolicyConfig:
    auto_close_threshold: float = 0.90
    low_confidence: float = 0.60
    audit_percent: int = 5
    budget_downgrade_ratio: float = 0.80
    skip_dev: bool = True


@dataclass
class Decision:
    action: str
    route: str | None = None
    audit: bool = False
    reasons: list[str] = field(default_factory=list)


def _bump(route: str) -> str:
    return TIERS[min(TIERS.index(route) + 1, len(TIERS) - 1)]


def _at_least(route: str, floor: str) -> str:
    return route if TIERS.index(route) >= TIERS.index(floor) else floor


def is_audit_sample(finding_id: int, percent: int) -> bool:
    # 같은 Finding은 항상 같은 결과가 나오도록 해시로 고른다.
    bucket = int(hashlib.sha256(str(finding_id).encode()).hexdigest(), 16) % 100
    return bucket < percent


def decide(
    inp: TriageInput, judgement: Judgement, budget_ratio: float, config: PolicyConfig
) -> Decision:
    reasons = list(judgement.reasons)

    if inp.malicious:
        return Decision(Action.MALICIOUS, reasons=["악성 패키지로 보고된 버전이 설치되어 있음"])
    if inp.scope == "dev" and config.skip_dev:
        return Decision(Action.DEV_ONLY, reasons=["dev 의존성에만 해당"])

    not_affected = judgement.exposure_probs.get("not_affected", 0.0)
    if (
        not_affected >= config.auto_close_threshold
        and judgement.route == "no_llm"
        and not inp.severe
    ):
        reasons.append(f"영향 없음 확률 {not_affected:.0%}")
        if is_audit_sample(inp.finding_id, config.audit_percent):
            reasons.append("자동 종결 감사 표본: Haiku로 재확인")
            return Decision(Action.AUTO_CLOSE, route="haiku", audit=True, reasons=reasons)
        return Decision(Action.AUTO_CLOSE, reasons=reasons)

    if budget_ratio >= 1.0:
        return Decision(Action.BUDGET, reasons=[*reasons, "월 예산 소진"])

    route = judgement.route if judgement.route in TIERS else "haiku"
    # 확신도로 올리는 규칙은 보정된 확률을 내는 JEV에만 적용한다. 규칙 기반 값은 확률이 아니다.
    if judgement.provider != "rules" and judgement.confidence < config.low_confidence:
        route = _bump(route)
        reasons.append(f"판별 확신도 {judgement.confidence:.0%}로 낮아 한 단계 올림")
    if inp.severe:
        raised = _at_least(route, "sonnet")
        if raised != route:
            reasons.append("KEV 등재 또는 CVSS 9.0 이상이라 최소 Sonnet")
        route = raised
    if budget_ratio >= config.budget_downgrade_ratio and route == "opus":
        route = "sonnet"
        reasons.append("월 예산 80% 이상 사용으로 Opus 대신 Sonnet")
    return Decision(Action.ANALYZE, route=route, reasons=reasons)

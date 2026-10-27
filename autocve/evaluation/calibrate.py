"""정답 셋으로 JEV 자동 종결 임계값을 보정한다 (§4.4).

임계값마다 "자동 종결되었을 후보 수"와 "그중 실제로는 영향이 있던 비율"을 계산하고,
오판율이 기준(5%) 이하인 임계값 가운데 가장 많이 종결하는 값을 권장한다.
표본이 적으면 권장하지 않는다.
"""

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.evaluation.dataset import Case, resolve
from autocve.models import TriageResult, Verdict, Workspace

JEV_PROVIDERS = ("typesafe", "openrouter")
GRID = [round(0.80 + i * 0.01, 2) for i in range(20)]  # 0.80 ~ 0.99
MAX_ERROR_RATE = 0.05
MIN_SAMPLES = 20


@dataclass
class Point:
    threshold: float
    closed: int
    errors: int

    @property
    def error_rate(self) -> float | None:
        return self.errors / self.closed if self.closed else None


@dataclass
class Calibration:
    samples: int
    points: list[Point] = field(default_factory=list)
    recommended: float | None = None
    reason: str = ""


@dataclass(frozen=True)
class Sample:
    not_affected: float
    route_no_llm: bool
    severe: bool
    expected: str


def samples(session: Session, cases: list[Case]) -> list[Sample]:
    """정답이 있는 Finding의 JEV 판별 확률. 규칙·캐시 판별은 확률이 아니므로 뺀다."""
    out = []
    for case in cases:
        for finding in resolve(session, case):
            triage = session.scalar(
                select(TriageResult)
                .where(
                    TriageResult.finding_id == finding.id,
                    TriageResult.provider.in_(JEV_PROVIDERS),
                )
                .order_by(TriageResult.id.desc())
            )
            if triage is None or not triage.exposure_probs:
                continue
            route = triage.route_probs or {}
            out.append(
                Sample(
                    not_affected=float(triage.exposure_probs.get("not_affected", 0.0)),
                    route_no_llm=bool(route) and max(route, key=route.get) == "no_llm",
                    severe=bool((triage.evidence or {}).get("severe")),
                    expected=case.expected,
                )
            )
    return out


def calibrate(data: list[Sample], *, max_error_rate: float = MAX_ERROR_RATE) -> Calibration:
    result = Calibration(samples=len(data))
    for threshold in GRID:
        closed = [
            s for s in data if s.not_affected >= threshold and s.route_no_llm and not s.severe
        ]
        errors = sum(s.expected == Verdict.AFFECTED for s in closed)
        result.points.append(Point(threshold, len(closed), errors))
    if len(data) < MIN_SAMPLES:
        result.reason = (
            f"JEV 판별이 있는 정답 표본이 {len(data)}건이라 권장하지 않습니다 "
            f"(최소 {MIN_SAMPLES}건)"
        )
        return result
    eligible = [
        p
        for p in result.points
        if p.closed and p.error_rate is not None and p.error_rate <= max_error_rate
    ]
    if not eligible:
        result.recommended = GRID[-1]
        result.reason = "모든 임계값에서 오판율이 기준을 넘어 가장 보수적인 값을 권장합니다"
        return result
    best = max(eligible, key=lambda p: (p.closed, -p.threshold))
    result.recommended = best.threshold
    result.reason = (
        f"오판율 {best.error_rate:.1%}로 {best.closed}건을 Claude 없이 종결할 수 있습니다"
    )
    return result


def apply(session: Session, workspace: Workspace, threshold: float) -> None:
    settings = dict(workspace.model_settings or {})
    settings["auto_close_threshold"] = threshold
    workspace.model_settings = settings
    session.commit()

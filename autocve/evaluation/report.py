"""평가 결과를 Markdown으로 정리한다 (CLI 출력, 문서 첨부용)."""

from autocve.evaluation.calibrate import Calibration
from autocve.evaluation.experiment import ExperimentResult
from autocve.evaluation.metrics import Accuracy, Metric


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.1%}"


def _status(passed: bool | None) -> str:
    return {True: "달성", False: "미달", None: "-"}[passed]


def format_metric(metric: Metric) -> str:
    if metric.value is None:
        return "-"
    if metric.key == "notify_lag_p90":
        return f"{metric.value:.1f}시간"
    if metric.key == "cost_per_finding":
        return f"${metric.value:.4f}"
    return _pct(metric.value)


def metrics_table(metrics: list[Metric]) -> str:
    lines = ["| 지표 | 값 | 목표 | 결과 | 비고 |", "|------|----|------|------|------|"]
    for m in metrics:
        lines.append(
            f"| {m.label} | {format_metric(m)} | {m.target} | {_status(m.passed)} | {m.detail} |"
        )
    return "\n".join(lines)


def accuracy_section(title: str, acc: Accuracy) -> str:
    lines = [
        f"### {title}",
        "",
        f"- 정답 항목 {acc.cases}건, 판정이 있는 Finding {acc.decided}건, "
        f"보류(uncertain) {acc.uncertain}건, 분석 전 {acc.pending}건, "
        f"찾지 못함 {len(acc.unmatched)}건",
        f"- 정확도 {_pct(acc.accuracy)}, 정밀도 {_pct(acc.precision)}, 재현율 {_pct(acc.recall)}",
        f"- **놓친 비율(영향 있는데 영향 없음으로 판정) {_pct(acc.false_negative_rate)}**",
        "",
        "| | 시스템: 영향 있음 | 시스템: 영향 없음 |",
        "|---|---|---|",
        f"| 정답: 영향 있음 | {acc.true_positive} | {acc.false_negative} |",
        f"| 정답: 영향 없음 | {acc.false_positive} | {acc.true_negative} |",
    ]
    if acc.auto_closed_affected:
        lines += [
            "",
            f"- 자동 종결됐지만 실제로는 영향이 있던 건: **{acc.auto_closed_affected}건**",
        ]
    return "\n".join(lines)


def calibration_section(cal: Calibration) -> str:
    lines = [
        "### 자동 종결 임계값 보정",
        "",
        f"- JEV 판별이 있는 정답 표본 {cal.samples}건",
        f"- 권장: {cal.recommended if cal.recommended is not None else '없음'} ({cal.reason})",
        "",
        "| 임계값 | 자동 종결 | 그중 실제 영향 있음 | 오판율 |",
        "|--------|-----------|---------------------|--------|",
    ]
    for p in cal.points[::2]:
        lines.append(f"| {p.threshold:.2f} | {p.closed} | {p.errors} | {_pct(p.error_rate)} |")
    return "\n".join(lines)


def experiment_section(results: list[ExperimentResult]) -> str:
    lines = [
        "### 비교 실험",
        "",
        "| 전략 | 정확도 | 재현율 | 놓친 비율 | 보류 | 총 비용 | 건당 비용 |",
        "|------|--------|--------|-----------|------|---------|-----------|",
    ]
    for r in results:
        a = r.accuracy
        per = f"${r.cost_per_case}" if r.cost_per_case is not None else "-"
        lines.append(
            f"| {r.strategy} | {_pct(a.accuracy)} | {_pct(a.recall)} | "
            f"{_pct(a.false_negative_rate)} | {a.uncertain} | ${r.cost_usd:.4f} | {per} |"
        )
    return "\n".join(lines)

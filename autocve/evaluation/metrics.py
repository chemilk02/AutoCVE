"""MVP 성공 지표 (docs/01-mvp-scope.md §6)와 정답 셋 대비 정확도."""

import statistics
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.analysis.run import FINAL_VERDICTS
from autocve.collector.osv import as_utc
from autocve.evaluation.dataset import Case, resolve
from autocve.models import (
    Advisory,
    Analysis,
    Feedback,
    FeedbackAction,
    Finding,
    LlmUsage,
    Project,
    TriageResult,
    Verdict,
    Workspace,
)
from autocve.usage import NO_LLM_ACTIONS

NOTIFY_LAG_TARGET = timedelta(hours=2)


@dataclass
class Metric:
    key: str
    label: str
    value: float | None
    target: str
    passed: bool | None
    detail: str = ""


def _ratio(part: int, whole: int) -> float | None:
    return part / whole if whole else None


def _project_ids(workspace: Workspace):
    return select(Project.id).where(Project.workspace_id == workspace.id)


def latest_triage(session: Session, workspace: Workspace) -> list[TriageResult]:
    finding_ids = select(Finding.id).where(Finding.project_id.in_(_project_ids(workspace)))
    latest = (
        select(func.max(TriageResult.id))
        .where(TriageResult.finding_id.in_(finding_ids))
        .group_by(TriageResult.finding_id)
    )
    return session.scalars(select(TriageResult).where(TriageResult.id.in_(latest))).all()


def notify_lags(session: Session, workspace: Workspace) -> list[timedelta]:
    """OSV 반영 시각 → 알림 시각. 저장소 등록 전부터 있던 취약점(초기 적재분)은 뺀다."""
    rows = session.execute(
        select(Finding.notified_at, Advisory.modified, Project.created_at)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Project, Project.id == Finding.project_id)
        .where(Project.workspace_id == workspace.id, Finding.notified_at.is_not(None))
    )
    lags = []
    for notified_at, modified, project_created in rows:
        if as_utc(modified) >= as_utc(project_created):
            lags.append(as_utc(notified_at) - as_utc(modified))
    return lags


def success_metrics(session: Session, workspace: Workspace) -> list[Metric]:
    triage = latest_triage(session, workspace)
    triaged = len(triage)
    no_llm = sum(t.action in NO_LLM_ACTIONS and not t.audit for t in triage)
    finding_ids = [t.finding_id for t in triage]

    audited = [t for t in triage if t.audit]
    audit_errors = 0
    audit_done = 0
    for t in audited:
        analysis = session.scalar(
            select(Analysis)
            .where(Analysis.finding_id == t.finding_id, Analysis.verdict.in_(list(FINAL_VERDICTS)))
            .order_by(Analysis.id.desc())
        )
        if analysis is not None:
            audit_done += 1
            audit_errors += analysis.verdict == Verdict.AFFECTED

    opus = 0
    analyzed = 0
    if finding_ids:
        analyzed = session.scalar(
            select(func.count(func.distinct(Analysis.finding_id))).where(
                Analysis.finding_id.in_(finding_ids)
            )
        )
        opus = session.scalar(
            select(func.count(func.distinct(Analysis.finding_id))).where(
                Analysis.finding_id.in_(finding_ids), Analysis.model.like("%opus%")
            )
        )

    feedback = session.scalars(
        select(Feedback)
        .join(Finding, Finding.id == Feedback.finding_id)
        .where(Finding.project_id.in_(_project_ids(workspace)))
    ).all()
    judged = [f for f in feedback if f.system_verdict in (Verdict.AFFECTED, Verdict.NOT_AFFECTED)]
    overridden = [
        f
        for f in judged
        if (f.user_verdict == FeedbackAction.NOT_AFFECTED and f.system_verdict == Verdict.AFFECTED)
        or (
            f.user_verdict in (FeedbackAction.CONFIRM, FeedbackAction.FIXED)
            and f.system_verdict == Verdict.NOT_AFFECTED
        )
    ]

    total_cost = session.scalar(
        select(func.coalesce(func.sum(LlmUsage.cost_usd), 0)).where(
            LlmUsage.workspace_id == workspace.id, LlmUsage.stage != "eval"
        )
    )
    cost_per = Decimal(str(total_cost)) / triaged if triaged else None

    lags = notify_lags(session, workspace)
    p90 = None
    if lags:
        ordered = sorted(lags)
        p90 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.9))]

    def check(value, ok):
        return None if value is None else ok(value)

    no_llm_rate = _ratio(no_llm, triaged)
    audit_rate = _ratio(audit_errors, audit_done)
    # Claude 분석이 한 번도 없으면 "Opus를 안 썼다"는 의미가 없으므로 판단하지 않는다.
    opus_rate = _ratio(opus, triaged) if analyzed else None
    override_rate = _ratio(len(overridden), len(judged))
    return [
        Metric(
            "notify_lag_p90",
            "알림 지연 (OSV 반영 → 알림, p90)",
            p90.total_seconds() / 3600 if p90 else None,
            "2시간 이내",
            check(p90, lambda v: v <= NOTIFY_LAG_TARGET),
            f"표본 {len(lags)}건"
            + (
                f", 중앙값 {statistics.median(lags).total_seconds() / 3600:.1f}시간" if lags else ""
            ),
        ),
        Metric(
            "no_llm_rate",
            "Claude 호출 없이 종결된 후보 비율",
            no_llm_rate,
            "60% 이상",
            check(no_llm_rate, lambda v: v >= 0.60),
            f"{no_llm}/{triaged}건",
        ),
        Metric(
            "audit_error_rate",
            "JEV 자동 종결 감사 표본 오판율",
            audit_rate,
            "5% 이하",
            check(audit_rate, lambda v: v <= 0.05),
            f"{audit_errors}/{audit_done}건 (감사 대기 {len(audited) - audit_done}건)",
        ),
        Metric(
            "opus_rate",
            "Opus 도달 비율",
            opus_rate,
            "10% 이하",
            check(opus_rate, lambda v: v <= 0.10),
            f"{opus}/{triaged}건" if analyzed else "Claude 분석 기록 없음",
        ),
        Metric(
            "override_rate",
            "사용자가 판정을 뒤집은 비율",
            override_rate,
            "15% 이하",
            check(override_rate, lambda v: v <= 0.15),
            f"{len(overridden)}/{len(judged)}건",
        ),
        Metric(
            "cost_per_finding",
            "후보 1건당 평균 LLM 비용 (USD)",
            float(cost_per) if cost_per is not None else None,
            "기준선 측정",
            None,
            f"총 ${float(total_cost):.4f} / {triaged}건",
        ),
    ]


@dataclass
class Accuracy:
    cases: int = 0
    unmatched: list[Case] = field(default_factory=list)
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    uncertain: int = 0
    pending: int = 0
    # 정답이 affected인데 Claude 없이 자동 종결된 건 (가장 위험한 오류)
    auto_closed_affected: int = 0

    @property
    def decided(self) -> int:
        return self.true_positive + self.false_positive + self.true_negative + self.false_negative

    @property
    def accuracy(self) -> float | None:
        return _ratio(self.true_positive + self.true_negative, self.decided)

    @property
    def precision(self) -> float | None:
        return _ratio(self.true_positive, self.true_positive + self.false_positive)

    @property
    def recall(self) -> float | None:
        return _ratio(self.true_positive, self.true_positive + self.false_negative)

    @property
    def false_negative_rate(self) -> float | None:
        return _ratio(self.false_negative, self.true_positive + self.false_negative)


def score_verdict(accuracy: Accuracy, expected: str, predicted: str | None) -> None:
    if predicted is None:
        accuracy.pending += 1
    elif predicted == Verdict.UNCERTAIN:
        accuracy.uncertain += 1
    elif expected == Verdict.AFFECTED:
        if predicted == Verdict.AFFECTED:
            accuracy.true_positive += 1
        else:
            accuracy.false_negative += 1
    elif predicted == Verdict.AFFECTED:
        accuracy.false_positive += 1
    else:
        accuracy.true_negative += 1


def current_accuracy(session: Session, cases: list[Case]) -> Accuracy:
    """현재 시스템 판정을 정답과 비교한다. 사용자 처리 이전의 시스템 판정을 쓴다."""
    result = Accuracy(cases=len(cases))
    for case in cases:
        findings = resolve(session, case)
        if not findings:
            result.unmatched.append(case)
            continue
        for finding in findings:
            score_verdict(result, case.expected, system_verdict(session, finding))
            if case.expected == Verdict.AFFECTED and was_auto_closed(session, finding):
                result.auto_closed_affected += 1
    return result


def system_verdict(session: Session, finding: Finding) -> str | None:
    """사용자가 처리했으면 처리 직전의 시스템 판정, 아니면 현재 판정."""
    first = session.scalar(
        select(Feedback).where(Feedback.finding_id == finding.id).order_by(Feedback.id)
    )
    return first.system_verdict if first is not None else finding.verdict


def was_auto_closed(session: Session, finding: Finding) -> bool:
    return (
        session.scalar(
            select(func.count())
            .select_from(TriageResult)
            .where(
                TriageResult.finding_id == finding.id,
                TriageResult.action == "auto_close",
                TriageResult.audit.is_(False),
            )
        )
        > 0
    )

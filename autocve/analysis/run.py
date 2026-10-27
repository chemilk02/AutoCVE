"""판별 결과에 따라 Claude 분석을 돌리고 판정과 위험도를 반영한다 (§4.5, §6).

- 경로: haiku(경량) / sonnet·opus(도구 기반 심층)
- `uncertain`이면 한 단계 위 모델로 한 번만 올린다. Opus에서도 불확실하면 사람 검토로 남긴다.
- Haiku가 거부하면 Sonnet으로 한 번 다시 시도한다 (Haiku에는 서버 측 fallback이 없다).
- 자동 종결 감사 표본은 Haiku로 다시 보고, 오판이 많으면 자동 종결 임계값을 올린다.
"""

import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import anthropic
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.analysis import batch as batch_mod
from autocve.analysis import deep, light
from autocve.analysis.common import PROMPT_VERSION, TIERS, AnalysisOutcome, build_context
from autocve.analysis.profile import PROMPT_VERSION as PROFILE_VERSION
from autocve.credentials.service import CredentialError
from autocve.llm.gateway import BudgetExceeded, LlmGateway, LlmUnavailable
from autocve.models import (
    Advisory,
    AdvisoryProfile,
    Analysis,
    Component,
    Finding,
    FindingStatus,
    Project,
    TriageResult,
    Verdict,
    Workspace,
)
from autocve.scoring.risk import score_findings
from autocve.security.keyvault import KeyVault
from autocve.triage.policy import Action

logger = logging.getLogger(__name__)

FINAL_VERDICTS = {Verdict.AFFECTED, Verdict.NOT_AFFECTED, Verdict.UNCERTAIN}
BATCH_THRESHOLD = 20

# 감사 표본 오판율 기준 (§4.4)
AUDIT_WINDOW = 100
AUDIT_MIN_SAMPLES = 20
AUDIT_MAX_ERROR_RATE = 0.05
THRESHOLD_STEP = 0.02
THRESHOLD_MAX = 0.99
DEFAULT_AUTO_CLOSE_THRESHOLD = 0.90


@dataclass
class AnalysisSummary:
    analyzed: int = 0
    escalated: int = 0
    refused: int = 0
    errors: int = 0
    cache_hits: int = 0
    batched: int = 0
    budget_stopped: int = 0
    audit_mismatches: int = 0
    by_model: Counter = field(default_factory=Counter)

    def as_dict(self) -> dict:
        return {**self.__dict__, "by_model": dict(self.by_model)}


def analysis_key(triage: TriageResult, tier: str) -> str | None:
    if not triage.cache_key:
        return None
    raw = f"{triage.cache_key}:{PROMPT_VERSION}:{tier}"
    return hashlib.sha256(raw.encode()).hexdigest()


def latest_triage(session: Session, finding_id: int) -> TriageResult | None:
    return session.scalar(
        select(TriageResult)
        .where(TriageResult.finding_id == finding_id)
        .order_by(TriageResult.id.desc())
    )


def advisory_profile(session: Session, workspace: Workspace, advisory_id: str) -> dict:
    row = session.scalar(
        select(AdvisoryProfile).where(
            AdvisoryProfile.workspace_id == workspace.id,
            AdvisoryProfile.advisory_id == advisory_id,
            AdvisoryProfile.prompt_version == PROFILE_VERSION,
        )
    )
    return row.profile if row else {}


def record_outcome(
    session: Session,
    finding: Finding,
    triage: TriageResult | None,
    outcome: AnalysisOutcome,
    cache_key: str | None,
    summary: AnalysisSummary,
) -> None:
    session.add(
        Analysis(
            finding_id=finding.id,
            model=outcome.model,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            rationale=outcome.rationale,
            evidence=[*outcome.evidence, *({"data_flow": s} for s in outcome.data_flow)],
            cache_key=cache_key or "",
        )
    )
    summary.by_model[outcome.model] += 1
    if outcome.verdict in FINAL_VERDICTS:
        finding.verdict = outcome.verdict
        finding.status = FindingStatus.ANALYZED
        summary.analyzed += 1
        if triage is not None and triage.audit and outcome.verdict != Verdict.NOT_AFFECTED:
            summary.audit_mismatches += 1
    elif outcome.verdict == "refused":
        finding.status = FindingStatus.ANALYSIS_REFUSED
        summary.refused += 1
    else:
        # API 오류 등: 다음 분석 때 다시 시도한다.
        finding.status = FindingStatus.TRIAGED
        summary.errors += 1
    session.commit()


def _run_tier(
    gateway: LlmGateway, tier: str, context: str, checkout: Path | None, finding_id: int
) -> AnalysisOutcome | None:
    if tier == "haiku":
        return light.analyze(gateway, context, finding_id)
    if checkout is None:
        return None  # 심층 분석은 코드가 있어야 한다
    return deep.analyze(gateway, tier, context, checkout, finding_id)


def _next_tier(tier: str) -> str | None:
    index = TIERS.index(tier)
    return TIERS[index + 1] if index + 1 < len(TIERS) else None


def analyze_one(
    gateway: LlmGateway, tier: str, context: str, checkout: Path | None, finding_id: int
) -> tuple[AnalysisOutcome | None, bool]:
    """(결과, 올렸는지). 코드가 없어 심층 분석을 못 하면 결과가 None."""
    outcome = _run_tier(gateway, tier, context, checkout, finding_id)
    if outcome is None:
        return None, False
    retry_tier = None
    if outcome.verdict == "uncertain":
        retry_tier = _next_tier(tier)
    elif outcome.verdict == "refused" and tier == "haiku":
        retry_tier = "sonnet"
    if retry_tier is None:
        return outcome, False
    retried = _run_tier(gateway, retry_tier, context, checkout, finding_id)
    if retried is None or retried.verdict == "error":
        return outcome, False
    return retried, True


def update_auto_close_threshold(session: Session, workspace: Workspace) -> float:
    """최근 감사 표본의 오판율이 기준을 넘으면 자동 종결 임계값을 올린다."""
    audited = (
        session.execute(
            select(TriageResult.finding_id)
            .join(Finding, Finding.id == TriageResult.finding_id)
            .where(
                Finding.project_id.in_(
                    select(Project.id).where(Project.workspace_id == workspace.id)
                )
            )
            .where(TriageResult.audit.is_(True))
            .order_by(TriageResult.id.desc())
            .limit(AUDIT_WINDOW)
        )
        .scalars()
        .all()
    )
    verdicts = []
    for finding_id in audited:
        analysis = session.scalar(
            select(Analysis)
            .where(Analysis.finding_id == finding_id, Analysis.verdict.in_(list(FINAL_VERDICTS)))
            .order_by(Analysis.id.desc())
        )
        if analysis is not None:
            verdicts.append(analysis.verdict)
    settings = dict(workspace.model_settings or {})
    threshold = float(settings.get("auto_close_threshold", DEFAULT_AUTO_CLOSE_THRESHOLD))
    if len(verdicts) >= AUDIT_MIN_SAMPLES:
        rate = sum(v == Verdict.AFFECTED for v in verdicts) / len(verdicts)
        if rate > AUDIT_MAX_ERROR_RATE and threshold < THRESHOLD_MAX:
            threshold = round(min(THRESHOLD_MAX, threshold + THRESHOLD_STEP), 2)
            settings["auto_close_threshold"] = threshold
            workspace.model_settings = settings
            session.commit()
            logger.warning(
                "자동 종결 감사 오판율 %.1f%% → 임계값을 %.2f로 올립니다", rate * 100, threshold
            )
    return threshold


def analyze_findings(
    session: Session,
    project: Project,
    *,
    vault: KeyVault,
    checkout: Path | None,
    gateway: LlmGateway | None = None,
    batch_threshold: int = BATCH_THRESHOLD,
) -> AnalysisSummary:
    workspace = session.get(Workspace, project.workspace_id)
    gateway = gateway or LlmGateway(session, workspace, vault)
    summary = AnalysisSummary()
    if not gateway.available():
        score_findings(session, project_id=project.id)
        return summary

    rows = session.execute(
        select(Finding, Component, Advisory)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .where(
            Finding.project_id == project.id,
            Finding.status == FindingStatus.TRIAGED,
            Finding.verdict.is_(None),
        )
        .order_by(Finding.id)
    ).all()

    work = []
    for finding, component, advisory in rows:
        triage = latest_triage(session, finding.id)
        if triage is None or not triage.route:
            continue
        if triage.action not in (Action.ANALYZE, Action.AUTO_CLOSE):
            continue
        context = build_context(
            advisory=advisory,
            component=component,
            project=project,
            profile=advisory_profile(session, workspace, advisory.id),
            evidence=triage.evidence or {},
        )
        work.append((finding, triage, context))

    # 실시간이 필요 없는 Haiku 분석이 많으면 Batch API로 보낸다.
    batchable = [w for w in work if w[1].route == "haiku" and not w[1].audit and not _severe(w[1])]
    if len(batchable) >= batch_threshold:
        items = [
            batch_mod.BatchItem(f.id, ctx, analysis_key(t, "haiku") or "")
            for f, t, ctx in batchable
        ]
        try:
            batch_mod.submit(session, gateway, items)
            summary.batched = len(items)
            done = {f.id for f, _, _ in batchable}
            work = [w for w in work if w[0].id not in done]
        except (BudgetExceeded, LlmUnavailable, CredentialError, anthropic.APIError) as e:
            logger.warning("배치 제출 실패, 실시간으로 분석합니다: %s", type(e).__name__)
            session.rollback()

    for finding, triage, context in work:
        key = analysis_key(triage, triage.route)
        cached = None
        if key:
            cached = session.scalar(
                select(Analysis)
                .where(Analysis.cache_key == key, Analysis.verdict.in_(list(FINAL_VERDICTS)))
                .order_by(Analysis.id.desc())
            )
        if cached is not None:
            outcome = AnalysisOutcome(
                cached.verdict,
                cached.model,
                cached.confidence,
                cached.rationale or "",
                [e for e in cached.evidence or [] if "data_flow" not in e],
                [e["data_flow"] for e in cached.evidence or [] if "data_flow" in e],
            )
            summary.cache_hits += 1
            record_outcome(session, finding, triage, outcome, key, summary)
            continue
        if gateway.budget().ratio >= 1.0:
            finding.status = FindingStatus.UNANALYZED
            summary.budget_stopped += 1
            session.commit()
            continue
        try:
            outcome, escalated = analyze_one(gateway, triage.route, context, checkout, finding.id)
        except BudgetExceeded:
            finding.status = FindingStatus.UNANALYZED
            summary.budget_stopped += 1
            session.commit()
            continue
        if outcome is None:
            continue  # 코드가 없어 심층 분석을 미룬다
        summary.escalated += int(escalated)
        record_outcome(session, finding, triage, outcome, key, summary)

    if summary.audit_mismatches:
        update_auto_close_threshold(session, workspace)
    score_findings(session, project_id=project.id)
    logger.info("프로젝트 %s 분석: %s", project.id, summary.as_dict())
    return summary


def _severe(triage: TriageResult) -> bool:
    return bool((triage.evidence or {}).get("severe"))


def collect_batches(session: Session, workspace: Workspace, vault: KeyVault, gateway=None) -> dict:
    """끝난 배치 결과를 반영한다. uncertain은 Sonnet 분석이 필요하므로 다시 판별 대기로 돌린다."""
    gateway = gateway or LlmGateway(session, workspace, vault)
    summary = AnalysisSummary()
    needs_deep: set[int] = set()

    def apply(finding: Finding, outcome: AnalysisOutcome, cache_key: str) -> None:
        triage = latest_triage(session, finding.id)
        if outcome.verdict == "uncertain" or outcome.verdict == "refused":
            session.add(
                Analysis(
                    finding_id=finding.id,
                    model=outcome.model,
                    verdict=outcome.verdict,
                    confidence=outcome.confidence,
                    rationale=outcome.rationale,
                    evidence=outcome.evidence,
                    cache_key=cache_key,
                )
            )
            session.add(
                TriageResult(
                    finding_id=finding.id,
                    provider="analysis",
                    action=Action.ANALYZE,
                    route="sonnet",
                    reasons=["Haiku 분석으로 결론이 나지 않아 Sonnet으로 올림"],
                    evidence=triage.evidence if triage else {},
                    cache_key=triage.cache_key if triage else None,
                )
            )
            finding.status = FindingStatus.TRIAGED
            summary.escalated += 1
            needs_deep.add(finding.project_id)
            session.commit()
            return
        record_outcome(session, finding, triage, outcome, cache_key, summary)

    collected = 0
    for batch in batch_mod.pending_batches(session, workspace.id):
        result = batch_mod.safe_collect(session, gateway, batch, apply)
        collected += result or 0
    if collected:
        score_findings(session)
    return {**summary.as_dict(), "collected": collected, "projects_to_analyze": sorted(needs_deep)}

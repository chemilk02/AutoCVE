"""사용량 대시보드 통계 (§5.3): 비용, Claude 호출 없이 종결된 비율, 라우팅 분포, 캐시 적중률."""

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.llm.gateway import BudgetStatus, budget_status, month_start
from autocve.models import Analysis, Finding, LlmUsage, Project, TriageResult, Workspace

# Claude 분석 없이 끝난 판별 행동
NO_LLM_ACTIONS = {"auto_close", "dev_only", "malicious", "withdrawn", "version_mismatch"}


@dataclass
class UsageStats:
    budget: BudgetStatus
    by_stage: list[tuple[str, int, Decimal]] = field(default_factory=list)
    by_model: list[tuple[str, int, Decimal]] = field(default_factory=list)
    daily: list[tuple[str, Decimal]] = field(default_factory=list)
    triaged: int = 0
    closed_without_llm: int = 0
    routes: Counter = field(default_factory=Counter)
    triage_sources: Counter = field(default_factory=Counter)
    analyses: int = 0
    cache_read_tokens: int = 0
    input_tokens_total: int = 0
    batch_calls: int = 0
    jev_calls: int = 0

    @property
    def no_llm_rate(self) -> float | None:
        return self.closed_without_llm / self.triaged if self.triaged else None

    @property
    def cache_hit_rate(self) -> float | None:
        return self.cache_read_tokens / self.input_tokens_total if self.input_tokens_total else None

    @property
    def max_daily(self) -> Decimal:
        return max((cost for _, cost in self.daily), default=Decimal(0))


def collect(session: Session, workspace: Workspace, days: int = 30) -> UsageStats:
    stats = UsageStats(budget=budget_status(session, workspace))
    since_month = month_start()
    base = select(LlmUsage).where(
        LlmUsage.workspace_id == workspace.id, LlmUsage.created_at >= since_month
    )
    rows = session.scalars(base).all()

    stage: dict[str, list] = {}
    model: dict[str, list] = {}
    for usage in rows:
        for bucket, key in ((stage, usage.stage), (model, usage.model)):
            entry = bucket.setdefault(key, [0, Decimal(0)])
            entry[0] += 1
            entry[1] += Decimal(usage.cost_usd or 0)
        if usage.provider == "anthropic":
            stats.cache_read_tokens += usage.cache_read_input_tokens
            stats.input_tokens_total += (
                usage.input_tokens
                + usage.cache_read_input_tokens
                + usage.cache_creation_input_tokens
            )
        stats.batch_calls += int(usage.batch)
        stats.jev_calls += int(usage.stage == "jev")
    stats.by_stage = sorted(((k, v[0], v[1]) for k, v in stage.items()), key=lambda r: -r[2])
    stats.by_model = sorted(((k, v[0], v[1]) for k, v in model.items()), key=lambda r: -r[2])

    since_days = datetime.now(UTC) - timedelta(days=days - 1)
    day_start = since_days.replace(hour=0, minute=0, second=0, microsecond=0)
    daily: dict[str, Decimal] = {}
    for usage in session.scalars(
        select(LlmUsage).where(
            LlmUsage.workspace_id == workspace.id, LlmUsage.created_at >= day_start
        )
    ):
        key = usage.created_at.strftime("%m-%d")
        daily[key] = daily.get(key, Decimal(0)) + Decimal(usage.cost_usd or 0)
    stats.daily = [
        ((day_start + timedelta(days=i)).strftime("%m-%d"),
         daily.get((day_start + timedelta(days=i)).strftime("%m-%d"), Decimal(0)))
        for i in range(days)
    ]  # fmt: skip

    project_ids = select(Project.id).where(Project.workspace_id == workspace.id)
    finding_ids = select(Finding.id).where(Finding.project_id.in_(project_ids))
    # Finding마다 마지막 판별 결과만 센다 (배치 결과로 다시 판별된 경우 등).
    latest = (
        select(func.max(TriageResult.id))
        .where(TriageResult.finding_id.in_(finding_ids))
        .group_by(TriageResult.finding_id)
    )
    for result in session.scalars(select(TriageResult).where(TriageResult.id.in_(latest))):
        stats.triaged += 1
        stats.triage_sources[result.provider] += 1
        if result.action in NO_LLM_ACTIONS and not result.audit:
            stats.closed_without_llm += 1
        if result.route:
            stats.routes[result.route] += 1
    stats.analyses = session.scalar(
        select(func.count()).select_from(Analysis).where(Analysis.finding_id.in_(finding_ids))
    )
    return stats

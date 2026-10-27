"""비교 실험 (§5.2).

현재 파이프라인(JEV 캐스케이드)과 "Opus 단일 + 낮은 effort"를 같은 정답 셋에서 비교한다.

- `current`: 이미 DB에 있는 판정과 기록된 비용을 쓴다. API를 부르지 않는다.
- `opus_low`: 정답 셋의 Finding마다 Opus(effort low)로 심층 분석을 새로 돌린다. 비용이 든다.
  비용은 stage="eval"로 따로 기록해 운영 지표와 섞이지 않게 한다.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.analysis import deep
from autocve.analysis.common import build_context
from autocve.analysis.run import advisory_profile, latest_triage
from autocve.config import Settings
from autocve.credentials.service import load_secret
from autocve.evaluation.dataset import Case, resolve
from autocve.evaluation.metrics import Accuracy, score_verdict, system_verdict
from autocve.inventory.scan import checked_out
from autocve.llm.gateway import LlmGateway
from autocve.models import Advisory, Component, Finding, LlmUsage, Project, Provider, Workspace
from autocve.security.keyvault import KeyVault

logger = logging.getLogger(__name__)

STRATEGIES = ("current", "opus_low")
# 사전 안내용 상한 추정: Opus 도구 루프 1건 ≈ 누적 입력 100K, 출력 5K (docs/01 §6)
ESTIMATED_COST_PER_CASE = Decimal("0.50")


@dataclass
class ExperimentResult:
    strategy: str
    accuracy: Accuracy
    cost_usd: Decimal = Decimal(0)
    per_case: list[dict] = field(default_factory=list)

    @property
    def cost_per_case(self) -> Decimal | None:
        decided = len(self.per_case)
        return (self.cost_usd / decided).quantize(Decimal("0.0001")) if decided else None


def _cost(session: Session, finding_ids: list[int], *, stage_eval: bool) -> Decimal:
    if not finding_ids:
        return Decimal(0)
    query = select(func.coalesce(func.sum(LlmUsage.cost_usd), 0)).where(
        LlmUsage.finding_id.in_(finding_ids)
    )
    query = (
        query.where(LlmUsage.stage == "eval")
        if stage_eval
        else query.where(LlmUsage.stage != "eval")
    )
    return Decimal(str(session.scalar(query)))


def run_current(session: Session, cases: list[Case]) -> ExperimentResult:
    result = ExperimentResult("current", Accuracy(cases=len(cases)))
    ids = []
    for case in cases:
        findings = resolve(session, case)
        if not findings:
            result.accuracy.unmatched.append(case)
        for finding in findings:
            predicted = system_verdict(session, finding)
            score_verdict(result.accuracy, case.expected, predicted)
            result.per_case.append(
                {"finding_id": finding.id, "expected": case.expected, "predicted": predicted}
            )
            ids.append(finding.id)
    result.cost_usd = _cost(session, ids, stage_eval=False)
    return result


def run_opus_low(
    session: Session,
    cases: list[Case],
    workspace: Workspace,
    vault: KeyVault,
    settings: Settings,
    *,
    gateway: LlmGateway | None = None,
    allow_local: bool = False,
) -> ExperimentResult:
    gateway = gateway or LlmGateway(session, workspace, vault)
    result = ExperimentResult("opus_low", Accuracy(cases=len(cases)))
    by_project: dict[int, list[tuple[Case, Finding]]] = defaultdict(list)
    for case in cases:
        findings = resolve(session, case)
        if not findings:
            result.accuracy.unmatched.append(case)
        for finding in findings:
            by_project[finding.project_id].append((case, finding))

    token = load_secret(session, vault, workspace, Provider.GITHUB)
    ids = []
    for project_id, items in by_project.items():
        project = session.get(Project, project_id)
        with checked_out(
            session, project, token=token, workdir=settings.scan_workdir, allow_local=allow_local
        ) as (root, _):
            for case, finding in items:
                triage = latest_triage(session, finding.id)
                context = build_context(
                    advisory=session.get(Advisory, finding.advisory_id),
                    component=session.get(Component, finding.component_id),
                    project=project,
                    profile=advisory_profile(session, workspace, finding.advisory_id),
                    evidence=(triage.evidence if triage else None) or {},
                )
                outcome = deep.analyze(
                    gateway, "opus", context, root, finding.id, effort="low", stage="eval"
                )
                predicted = (
                    outcome.verdict
                    if outcome.verdict in ("affected", "not_affected", "uncertain")
                    else None
                )
                score_verdict(result.accuracy, case.expected, predicted)
                result.per_case.append(
                    {
                        "finding_id": finding.id,
                        "expected": case.expected,
                        "predicted": predicted,
                        "rationale": outcome.rationale,
                    }
                )
                ids.append(finding.id)
    result.cost_usd = _cost(session, ids, stage_eval=True)
    return result


def estimate_cost(session: Session, cases: list[Case]) -> tuple[int, Decimal]:
    count = sum(len(resolve(session, case)) for case in cases)
    return count, ESTIMATED_COST_PER_CASE * count

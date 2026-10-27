"""새 후보 Finding을 판별한다: G0 필터 → 프로파일 → 증거 → JEV(또는 규칙) → 정책."""

import hashlib
import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.analysis.profile import PROMPT_VERSION, get_profile
from autocve.collector.osv import as_utc
from autocve.config import Settings
from autocve.credentials.service import CredentialError, load_secret
from autocve.llm.gateway import LlmGateway, record_usage
from autocve.matcher.matcher import affects
from autocve.models import (
    Advisory,
    Component,
    ExploitSignal,
    Finding,
    FindingStatus,
    JevProvider,
    Project,
    Provider,
    TriageResult,
    Verdict,
    Workspace,
)
from autocve.scoring.cvss import attack_vector, severity_score
from autocve.security.keyvault import KeyVault
from autocve.triage.evidence import collect_evidence
from autocve.triage.inputs import TriageInput
from autocve.triage.models import Judgement, RuleTriage, SystemOneTriage, TriageError, TriageModel
from autocve.triage.policy import Action, PolicyConfig, decide

logger = logging.getLogger(__name__)


def jev_model(
    session: Session,
    workspace: Workspace,
    vault: KeyVault,
    settings: Settings,
    http: httpx.Client | None = None,
) -> SystemOneTriage | None:
    choice = JevProvider(workspace.jev_provider)
    if choice == JevProvider.NONE:
        return None
    provider = Provider(choice.value)
    try:
        key = load_secret(session, vault, workspace, provider)
    except CredentialError as e:
        logger.warning("JEV 키를 읽을 수 없어 규칙 기반으로 판별합니다: %s", e)
        return None
    if key is None:
        return None
    if provider == Provider.TYPESAFE:
        base, default_model = settings.typesafe_base_url, settings.jev_typesafe_model
    else:
        base, default_model = settings.openrouter_base_url, settings.jev_openrouter_model
    return SystemOneTriage(provider.value, base, key, workspace.jev_model or default_model, http)


def exploit_signals(session: Session, advisory: Advisory) -> tuple[float | None, bool]:
    cves = [a for a in [advisory.id, *(advisory.aliases or [])] if a.startswith("CVE-")]
    if not cves:
        return None, False
    signals = session.scalars(select(ExploitSignal).where(ExploitSignal.cve_id.in_(cves))).all()
    epss = max((s.epss for s in signals if s.epss is not None), default=None)
    return epss, any(s.in_kev for s in signals)


def cache_key(inp: TriageInput, advisory: Advisory, provider: str) -> str:
    payload = {
        "advisory": advisory.id,
        "modified": as_utc(advisory.modified).isoformat(),
        "package": inp.package,
        "direct": inp.direct,
        "scope": inp.scope,
        "evidence": inp.evidence.fingerprint,
        "profile": PROMPT_VERSION,
        "provider": provider,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


@dataclass
class TriageSummary:
    triaged: int = 0
    resolved: int = 0
    actions: Counter = field(default_factory=Counter)
    jev_calls: int = 0
    degraded: int = 0
    cache_hits: int = 0


def _resolve(session: Session, finding: Finding, action: str, reason: str) -> None:
    finding.status = FindingStatus.RESOLVED
    session.add(
        TriageResult(finding_id=finding.id, provider="rules", action=action, reasons=[reason])
    )


def triage_findings(
    session: Session,
    project: Project,
    *,
    vault: KeyVault,
    settings: Settings,
    checkout: Path | None = None,
    http: httpx.Client | None = None,
    gateway: LlmGateway | None = None,
    jev: TriageModel | None = None,
    config: PolicyConfig | None = None,
) -> TriageSummary:
    """프로젝트의 `new` Finding을 판별한다. `jev`를 넘기지 않으면 워크스페이스 설정을 따른다."""
    workspace = session.get(Workspace, project.workspace_id)
    if config is None:
        # 감사 표본 오판율이 높으면 분석 단계가 임계값을 올려 둔다 (analysis/run.py).
        threshold = (workspace.model_settings or {}).get("auto_close_threshold")
        config = (
            PolicyConfig(auto_close_threshold=float(threshold)) if threshold else PolicyConfig()
        )
    gateway = gateway or LlmGateway(session, workspace, vault)
    if jev is None:
        jev = jev_model(session, workspace, vault, settings, http)
    rules = RuleTriage()
    summary = TriageSummary()

    rows = session.execute(
        select(Finding, Component, Advisory)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .where(Finding.project_id == project.id, Finding.status == FindingStatus.NEW)
        .order_by(Finding.id)
    ).all()

    for finding, component, advisory in rows:
        # G0: 매칭 이후 취약점이 바뀌었을 수 있으므로 다시 확인한다.
        if advisory.withdrawn is not None:
            _resolve(session, finding, "withdrawn", "취약점이 철회됨")
            summary.resolved += 1
            session.commit()
            continue
        if not affects(advisory, component):
            _resolve(session, finding, "version_mismatch", "현재 버전은 영향 범위가 아님")
            summary.resolved += 1
            session.commit()
            continue

        malicious = advisory.id.startswith("MAL-")
        epss, in_kev = exploit_signals(session, advisory)
        profile: dict = {}
        dev_skipped = component.scope == "dev" and config.skip_dev
        if not dev_skipped and (malicious or gateway.available()):
            profile = get_profile(
                session, gateway, workspace, advisory, component.name, http=http
            ).profile
        evidence = collect_evidence(
            session, component, profile.get("vulnerable_symbols") or [], checkout
        )
        inp = TriageInput(
            finding_id=finding.id,
            advisory_id=advisory.id,
            summary=(advisory.summary or "")[:500],
            package=component.purl,
            direct=component.direct,
            scope=component.scope,
            cvss=severity_score(advisory),
            epss=epss,
            in_kev=in_kev,
            attack_vector=attack_vector(advisory),
            malicious=malicious,
            profile=profile,
            evidence=evidence,
        )

        provider_name = getattr(jev, "provider", None) or rules.provider
        key = cache_key(inp, advisory, provider_name)
        judgement: Judgement | None = None
        degraded = False
        cached = session.scalar(
            select(TriageResult)
            .where(TriageResult.cache_key == key, TriageResult.finding_id != finding.id)
            .order_by(TriageResult.id.desc())
        )
        if cached is not None and cached.exposure_probs:
            judgement = Judgement(
                exposure_probs=cached.exposure_probs,
                route_probs=cached.route_probs,
                confidence=cached.confidence or 0.0,
                provider="cache",
                model_version=cached.model_version,
                reasons=["같은 입력의 이전 판별 결과를 재사용"],
            )
            summary.cache_hits += 1
        elif not (malicious or dev_skipped):
            if jev is not None:
                try:
                    judgement = jev.judge(inp, include_snippets=project.jev_snippets)
                    summary.jev_calls += 1
                    record_usage(
                        session,
                        workspace,
                        provider=judgement.provider,
                        model=judgement.model_version or "jev",
                        stage="jev",
                        finding_id=finding.id,
                        input_tokens=judgement.input_tokens,
                    )
                except TriageError as e:
                    logger.warning("JEV 판별 실패, 규칙으로 대체 (finding %s): %s", finding.id, e)
                    degraded = True
                    summary.degraded += 1
            if judgement is None:
                judgement = rules.judge(inp)
        if judgement is None:
            # 악성 패키지, dev 전용: 판별 모델을 부르지 않는다.
            judgement = Judgement({}, {}, 1.0, provider="rules")

        decision = decide(inp, judgement, gateway.budget().ratio, config)
        session.add(
            TriageResult(
                finding_id=finding.id,
                provider=judgement.provider,
                model_version=judgement.model_version,
                exposure_probs=judgement.exposure_probs,
                route_probs=judgement.route_probs,
                confidence=judgement.confidence,
                action=decision.action,
                route=decision.route,
                reasons=decision.reasons,
                # severe: 분석 단계가 Batch API로 미룰지 정할 때 쓴다 (KEV, CVSS 9 이상은 실시간)
                evidence={**evidence.as_dict(), "severe": inp.severe},
                audit=decision.audit,
                degraded=degraded,
                cache_key=key if judgement.exposure_probs else None,
            )
        )
        if decision.action == Action.AUTO_CLOSE and not decision.audit:
            finding.verdict = Verdict.NOT_AFFECTED
            finding.status = FindingStatus.TRIAGED
        elif decision.action == Action.MALICIOUS:
            finding.verdict = Verdict.AFFECTED
            finding.status = FindingStatus.TRIAGED
        elif decision.action == Action.BUDGET:
            finding.status = FindingStatus.UNANALYZED
        else:
            finding.status = FindingStatus.TRIAGED
        summary.triaged += 1
        summary.actions[decision.action] += 1
        session.commit()

    logger.info(
        "프로젝트 %s 판별: %d건 (%s), JEV %d회, 캐시 %d회, 대체 %d회",
        project.id,
        summary.triaged,
        dict(summary.actions),
        summary.jev_calls,
        summary.cache_hits,
        summary.degraded,
    )
    return summary

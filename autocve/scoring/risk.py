"""위험도 산정 (§6).

risk = 100 × severity × exploit × reachability × exposure

모든 요소 값을 함께 저장해, 화면에서 왜 이 등급인지 바로 보여줄 수 있게 한다.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.models import Advisory, Component, Finding, FindingStatus, Project, Verdict
from autocve.scoring.cvss import severity_score

DEFAULT_SEVERITY = 5.0  # 심각도 정보가 없을 때의 중간값

REACHABILITY = {Verdict.AFFECTED: 1.0, Verdict.NOT_AFFECTED: 0.05, Verdict.UNCERTAIN: 0.6}
PENDING_REACHABILITY = 0.6  # 아직 분석 전이면 uncertain과 같게 본다
EXPOSURE = {"internet": 1.0, "internal": 0.7, "dev": 0.2}
DEV_SCOPE_EXPOSURE = 0.2

GRADES = ((70, "critical"), (40, "high"), (20, "medium"), (5, "low"), (0, "info"))
GRADE_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


@dataclass(frozen=True)
class RiskInput:
    cvss: float | None
    epss: float | None
    in_kev: bool
    verdict: str | None
    project_exposure: str
    scope: str
    malicious: bool = False


def grade_for(score: float) -> str:
    return next(grade for threshold, grade in GRADES if score >= threshold)


def compute(inp: RiskInput) -> tuple[float, str, dict]:
    if inp.malicious:
        severity, exploit = 1.0, 1.0
    else:
        severity = (inp.cvss if inp.cvss is not None else DEFAULT_SEVERITY) / 10
        exploit = 1.0 if inp.in_kev else 0.7 + 0.3 * (inp.epss or 0.0)
    reachability = REACHABILITY.get(inp.verdict, PENDING_REACHABILITY)
    exposure = EXPOSURE.get(inp.project_exposure, 1.0)
    if inp.scope == "dev":
        exposure = min(exposure, DEV_SCOPE_EXPOSURE)
    score = round(100 * severity * exploit * reachability * exposure, 1)
    factors = {
        "severity": round(severity, 3),
        "cvss": inp.cvss,
        "exploit": round(exploit, 3),
        "epss": inp.epss,
        "in_kev": inp.in_kev,
        "reachability": reachability,
        "verdict": inp.verdict,
        "exposure": exposure,
        "malicious": inp.malicious,
    }
    return score, grade_for(score), factors


def score_findings(
    session: Session,
    finding_ids: list[int] | None = None,
    project_id: int | None = None,
    *,
    include_closed: bool = False,
) -> int:
    """Finding의 위험도를 다시 계산한다. 해소·기각된 것은 `include_closed`일 때만 계산한다."""
    from autocve.triage.run import exploit_signals  # 순환 import 방지

    query = (
        select(Finding, Component, Advisory, Project)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Project, Project.id == Finding.project_id)
    )
    if not include_closed:
        query = query.where(
            Finding.status.not_in([FindingStatus.RESOLVED, FindingStatus.DISMISSED])
        )
    if finding_ids is not None:
        query = query.where(Finding.id.in_(finding_ids))
    if project_id is not None:
        query = query.where(Finding.project_id == project_id)
    count = 0
    for finding, component, advisory, project in session.execute(query):
        epss, in_kev = exploit_signals(session, advisory)
        score, grade, factors = compute(
            RiskInput(
                cvss=severity_score(advisory),
                epss=epss,
                in_kev=in_kev,
                verdict=finding.verdict,
                project_exposure=project.exposure,
                scope=component.scope,
                malicious=advisory.id.startswith("MAL-"),
            )
        )
        finding.risk_score, finding.grade, finding.risk_factors = score, grade, factors
        count += 1
    session.commit()
    return count

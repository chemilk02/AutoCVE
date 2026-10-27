"""정답 셋: 저장소·취약점·패키지마다 실제 영향 여부(affected / not_affected).

두 가지로 만든다.
- 사용자 처리 기록에서 내보내기: 영향 있음 확인·수정 완료 → affected, 해당 없음 → not_affected
- 직접 작성한 JSON 파일 (형식은 docs/03-evaluation.md)
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from autocve.ecosystems import PYPI, normalize_name
from autocve.models import (
    Advisory,
    Component,
    Feedback,
    FeedbackAction,
    Finding,
    Project,
    Verdict,
    Workspace,
)

LABELS = (Verdict.AFFECTED.value, Verdict.NOT_AFFECTED.value)
FEEDBACK_LABELS = {
    FeedbackAction.CONFIRM: Verdict.AFFECTED,
    FeedbackAction.FIXED: Verdict.AFFECTED,
    FeedbackAction.NOT_AFFECTED: Verdict.NOT_AFFECTED,
}


class DatasetError(Exception):
    pass


@dataclass(frozen=True)
class Case:
    repo_url: str
    advisory_id: str
    package: str
    expected: str
    note: str = ""


def load(path: Path) -> list[Case]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise DatasetError(f"정답 셋을 읽지 못했습니다: {e}") from e
    cases = []
    for i, raw in enumerate(data.get("cases", [])):
        try:
            case = Case(
                repo_url=str(raw["repo_url"]).strip(),
                advisory_id=str(raw["advisory_id"]).strip(),
                package=str(raw["package"]).strip(),
                expected=str(raw["expected"]).strip(),
                note=str(raw.get("note", "")),
            )
        except KeyError as e:
            raise DatasetError(f"{i}번째 항목에 {e} 필드가 없습니다") from e
        if case.expected not in LABELS:
            raise DatasetError(f"{i}번째 항목의 expected는 {LABELS} 중 하나여야 합니다")
        cases.append(case)
    return cases


def dump(cases: list[Case]) -> str:
    return json.dumps({"cases": [asdict(c) for c in cases]}, ensure_ascii=False, indent=2)


def from_feedback(session: Session, workspace: Workspace) -> list[Case]:
    """Finding마다 마지막 처리 기록을 정답으로 쓴다. '다시 열기'만 있는 것은 뺀다."""
    latest = (
        select(func.max(Feedback.id))
        .join(Finding, Finding.id == Feedback.finding_id)
        .join(Project, Project.id == Finding.project_id)
        .where(Project.workspace_id == workspace.id)
        .group_by(Feedback.finding_id)
    )
    rows = session.execute(
        select(Feedback, Finding, Component, Project)
        .join(Finding, Finding.id == Feedback.finding_id)
        .join(Component, Component.id == Finding.component_id)
        .join(Project, Project.id == Finding.project_id)
        .where(Feedback.id.in_(latest))
        .order_by(Feedback.id)
    )
    cases = []
    for feedback, finding, component, project in rows:
        label = FEEDBACK_LABELS.get(FeedbackAction(feedback.user_verdict))
        if label is None:
            continue
        cases.append(
            Case(
                repo_url=project.repo_url,
                advisory_id=finding.advisory_id,
                package=component.name,
                expected=label.value,
                note=feedback.reason or "",
            )
        )
    return cases


def resolve(session: Session, case: Case) -> list[Finding]:
    """정답 항목에 해당하는 Finding. 같은 패키지가 여러 위치에 설치되어 있으면 모두 돌려준다.

    취약점 ID는 별칭(GHSA, CVE, PYSEC)으로 적어도 찾는다.
    """
    rows = session.execute(
        select(Finding, Component, Advisory)
        .join(Component, Component.id == Finding.component_id)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Project, Project.id == Finding.project_id)
        .where(Project.repo_url == case.repo_url)
    ).all()
    matches = []
    for finding, component, advisory in rows:
        names = {component.name, normalize_name(PYPI, component.name)}
        if case.package not in names and normalize_name(PYPI, case.package) not in names:
            continue
        if case.advisory_id == advisory.id or case.advisory_id in (advisory.aliases or []):
            matches.append(finding)
    return matches

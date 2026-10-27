"""컴포넌트와 취약점을 대조해 후보 Finding을 만든다.

양방향으로 쓴다.
- 새/변경 취약점 → `match_advisories`
- 새/변경 컴포넌트 → `match_components`

버전이 바뀌어 더 이상 영향 범위가 아닌 미처리 Finding은 `resolved`로 바꾼다.
철회 등 그 밖의 종결 판단은 판별 단계(G0)가 맡는다.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from autocve.ecosystems import normalize_name
from autocve.matcher.versions import is_affected
from autocve.models import Advisory, AdvisoryPackage, Component, Finding, FindingStatus

OPEN_STATUSES = {
    FindingStatus.NEW,
    FindingStatus.TRIAGED,
    FindingStatus.ANALYZING,
    FindingStatus.ANALYZED,
    FindingStatus.NOTIFIED,
    FindingStatus.UNANALYZED,
    FindingStatus.ANALYSIS_REFUSED,
}


@dataclass
class MatchResult:
    created: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)


def affects(advisory: Advisory, component: Component) -> bool:
    if advisory.withdrawn is not None:
        return False
    for entry in advisory.affected or []:
        package = entry.get("package") or {}
        if package.get("ecosystem") != component.ecosystem:
            continue
        if normalize_name(component.ecosystem, package.get("name", "")) != component.name:
            continue
        if is_affected(component.ecosystem, component.version, entry):
            return True
    return False


def _existing(session: Session, pairs: set[tuple[int, str]]) -> dict[tuple[int, str], Finding]:
    if not pairs:
        return {}
    found: dict[tuple[int, str], Finding] = {}
    pair_list = list(pairs)
    for i in range(0, len(pair_list), 500):
        chunk = pair_list[i : i + 500]
        rows = session.scalars(
            select(Finding).where(tuple_(Finding.component_id, Finding.advisory_id).in_(chunk))
        )
        for finding in rows:
            found[(finding.component_id, finding.advisory_id)] = finding
    return found


def advisory_keys(advisory: Advisory) -> set[str]:
    return {advisory.id, *(advisory.aliases or [])}


# 같은 취약점이 여러 DB에 실려 있으면(GHSA-…, PYSEC-…) 이 순서로 하나만 남긴다.
_PREFERENCE = ("GHSA-", "CVE-", "PYSEC-")


def _preference(advisory: Advisory) -> tuple[int, str]:
    for rank, prefix in enumerate(_PREFERENCE):
        if advisory.id.startswith(prefix):
            return rank, advisory.id
    return len(_PREFERENCE), advisory.id


def _covered_keys(session: Session, component_ids: set[int]) -> dict[int, set[str]]:
    """컴포넌트별로 이미 Finding이 있는 취약점 ID와 별칭.

    업그레이드 등으로 해소된 Finding은 빼서, 별칭 중 하나만 철회된 경우 다른 쪽이 다시 잡히게 한다.
    """
    covered: dict[int, set[str]] = {}
    ids = list(component_ids)
    for i in range(0, len(ids), 500):
        rows = session.execute(
            select(Finding.component_id, Advisory)
            .join(Advisory, Advisory.id == Finding.advisory_id)
            .where(
                Finding.component_id.in_(ids[i : i + 500]),
                Finding.status != FindingStatus.RESOLVED,
            )
        )
        for component_id, advisory in rows:
            covered.setdefault(component_id, set()).update(advisory_keys(advisory))
    return covered


def _evaluate(session: Session, pairs: Iterable[tuple[Component, Advisory]]) -> MatchResult:
    pairs = sorted(pairs, key=lambda pair: _preference(pair[1]))
    existing = _existing(session, {(c.id, a.id) for c, a in pairs})
    covered = _covered_keys(session, {c.id for c, _ in pairs})
    result = MatchResult()
    for component, advisory in pairs:
        finding = existing.get((component.id, advisory.id))
        if affects(advisory, component):
            if finding is None:
                keys = advisory_keys(advisory)
                component_covered = covered.setdefault(component.id, set())
                if keys & component_covered:
                    continue  # 별칭으로 연결된 같은 취약점의 Finding이 이미 있다
                component_covered.update(keys)
                finding = Finding(
                    project_id=component.project_id,
                    component_id=component.id,
                    advisory_id=advisory.id,
                    status=FindingStatus.NEW,
                )
                session.add(finding)
                existing[(component.id, advisory.id)] = finding
                result.created.append(finding)
            elif finding.status == FindingStatus.RESOLVED:
                # 다운그레이드 등으로 다시 영향 범위에 들면 새 후보로 되살린다.
                # 사용자가 직접 닫은 것(dismissed)은 그대로 둔다.
                finding.status = FindingStatus.NEW
                finding.verdict = None
                result.created.append(finding)
        elif finding is not None and finding.status in OPEN_STATUSES:
            finding.status = FindingStatus.RESOLVED
            result.resolved.append(finding)
    session.commit()
    return result


def match_components(session: Session, components: Iterable[Component]) -> MatchResult:
    components = list(components)
    keys = {(c.ecosystem, c.name) for c in components}
    if not keys:
        return MatchResult()
    advisories_by_key: dict[tuple[str, str], list[Advisory]] = {}
    key_list = list(keys)
    for i in range(0, len(key_list), 500):
        rows = session.execute(
            select(AdvisoryPackage.ecosystem, AdvisoryPackage.name, Advisory)
            .join(Advisory, Advisory.id == AdvisoryPackage.advisory_id)
            .where(
                tuple_(AdvisoryPackage.ecosystem, AdvisoryPackage.name).in_(key_list[i : i + 500])
            )
        )
        for ecosystem, name, advisory in rows:
            advisories_by_key.setdefault((ecosystem, name), []).append(advisory)

    # 컴포넌트에 이미 걸린 Finding도 다시 평가해야 업그레이드로 해소된 것을 찾을 수 있다.
    linked = session.execute(
        select(Finding.component_id, Advisory)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .where(Finding.component_id.in_([c.id for c in components]))
    )
    linked_by_component: dict[int, list[Advisory]] = {}
    for component_id, advisory in linked:
        linked_by_component.setdefault(component_id, []).append(advisory)

    pairs = []
    for component in components:
        advisories = {
            a.id: a for a in advisories_by_key.get((component.ecosystem, component.name), [])
        }
        advisories.update({a.id: a for a in linked_by_component.get(component.id, [])})
        pairs.extend((component, a) for a in advisories.values())
    return _evaluate(session, pairs)


def match_advisories(session: Session, advisory_ids: Iterable[str]) -> MatchResult:
    advisory_ids = list(advisory_ids)
    pairs = []
    for i in range(0, len(advisory_ids), 500):
        chunk = advisory_ids[i : i + 500]
        rows = session.execute(
            select(Component, Advisory)
            .join(
                AdvisoryPackage,
                (AdvisoryPackage.ecosystem == Component.ecosystem)
                & (AdvisoryPackage.name == Component.name),
            )
            .join(Advisory, Advisory.id == AdvisoryPackage.advisory_id)
            .where(Advisory.id.in_(chunk))
        )
        pairs.extend((c, a) for c, a in rows)
        # 패키지 목록에서 빠진 경우에도 기존 Finding은 다시 평가한다.
        linked = session.execute(
            select(Component, Advisory)
            .join(Finding, Finding.component_id == Component.id)
            .join(Advisory, Advisory.id == Finding.advisory_id)
            .where(Advisory.id.in_(chunk))
        )
        pairs.extend((c, a) for c, a in linked)
    unique = {(c.id, a.id): (c, a) for c, a in pairs}
    return _evaluate(session, unique.values())

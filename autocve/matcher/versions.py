"""OSV `affected` 항목에 대해 버전이 영향 범위에 드는지 판정한다.

OSV 스키마의 범위 평가 규칙을 따른다: 이벤트를 버전 순으로 정렬해 차례로 보며
`introduced` 이상이면 영향, `fixed` 이상이거나 `last_affected` 초과면 비영향으로 바꾼다.
"""

import re
from functools import total_ordering

from packaging.version import InvalidVersion, Version

from autocve.ecosystems import NPM, PYPI

_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@total_ordering
class SemVer:
    def __init__(self, text: str):
        match = _SEMVER.match(text.strip())
        if match is None:
            raise ValueError(f"SemVer가 아닙니다: {text}")
        self.core = (int(match["major"]), int(match["minor"]), int(match["patch"]))
        self.pre = tuple(match["pre"].split(".")) if match["pre"] else ()

    def _pre_key(self) -> tuple:
        # 프리릴리스가 없는 버전이 같은 core의 프리릴리스보다 크다.
        if not self.pre:
            return (1,)
        parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre)
        return (0, parts)

    def _key(self) -> tuple:
        return (self.core, self._pre_key())

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other: "SemVer") -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def parse_version(ecosystem: str, text: str):
    """비교 가능한 버전 객체를 돌려준다. 해석할 수 없으면 None."""
    try:
        if ecosystem == NPM:
            return SemVer(text)
        if ecosystem == PYPI:
            return Version(text)
    except (ValueError, InvalidVersion):
        return None
    return None


_ZERO = object()  # introduced: "0" — 모든 버전보다 작다


def _event_version(ecosystem: str, value: str):
    return _ZERO if value == "0" else parse_version(ecosystem, value)


def _in_range(ecosystem: str, version, events: list[dict]) -> bool | None:
    parsed: list[tuple[str, object]] = []
    for event in events:
        for kind in ("introduced", "fixed", "last_affected"):
            if kind in event:
                value = _event_version(ecosystem, event[kind])
                if value is None:
                    return None  # 해석할 수 없는 이벤트가 있으면 판단을 보류한다
                parsed.append((kind, value))

    def sort_key(item):
        _, value = item
        return (0,) if value is _ZERO else (1, value)

    affected = False
    for kind, value in sorted(parsed, key=sort_key):
        if kind == "introduced" and (value is _ZERO or version >= value):
            affected = True
        elif kind == "fixed" and value is not _ZERO and version >= value:
            affected = False
        elif kind == "last_affected" and value is not _ZERO and version > value:
            affected = False
    return affected


def is_affected(ecosystem: str, version_text: str, affected_entry: dict) -> bool:
    """하나의 OSV `affected` 항목에 대해 판정한다. 해석할 수 없는 범위는 영향 없음으로 본다."""
    if version_text in affected_entry.get("versions", []):
        return True
    version = parse_version(ecosystem, version_text)
    if version is None:
        return False
    for range_ in affected_entry.get("ranges", []):
        if range_.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue  # GIT 범위는 커밋 기준이라 패키지 버전과 비교할 수 없다
        if _in_range(ecosystem, version, range_.get("events", [])):
            return True
    return False

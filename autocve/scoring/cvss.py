"""OSV `severity`에서 0~10 점수를 얻는다.

- CVSS v3.x 벡터는 명세(FIRST CVSS v3.1 §7)대로 기본 점수를 계산한다.
- v4 벡터나 벡터가 없는 경우에는 GHSA 등급(database_specific.severity)을 대표값으로 바꾼다.
"""

import math

from autocve.models import Advisory

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


def _roundup(value: float) -> float:
    # CVSS v3.1 부록 A의 Roundup: 부동소수 오차 없이 소수 첫째 자리로 올림
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def _severity_entries(advisory: Advisory) -> list[dict]:
    entries = list(advisory.severity or [])
    for affected in advisory.affected or []:
        entries.extend(affected.get("severity") or [])
    return entries


def severity_score(advisory: Advisory) -> float | None:
    scores = [
        score
        for entry in _severity_entries(advisory)
        if entry.get("type") == "CVSS_V3"
        and (score := cvss3_base_score(entry.get("score", ""))) is not None
    ]
    if scores:
        return max(scores)
    label = str((advisory.database_specific or {}).get("severity", "")).upper()
    return LABEL_SCORES.get(label)


def attack_vector(advisory: Advisory) -> str | None:
    """CVSS 벡터의 AV 값 (N/A/L/P). v3, v4 모두 같은 표기를 쓴다."""
    for entry in _severity_entries(advisory):
        for part in entry.get("score", "").split("/"):
            if part.startswith("AV:"):
                return part[3:]
    return None

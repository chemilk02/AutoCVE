from decimal import Decimal
from types import SimpleNamespace

import pytest

from autocve.llm.pricing import cost_usd
from autocve.scoring.cvss import attack_vector, cvss3_base_score, severity_score


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_non_v3_vectors_are_ignored():
    assert cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H") is None
    assert cvss3_base_score("CVSS:3.1/AV:N/garbage") is None


def advisory(severity=None, database_specific=None, affected=None):
    return SimpleNamespace(
        severity=severity or [], database_specific=database_specific or {}, affected=affected or []
    )


def test_severity_prefers_v3_vector_then_label():
    v3 = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert severity_score(advisory([v3], {"severity": "LOW"})) == 9.8
    v4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}
    assert severity_score(advisory([v4], {"severity": "MODERATE"})) == 5.5
    assert severity_score(advisory()) is None
    assert attack_vector(advisory([v4])) == "L"


def test_cost_usd():
    cost = cost_usd(
        "anthropic",
        "claude-opus-5-5",
        input_tokens=100_000,
        output_tokens=5_000,
        cache_read_input_tokens=50_000,
    )
    assert cost == Decimal("0.510000")  # 0.4 + 0.1 + 0.01
    assert cost_usd("typesafe", "jev-1.14", input_tokens=4_000) == Decimal("0.000168")
    assert cost_usd("anthropic", "unknown-model", input_tokens=1) == 0

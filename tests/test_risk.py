import pytest
from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace
from autocve.ecosystems import purl
from autocve.models import Component, ExploitSignal, Finding, Project
from autocve.scoring.risk import RiskInput, compute, grade_for, score_findings
from tests.osv_fixtures import advisory


def risk(**overrides):
    values = {
        "cvss": 7.5,
        "epss": 0.01,
        "in_kev": False,
        "verdict": "affected",
        "project_exposure": "internet",
        "scope": "prod",
    }
    values.update(overrides)
    return compute(RiskInput(**values))


def test_kev_critical_reachable_is_critical():
    score, grade, factors = risk(cvss=9.8, in_kev=True)
    assert (score, grade) == (98.0, "critical")
    assert factors["exploit"] == 1.0


def test_reachable_high_without_exploitation_stays_high():
    score, grade, _ = risk()
    assert score == pytest.approx(52.7)
    assert grade == "high"


@pytest.mark.parametrize(
    ("overrides", "grade"),
    [
        ({"verdict": "not_affected"}, "info"),
        ({"verdict": "uncertain"}, "medium"),
        ({"verdict": None}, "medium"),
        ({"scope": "dev"}, "low"),
        ({"project_exposure": "internal"}, "medium"),
        ({"cvss": None}, "medium"),
    ],
)
def test_factors_lower_the_grade(overrides, grade):
    assert risk(**overrides)[1] == grade


def test_malicious_package_ignores_cvss():
    score, grade, _ = risk(cvss=None, epss=None, malicious=True)
    assert (score, grade) == (100.0, "critical")


def test_grade_boundaries():
    assert [grade_for(s) for s in (70, 69.9, 40, 20, 5, 4.9)] == [
        "critical",
        "high",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_score_findings_uses_signals(session_factory):
    with session_factory() as session:
        workspace = get_or_create_default_workspace(session)
        project = Project(workspace_id=workspace.id, name="a", repo_url="https://github.com/o/a")
        session.add(project)
        record = advisory("GHSA-1", "lodash", "4.17.12", aliases=["CVE-2019-10744"])
        record["severity"] = [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
        upsert_advisory(session, record)
        session.add(ExploitSignal(cve_id="CVE-2019-10744", epss=0.5, in_kev=True))
        session.flush()
        component = Component(
            project_id=project.id,
            locator="node_modules/lodash",
            purl=purl("npm", "lodash", "4.17.11"),
            ecosystem="npm",
            name="lodash",
            version="4.17.11",
            direct=True,
            scope="prod",
            manifest_path="package-lock.json",
        )
        session.add(component)
        session.flush()
        session.add(
            Finding(
                project_id=project.id,
                component_id=component.id,
                advisory_id="GHSA-1",
                verdict="affected",
            )
        )
        session.commit()

        assert score_findings(session, project_id=project.id) == 1
        finding = session.scalar(select(Finding))
        assert (finding.risk_score, finding.grade) == (98.0, "critical")
        assert finding.risk_factors["in_kev"] is True

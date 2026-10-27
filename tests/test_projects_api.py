import re

from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.ecosystems import purl
from autocve.models import Component, ExploitSignal, Finding, Project
from tests.osv_fixtures import advisory


def test_create_project_enqueues_scan(client, queue, session_factory):
    response = client.post(
        "/projects",
        data={"name": "web", "repo_url": "https://github.com/acme/web", "exposure": "internal"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    with session_factory() as session:
        project = session.scalar(select(Project))
    assert response.headers["location"] == f"/projects/{project.id}?queued=1"
    assert project.exposure == "internal"
    assert queue.jobs == [("scan_project", project.id)]


def test_create_project_rejects_bad_url(client, queue):
    response = client.post("/projects", data={"name": "x", "repo_url": "http://example.com/r"})
    assert response.status_code == 400
    assert "https://" in response.text
    assert queue.jobs == []


def test_duplicate_repo_rejected(client):
    data = {"name": "web", "repo_url": "https://github.com/acme/web"}
    client.post("/projects", data=data)
    assert client.post("/projects", data=data).status_code == 400


def test_detail_shows_findings_with_signals(client, session_factory):
    client.post("/projects", data={"name": "web", "repo_url": "https://github.com/acme/web"})
    with session_factory() as session:
        project = session.scalar(select(Project))
        upsert_advisory(
            session, advisory("GHSA-1", "lodash", "4.17.12", aliases=["CVE-2019-10744"])
        )
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
        session.add(ExploitSignal(cve_id="CVE-2019-10744", epss=0.0321, in_kev=True))
        session.flush()
        session.add(Finding(project_id=project.id, component_id=component.id, advisory_id="GHSA-1"))
        session.commit()
        project_id = project.id

    page = client.get(f"/projects/{project_id}").text
    assert "GHSA-1" in page
    assert "lodash@4.17.11" in page
    assert "KEV" in page
    assert "EPSS 3.2%" in page

    listing = client.get("/projects").text
    assert "web" in listing


def test_rescan_and_delete(client, queue, session_factory):
    client.post("/projects", data={"name": "web", "repo_url": "https://github.com/acme/web"})
    with session_factory() as session:
        project_id = session.scalar(select(Project.id))

    client.post(f"/projects/{project_id}/scan")
    assert queue.jobs[-1] == ("scan_project", project_id)

    client.post(f"/projects/{project_id}/delete")
    assert client.get(f"/projects/{project_id}").status_code == 404


def test_unknown_project_404(client):
    assert client.get("/projects/999").status_code == 404


def test_project_settings_update(client, session_factory):
    client.post("/projects", data={"name": "web", "repo_url": "https://github.com/acme/web"})
    with session_factory() as session:
        project_id = session.scalar(select(Project.id))
    client.post(f"/projects/{project_id}/settings", data={"exposure": "dev"})
    with session_factory() as session:
        project = session.get(Project, project_id)
        assert (project.exposure, project.jev_snippets) == ("dev", False)
    client.post(
        f"/projects/{project_id}/settings", data={"exposure": "internal", "jev_snippets": "on"}
    )
    with session_factory() as session:
        project = session.get(Project, project_id)
        assert (project.exposure, project.jev_snippets) == ("internal", True)
    assert (
        client.post(f"/projects/{project_id}/settings", data={"exposure": "x"}).status_code == 400
    )


def test_detail_shows_triage_result(client, session_factory):
    from autocve.models import TriageResult

    test_detail_shows_findings_with_signals(client, session_factory)
    with session_factory() as session:
        finding = session.scalar(select(Finding))
        session.add(
            TriageResult(
                finding_id=finding.id,
                provider="openrouter",
                exposure_probs={
                    "not_affected": 0.1,
                    "possibly_affected": 0.2,
                    "likely_affected": 0.7,
                },
                route_probs={"sonnet": 1.0},
                confidence=0.7,
                action="analyze",
                route="sonnet",
                reasons=["취약 API 사용 위치 2곳"],
            )
        )
        session.commit()
        project_id = finding.project_id
    page = client.get(f"/projects/{project_id}").text
    assert "분석 대기 → Sonnet" in page
    assert "영향 가능성 높음 70%" in page
    assert "취약 API 사용 위치 2곳" in page


def test_rule_based_triage_hides_percentage():
    from autocve.api.routes_projects import describe_triage
    from autocve.models import TriageResult

    result = TriageResult(
        provider="rules",
        exposure_probs={"not_affected": 0.2, "possibly_affected": 0.6, "likely_affected": 0.2},
        action="analyze",
        route="haiku",
    )
    assert describe_triage(result)["exposure"] == "영향 가능"


def test_detail_shows_grade_and_analysis(client, session_factory):
    from autocve.models import Analysis

    test_detail_shows_findings_with_signals(client, session_factory)
    with session_factory() as session:
        finding = session.scalar(select(Finding))
        finding.risk_score, finding.grade = 98.0, "critical"
        session.add(
            Analysis(
                finding_id=finding.id,
                model="claude-sonnet-5-5",
                verdict="affected",
                rationale="render.js에서 사용자 입력이 _.template로 전달됩니다.",
                cache_key="",
            )
        )
        session.commit()
        project_id = finding.project_id
    page = client.get(f"/projects/{project_id}").text
    assert re.search(r'Critical</div>\s*<div class="tile-value">1<', page)
    assert "영향 있음" in page and "claude-sonnet-5-5" in page
    assert "render.js에서 사용자 입력이" in page

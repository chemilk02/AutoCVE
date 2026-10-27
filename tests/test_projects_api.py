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

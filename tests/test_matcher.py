from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace
from autocve.ecosystems import purl
from autocve.matcher.matcher import match_advisories, match_components
from autocve.models import Component, Finding, FindingStatus, Project
from tests.osv_fixtures import advisory


def make_component(session, name="lodash", version="4.17.11", ecosystem="npm"):
    workspace = get_or_create_default_workspace(session)
    project = session.scalar(select(Project)) or Project(
        workspace_id=workspace.id, name="app", repo_url="https://github.com/o/app"
    )
    session.add(project)
    session.flush()
    component = Component(
        project_id=project.id,
        locator=f"node_modules/{name}",
        purl=purl(ecosystem, name, version),
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=True,
        scope="prod",
        manifest_path="package-lock.json",
    )
    session.add(component)
    session.commit()
    return component


def test_new_component_matches_existing_advisory(session_factory):
    with session_factory() as session:
        upsert_advisory(session, advisory("GHSA-1", "lodash", "4.17.12"))
        upsert_advisory(session, advisory("GHSA-2", "lodash", "4.0.0"))
        session.commit()
        component = make_component(session)

        result = match_components(session, [component])
        assert [f.advisory_id for f in result.created] == ["GHSA-1"]

        # 다시 돌려도 중복 Finding을 만들지 않는다.
        assert match_components(session, [component]).created == []


def test_upgrade_resolves_open_finding(session_factory):
    with session_factory() as session:
        upsert_advisory(session, advisory("GHSA-1", "lodash", "4.17.12"))
        session.commit()
        component = make_component(session)
        match_components(session, [component])

        component.version = "4.17.21"
        session.commit()
        result = match_components(session, [component])
        assert [f.advisory_id for f in result.resolved] == ["GHSA-1"]
        assert session.scalar(select(Finding)).status == FindingStatus.RESOLVED

        # 다시 취약한 버전으로 내려가면 같은 Finding을 되살린다.
        component.version = "4.17.10"
        session.commit()
        result = match_components(session, [component])
        assert [f.advisory_id for f in result.created] == ["GHSA-1"]
        assert session.scalar(select(Finding)).status == FindingStatus.NEW


def test_dismissed_finding_is_not_reopened(session_factory):
    with session_factory() as session:
        upsert_advisory(session, advisory("GHSA-1", "lodash", "4.17.12"))
        session.commit()
        component = make_component(session)
        match_components(session, [component])
        session.scalar(select(Finding)).status = FindingStatus.DISMISSED
        session.commit()

        assert match_components(session, [component]).created == []
        assert session.scalar(select(Finding)).status == FindingStatus.DISMISSED


def test_new_advisory_matches_existing_component(session_factory):
    with session_factory() as session:
        component = make_component(session, name="minimist", version="1.2.5")
        upsert_advisory(session, advisory("GHSA-3", "minimist", "1.2.6"))
        session.commit()

        result = match_advisories(session, ["GHSA-3"])
        assert [(f.component_id, f.advisory_id) for f in result.created] == [
            (component.id, "GHSA-3")
        ]


def test_withdrawn_advisory_resolves_finding(session_factory):
    with session_factory() as session:
        make_component(session)
        upsert_advisory(session, advisory("GHSA-1", "lodash", "4.17.12"))
        session.commit()
        match_advisories(session, ["GHSA-1"])

        upsert_advisory(
            session,
            advisory(
                "GHSA-1",
                "lodash",
                "4.17.12",
                modified="2026-06-01T00:00:00Z",
                withdrawn="2026-06-01T00:00:00Z",
            ),
        )
        session.commit()
        result = match_advisories(session, ["GHSA-1"])
        assert len(result.resolved) == 1


def test_aliased_advisories_produce_one_finding(session_factory):
    with session_factory() as session:
        upsert_advisory(
            session,
            advisory(
                "PYSEC-2019-217",
                "jinja2",
                "2.10.1",
                ecosystem="PyPI",
                aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
            ),
        )
        upsert_advisory(
            session,
            advisory(
                "GHSA-462w-v97r-4m45",
                "jinja2",
                "2.10.1",
                ecosystem="PyPI",
                aliases=["CVE-2019-10906", "PYSEC-2019-217"],
            ),
        )
        session.commit()
        component = make_component(session, name="jinja2", version="2.10", ecosystem="PyPI")

        result = match_components(session, [component])
        assert [f.advisory_id for f in result.created] == ["GHSA-462w-v97r-4m45"]
        # 별칭 쪽 레코드가 나중에 갱신되어도 중복을 만들지 않는다.
        assert match_advisories(session, ["PYSEC-2019-217"]).created == []


def test_pypi_names_are_compared_normalized(session_factory):
    with session_factory() as session:
        upsert_advisory(session, advisory("PYSEC-1", "Django", "4.2.2", ecosystem="PyPI"))
        session.commit()
        component = make_component(session, name="django", version="4.2.1", ecosystem="PyPI")
        assert len(match_components(session, [component]).created) == 1

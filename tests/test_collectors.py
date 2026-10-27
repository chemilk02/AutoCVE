import gzip

import httpx
import pytest
from sqlalchemy import select

from autocve.collector import exploit, osv
from autocve.collector.cursors import get_cursor
from autocve.models import Advisory, AdvisoryPackage, ExploitSignal
from tests.osv_fixtures import BASE_URL, FakeOsv, advisory


@pytest.fixture
def fake_osv():
    return FakeOsv()


def sync(session, fake, ecosystem="npm"):
    return osv.sync_ecosystem(session, osv.OsvClient(fake.client(), BASE_URL), ecosystem)


def test_parse_time_truncates_nanoseconds():
    parsed = osv.parse_time("2026-10-26T21:30:05.269205908Z")
    assert parsed.microsecond == 269205
    assert parsed.utcoffset().total_seconds() == 0


def test_bootstrap_loads_dump_and_sets_cursor(session_factory, fake_osv):
    fake_osv.put("npm", advisory("GHSA-1", "lodash", "4.17.12", modified="2026-01-02T00:00:00Z"))
    fake_osv.put("npm", advisory("GHSA-2", "qs", "6.10.3", modified="2026-01-01T00:00:00Z"))
    with session_factory() as session:
        result = sync(session, fake_osv)
        assert result.bootstrapped
        assert {a.id for a in session.scalars(select(Advisory))} == {"GHSA-1", "GHSA-2"}
        assert get_cursor(session, "osv:npm").startswith("2026-01-02T00:00:00")
    assert "npm/all.zip" in fake_osv.requests


def test_incremental_fetches_only_newer_records(session_factory, fake_osv):
    fake_osv.put("npm", advisory("GHSA-1", "lodash", "4.17.12", modified="2026-01-01T00:00:00Z"))
    with session_factory() as session:
        sync(session, fake_osv)
        fake_osv.requests.clear()

        fake_osv.put(
            "npm", advisory("GHSA-1", "lodash", "4.17.13", modified="2026-02-01T00:00:00Z")
        )
        fake_osv.put(
            "npm", advisory("GHSA-3", "minimist", "1.2.6", modified="2026-02-02T00:00:00Z")
        )
        result = sync(session, fake_osv)

        assert not result.bootstrapped
        assert sorted(result.changed_ids) == ["GHSA-1", "GHSA-3"]
        assert "npm/all.zip" not in fake_osv.requests
        updated = session.get(Advisory, "GHSA-1")
        assert updated.affected[0]["ranges"][0]["events"][1]["fixed"] == "4.17.13"

        # 바뀐 것이 없으면 아무것도 받지 않는다.
        fake_osv.requests.clear()
        assert sync(session, fake_osv).changed_ids == []
        assert fake_osv.requests == ["npm/modified_id.csv"]


def test_missing_record_is_skipped(session_factory, fake_osv):
    fake_osv.put("npm", advisory("GHSA-1", "lodash", "4.17.12"))
    with session_factory() as session:
        sync(session, fake_osv)
        fake_osv.put("npm", advisory("GHSA-9", "x", "1.0.0", modified="2026-03-01T00:00:00Z"))
        original = fake_osv.handler

        def without_record(request):
            if request.url.path.endswith("GHSA-9.json"):
                return httpx.Response(404)
            return original(request)

        fake_osv.handler = without_record
        assert sync(session, fake_osv).changed_ids == []


def test_package_rows_normalize_pypi_and_skip_unsupported():
    record = {
        "id": "GHSA-x",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "Django_REST.framework"}},
            {"package": {"ecosystem": "RubyGems", "name": "rails"}},
            {"package": {"ecosystem": "npm", "name": "@scope/Pkg"}},
        ],
    }
    assert osv.package_rows(record) == [
        {"advisory_id": "GHSA-x", "ecosystem": "PyPI", "name": "django-rest-framework"},
        {"advisory_id": "GHSA-x", "ecosystem": "npm", "name": "@scope/Pkg"},
    ]


def test_upsert_ignores_older_record(session_factory):
    with session_factory() as session:
        newer = advisory("GHSA-1", "a", "2.0.0", modified="2026-05-01T00:00:00Z")
        older = advisory("GHSA-1", "a", "1.0.0", modified="2026-04-01T00:00:00Z")
        assert osv.upsert_advisory(session, newer)
        session.commit()
        assert not osv.upsert_advisory(session, older)
        packages = session.scalars(select(AdvisoryPackage)).all()
        assert [(p.ecosystem, p.name) for p in packages] == [("npm", "a")]


def mock_http(routes: dict[str, httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda r: routes[str(r.url)]))


def test_epss_keeps_only_known_cves(session_factory):
    csv_text = (
        "#model_version:v2025.03.14,score_date:2026-10-26T12:55:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2019-10744,0.0321,0.87\n"
        "CVE-1999-0001,0.5,0.99\n"
    )
    http = mock_http(
        {
            "https://epss.test/x.csv.gz": httpx.Response(
                200, content=gzip.compress(csv_text.encode())
            )
        }
    )
    with session_factory() as session:
        osv.upsert_advisory(
            session, advisory("GHSA-1", "lodash", "4.17.12", aliases=["CVE-2019-10744"])
        )
        session.commit()
        result = exploit.sync_epss(session, http, "https://epss.test/x.csv.gz")
        assert result.updated == 1
        assert str(result.score_date) == "2026-10-26"
        signal = session.get(ExploitSignal, "CVE-2019-10744")
        assert signal.epss == pytest.approx(0.0321)
        assert session.get(ExploitSignal, "CVE-1999-0001") is None


def test_kev_sets_and_clears_flag(session_factory):
    url = "https://kev.test/kev.json"
    first = {
        "catalogVersion": "1",
        "vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2026-01-05"}, {"cveID": "CVE-2"}],
    }
    second = {"catalogVersion": "2", "vulnerabilities": [{"cveID": "CVE-2"}]}
    with session_factory() as session:
        exploit.sync_kev(session, mock_http({url: httpx.Response(200, json=first)}), url)
        assert session.get(ExploitSignal, "CVE-1").in_kev
        assert str(session.get(ExploitSignal, "CVE-1").kev_date_added) == "2026-01-05"

        exploit.sync_kev(session, mock_http({url: httpx.Response(200, json=second)}), url)
        assert not session.get(ExploitSignal, "CVE-1").in_kev
        assert session.get(ExploitSignal, "CVE-2").in_kev
        assert get_cursor(session, "kev") == "2"

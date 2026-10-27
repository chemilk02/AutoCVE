import pytest

from autocve.ecosystems import NPM, PYPI
from autocve.matcher.versions import SemVer, is_affected, parse_version


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.9.0", "1.10.0"),
        ("1.0.0-alpha", "1.0.0"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
    ],
)
def test_semver_ordering(lower, higher):
    assert SemVer(lower) < SemVer(higher)


def test_semver_ignores_build_metadata_and_v_prefix():
    assert SemVer("v1.2.3+build.5") == SemVer("1.2.3")


def test_invalid_versions_return_none():
    assert parse_version(NPM, "latest") is None
    assert parse_version(PYPI, "not a version!") is None


def semver_range(*events):
    return {"ranges": [{"type": "SEMVER", "events": list(events)}]}


@pytest.mark.parametrize(
    ("version", "expected"),
    [("4.17.11", True), ("4.17.12", False), ("0.1.0", True), ("5.0.0", False)],
)
def test_introduced_fixed(version, expected):
    entry = semver_range({"introduced": "0"}, {"fixed": "4.17.12"})
    assert is_affected(NPM, version, entry) is expected


def test_last_affected_is_inclusive():
    entry = semver_range({"introduced": "1.0.0"}, {"last_affected": "1.2.0"})
    assert is_affected(NPM, "1.2.0", entry)
    assert not is_affected(NPM, "1.2.1", entry)
    assert not is_affected(NPM, "0.9.0", entry)


def test_multiple_intervals():
    entry = semver_range(
        {"introduced": "1.0.0"},
        {"fixed": "1.0.5"},
        {"introduced": "2.0.0"},
        {"fixed": "2.1.0"},
    )
    assert is_affected(NPM, "1.0.4", entry)
    assert not is_affected(NPM, "1.5.0", entry)
    assert is_affected(NPM, "2.0.3", entry)
    assert not is_affected(NPM, "2.1.0", entry)


def test_explicit_versions_list():
    entry = {"versions": ["0.0.1-security"], "ranges": []}
    assert is_affected(NPM, "0.0.1-security", entry)
    assert not is_affected(NPM, "0.0.2", entry)


def test_pypi_ecosystem_range_uses_pep440():
    entry = {
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.28"}]}]
    }
    assert is_affected(PYPI, "2.2.27", entry)
    assert is_affected(PYPI, "2.2.28rc1", entry)
    assert not is_affected(PYPI, "2.2.28", entry)
    assert not is_affected(PYPI, "3.0", entry)


def test_git_ranges_are_ignored():
    entry = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
    assert not is_affected(NPM, "1.0.0", entry)


def test_unparseable_version_is_not_affected():
    assert not is_affected(NPM, "github:user/repo", semver_range({"introduced": "0"}))

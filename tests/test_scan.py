import json
import subprocess

import pytest
from sqlalchemy import select

from autocve.collector.osv import upsert_advisory
from autocve.credentials.service import get_or_create_default_workspace
from autocve.inventory import repo
from autocve.models import CodeFile, Component, Finding, Project
from autocve.pipeline import scan_and_match
from autocve.security.keyvault import KeyVault
from tests.osv_fixtures import advisory


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def write_lock(path, versions: dict[str, str]):
    packages = {"": {"dependencies": {name: "*" for name in versions}}}
    packages.update({f"node_modules/{n}": {"version": v} for n, v in versions.items()})
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))


@pytest.fixture
def source_repo(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write_lock(root / "package-lock.json", {"lodash": "4.17.11", "express": "4.18.2"})
    (root / "index.js").write_text("const _ = require('lodash');\n")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "init")
    return root


def make_project(session, url):
    workspace = get_or_create_default_workspace(session)
    project = Project(workspace_id=workspace.id, name="app", repo_url=url)
    session.add(project)
    session.commit()
    return project


def test_scan_creates_components_findings_and_index(session_factory, settings, source_repo):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with session_factory() as session:
        upsert_advisory(session, advisory("GHSA-1", "lodash", "4.17.12"))
        session.commit()
        project = make_project(session, str(source_repo))

        summary = scan_and_match(session, project, vault, settings, allow_local=True)
        assert summary.components == 2
        assert summary.new_findings == 1
        assert len(summary.commit) == 40
        code = session.scalar(select(CodeFile))
        assert (code.path, code.imports) == ("index.js", ["lodash"])

        # 업그레이드 후 다시 스캔하면 바뀐 컴포넌트만 처리하고 Finding을 해소한다.
        write_lock(source_repo / "package-lock.json", {"lodash": "4.17.21", "express": "4.18.2"})
        git(source_repo, "commit", "-qam", "upgrade")
        component_ids = {c.id for c in session.scalars(select(Component))}

        summary = scan_and_match(session, project, vault, settings, allow_local=True)
        assert summary.changed_components == 1
        assert summary.resolved_findings == 1
        assert {c.id for c in session.scalars(select(Component))} == component_ids
        assert session.scalar(select(Finding)).status == "resolved"


def test_scan_records_clone_error(session_factory, settings, tmp_path):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with session_factory() as session:
        project = make_project(session, str(tmp_path / "missing"))
        with pytest.raises(repo.RepoError):
            scan_and_match(session, project, vault, settings, allow_local=True)
        assert "clone" in session.get(Project, project.id).last_scan_error


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r",
        "ext::sh -c touch% /tmp/pwned",
        "file:///etc",
        "https://user:pass@github.com/o/r",
        "-u https://github.com/o/r",
        "git@github.com:o/r.git",
    ],
)
def test_rejects_unsafe_repo_urls(url):
    with pytest.raises(repo.RepoError):
        repo.validate_repo_url(url)


def test_token_only_sent_to_github():
    env = repo._git_env("tok", "https")
    assert "GIT_CONFIG_VALUE_0" in env
    assert "tok" not in env["GIT_CONFIG_VALUE_0"]  # base64로 인코딩되어 있다
    assert repo.is_github("https://github.com/o/r")
    assert not repo.is_github("https://gitlab.com/o/r")
    assert not repo.is_github("https://github.com.evil.example/o/r")

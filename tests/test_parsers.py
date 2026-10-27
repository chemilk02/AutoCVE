import json
from textwrap import dedent

from autocve.ecosystems import NPM, PYPI
from autocve.inventory.parsers import (
    find_manifests,
    is_dev_requirements,
    parse_package_lock,
    parse_poetry_lock,
    parse_requirements,
)


def by_locator(deps):
    return {d.locator: d for d in deps}


def test_package_lock_v3():
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "dependencies": {"express": "^4.18.0", "@scope/util": "1.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
            },
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/@scope/util": {"version": "1.0.0"},
            "node_modules/qs": {"version": "6.11.0"},
            "node_modules/express/node_modules/qs": {"version": "6.5.0"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
            "node_modules/local-lib": {"resolved": "../lib", "link": True},
            "node_modules/aliased": {"name": "real-pkg", "version": "2.0.0"},
        },
    }
    deps = by_locator(parse_package_lock(json.dumps(lock)))

    assert deps["node_modules/express"].direct
    assert deps["node_modules/express"].scope == "prod"
    assert deps["node_modules/@scope/util"].name == "@scope/util"
    assert deps["node_modules/@scope/util"].direct
    assert not deps["node_modules/qs"].direct
    nested = deps["node_modules/express/node_modules/qs"]
    assert (nested.name, nested.version, nested.direct) == ("qs", "6.5.0", False)
    assert deps["node_modules/jest"].scope == "dev"
    assert deps["node_modules/jest"].direct
    assert "node_modules/local-lib" not in deps
    assert deps["node_modules/aliased"].name == "real-pkg"
    assert all(d.ecosystem == NPM for d in deps.values())


def test_package_lock_v1():
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.11"},
            "mocha": {
                "version": "5.0.0",
                "dev": True,
                "dependencies": {"debug": {"version": "3.1.0", "dev": True}},
            },
        },
    }
    deps = by_locator(parse_package_lock(json.dumps(lock)))
    assert deps["node_modules/lodash"].direct
    assert deps["node_modules/mocha/node_modules/debug"].scope == "dev"
    assert not deps["node_modules/mocha/node_modules/debug"].direct


def test_poetry_lock_with_groups_and_pyproject():
    lock = dedent(
        """
        [[package]]
        name = "Django"
        version = "4.2.1"
        groups = ["main"]

        [[package]]
        name = "sqlparse"
        version = "0.4.4"
        groups = ["main"]

        [[package]]
        name = "pytest"
        version = "7.4.0"
        groups = ["dev"]
        """
    )
    pyproject = dedent(
        """
        [tool.poetry.dependencies]
        python = "^3.11"
        django = "^4.2"

        [tool.poetry.group.dev.dependencies]
        pytest = "^7"
        """
    )
    deps = by_locator(parse_poetry_lock(lock, pyproject))
    assert deps["django"].direct and deps["django"].scope == "prod"
    assert not deps["sqlparse"].direct
    assert deps["pytest"].scope == "dev" and deps["pytest"].direct
    assert all(d.ecosystem == PYPI for d in deps.values())


def test_old_poetry_lock_category():
    lock = '[[package]]\nname = "black"\nversion = "23.1.0"\ncategory = "dev"\n'
    (dep,) = parse_poetry_lock(lock)
    assert dep.scope == "dev"
    assert not dep.direct  # pyproject가 없으면 직접 여부를 알 수 없다


def test_requirements_pinned_only():
    text = dedent(
        """
        # comment
        Flask==2.0.1
        requests[socks]==2.31.0 ; python_version >= "3.8"
        numpy>=1.20
        -e git+https://github.com/x/y.git#egg=y
        PyYAML===6.0
        """
    )
    deps = by_locator(parse_requirements(text, "requirements.txt"))
    assert set(deps) == {"flask", "requests", "pyyaml"}
    assert deps["requests"].version == "2.31.0"
    assert all(d.direct and d.scope == "prod" for d in deps.values())


def test_pip_compile_via_comments():
    text = dedent(
        """
        flask==3.0.0 \\
            --hash=sha256:aaa
            # via -r requirements.in
        werkzeug==3.0.1
            # via flask
        click==8.1.7
            # via
            #   flask
            #   other
        """
    )
    deps = by_locator(parse_requirements(text, "requirements.txt"))
    assert deps["flask"].direct
    assert not deps["werkzeug"].direct
    assert not deps["click"].direct


def test_dev_requirements_detection():
    assert is_dev_requirements("requirements-dev.txt")
    assert is_dev_requirements("dev-requirements.txt")
    assert is_dev_requirements("requirements/test.txt")
    assert not is_dev_requirements("requirements.txt")
    assert not is_dev_requirements("requirements/prod.txt")


def test_find_manifests_skips_vendored_dirs(tmp_path):
    for rel in [
        "package-lock.json",
        "web/package-lock.json",
        "node_modules/x/package-lock.json",
        "api/poetry.lock",
        "requirements-dev.txt",
        "requirements/base.txt",
        ".venv/lib/requirements.txt",
        "notes.txt",
    ]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    found = {p.relative_to(tmp_path).as_posix() for p in find_manifests(tmp_path)}
    assert found == {
        "package-lock.json",
        "web/package-lock.json",
        "api/poetry.lock",
        "requirements-dev.txt",
        "requirements/base.txt",
    }

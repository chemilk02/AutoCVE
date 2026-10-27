"""lockfile 파서. 지원 형식: package-lock.json(v1~v3), poetry.lock, requirements*.txt"""

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from autocve.ecosystems import NPM, PYPI, normalize_name


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str  # 정규화된 이름
    version: str
    direct: bool
    scope: str  # prod | dev
    locator: str


class ParseError(Exception):
    pass


# --- npm -----------------------------------------------------------------


def _npm_name_from_path(path: str) -> str:
    # "node_modules/a/node_modules/@s/b" → "@s/b"
    tail = path.rsplit("node_modules/", 1)[-1]
    return tail


def parse_package_lock(text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ParseError(f"package-lock.json 해석 실패: {e}") from e

    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2, 3
        root = packages.get("", {})
        root_prod = set(root.get("dependencies", {})) | set(root.get("optionalDependencies", {}))
        root_dev = set(root.get("devDependencies", {}))
        for path, info in packages.items():
            if not path or "node_modules/" not in path or info.get("link"):
                continue
            version = info.get("version")
            if not version:
                continue
            name = info.get("name") or _npm_name_from_path(path)
            top_level = path == f"node_modules/{name}"
            # devOptional은 optional 설치로 prod에도 들어갈 수 있으므로 prod로 본다 (위험한 쪽).
            dev = bool(info.get("dev"))
            deps.append(
                Dependency(
                    ecosystem=NPM,
                    name=name,
                    version=version,
                    direct=top_level and name in (root_prod | root_dev),
                    scope="dev" if dev else "prod",
                    locator=path,
                )
            )
        return deps

    # lockfileVersion 1: 중첩된 dependencies 트리
    def walk(tree: dict, prefix: str, depth: int) -> None:
        for name, info in tree.items():
            path = f"{prefix}node_modules/{name}"
            version = info.get("version")
            if version and not version.startswith(("file:", "git", "http")):
                deps.append(
                    Dependency(
                        ecosystem=NPM,
                        name=name,
                        version=version,
                        direct=depth == 0 and not info.get("bundled"),
                        scope="dev" if info.get("dev") else "prod",
                        locator=path,
                    )
                )
            walk(info.get("dependencies", {}), f"{path}/", depth + 1)

    walk(data.get("dependencies", {}), "", 0)
    # v1은 직접 의존성 목록이 lockfile에 없다. 최상위를 직접 의존성으로 근사한다.
    return deps


# --- Python --------------------------------------------------------------


def _pyproject_direct(pyproject_text: str | None) -> tuple[set[str], set[str]] | None:
    """pyproject.toml에서 (prod 직접 의존성, dev 직접 의존성) 이름을 읽는다."""
    if not pyproject_text:
        return None
    try:
        data = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError:
        return None
    prod: set[str] = set()
    dev: set[str] = set()
    poetry = data.get("tool", {}).get("poetry", {})
    prod.update(k for k in poetry.get("dependencies", {}) if k.lower() != "python")
    dev.update(poetry.get("dev-dependencies", {}))
    for group, spec in poetry.get("group", {}).items():
        target = prod if group == "main" else dev
        target.update(spec.get("dependencies", {}))
    requirement_name = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
    for req in data.get("project", {}).get("dependencies", []):
        if m := requirement_name.match(req):
            prod.add(m[1])
    for reqs in data.get("dependency-groups", {}).values():
        for req in reqs:
            if isinstance(req, str) and (m := requirement_name.match(req)):
                dev.add(m[1])
    return {normalize_name(PYPI, n) for n in prod}, {normalize_name(PYPI, n) for n in dev}


def parse_poetry_lock(text: str, pyproject_text: str | None = None) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ParseError(f"poetry.lock 해석 실패: {e}") from e
    direct = _pyproject_direct(pyproject_text)
    deps = []
    for package in data.get("package", []):
        name = normalize_name(PYPI, package["name"])
        groups = package.get("groups")
        if groups is not None:
            dev = "main" not in groups
        else:
            dev = package.get("category") == "dev"
        is_direct = bool(direct and (name in direct[0] or name in direct[1]))
        deps.append(
            Dependency(
                ecosystem=PYPI,
                name=name,
                version=package["version"],
                direct=is_direct,
                scope="dev" if dev else "prod",
                locator=name,
            )
        )
    return deps


_PINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\]+)")
_DEV_FILE = re.compile(r"(^|[-_.])(dev|test|tests|lint|docs)([-_.]|$)", re.IGNORECASE)


def is_dev_requirements(path: str) -> bool:
    stem = PurePosixPath(path).name.removesuffix(".txt")
    return bool(_DEV_FILE.search(stem.replace("requirements", "")))


def parse_requirements(text: str, path: str) -> list[Dependency]:
    """`name==version`으로 고정된 줄만 읽는다. 범위 지정은 실제 설치 버전을 알 수 없어 건너뛴다.

    pip-compile 출력이면 `# via` 주석으로 직접/간접 의존성을 구분한다.
    """
    scope = "dev" if is_dev_requirements(path) else "prod"
    lines = text.splitlines()
    deps = []
    for i, line in enumerate(lines):
        match = _PINNED.match(line)
        if not match:
            continue
        name = normalize_name(PYPI, match[1])
        via = _via_sources(lines, i)
        direct = not via or any(v.startswith("-r") or v.endswith(".in") for v in via)
        deps.append(
            Dependency(
                ecosystem=PYPI,
                name=name,
                version=match[2],
                direct=direct,
                scope=scope,
                locator=name,
            )
        )
    return deps


def _via_sources(lines: list[str], index: int) -> list[str]:
    """pip-compile 형식에서 패키지 줄 아래의 `# via ...` 주석을 모은다."""
    sources: list[str] = []
    in_via = False
    for line in lines[index + 1 :]:
        stripped = line.strip()
        if stripped.startswith("--hash") or stripped == "\\":
            continue
        if stripped.startswith("# via"):
            in_via = True
            if rest := stripped.removeprefix("# via").strip():
                sources.append(rest)
            continue
        if in_via and stripped.startswith("#"):
            sources.append(stripped.lstrip("#").strip())
            continue
        break
    return sources


# --- 탐색 ------------------------------------------------------------------

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    "site-packages",
    "vendor",
}


def find_manifests(root: Path) -> list[Path]:
    found = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not path.is_file():
            continue
        name = path.name
        is_requirements = name.endswith(".txt") and (
            name.startswith("requirements") or path.parent.name == "requirements"
        )
        if name in ("package-lock.json", "poetry.lock") or is_requirements:
            found.append(path)
    return found


def parse_manifest(root: Path, path: Path) -> list[Dependency]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "package-lock.json":
        return parse_package_lock(text)
    if path.name == "poetry.lock":
        pyproject = path.with_name("pyproject.toml")
        return parse_poetry_lock(text, pyproject.read_text() if pyproject.exists() else None)
    return parse_requirements(text, rel)

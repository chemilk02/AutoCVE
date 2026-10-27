"""파일별 import 목록과 해시를 만든다. 판별 단계에서 "prod 코드가 이 패키지를 쓰는가"의 근거가 된다.

- Python: `ast`로 최상위 모듈 이름을 뽑는다 (`import a.b` → `a`).
- JS/TS: import/require/동적 import/re-export에서 패키지 이름을 뽑는다 (`@s/p/x` → `@s/p`).
  상대 경로와 Node 내장 모듈은 제외한다.
"""

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from autocve.inventory.parsers import SKIP_DIRS

MAX_FILE_BYTES = 1_000_000

PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}

_JS_SPECIFIERS = re.compile(
    r"""(?:\bimport\s+(?:[\w*{}\s,$]+\s+from\s+)?|\bexport\s+[\w*{}\s,$]+\s+from\s+|"""
    r"""\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"\n]+)['"]"""
)
_NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs",
    "http", "http2", "https", "net", "os", "path", "perf_hooks", "process", "querystring",
    "readline", "stream", "string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm",
    "worker_threads", "zlib",
}  # fmt: skip

_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?)(/|$)"
    r"|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$"
)


@dataclass(frozen=True)
class IndexedFile:
    path: str
    sha256: str
    imports: list[str]
    is_test: bool


def python_imports(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return sorted(names)


def js_package_name(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#")) or "://" in specifier:
        return None
    if specifier.startswith("node:"):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    if parts[0] in _NODE_BUILTINS:
        return None
    return parts[0]


def js_imports(source: str) -> list[str]:
    names = {js_package_name(m) for m in _JS_SPECIFIERS.findall(source)}
    return sorted(n for n in names if n)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def index_repository(root: Path) -> list[IndexedFile]:
    files = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in PY_SUFFIXES | JS_SUFFIXES or path.name.endswith(".d.ts"):
            continue
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES or b"\0" in raw[:1024]:
            continue
        text = raw.decode("utf-8", errors="replace")
        imports = python_imports(text) if suffix in PY_SUFFIXES else js_imports(text)
        rel_posix = PurePosixPath(rel).as_posix()
        files.append(
            IndexedFile(
                path=rel_posix,
                sha256=hashlib.sha256(raw).hexdigest(),
                imports=imports,
                is_test=is_test_path(rel_posix),
            )
        )
    return files

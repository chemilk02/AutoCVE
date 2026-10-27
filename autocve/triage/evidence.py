"""판별 증거 수집: 패키지를 import하는 파일과, 취약 심볼이 나오는 위치(스니펫).

코드 인덱스(import 목록)만으로도 셀 수 있는 것은 DB에서 세고,
스니펫은 clone한 코드가 있을 때만 뽑는다.
"""

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.ecosystems import PYPI
from autocve.models import CodeFile, Component

SNIPPET_CONTEXT_LINES = 10
MAX_STORED_SNIPPETS = 10
MIN_SYMBOL_LENGTH = 3

# 배포 이름과 import 이름이 다른 흔한 PyPI 패키지
_PYPI_IMPORT_NAMES = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "protobuf": ["google"],
    "attrs": ["attr", "attrs"],
    "pyjwt": ["jwt"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "python-multipart": ["multipart", "python_multipart"],
    "pyopenssl": ["OpenSSL"],
    "djangorestframework": ["rest_framework"],
    "python-jose": ["jose"],
    "setuptools": ["setuptools", "pkg_resources"],
    "mysqlclient": ["MySQLdb"],
    "psycopg2-binary": ["psycopg2"],
    "psycopg-binary": ["psycopg"],
    "msgpack-python": ["msgpack"],
    "python-ldap": ["ldap"],
    "pymongo": ["pymongo", "bson", "gridfs"],
}


def import_names(component: Component) -> set[str]:
    """이 컴포넌트를 코드에서 가리킬 때 쓰는 import 이름 후보 (소문자)."""
    if component.ecosystem != PYPI:
        return {component.name.lower()}
    name = component.name
    names = {n.lower() for n in _PYPI_IMPORT_NAMES.get(name, [])}
    names.add(name.replace("-", "_"))
    names.add(name.replace("-", ""))
    if name.startswith("python-"):
        names.add(name.removeprefix("python-").replace("-", "_"))
    return names


@dataclass
class Snippet:
    path: str
    line: int
    symbol: str
    code: str


@dataclass
class Evidence:
    prod_import_files: list[str] = field(default_factory=list)
    test_import_files: list[str] = field(default_factory=list)
    symbols_searched: list[str] = field(default_factory=list)
    call_site_count: int = 0
    snippets: list[Snippet] = field(default_factory=list)
    checkout_available: bool = False
    fingerprint: str = ""

    def as_dict(self) -> dict:
        data = asdict(self)
        data["prod_import_count"] = len(self.prod_import_files)
        data["test_import_count"] = len(self.test_import_files)
        return data


def _symbol_names(symbols: list[str]) -> list[str]:
    """`lodash.template`, `_.template()` → `template`. 너무 짧은 이름은 오탐이 많아 뺀다."""
    names = []
    for symbol in symbols:
        last = re.split(r"[.#:]", symbol.strip().rstrip("()"))[-1]
        if len(last) >= MIN_SYMBOL_LENGTH and re.fullmatch(r"[A-Za-z_$][\w$]*", last):
            names.append(last)
    return sorted(set(names))


def collect_evidence(
    session: Session,
    component: Component,
    vulnerable_symbols: list[str],
    checkout: Path | None,
) -> Evidence:
    names = import_names(component)
    evidence = Evidence(checkout_available=checkout is not None)
    files = session.scalars(select(CodeFile).where(CodeFile.project_id == component.project_id))
    importing: list[CodeFile] = []
    for code_file in files:
        if names & {i.lower() for i in code_file.imports or []}:
            importing.append(code_file)
            target = evidence.test_import_files if code_file.is_test else evidence.prod_import_files
            target.append(code_file.path)
    evidence.prod_import_files.sort()
    evidence.test_import_files.sort()

    symbols = _symbol_names(vulnerable_symbols)
    evidence.symbols_searched = symbols
    if checkout is not None and symbols:
        pattern = re.compile(r"\b(" + "|".join(map(re.escape, symbols)) + r")\b")
        for code_file in sorted(importing, key=lambda f: f.path):
            if code_file.is_test:
                continue
            path = checkout / code_file.path
            if not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for number, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if not match:
                    continue
                evidence.call_site_count += 1
                if len(evidence.snippets) < MAX_STORED_SNIPPETS:
                    start = max(0, number - 1 - SNIPPET_CONTEXT_LINES)
                    end = min(len(lines), number + SNIPPET_CONTEXT_LINES)
                    evidence.snippets.append(
                        Snippet(
                            path=code_file.path,
                            line=number,
                            symbol=match.group(1),
                            code="\n".join(lines[start:end]),
                        )
                    )

    # 판별 캐시 키에 쓰는 지문: 관련 파일의 내용이 바뀌면 달라진다.
    digest = hashlib.sha256()
    for code_file in sorted(importing, key=lambda f: f.path):
        digest.update(f"{code_file.path}:{code_file.sha256}\n".encode())
    digest.update(",".join(symbols).encode())
    evidence.fingerprint = digest.hexdigest()
    return evidence

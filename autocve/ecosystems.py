"""지원하는 패키지 생태계와 이름 정규화, purl 생성."""

import re
from urllib.parse import quote

NPM = "npm"
PYPI = "PyPI"  # OSV의 생태계 표기를 그대로 쓴다
SUPPORTED = (NPM, PYPI)

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == PYPI:
        # PEP 503 정규화: 대소문자, -, _, . 차이를 없앤다.
        return _PYPI_SEPARATORS.sub("-", name).lower()
    return name


def purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == NPM:
        if name.startswith("@") and "/" in name:
            scope, _, bare = name.partition("/")
            return f"pkg:npm/{quote(scope)}/{quote(bare)}@{quote(version)}"
        return f"pkg:npm/{quote(name)}@{quote(version)}"
    if ecosystem == PYPI:
        return f"pkg:pypi/{quote(normalize_name(PYPI, name))}@{quote(version)}"
    raise ValueError(f"지원하지 않는 생태계: {ecosystem}")

"""OSV 취약점 수집.

- 최초 적재: 생태계별 `all.zip`을 받아 대량 insert 한다.
- 이후: `modified_id.csv`(최신순 정렬)를 커서 시각까지만 읽고, 바뀐 레코드만 개별 JSON으로 받는다.
"""

import json
import logging
import re
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from autocve.collector.cursors import get_cursor, set_cursor
from autocve.ecosystems import SUPPORTED, normalize_name
from autocve.models import Advisory, AdvisoryPackage

logger = logging.getLogger(__name__)

BATCH_SIZE = 2000
_SUBMICRO = re.compile(r"(\.\d{6})\d+")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    # OSV는 나노초까지 주기도 한다. datetime은 마이크로초까지만 받으므로 잘라낸다.
    parsed = datetime.fromisoformat(_SUBMICRO.sub(r"\1", value.replace("Z", "+00:00")))
    return as_utc(parsed)


def as_utc(value: datetime) -> datetime:
    # SQLite는 시간대 정보를 버리므로, 비교 전에 항상 UTC 기준 aware 값으로 맞춘다.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class OsvClient:
    def __init__(self, http: httpx.Client, base_url: str):
        self._http = http
        self._base = base_url.rstrip("/")

    def modified_ids(self, ecosystem: str) -> Iterator[tuple[datetime, str]]:
        """최신순으로 (modified, id)를 돌려준다."""
        with self._http.stream("GET", f"{self._base}/{ecosystem}/modified_id.csv") as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line.strip():
                    continue
                stamp, _, vuln_id = line.partition(",")
                yield parse_time(stamp), vuln_id.strip()

    def get(self, ecosystem: str, vuln_id: str) -> dict:
        response = self._http.get(f"{self._base}/{ecosystem}/{vuln_id}.json")
        response.raise_for_status()
        return response.json()

    def iter_all(self, ecosystem: str) -> Iterator[dict]:
        # 수백 MB가 될 수 있으므로 메모리 대신 임시 파일에 받는다.
        with tempfile.TemporaryFile() as tmp:
            with self._http.stream("GET", f"{self._base}/{ecosystem}/all.zip") as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    tmp.write(chunk)
            tmp.seek(0)
            with zipfile.ZipFile(tmp) as archive:
                for name in archive.namelist():
                    if name.endswith(".json"):
                        yield json.loads(archive.read(name))


def advisory_row(record: dict) -> dict:
    return {
        "id": record["id"],
        "aliases": record.get("aliases", []),
        "modified": parse_time(record["modified"]),
        "published": parse_time(record.get("published")),
        "withdrawn": parse_time(record.get("withdrawn")),
        "summary": record.get("summary"),
        "details": record.get("details"),
        "severity": record.get("severity", []),
        "affected": record.get("affected", []),
        "references": record.get("references", []),
    }


def package_rows(record: dict) -> list[dict]:
    keys = set()
    for affected in record.get("affected", []):
        package = affected.get("package") or {}
        ecosystem = package.get("ecosystem")
        if ecosystem in SUPPORTED and package.get("name"):
            keys.add((ecosystem, normalize_name(ecosystem, package["name"])))
    return [{"advisory_id": record["id"], "ecosystem": e, "name": n} for e, n in sorted(keys)]


def upsert_advisory(session: Session, record: dict) -> bool:
    """레코드를 반영하고, 새로 들어왔거나 내용이 바뀌었으면 True."""
    row = advisory_row(record)
    existing = session.get(Advisory, row["id"])
    if existing is not None and as_utc(existing.modified) >= row["modified"]:
        return False
    if existing is None:
        session.add(Advisory(**row))
    else:
        for key, value in row.items():
            setattr(existing, key, value)
    session.flush()
    session.execute(delete(AdvisoryPackage).where(AdvisoryPackage.advisory_id == row["id"]))
    packages = package_rows(record)
    if packages:
        session.execute(insert(AdvisoryPackage), packages)
    return True


@dataclass
class SyncResult:
    ecosystem: str
    bootstrapped: bool = False
    changed_ids: list[str] = field(default_factory=list)


def _bootstrap(session: Session, client: OsvClient, ecosystem: str) -> int:
    """빈 DB에 전체 덤프를 적재한다. 같은 id가 다른 생태계 덤프에 이미 있으면 건너뛴다."""
    known = set(session.scalars(select(Advisory.id)))
    advisories: list[dict] = []
    packages: list[dict] = []
    total = 0

    def flush() -> None:
        if advisories:
            session.execute(insert(Advisory), advisories)
        if packages:
            session.execute(insert(AdvisoryPackage), packages)
        session.commit()
        advisories.clear()
        packages.clear()

    for record in client.iter_all(ecosystem):
        if record["id"] in known:
            continue
        known.add(record["id"])
        advisories.append(advisory_row(record))
        packages.extend(package_rows(record))
        total += 1
        if len(advisories) >= BATCH_SIZE:
            flush()
    flush()
    return total


def sync_ecosystem(session: Session, client: OsvClient, ecosystem: str) -> SyncResult:
    source = f"osv:{ecosystem}"
    cursor = parse_time(get_cursor(session, source))
    result = SyncResult(ecosystem)

    if cursor is None:
        # 덤프를 받는 동안 바뀐 레코드는 다음 증분 수집에서 다시 받도록, 덤프 전에 커서를 정한다.
        newest = next(client.modified_ids(ecosystem), None)
        count = _bootstrap(session, client, ecosystem)
        set_cursor(session, source, newest[0].isoformat() if newest else None)
        session.commit()
        logger.info("OSV %s 최초 적재: %d건", ecosystem, count)
        result.bootstrapped = True
        return result

    newest_seen: datetime | None = None
    for processed, (modified, vuln_id) in enumerate(client.modified_ids(ecosystem), start=1):
        if modified <= cursor:
            break
        newest_seen = newest_seen or modified
        try:
            record = client.get(ecosystem, vuln_id)
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                raise
            logger.warning("OSV %s 레코드를 찾을 수 없음: %s", ecosystem, vuln_id)
            continue
        if upsert_advisory(session, record):
            result.changed_ids.append(vuln_id)
        if processed % 200 == 0:
            session.commit()
    if newest_seen is not None:
        set_cursor(session, source, newest_seen.isoformat())
    session.commit()
    logger.info("OSV %s 증분 수집: %d건 변경", ecosystem, len(result.changed_ids))
    return result

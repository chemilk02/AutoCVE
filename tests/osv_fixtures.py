"""OSV 미러를 흉내 내는 httpx MockTransport."""

import io
import json
import zipfile

import httpx

BASE_URL = "https://osv.test"


def advisory(
    vuln_id: str,
    package: str,
    fixed: str | None,
    *,
    ecosystem: str = "npm",
    modified: str = "2026-01-01T00:00:00Z",
    introduced: str = "0",
    aliases: list[str] | None = None,
    withdrawn: str | None = None,
) -> dict:
    events = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    record = {
        "id": vuln_id,
        "modified": modified,
        "aliases": aliases or [],
        "summary": f"{package} issue",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": package},
                "ranges": [
                    {"type": "SEMVER" if ecosystem == "npm" else "ECOSYSTEM", "events": events}
                ],
            }
        ],
    }
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


class FakeOsv:
    """생태계별 레코드를 들고 modified_id.csv, all.zip, 개별 JSON을 제공한다."""

    def __init__(self):
        self.records: dict[str, dict[str, dict]] = {}
        self.requests: list[str] = []

    def put(self, ecosystem: str, record: dict) -> None:
        self.records.setdefault(ecosystem, {})[record["id"]] = record

    def _zip(self, ecosystem: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            for vuln_id, record in self.records.get(ecosystem, {}).items():
                archive.writestr(f"{vuln_id}.json", json.dumps(record))
        return buf.getvalue()

    def _modified_csv(self, ecosystem: str) -> str:
        rows = sorted(
            ((r["modified"], r["id"]) for r in self.records.get(ecosystem, {}).values()),
            reverse=True,
        )
        return "".join(f"{m},{i}\n" for m, i in rows)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.strip("/")
        self.requests.append(path)
        ecosystem, _, name = path.partition("/")
        if name == "all.zip":
            return httpx.Response(200, content=self._zip(ecosystem))
        if name == "modified_id.csv":
            return httpx.Response(200, text=self._modified_csv(ecosystem))
        record = self.records.get(ecosystem, {}).get(name.removesuffix(".json"))
        if record is None:
            return httpx.Response(404)
        return httpx.Response(200, json=record)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

"""심층 분석: Sonnet/Opus가 읽기 전용 도구로 저장소를 직접 살펴보고 판정한다.

- 도구는 read_file, search_code, list_dir 세 가지다. 경로는 저장소 루트 밖으로 나갈 수 없다.
- 거부(refusal)에 대비해 서버 측 fallback(`fallbacks: "default"`)을 켠다.
- 대화 앞부분이 매 턴 같으므로 자동 프롬프트 캐싱으로 다시 읽는 비용을 줄인다.
"""

import logging
import re
from pathlib import Path

import anthropic

from autocve.analysis.common import (
    ANALYSIS_SCHEMA,
    MODELS,
    SYSTEM_PROMPT,
    AnalysisOutcome,
    parse_outcome,
)
from autocve.inventory.parsers import SKIP_DIRS
from autocve.llm.gateway import LlmGateway

logger = logging.getLogger(__name__)

MAX_TURNS = 12
MAX_TOKENS = 16000
MAX_READ_LINES = 400
MAX_SEARCH_RESULTS = 50
MAX_LIST_ENTRIES = 200
MAX_FILE_BYTES = 2_000_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"

DEEP_INSTRUCTIONS = """

You can inspect the repository with read-only tools. Follow the data flow from where untrusted \
input enters (HTTP handlers, CLI arguments, message consumers, file parsers) to the vulnerable \
call. Read only what you need; you have a limited number of tool calls. When you have enough \
evidence, stop calling tools and give the final answer in the required JSON format."""


def _tool(name: str, description: str, properties: dict) -> dict:
    return {
        "name": name,
        "description": description,
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        },
    }


TOOLS = [
    _tool(
        "read_file",
        "Read a range of lines from a file in the repository. Paths are relative to the "
        f"repository root. At most {MAX_READ_LINES} lines are returned per call.",
        {
            "path": {"type": "string"},
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
        },
    ),
    _tool(
        "search_code",
        "Search source files with a Python regular expression. Returns up to "
        f"{MAX_SEARCH_RESULTS} matching lines as 'path:line: text'. Use path_prefix to limit "
        "the search to a directory, or an empty string for the whole repository. Dependency "
        "folders such as node_modules are skipped.",
        {"pattern": {"type": "string"}, "path_prefix": {"type": "string"}},
    ),
    _tool(
        "list_dir",
        "List the entries of a directory in the repository. Use an empty string for the root.",
        {"path": {"type": "string"}},
    ),
]


class RepoTools:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def _resolve(self, rel: str) -> Path:
        path = (self.root / rel.lstrip("/")).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError("저장소 밖의 경로는 읽을 수 없습니다")
        return path

    def _source_files(self, base: Path):
        for path in sorted(base.rglob("*")):
            rel = path.relative_to(self.root)
            if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not path.is_file():
                continue
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            yield path, rel.as_posix()

    def read_file(self, path: str, start_line: int, end_line: int) -> str:
        target = self._resolve(path)
        if not target.is_file():
            raise ValueError(f"파일이 없습니다: {path}")
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, start_line)
        end = min(len(lines), end_line, start + MAX_READ_LINES - 1)
        body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
        return f"{path} ({len(lines)} lines total)\n{body}"

    def search_code(self, pattern: str, path_prefix: str) -> str:
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"정규식 오류: {e}") from e
        base = self._resolve(path_prefix or "")
        if not base.is_dir():
            raise ValueError(f"디렉터리가 없습니다: {path_prefix}")
        results = []
        for path, rel in self._source_files(base):
            raw = path.read_bytes()
            if b"\0" in raw[:1024]:
                continue
            for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    results.append(f"{rel}:{number}: {line.strip()[:300]}")
                    if len(results) >= MAX_SEARCH_RESULTS:
                        return "\n".join(results) + "\n(결과가 더 있지만 생략했습니다)"
        return "\n".join(results) or "일치하는 줄이 없습니다"

    def list_dir(self, path: str) -> str:
        base = self._resolve(path or "")
        if not base.is_dir():
            raise ValueError(f"디렉터리가 없습니다: {path}")
        entries = []
        for child in sorted(base.iterdir())[:MAX_LIST_ENTRIES]:
            if child.name in SKIP_DIRS:
                continue
            entries.append(child.name + ("/" if child.is_dir() else ""))
        return "\n".join(entries) or "(비어 있음)"

    def run(self, name: str, arguments: dict) -> tuple[str, bool]:
        """(결과, 오류 여부). 오류도 모델에 돌려줘 다른 방법을 찾게 한다."""
        try:
            if name == "read_file":
                return self.read_file(
                    str(arguments["path"]),
                    int(arguments["start_line"]),
                    int(arguments["end_line"]),
                ), False
            if name == "search_code":
                return self.search_code(
                    str(arguments["pattern"]), str(arguments["path_prefix"])
                ), False
            if name == "list_dir":
                return self.list_dir(str(arguments["path"])), False
            return f"알 수 없는 도구: {name}", True
        except (KeyError, TypeError, ValueError, OSError) as e:
            return str(e), True


def analyze(
    gateway: LlmGateway,
    tier: str,
    context: str,
    checkout: Path,
    finding_id: int,
    *,
    max_turns: int = MAX_TURNS,
) -> AnalysisOutcome:
    model = MODELS[tier]
    tools = RepoTools(checkout)
    messages: list[dict] = [{"role": "user", "content": context}]
    for turn in range(max_turns):
        try:
            response = gateway.create(
                stage=tier,
                finding_id=finding_id,
                beta=True,
                betas=[FALLBACK_BETA],
                fallbacks="default",
                model=model,
                max_tokens=MAX_TOKENS,
                system=[{"type": "text", "text": SYSTEM_PROMPT + DEEP_INSTRUCTIONS}],
                tools=TOOLS,
                messages=messages,
                cache_control={"type": "ephemeral"},
                output_config={
                    "effort": "medium",
                    "format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA},
                },
            )
        except anthropic.APIError as e:
            logger.warning("심층 분석 실패 (finding %s): %s", finding_id, type(e).__name__)
            return AnalysisOutcome("error", model, rationale=f"API 오류: {type(e).__name__}")

        if response.stop_reason == "refusal":
            return AnalysisOutcome("refused", model, rationale="모델이 분석을 거부했습니다")
        # 생각(thinking) 블록을 포함해 응답을 그대로 이어 붙여야 다음 턴이 유효하다.
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "pause_turn":
            continue
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if tool_uses:
            results: list[dict] = []
            for block in tool_uses:
                output, is_error = tools.run(block.name, block.input)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": output,
                        "is_error": is_error,
                    }
                )
            if turn == max_turns - 2:
                results.append(
                    {"type": "text", "text": "Tool budget is almost used up. Answer now."}
                )
            messages.append({"role": "user", "content": results})
            continue
        text = next((b.text for b in response.content if b.type == "text"), "")
        return parse_outcome(text, response.model or model)
    return AnalysisOutcome(
        "uncertain", model, rationale="도구 호출 한도 안에서 결론을 내지 못했습니다"
    )

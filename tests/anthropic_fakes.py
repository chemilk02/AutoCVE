"""실제 Anthropic SDK에 MockTransport를 끼워, 요청 본문과 헤더까지 검증할 수 있게 한다."""

import json

import anthropic
import httpx2

BATCH_ID = "msgbatch_test"


def _message(content: list[dict], *, stop_reason: str, model: str, usage: dict) -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": usage,
    }


def _usage(input_tokens: int, output_tokens: int, cache_read: int = 0) -> dict:
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": cache_read,
    }


class FakeAnthropic:
    def __init__(self):
        self.requests: list[dict] = []
        self.headers: list[dict] = []
        self.replies: list[dict] = []
        self.batch_requests: list[dict] = []
        self.batch_results: list[dict] = []
        self.batch_status = "in_progress"

    # --- Messages API -------------------------------------------------------

    def reply_json(self, payload: dict, **kwargs) -> None:
        self.reply_text(json.dumps(payload), **kwargs)

    def reply_text(
        self,
        text: str,
        *,
        stop_reason: str = "end_turn",
        input_tokens: int = 1000,
        output_tokens: int = 200,
        cache_read: int = 0,
        model: str = "claude-haiku-5-5",
    ) -> None:
        self.replies.append(
            _message(
                [{"type": "text", "text": text}],
                stop_reason=stop_reason,
                model=model,
                usage=_usage(input_tokens, output_tokens, cache_read),
            )
        )

    def reply_tool_use(self, name: str, arguments: dict, *, model: str = "claude-sonnet-5-5"):
        self.replies.append(
            _message(
                [
                    {
                        "type": "tool_use",
                        "id": f"toolu_{len(self.replies)}",
                        "name": name,
                        "input": arguments,
                    }
                ],
                stop_reason="tool_use",
                model=model,
                usage=_usage(2000, 100),
            )
        )

    # --- Batch API ----------------------------------------------------------

    def batch_succeeds(self, custom_id: str, payload: dict, **kwargs) -> None:
        self.batch_results.append(
            {
                "custom_id": custom_id,
                "result": {
                    "type": "succeeded",
                    "message": _message(
                        [{"type": "text", "text": json.dumps(payload)}],
                        stop_reason="end_turn",
                        model="claude-haiku-5-5",
                        usage=_usage(kwargs.get("input_tokens", 1000), 200),
                    ),
                },
            }
        )

    def batch_errors(self, custom_id: str) -> None:
        self.batch_results.append(
            {
                "custom_id": custom_id,
                "result": {
                    "type": "errored",
                    "error": {"type": "error", "error": {"type": "api_error", "message": "x"}},
                },
            }
        )

    def _batch(self) -> dict:
        ended = self.batch_status == "ended"
        return {
            "id": BATCH_ID,
            "type": "message_batch",
            "processing_status": self.batch_status,
            "request_counts": {
                "processing": 0 if ended else len(self.batch_requests),
                "succeeded": len(self.batch_results) if ended else 0,
                "errored": 0,
                "canceled": 0,
                "expired": 0,
            },
            "created_at": "2026-10-27T00:00:00Z",
            "expires_at": "2026-10-28T00:00:00Z",
            "ended_at": "2026-10-27T01:00:00Z" if ended else None,
            "cancel_initiated_at": None,
            "archived_at": None,
            "results_url": f"https://api.anthropic.com/v1/messages/batches/{BATCH_ID}/results"
            if ended
            else None,
        }

    # --- transport ----------------------------------------------------------

    def _handler(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        self.headers.append(dict(request.headers))
        if path == "/v1/messages/batches" and request.method == "POST":
            self.batch_requests = json.loads(request.content)["requests"]
            return httpx2.Response(200, json=self._batch())
        if path == f"/v1/messages/batches/{BATCH_ID}":
            return httpx2.Response(200, json=self._batch())
        if path == f"/v1/messages/batches/{BATCH_ID}/results":
            body = "\n".join(json.dumps(r) for r in self.batch_results)
            return httpx2.Response(200, text=body, headers={"content-type": "application/binary"})
        self.requests.append(json.loads(request.content))
        if not self.replies:
            return httpx2.Response(
                500, json={"type": "error", "error": {"type": "api_error", "message": "no reply"}}
            )
        return httpx2.Response(200, json=self.replies.pop(0))

    def factory(self, api_key: str) -> anthropic.Anthropic:
        return anthropic.Anthropic(
            api_key=api_key,
            max_retries=0,
            http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(self._handler)),
        )

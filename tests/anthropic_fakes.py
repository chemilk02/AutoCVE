"""실제 Anthropic SDK에 MockTransport를 끼워, 요청 본문까지 검증할 수 있게 한다."""

import json

import anthropic
import httpx2


class FakeAnthropic:
    def __init__(self):
        self.requests: list[dict] = []
        self.replies: list[dict] = []

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
    ) -> None:
        self.replies.append(
            {
                "id": f"msg_{len(self.replies)}",
                "type": "message",
                "role": "assistant",
                "model": "claude-haiku-5-5",
                "content": [{"type": "text", "text": text}],
                "stop_reason": stop_reason,
                "stop_sequence": None,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": cache_read,
                },
            }
        )

    def _handler(self, request: httpx2.Request) -> httpx2.Response:
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

import json

import anthropic
import httpx
import httpx2

from autocve.credentials.validators import (
    validate_anthropic,
    validate_openrouter,
    validate_typesafe,
)
from autocve.models import CredentialStatus

MODELS_PAGE = {"data": [], "has_more": False, "first_id": None, "last_id": None}


def anthropic_client(handler) -> anthropic.DefaultHttpxClient:
    return anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler))


def httpx_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestAnthropic:
    def test_valid_key_lists_models(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx2.Response(200, json=MODELS_PAGE)

        result = validate_anthropic("sk-ant-good", http_client=anthropic_client(handler))
        assert result.status == CredentialStatus.VALID
        assert requests[0].method == "GET"
        assert requests[0].url.path == "/v1/models"
        assert requests[0].headers["authorization"] == "Bearer sk-ant-good"

    def test_rejected_key(self):
        def handler(request):
            return httpx2.Response(
                401,
                json={
                    "type": "error",
                    "error": {"type": "authentication_error", "message": "invalid x-api-key"},
                },
            )

        result = validate_anthropic("sk-ant-bad", http_client=anthropic_client(handler))
        assert result.status == CredentialStatus.INVALID

    def test_server_error_is_unverified(self):
        def handler(request):
            return httpx2.Response(
                503,
                json={"type": "error", "error": {"type": "overloaded_error", "message": "busy"}},
            )

        result = validate_anthropic("sk-ant-maybe", http_client=anthropic_client(handler))
        assert result.status == CredentialStatus.UNVERIFIED

    def test_connection_error_is_unverified(self):
        def handler(request):
            raise httpx2.ConnectError("offline")

        result = validate_anthropic("sk-ant-maybe", http_client=anthropic_client(handler))
        assert result.status == CredentialStatus.UNVERIFIED

    def test_wrong_prefix_rejected_without_request(self):
        def handler(request):
            raise AssertionError("요청을 보내면 안 된다")

        result = validate_anthropic("sk-or-v1-abc", http_client=anthropic_client(handler))
        assert result.status == CredentialStatus.INVALID


class TestOpenRouter:
    base_url = "https://openrouter.test/api/v1"

    def test_valid_key(self):
        def handler(request):
            assert request.url == f"{self.base_url}/key"
            assert request.headers["authorization"] == "Bearer sk-or-v1-good"
            return httpx.Response(200, json={"data": {"label": "test"}})

        result = validate_openrouter(
            "sk-or-v1-good", base_url=self.base_url, http_client=httpx_client(handler)
        )
        assert result.status == CredentialStatus.VALID

    def test_rejected_key(self):
        result = validate_openrouter(
            "sk-or-v1-bad",
            base_url=self.base_url,
            http_client=httpx_client(lambda r: httpx.Response(401)),
        )
        assert result.status == CredentialStatus.INVALID

    def test_connection_error_is_unverified(self):
        def handler(request):
            raise httpx.ConnectError("offline")

        result = validate_openrouter(
            "sk-or-v1-x", base_url=self.base_url, http_client=httpx_client(handler)
        )
        assert result.status == CredentialStatus.UNVERIFIED

    def test_wrong_prefix(self):
        result = validate_openrouter("sk-ant-abc", base_url=self.base_url)
        assert result.status == CredentialStatus.INVALID


class TestTypeSafe:
    base_url = "https://typesafe.test/v1"

    def test_valid_key_sends_choice_question(self):
        def handler(request):
            assert request.url == f"{self.base_url}/systemone"
            assert request.headers["authorization"] == "Bearer ts-key"
            body = json.loads(request.content)
            assert body["model"] == "jev-test"
            assert body["questions"]["ping"]["type"] == "choice"
            return httpx.Response(200, json={"answers": {}})

        result = validate_typesafe(
            "ts-key", base_url=self.base_url, model="jev-test", http_client=httpx_client(handler)
        )
        assert result.status == CredentialStatus.VALID

    def test_forbidden_is_invalid(self):
        result = validate_typesafe(
            "ts-key",
            base_url=self.base_url,
            model="jev-test",
            http_client=httpx_client(lambda r: httpx.Response(403)),
        )
        assert result.status == CredentialStatus.INVALID

    def test_schema_mismatch_is_unverified(self):
        result = validate_typesafe(
            "ts-key",
            base_url=self.base_url,
            model="jev-test",
            http_client=httpx_client(lambda r: httpx.Response(422)),
        )
        assert result.status == CredentialStatus.UNVERIFIED
        assert "422" in result.message

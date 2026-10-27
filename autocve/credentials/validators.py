"""제공자별 API 키 검증.

가능한 한 토큰/크레딧을 쓰지 않는 요청으로 확인한다.
- Anthropic: GET /v1/models
- OpenRouter: GET /api/v1/key (키 정보 조회)
- GitHub: GET /user
- TypeSafe: 토큰이 들지 않는 엔드포인트를 확인하지 못해 최소 판별 요청 1회를 보낸다.
  요청 형식은 공식 문서로 아직 검증하지 않았다 (docs/02-architecture.md §4.6).
"""

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass

import anthropic
import httpx

from autocve.config import Settings
from autocve.models import CredentialStatus, Provider

TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class ValidationResult:
    status: CredentialStatus
    message: str


Validator = Callable[[str], ValidationResult]


def _valid() -> ValidationResult:
    return ValidationResult(CredentialStatus.VALID, "검증 완료")


def _http_result(response: httpx.Response) -> ValidationResult:
    if response.is_success:
        return _valid()
    if response.status_code in (401, 403):
        return ValidationResult(CredentialStatus.INVALID, "키가 거부되었습니다")
    return ValidationResult(
        CredentialStatus.UNVERIFIED, f"검증 요청이 실패했습니다 (HTTP {response.status_code})"
    )


def _httpx_client(http_client: httpx.Client | None):
    return nullcontext(http_client) if http_client else httpx.Client(timeout=TIMEOUT_SECONDS)


def validate_anthropic(
    key: str, *, http_client: anthropic.DefaultHttpxClient | None = None
) -> ValidationResult:
    if not key.startswith("sk-ant-"):
        return ValidationResult(CredentialStatus.INVALID, "Anthropic 키는 sk-ant- 로 시작합니다")
    try:
        with anthropic.Anthropic(
            api_key=key, max_retries=1, timeout=TIMEOUT_SECONDS, http_client=http_client
        ) as client:
            client.models.list(limit=1)
    except anthropic.AuthenticationError:
        return ValidationResult(CredentialStatus.INVALID, "키가 거부되었습니다")
    except anthropic.PermissionDeniedError:
        return ValidationResult(CredentialStatus.INVALID, "키에 필요한 권한이 없습니다")
    except anthropic.APIStatusError as e:
        return ValidationResult(
            CredentialStatus.UNVERIFIED, f"검증 요청이 실패했습니다 (HTTP {e.status_code})"
        )
    except anthropic.APIConnectionError:
        return ValidationResult(CredentialStatus.UNVERIFIED, "Anthropic API에 연결하지 못했습니다")
    return _valid()


def validate_openrouter(
    key: str, *, base_url: str, http_client: httpx.Client | None = None
) -> ValidationResult:
    if not key.startswith("sk-or-"):
        return ValidationResult(CredentialStatus.INVALID, "OpenRouter 키는 sk-or- 로 시작합니다")
    try:
        with _httpx_client(http_client) as client:
            response = client.get(f"{base_url}/key", headers={"Authorization": f"Bearer {key}"})
    except httpx.HTTPError:
        return ValidationResult(CredentialStatus.UNVERIFIED, "OpenRouter에 연결하지 못했습니다")
    return _http_result(response)


def validate_typesafe(
    key: str, *, base_url: str, model: str, http_client: httpx.Client | None = None
) -> ValidationResult:
    body = {
        "model": model,
        "state": "AutoCVE API key validation.",
        "questions": {
            "ping": {
                "type": "choice",
                "instructions": "Select ok.",
                "options": {"ok": "Always select this option.", "other": "Never select this."},
            }
        },
    }
    try:
        with _httpx_client(http_client) as client:
            response = client.post(
                f"{base_url}/systemone", json=body, headers={"Authorization": f"Bearer {key}"}
            )
    except httpx.HTTPError:
        return ValidationResult(CredentialStatus.UNVERIFIED, "TypeSafe에 연결하지 못했습니다")
    return _http_result(response)


def validate_github(
    key: str, *, api_url: str, http_client: httpx.Client | None = None
) -> ValidationResult:
    try:
        with _httpx_client(http_client) as client:
            response = client.get(
                f"{api_url}/user",
                headers={"Authorization": f"Bearer {key}", "Accept": "application/vnd.github+json"},
            )
    except httpx.HTTPError:
        return ValidationResult(CredentialStatus.UNVERIFIED, "GitHub API에 연결하지 못했습니다")
    return _http_result(response)


def validate_slack_webhook(url: str) -> ValidationResult:
    # 검증 요청을 보내면 채널에 메시지가 올라가므로 형식만 확인한다.
    # 실제 전송은 알림 설정의 "테스트 전송"으로 확인한다.
    if not url.startswith("https://hooks.slack.com/"):
        return ValidationResult(
            CredentialStatus.INVALID,
            "Slack Webhook 주소는 https://hooks.slack.com/ 으로 시작합니다",
        )
    return ValidationResult(CredentialStatus.VALID, "형식 확인 (테스트 전송으로 확인하세요)")


def default_validators(settings: Settings) -> dict[Provider, Validator]:
    return {
        Provider.ANTHROPIC: validate_anthropic,
        Provider.OPENROUTER: lambda key: validate_openrouter(
            key, base_url=settings.openrouter_base_url
        ),
        Provider.TYPESAFE: lambda key: validate_typesafe(
            key, base_url=settings.typesafe_base_url, model=settings.jev_typesafe_model
        ),
        Provider.GITHUB: lambda key: validate_github(key, api_url=settings.github_api_url),
        Provider.SLACK: validate_slack_webhook,
    }

""".env 설정을 DB에 반영한다. 웹 앱·워커·CLI가 시작할 때마다 호출한다.

- API 키: .env에 값이 있으면 암호화해서 저장하고(source=env), 웹 화면에서는 바꿀 수 없게 잠근다.
  .env에서 지우면 DB에서도 지운다. 화면에서 입력한 키(source=ui)는 건드리지 않는다.
- 키 값이 그대로면 다시 쓰지 않는다. 화면에서 재검증한 상태가 유지된다.
- JEV 제공자, 월 예산, 알림 설정도 .env 값이 있으면 그 값으로 덮어쓴다.
"""

import logging
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy.orm import Session

from autocve.config import Settings
from autocve.credentials import service
from autocve.credentials.service import CredentialError
from autocve.credentials.validators import check_format
from autocve.models import CredentialStatus, JevProvider, Provider
from autocve.security.keyvault import KeyVault

logger = logging.getLogger(__name__)

ENV_KEYS: dict[Provider, tuple[str, str]] = {
    Provider.ANTHROPIC: ("anthropic_api_key", "AUTOCVE_ANTHROPIC_API_KEY"),
    Provider.TYPESAFE: ("typesafe_api_key", "AUTOCVE_TYPESAFE_API_KEY"),
    Provider.OPENROUTER: ("openrouter_api_key", "AUTOCVE_OPENROUTER_API_KEY"),
    Provider.GITHUB: ("github_token", "AUTOCVE_GITHUB_TOKEN"),
    Provider.SLACK: ("slack_webhook_url", "AUTOCVE_SLACK_WEBHOOK_URL"),
}


@dataclass
class EnvLocks:
    """.env로 관리되어 웹 화면에서 바꿀 수 없는 항목."""

    providers: set[Provider] = field(default_factory=set)
    jev_provider: bool = False
    budget: bool = False
    notify_email: bool = False
    notify_grade: bool = False
    notify_digest: bool = False

    def env_name(self, provider: Provider) -> str:
        return ENV_KEYS[provider][1]


def env_locks(settings: Settings) -> EnvLocks:
    return EnvLocks(
        providers={p for p, (attr, _) in ENV_KEYS.items() if getattr(settings, attr) is not None},
        jev_provider=settings.jev_provider is not None,
        budget=settings.monthly_budget_usd is not None,
        notify_email=settings.notify_email_to is not None,
        notify_grade=settings.notify_immediate_grade is not None,
        notify_digest=settings.notify_digest is not None,
    )


@dataclass
class SyncReport:
    stored: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)


def _current_secret(session, vault, workspace, provider) -> str | None:
    try:
        return service.load_secret(session, vault, workspace, provider)
    except CredentialError:
        return None  # 마스터 키가 바뀌었으면 .env 값으로 다시 쓴다


def apply_env_settings(session: Session, vault: KeyVault, settings: Settings) -> SyncReport:
    workspace = service.get_or_create_default_workspace(session)
    report = SyncReport()

    for provider, (attr, env_name) in ENV_KEYS.items():
        value = getattr(settings, attr)
        credential = service.get_credential(session, workspace, provider)
        if value is None:
            if credential is not None and credential.source == "env":
                service.delete_credential(session, workspace, provider)
                report.removed.append(env_name)
            continue
        secret = value.get_secret_value().strip()
        if (
            credential is not None
            and credential.source == "env"
            and _current_secret(session, vault, workspace, provider) == secret
        ):
            continue
        result = service.save_credential(
            session,
            vault,
            workspace,
            provider,
            secret,
            lambda key, p=provider: check_format(p, key),
            source="env",
        )
        if result.status == CredentialStatus.INVALID:
            logger.error("%s 값을 쓰지 않았습니다: %s", env_name, result.message)
            report.rejected.append(env_name)
            if credential is not None and credential.source == "env":
                service.delete_credential(session, workspace, provider)
        else:
            report.stored.append(env_name)

    if settings.jev_provider is not None:
        workspace.jev_provider = JevProvider(settings.jev_provider).value
        if settings.jev_provider != "none" and Provider(settings.jev_provider) not in {
            p for p in ENV_KEYS if service.get_credential(session, workspace, p)
        }:
            logger.warning(
                "AUTOCVE_JEV_PROVIDER=%s인데 키가 없어 규칙 기반으로 판별합니다",
                settings.jev_provider,
            )
    if settings.monthly_budget_usd is not None:
        workspace.monthly_budget_usd = settings.monthly_budget_usd.quantize(Decimal("0.01"))

    notify = dict(workspace.notification_settings or {})
    if settings.notify_email_list is not None:
        notify["email_to"] = settings.notify_email_list
    if settings.notify_immediate_grade is not None:
        notify["immediate_grade"] = settings.notify_immediate_grade
    if settings.notify_digest is not None:
        notify["digest"] = settings.notify_digest
    workspace.notification_settings = notify
    session.commit()

    if report.stored or report.removed:
        logger.info(".env 반영: 저장 %s, 삭제 %s", report.stored, report.removed)
    return report

from decimal import Decimal
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# .env에 빈 값으로 남겨 둔 선택 항목은 "설정 안 함"으로 본다.
_OPTIONAL_FIELDS = (
    "admin_password",
    "anthropic_api_key",
    "jev_provider",
    "typesafe_api_key",
    "openrouter_api_key",
    "github_token",
    "slack_webhook_url",
    "monthly_budget_usd",
    "notify_email_to",
    "notify_immediate_grade",
    "notify_digest",
    "smtp_host",
    "smtp_username",
    "smtp_password",
    "smtp_from",
    "scan_workdir",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTOCVE_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://autocve:autocve@localhost:5432/autocve"
    redis_url: str = "redis://localhost:6379/0"
    master_key: SecretStr
    admin_password: SecretStr | None = None
    log_level: str = "INFO"

    # JEV 모델 ID. 임계값 보정이 모델 버전에 묶이므로 운영에서는 버전을 고정한다.
    jev_typesafe_model: str = "jev-latest"
    jev_openrouter_model: str = "typesafe/jev-1.14"
    typesafe_base_url: str = "https://api.typesafe.ai/v1"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # 취약점 피드
    osv_base_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    github_api_url: str = "https://api.github.com"
    # 저장소 clone 작업 디렉터리. 스캔이 끝나면 지운다.
    scan_workdir: str | None = None

    # --- .env로 관리하는 운영 설정 ------------------------------------------
    # 값이 있으면 시작할 때 DB에 반영하고, 웹 화면에서는 바꿀 수 없게 잠근다 (autocve/envsync.py).
    anthropic_api_key: SecretStr | None = None
    jev_provider: Literal["none", "typesafe", "openrouter"] | None = None
    typesafe_api_key: SecretStr | None = None
    openrouter_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    slack_webhook_url: SecretStr | None = None
    monthly_budget_usd: Decimal | None = None
    notify_email_to: str | None = None  # 쉼표로 구분
    notify_immediate_grade: Literal["critical", "high"] | None = None
    notify_digest: bool | None = None

    # 알림에 넣을 웹 UI 주소
    public_url: str = "http://127.0.0.1:8000"
    # 이메일 알림 (SMTP). host가 없으면 이메일 알림을 쓰지 않는다.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True

    @field_validator(*_OPTIONAL_FIELDS, mode="before")
    @classmethod
    def _empty_is_unset(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("monthly_budget_usd")
    @classmethod
    def _positive_budget(cls, value: Decimal | None) -> Decimal | None:
        if value is not None and value <= 0:
            raise ValueError("AUTOCVE_MONTHLY_BUDGET_USD는 0보다 커야 합니다")
        return value

    @property
    def notify_email_list(self) -> list[str] | None:
        if self.notify_email_to is None:
            return None
        return [e.strip() for e in self.notify_email_to.replace(";", ",").split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

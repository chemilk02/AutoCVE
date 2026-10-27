from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache
def get_settings() -> Settings:
    return Settings()

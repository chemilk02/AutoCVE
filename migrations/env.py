import os
from logging.config import fileConfig

from alembic import context
from dotenv import dotenv_values
from sqlalchemy import engine_from_config, pool

from autocve.config import Settings
from autocve.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 마이그레이션에는 마스터 키가 필요 없으므로 Settings 전체를 읽지 않고 DB URL만 가져온다.
# 환경변수 → .env → 기본값 순서로 찾는다.
database_url = (
    os.environ.get("AUTOCVE_DATABASE_URL")
    or dotenv_values(".env").get("AUTOCVE_DATABASE_URL")
    or Settings.model_fields["database_url"].default
)
config.set_main_option("sqlalchemy.url", database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

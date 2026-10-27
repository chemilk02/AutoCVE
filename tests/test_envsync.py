from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from autocve.api.app import create_app
from autocve.config import Settings
from autocve.credentials import service
from autocve.envsync import apply_env_settings, env_locks
from autocve.models import ApiCredential, CredentialStatus, Provider, Workspace
from autocve.security.keyvault import KeyVault, generate_master_key

ANTHROPIC_KEY = "sk-ant-api03-envkey-1234"
OPENROUTER_KEY = "sk-or-v1-envkey-5678"
SLACK_URL = "https://hooks.slack.com/services/T000/B000/xyz9"


def with_env(settings: Settings, **values) -> Settings:
    return Settings(
        _env_file=None,
        database_url=settings.database_url,
        master_key=settings.master_key.get_secret_value(),
        **values,
    )


def sync(settings: Settings):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with Session(create_engine(settings.database_url)) as session:
        report = apply_env_settings(session, vault, settings)
        workspace = service.get_or_create_default_workspace(session)
        creds = {c.provider: c for c in session.scalars(select(ApiCredential))}
        secrets = {p: service.load_secret(session, vault, workspace, Provider(p)) for p in creds}
        session.expunge_all()
    return report, workspace, creds, secrets


def test_empty_values_mean_unset():
    s = Settings(
        _env_file=None,
        master_key=generate_master_key(),
        anthropic_api_key="",
        jev_provider="  ",
        monthly_budget_usd="",
        notify_digest="",
        smtp_host="",
    )
    assert s.anthropic_api_key is None
    assert s.jev_provider is None
    assert s.monthly_budget_usd is None
    assert s.notify_digest is None
    assert s.smtp_host is None
    assert env_locks(s).providers == set()


def test_budget_must_be_positive():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, master_key=generate_master_key(), monthly_budget_usd="0")


def test_email_list_accepts_comma_and_semicolon():
    s = Settings(
        _env_file=None, master_key=generate_master_key(), notify_email_to="a@x.io; b@x.io, "
    )
    assert s.notify_email_list == ["a@x.io", "b@x.io"]


def test_env_reads_dotenv_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"AUTOCVE_MASTER_KEY={generate_master_key()}\n"
        f"AUTOCVE_ANTHROPIC_API_KEY={ANTHROPIC_KEY}\n"
        "AUTOCVE_MONTHLY_BUDGET_USD=20\n"
        "AUTOCVE_GITHUB_TOKEN=\n"
    )
    s = Settings(_env_file=env_file)
    assert s.anthropic_api_key.get_secret_value() == ANTHROPIC_KEY
    assert s.monthly_budget_usd == Decimal("20")
    assert s.github_token is None


def test_keys_are_stored_encrypted_with_env_source(settings):
    s = with_env(settings, anthropic_api_key=ANTHROPIC_KEY, slack_webhook_url=SLACK_URL)
    report, _, creds, secrets = sync(s)
    assert set(report.stored) == {"AUTOCVE_ANTHROPIC_API_KEY", "AUTOCVE_SLACK_WEBHOOK_URL"}
    assert creds["anthropic"].source == "env"
    assert creds["anthropic"].status == CredentialStatus.UNVERIFIED
    assert ANTHROPIC_KEY.encode() not in creds["anthropic"].ciphertext
    assert secrets["anthropic"] == ANTHROPIC_KEY
    assert secrets["slack"] == SLACK_URL


def test_unchanged_key_keeps_validation_state(settings):
    s = with_env(settings, anthropic_api_key=ANTHROPIC_KEY)
    sync(s)
    with Session(create_engine(settings.database_url)) as session:
        cred = session.scalar(select(ApiCredential))
        cred.status = CredentialStatus.VALID
        session.commit()

    report, _, creds, _ = sync(s)
    assert report.stored == []
    assert creds["anthropic"].status == CredentialStatus.VALID


def test_changed_key_is_replaced(settings):
    sync(with_env(settings, anthropic_api_key=ANTHROPIC_KEY))
    report, _, _, secrets = sync(with_env(settings, anthropic_api_key="sk-ant-api03-new-0000"))
    assert report.stored == ["AUTOCVE_ANTHROPIC_API_KEY"]
    assert secrets["anthropic"] == "sk-ant-api03-new-0000"


def test_removed_env_key_is_deleted_but_ui_key_is_kept(settings):
    sync(with_env(settings, anthropic_api_key=ANTHROPIC_KEY))
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with Session(create_engine(settings.database_url)) as session:
        workspace = service.get_or_create_default_workspace(session)
        service.save_credential(
            session,
            vault,
            workspace,
            Provider.GITHUB,
            "github_pat_ui_1111",
            lambda key: check_valid(),
        )

    report, _, creds, _ = sync(with_env(settings))
    assert report.removed == ["AUTOCVE_ANTHROPIC_API_KEY"]
    assert set(creds) == {"github"}
    assert creds["github"].source == "ui"


def check_valid():
    from autocve.credentials.validators import ValidationResult

    return ValidationResult(CredentialStatus.VALID, "ok")


def test_wrong_format_is_rejected(settings):
    sync(with_env(settings, anthropic_api_key=ANTHROPIC_KEY))
    report, _, creds, _ = sync(with_env(settings, anthropic_api_key="not-an-anthropic-key"))
    assert report.rejected == ["AUTOCVE_ANTHROPIC_API_KEY"]
    assert "anthropic" not in creds


def test_env_key_overrides_ui_key(settings):
    vault = KeyVault.from_b64(settings.master_key.get_secret_value())
    with Session(create_engine(settings.database_url)) as session:
        workspace = service.get_or_create_default_workspace(session)
        service.save_credential(
            session, vault, workspace, Provider.ANTHROPIC, "sk-ant-ui-2222", lambda k: check_valid()
        )
    _, _, creds, secrets = sync(with_env(settings, anthropic_api_key=ANTHROPIC_KEY))
    assert creds["anthropic"].source == "env"
    assert secrets["anthropic"] == ANTHROPIC_KEY


def test_master_key_change_rewrites_env_key(settings):
    sync(with_env(settings, anthropic_api_key=ANTHROPIC_KEY))
    rotated = Settings(
        _env_file=None,
        database_url=settings.database_url,
        master_key=generate_master_key(),
        anthropic_api_key=ANTHROPIC_KEY,
    )
    report, _, _, secrets = sync(rotated)
    assert report.stored == ["AUTOCVE_ANTHROPIC_API_KEY"]
    assert secrets["anthropic"] == ANTHROPIC_KEY


def test_workspace_settings_follow_env(settings):
    s = with_env(
        settings,
        openrouter_api_key=OPENROUTER_KEY,
        jev_provider="openrouter",
        monthly_budget_usd="12.346",
        notify_email_to="sec@example.com, ops@example.com",
        notify_immediate_grade="critical",
        notify_digest="false",
    )
    _, workspace, _, _ = sync(s)
    assert workspace.jev_provider == "openrouter"
    assert workspace.monthly_budget_usd == Decimal("12.35")
    assert workspace.notification_settings == {
        "email_to": ["sec@example.com", "ops@example.com"],
        "immediate_grade": "critical",
        "digest": False,
    }


def test_unset_workspace_settings_are_left_alone(settings):
    with Session(create_engine(settings.database_url)) as session:
        workspace = service.get_or_create_default_workspace(session)
        workspace.monthly_budget_usd = Decimal("5")
        workspace.notification_settings = {"immediate_grade": "critical"}
        session.commit()
    _, workspace, _, _ = sync(with_env(settings))
    assert workspace.monthly_budget_usd == Decimal("5")
    assert workspace.notification_settings == {"immediate_grade": "critical"}


@pytest.fixture
def env_client(settings, validators, queue):
    s = with_env(
        settings,
        anthropic_api_key=ANTHROPIC_KEY,
        slack_webhook_url=SLACK_URL,
        jev_provider="none",
        monthly_budget_usd="30",
        notify_immediate_grade="critical",
    )
    with TestClient(create_app(s, validators, queue)) as c:
        yield c


def test_app_start_applies_env(env_client, settings):
    with Session(create_engine(settings.database_url)) as session:
        cred = session.scalar(select(ApiCredential).where(ApiCredential.provider == "anthropic"))
        workspace = session.scalar(select(Workspace))
        assert cred.source == "env"
        assert workspace.monthly_budget_usd == Decimal("30.00")


def test_keys_page_shows_env_note(env_client):
    text = env_client.get("/settings/keys").text
    assert "AUTOCVE_ANTHROPIC_API_KEY" in text
    assert "AUTOCVE_MONTHLY_BUDGET_USD" in text
    assert 'action="/settings/keys/anthropic"' not in text
    assert 'action="/settings/keys/github"' in text


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/settings/keys/anthropic", {"api_key": "sk-ant-other"}),
        ("/settings/keys/anthropic/delete", {}),
        ("/settings/jev-provider", {"provider": "none"}),
        ("/settings/budget", {"monthly_budget_usd": "99"}),
        ("/settings/notifications/slack/delete", {}),
        ("/settings/notifications", {"slack_webhook": "https://hooks.slack.com/services/new"}),
    ],
)
def test_env_managed_values_are_locked(env_client, path, data):
    response = env_client.post(path, data=data)
    assert response.status_code == 409
    assert ".env" in response.text


def test_locked_notification_fields_keep_env_values(env_client, settings):
    response = env_client.post(
        "/settings/notifications",
        data={"immediate_grade": "high", "email_to": "a@example.com", "digest": "on"},
    )
    assert response.status_code == 200
    with Session(create_engine(settings.database_url)) as session:
        config = session.scalar(select(Workspace)).notification_settings
    assert config == {"immediate_grade": "critical", "email_to": ["a@example.com"], "digest": True}


def test_unlocked_key_can_still_be_saved(env_client):
    response = env_client.post("/settings/keys/github", data={"api_key": "github_pat_abcd"})
    assert response.status_code == 200

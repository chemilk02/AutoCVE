import base64

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from autocve.api.app import create_app
from autocve.models import ApiCredential, CredentialStatus, Provider, Workspace
from autocve.security.keyvault import generate_master_key
from tests.fakes import FakeQueue

ANTHROPIC_KEY = "sk-ant-api03-testkey-1234"
OPENROUTER_KEY = "sk-or-v1-testkey-5678"
TYPESAFE_KEY = "typesafe-testkey-9012"


def db(settings) -> Session:
    return Session(create_engine(settings.database_url))


def workspace(settings) -> Workspace:
    with db(settings) as session:
        return session.scalar(select(Workspace))


def credentials(settings) -> dict[str, ApiCredential]:
    with db(settings) as session:
        return {c.provider: c for c in session.scalars(select(ApiCredential))}


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_index_redirects_to_projects(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/projects"


def test_keys_page_renders(client):
    response = client.get("/settings/keys")
    assert response.status_code == 200
    assert "Anthropic" in response.text
    assert "OpenRouter" in response.text
    assert "TypeSafe" in response.text


def test_save_valid_key_stores_ciphertext_only(client, settings):
    response = client.post("/settings/keys/anthropic", data={"api_key": f"  {ANTHROPIC_KEY} "})
    assert response.status_code == 200
    assert ANTHROPIC_KEY not in response.text
    assert "••••1234" in response.text

    cred = credentials(settings)["anthropic"]
    assert cred.status == CredentialStatus.VALID
    assert cred.last4 == "1234"
    assert ANTHROPIC_KEY.encode() not in cred.ciphertext


def test_invalid_key_is_not_stored(client, settings, validators):
    validators[Provider.ANTHROPIC].status = CredentialStatus.INVALID
    response = client.post("/settings/keys/anthropic", data={"api_key": ANTHROPIC_KEY})
    assert response.status_code == 400
    assert credentials(settings) == {}


def test_unverified_key_is_stored_for_retry(client, settings, validators):
    validators[Provider.ANTHROPIC].status = CredentialStatus.UNVERIFIED
    client.post("/settings/keys/anthropic", data={"api_key": ANTHROPIC_KEY})
    assert credentials(settings)["anthropic"].status == CredentialStatus.UNVERIFIED


def test_revalidate_uses_decrypted_key(client, settings, validators):
    validators[Provider.ANTHROPIC].status = CredentialStatus.UNVERIFIED
    client.post("/settings/keys/anthropic", data={"api_key": ANTHROPIC_KEY})

    validators[Provider.ANTHROPIC].status = CredentialStatus.VALID
    response = client.post("/settings/keys/anthropic/revalidate")
    assert response.status_code == 200
    assert validators[Provider.ANTHROPIC].seen == [ANTHROPIC_KEY, ANTHROPIC_KEY]
    assert credentials(settings)["anthropic"].status == CredentialStatus.VALID


def test_revalidate_without_key_is_rejected(client):
    assert client.post("/settings/keys/openrouter/revalidate").status_code == 400


def test_revalidate_after_master_key_change_asks_for_new_key(client, settings, validators):
    client.post("/settings/keys/anthropic", data={"api_key": ANTHROPIC_KEY})

    rotated = settings.model_copy(update={"master_key": SecretStr(generate_master_key())})
    with TestClient(create_app(rotated, validators, FakeQueue())) as other:
        response = other.post("/settings/keys/anthropic/revalidate")
    assert response.status_code == 400
    assert "복호화할 수 없습니다" in response.text


def test_first_jev_key_becomes_active_provider(client, settings):
    client.post("/settings/keys/openrouter", data={"api_key": OPENROUTER_KEY})
    assert workspace(settings).jev_provider == "openrouter"

    # 두 번째 제공자 키를 저장해도 사용 중인 제공자는 바뀌지 않는다.
    client.post("/settings/keys/typesafe", data={"api_key": TYPESAFE_KEY})
    assert workspace(settings).jev_provider == "openrouter"


def test_switch_jev_provider(client, settings):
    client.post("/settings/keys/openrouter", data={"api_key": OPENROUTER_KEY})
    client.post("/settings/keys/typesafe", data={"api_key": TYPESAFE_KEY})

    assert client.post("/settings/jev-provider", data={"provider": "typesafe"}).status_code == 200
    assert workspace(settings).jev_provider == "typesafe"
    assert client.post("/settings/jev-provider", data={"provider": "none"}).status_code == 200
    assert workspace(settings).jev_provider == "none"


def test_cannot_select_jev_provider_without_key(client, settings):
    response = client.post("/settings/jev-provider", data={"provider": "typesafe"})
    assert response.status_code == 400
    assert workspace(settings).jev_provider == "none"


def test_deleting_active_jev_key_falls_back_to_rules(client, settings):
    client.post("/settings/keys/openrouter", data={"api_key": OPENROUTER_KEY})
    client.post("/settings/keys/openrouter/delete")
    assert "openrouter" not in credentials(settings)
    assert workspace(settings).jev_provider == "none"


def test_unknown_provider_rejected(client):
    assert client.post("/settings/keys/openai", data={"api_key": "x"}).status_code == 422


def test_cross_origin_post_rejected(client, settings):
    response = client.post(
        "/settings/keys/anthropic",
        data={"api_key": ANTHROPIC_KEY},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert credentials(settings) == {}


def test_same_origin_post_allowed(client):
    response = client.post(
        "/settings/keys/anthropic",
        data={"api_key": ANTHROPIC_KEY},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200


def test_admin_password_required_when_configured(settings, validators):
    protected = settings.model_copy(update={"admin_password": SecretStr("s3cret")})
    with TestClient(create_app(protected, validators, FakeQueue())) as client:
        assert client.get("/settings/keys").status_code == 401
        assert client.get("/healthz").status_code == 200

        bad = base64.b64encode(b"admin:wrong").decode()
        assert (
            client.get("/settings/keys", headers={"Authorization": f"Basic {bad}"}).status_code
            == 401
        )

        good = base64.b64encode(b"admin:s3cret").decode()
        assert (
            client.get("/settings/keys", headers={"Authorization": f"Basic {good}"}).status_code
            == 200
        )


def test_budget_setting(client, settings):
    assert client.post("/settings/budget", data={"monthly_budget_usd": "12.5"}).status_code == 200
    assert str(workspace(settings).monthly_budget_usd) == "12.50"
    assert client.post("/settings/budget", data={"monthly_budget_usd": "-3"}).status_code == 400
    assert client.post("/settings/budget", data={"monthly_budget_usd": "abc"}).status_code == 400
    client.post("/settings/budget", data={"monthly_budget_usd": ""})
    assert workspace(settings).monthly_budget_usd is None

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.credentials.validators import ValidationResult, Validator
from autocve.models import (
    JEV_PROVIDERS,
    ApiCredential,
    CredentialStatus,
    JevProvider,
    Provider,
    Workspace,
)
from autocve.security.keyvault import KeyVault, KeyVaultError
from autocve.security.redaction import register_secret

DEFAULT_WORKSPACE = "default"


class CredentialError(Exception):
    pass


def get_or_create_default_workspace(session: Session) -> Workspace:
    workspace = session.scalar(select(Workspace).where(Workspace.name == DEFAULT_WORKSPACE))
    if workspace is None:
        workspace = Workspace(name=DEFAULT_WORKSPACE)
        session.add(workspace)
        session.commit()
    return workspace


def _context(workspace_id: int, provider: Provider) -> str:
    return f"workspace:{workspace_id}:provider:{provider}"


def get_credential(session: Session, workspace: Workspace, provider: Provider):
    return session.scalar(
        select(ApiCredential).where(
            ApiCredential.workspace_id == workspace.id, ApiCredential.provider == provider
        )
    )


def _apply_result(credential: ApiCredential, result: ValidationResult) -> None:
    credential.status = result.status
    credential.status_message = result.message
    credential.validated_at = datetime.now(UTC)


def save_credential(
    session: Session,
    vault: KeyVault,
    workspace: Workspace,
    provider: Provider,
    secret: str,
    validator: Validator,
    *,
    source: str = "ui",
) -> ValidationResult:
    """키를 검증하고, 거부되지 않았으면 암호화해서 저장한다.

    네트워크 오류로 검증하지 못한 키(UNVERIFIED)는 저장하고 나중에 다시 검증할 수 있게 한다.
    """
    secret = secret.strip()
    if not secret:
        raise CredentialError("키가 비어 있습니다")
    register_secret(secret)
    result = validator(secret)
    if result.status == CredentialStatus.INVALID:
        return result

    credential = get_credential(session, workspace, provider)
    if credential is None:
        credential = ApiCredential(workspace_id=workspace.id, provider=provider)
        session.add(credential)
    credential.ciphertext = vault.encrypt(secret, context=_context(workspace.id, provider))
    credential.key_id = vault.key_id
    credential.last4 = secret[-4:]
    credential.source = source
    _apply_result(credential, result)

    # JEV 키를 처음 저장하면 그 제공자를 바로 사용하도록 한다.
    if provider in JEV_PROVIDERS and workspace.jev_provider == JevProvider.NONE:
        workspace.jev_provider = provider.value
    session.commit()
    return result


def load_secret(
    session: Session, vault: KeyVault, workspace: Workspace, provider: Provider
) -> str | None:
    credential = get_credential(session, workspace, provider)
    if credential is None:
        return None
    try:
        secret = vault.decrypt(credential.ciphertext, context=_context(workspace.id, provider))
    except KeyVaultError as e:
        raise CredentialError(
            "저장된 키를 복호화할 수 없습니다. 마스터 키가 바뀌었다면 키를 다시 입력하세요"
        ) from e
    register_secret(secret)
    return secret


def revalidate_credential(
    session: Session,
    vault: KeyVault,
    workspace: Workspace,
    provider: Provider,
    validator: Validator,
) -> ValidationResult:
    credential = get_credential(session, workspace, provider)
    if credential is None:
        raise CredentialError("저장된 키가 없습니다")
    secret = load_secret(session, vault, workspace, provider)
    result = validator(secret)
    _apply_result(credential, result)
    session.commit()
    return result


def delete_credential(session: Session, workspace: Workspace, provider: Provider) -> None:
    credential = get_credential(session, workspace, provider)
    if credential is not None:
        session.delete(credential)
    if workspace.jev_provider == provider.value:
        workspace.jev_provider = JevProvider.NONE.value
    session.commit()


def set_jev_provider(session: Session, workspace: Workspace, choice: JevProvider) -> None:
    if choice != JevProvider.NONE:
        credential = get_credential(session, workspace, Provider(choice.value))
        if credential is None or credential.status == CredentialStatus.INVALID:
            raise CredentialError("먼저 해당 제공자의 키를 저장하세요")
    workspace.jev_provider = choice.value
    session.commit()

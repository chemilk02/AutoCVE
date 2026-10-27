import base64

import pytest

from autocve.security.keyvault import KeyVault, KeyVaultError, generate_master_key


@pytest.fixture
def vault() -> KeyVault:
    return KeyVault.from_b64(generate_master_key())


def test_roundtrip(vault):
    blob = vault.encrypt("sk-ant-secret-value", context="workspace:1:provider:anthropic")
    assert b"sk-ant-secret-value" not in blob
    assert vault.decrypt(blob, context="workspace:1:provider:anthropic") == "sk-ant-secret-value"


def test_same_plaintext_encrypts_differently(vault):
    assert vault.encrypt("key", context="c") != vault.encrypt("key", context="c")


def test_wrong_context_fails(vault):
    blob = vault.encrypt("key", context="workspace:1:provider:anthropic")
    with pytest.raises(KeyVaultError):
        vault.decrypt(blob, context="workspace:2:provider:anthropic")


def test_wrong_master_key_fails(vault):
    blob = vault.encrypt("key", context="c")
    other = KeyVault.from_b64(generate_master_key())
    with pytest.raises(KeyVaultError):
        other.decrypt(blob, context="c")


def test_tampered_ciphertext_fails(vault):
    blob = bytearray(vault.encrypt("key", context="c"))
    blob[-1] ^= 0x01
    with pytest.raises(KeyVaultError):
        vault.decrypt(bytes(blob), context="c")


@pytest.mark.parametrize("encoded", ["not base64!", base64.b64encode(b"short").decode()])
def test_rejects_bad_master_key(encoded):
    with pytest.raises(KeyVaultError):
        KeyVault.from_b64(encoded)

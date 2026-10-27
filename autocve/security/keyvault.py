"""사용자 API 키를 AES-256-GCM으로 암호화한다.

암호문 형식: version(1바이트) || nonce(12바이트) || ciphertext+tag.
`context`(워크스페이스와 제공자)를 AAD로 묶어,
다른 행에 암호문을 옮겨 붙이면 복호화가 실패하게 한다.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
NONCE_SIZE = 12


class KeyVaultError(Exception):
    pass


class KeyVault:
    def __init__(self, master_key: bytes, key_id: str = "v1"):
        if len(master_key) != 32:
            raise KeyVaultError("마스터 키는 32바이트여야 합니다")
        self._aead = AESGCM(master_key)
        self.key_id = key_id

    @classmethod
    def from_b64(cls, encoded: str, key_id: str = "v1") -> "KeyVault":
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as e:
            raise KeyVaultError("마스터 키가 올바른 base64가 아닙니다") from e
        return cls(raw, key_id)

    def encrypt(self, plaintext: str, *, context: str) -> bytes:
        nonce = os.urandom(NONCE_SIZE)
        sealed = self._aead.encrypt(nonce, plaintext.encode(), context.encode())
        return bytes([FORMAT_VERSION]) + nonce + sealed

    def decrypt(self, blob: bytes, *, context: str) -> str:
        if not blob or blob[0] != FORMAT_VERSION:
            raise KeyVaultError("지원하지 않는 암호문 형식입니다")
        nonce, sealed = blob[1 : 1 + NONCE_SIZE], blob[1 + NONCE_SIZE :]
        try:
            return self._aead.decrypt(nonce, sealed, context.encode()).decode()
        except InvalidTag as e:
            raise KeyVaultError("복호화 실패: 마스터 키 또는 context가 다릅니다") from e


def generate_master_key() -> str:
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()


if __name__ == "__main__":
    print(generate_master_key())

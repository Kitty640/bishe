from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from gmssl import sm2, sm4, func


@dataclass
class SM2KeyPair:
    private_key: str
    public_key: str


class KeyManager:
    """SM2/SM4 key management.

    - Generate/import/export SM2 key pairs
    - Generate SM4 session keys
    - Encrypt/decrypt session key by SM2
    """

    def __init__(self, key_dir: str | Path = "keys") -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def generate_sm2_keypair() -> SM2KeyPair:
        private_key = func.random_hex(64)
        crypt_sm2 = sm2.CryptSM2(private_key=private_key, public_key="")
        public_key = crypt_sm2._kg(int(private_key, 16), sm2.default_ecc_table["g"])
        return SM2KeyPair(private_key=private_key, public_key=public_key)

    def export_sm2_keypair(self, keypair: SM2KeyPair, name: str) -> Tuple[Path, Path]:
        pri_path = self.key_dir / f"{name}_sm2_private.pem"
        pub_path = self.key_dir / f"{name}_sm2_public.pem"
        pri_path.write_text(keypair.private_key, encoding="utf-8")
        pub_path.write_text(keypair.public_key, encoding="utf-8")
        return pri_path, pub_path

    @staticmethod
    def import_sm2_keypair(private_path: str | Path, public_path: str | Path) -> SM2KeyPair:
        private_key = Path(private_path).read_text(encoding="utf-8").strip()
        public_key = Path(public_path).read_text(encoding="utf-8").strip()
        return SM2KeyPair(private_key=private_key, public_key=public_key)

    @staticmethod
    def generate_sm4_session_key() -> bytes:
        return os.urandom(16)

    def encrypt_and_store_session_key(self, session_key: bytes, public_key: str, output_file: str | Path) -> Path:
        crypt_sm2 = sm2.CryptSM2(public_key=public_key, private_key="")
        encrypted = crypt_sm2.encrypt(session_key)
        payload = {"enc_session_key": encrypted.hex()}
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    @staticmethod
    def decrypt_session_key(encrypted_file: str | Path, private_key: str) -> bytes:
        payload = json.loads(Path(encrypted_file).read_text(encoding="utf-8"))
        encrypted = bytes.fromhex(payload["enc_session_key"])
        crypt_sm2 = sm2.CryptSM2(public_key="", private_key=private_key)
        return crypt_sm2.decrypt(encrypted)

    @staticmethod
    def sm4_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
        pad = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad]) * pad
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
        return crypt_sm4.crypt_ecb(padded)

    @staticmethod
    def sm4_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
        padded = crypt_sm4.crypt_ecb(ciphertext)
        return padded[:-padded[-1]]

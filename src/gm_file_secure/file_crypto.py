from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

from gmssl import sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

ProgressCallback = Callable[[int], None]


class FileCrypto:
    def __init__(self, chunk_size: int = 64 * 1024) -> None:
        self.chunk_size = chunk_size

    @staticmethod
    def sm3_hash(data: bytes) -> str:
        return sm3.sm3_hash(func.bytes_to_list(data))

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding]) * padding

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        padding = data[-1]
        if padding <= 0 or padding > 16:
            raise ValueError("Invalid padding")
        return data[:-padding]

    def encrypt_file(self, src: str | Path, key: bytes, progress: ProgressCallback | None = None) -> tuple[Path, str]:
        src_path = Path(src)
        out_path = src_path.with_suffix(src_path.suffix + ".enc")
        iv = os.urandom(16)
        plain = src_path.read_bytes()
        original_hash = self.sm3_hash(plain)

        crypt_sm4 = CryptSM4(mode=SM4_ENCRYPT)
        crypt_sm4.set_key(key, SM4_ENCRYPT)
        cipher = crypt_sm4.crypt_cbc(iv, self._pkcs7_pad(plain))

        out_path.write_bytes(iv + cipher)
        meta = {
            "source_name": src_path.name,
            "source_suffix": src_path.suffix,
            "sm3_before_encrypt": original_hash,
        }
        out_path.with_suffix(out_path.suffix + ".meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if progress:
            progress(100)
        return out_path, original_hash

    def decrypt_file(
        self, src_enc: str | Path, key: bytes, progress: ProgressCallback | None = None
    ) -> tuple[Path, str, str, bool]:
        enc_path = Path(src_enc)
        payload = enc_path.read_bytes()
        iv, ciphertext = payload[:16], payload[16:]

        crypt_sm4 = CryptSM4(mode=SM4_DECRYPT)
        crypt_sm4.set_key(key, SM4_DECRYPT)
        decrypted_padded = crypt_sm4.crypt_cbc(iv, ciphertext)
        decrypted = self._pkcs7_unpad(decrypted_padded)

        meta_path = enc_path.with_suffix(enc_path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        original_name = meta.get("source_name") or enc_path.stem
        out_path = enc_path.with_name(f"dec_{original_name}")
        out_path.write_bytes(decrypted)

        before_hash = meta.get("sm3_before_encrypt", "")
        after_hash = self.sm3_hash(decrypted)
        valid = before_hash == after_hash if before_hash else False
        if progress:
            progress(100)
        return out_path, before_hash, after_hash, valid

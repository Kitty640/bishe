from __future__ import annotations

import json
import mimetypes
import re
from pathlib import Path

import jieba
from sklearn.feature_extraction.text import TfidfVectorizer

from .crypto_manager import KeyManager


class KeywordProcessor:
    def __init__(self, top_k: int = 8) -> None:
        self.top_k = top_k

    def extract_keywords(self, file_path: str | Path) -> list[str]:
        path = Path(file_path)
        mime_type, _ = mimetypes.guess_type(path.name)
        if mime_type and mime_type.startswith("text") or path.suffix.lower() in {".txt", ".md", ".csv", ".json", ".py"}:
            return self._extract_text_keywords(path.read_text(encoding="utf-8", errors="ignore"))
        return self._extract_attr_keywords(path)

    def _extract_text_keywords(self, text: str) -> list[str]:
        text = re.sub(r"\s+", " ", text)
        tokens = [" ".join(jieba.cut(text))]
        vec = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")
        tfidf = vec.fit_transform(tokens)
        scores = tfidf.toarray()[0]
        words = vec.get_feature_names_out()
        ranked = sorted(zip(words, scores), key=lambda x: x[1], reverse=True)
        return [w for w, s in ranked[: self.top_k] if w and s > 0]

    @staticmethod
    def _extract_attr_keywords(path: Path) -> list[str]:
        st = path.stat()
        return [
            f"name:{path.stem}",
            f"suffix:{path.suffix.lower()}",
            f"size:{st.st_size}",
        ]

    @staticmethod
    def encrypt_keywords(keywords: list[str], sm4_key: bytes) -> list[str]:
        encrypted = []
        for kw in keywords:
            cipher = KeyManager.sm4_encrypt_ecb(kw.encode("utf-8"), sm4_key)
            encrypted.append(cipher.hex())
        return encrypted

    @staticmethod
    def decrypt_keywords(enc_keywords: list[str], sm4_key: bytes) -> list[str]:
        raw = []
        for ek in enc_keywords:
            plain = KeyManager.sm4_decrypt_ecb(bytes.fromhex(ek), sm4_key)
            raw.append(plain.decode("utf-8", errors="ignore"))
        return raw

    @staticmethod
    def save_labels(file_id: str, enc_keywords: list[str], output: str | Path) -> Path:
        payload = {"file_id": file_id, "enc_keywords": enc_keywords}
        out = Path(output)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

from __future__ import annotations

import json
from ftplib import FTP
from pathlib import Path


class FTPManager:
    def __init__(self, host: str, user: str, password: str, port: int = 21) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.ftp: FTP | None = None

    def connect(self) -> None:
        self.ftp = FTP()
        self.ftp.connect(self.host, self.port, timeout=10)
        self.ftp.login(self.user, self.password)

    def close(self) -> None:
        if self.ftp:
            self.ftp.quit()
            self.ftp = None

    def upload_files(self, paths: list[str | Path], remote_dir: str = "/") -> None:
        assert self.ftp is not None, "FTP not connected"
        self.ftp.cwd(remote_dir)
        for item in paths:
            p = Path(item)
            with p.open("rb") as f:
                self.ftp.storbinary(f"STOR {p.name}", f)

    def upload_file_and_label(self, enc_file: str | Path, label_file: str | Path, remote_dir: str = "/") -> None:
        self.upload_files([enc_file, label_file], remote_dir=remote_dir)

    def list_label_files(self, remote_dir: str = "/") -> list[str]:
        assert self.ftp is not None, "FTP not connected"
        self.ftp.cwd(remote_dir)
        names = self.ftp.nlst()
        return [n for n in names if n.endswith(".label.json")]

    def download_file(self, remote_name: str, local_path: str | Path, remote_dir: str = "/") -> Path:
        assert self.ftp is not None, "FTP not connected"
        self.ftp.cwd(remote_dir)
        out = Path(local_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("wb") as f:
            self.ftp.retrbinary(f"RETR {remote_name}", f.write)
        return out

    def search_by_keyword(self, query: str, sm4_key: bytes, local_temp: str | Path = "tmp_labels", remote_dir: str = "/") -> list[str]:
        """Search encrypted labels with fuzzy/exact mode.

        query format: "exact:word" or "fuzzy:part".
        """
        from .keyword_processor import KeywordProcessor

        assert self.ftp is not None, "FTP not connected"
        mode, value = query.split(":", 1) if ":" in query else ("fuzzy", query)
        temp = Path(local_temp)
        temp.mkdir(parents=True, exist_ok=True)
        matches = []

        for lf in self.list_label_files(remote_dir=remote_dir):
            local = self.download_file(lf, temp / lf, remote_dir=remote_dir)
            payload = json.loads(local.read_text(encoding="utf-8"))
            kws = KeywordProcessor.decrypt_keywords(payload.get("enc_keywords", []), sm4_key)

            hit = False
            for kw in kws:
                if mode == "exact" and kw == value:
                    hit = True
                elif mode == "fuzzy" and value in kw:
                    hit = True
            if hit:
                matches.append(payload.get("file_id", ""))
        return [m for m in matches if m]

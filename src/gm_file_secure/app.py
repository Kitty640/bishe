from __future__ import annotations

import sys
import uuid
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QProgressBar,
)

from .crypto_manager import KeyManager, SM2KeyPair
from .file_crypto import FileCrypto
from .ftp_manager import FTPManager
from .keyword_processor import KeywordProcessor


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("国密文件加密软件（PyQt5）")
        self.resize(1000, 720)

        self.key_mgr = KeyManager()
        self.file_crypto = FileCrypto()
        self.kw_processor = KeywordProcessor()

        self.sm2_keypair: SM2KeyPair | None = None
        self.session_key: bytes | None = None
        self.selected_file: Path | None = None
        self.selected_enc_file: Path | None = None

        self.ftp_host_input = QLineEdit("127.0.0.1")
        self.ftp_user_input = QLineEdit("anonymous")
        self.ftp_pwd_input = QLineEdit("")
        self.ftp_pwd_input.setEchoMode(QLineEdit.Password)
        self.search_query_input = QLineEdit("fuzzy:")

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)

        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        layout = QVBoxLayout()
        grid = QGridLayout()

        btn_gen_sm2 = QPushButton("1) 生成SM2密钥对")
        btn_import_sm2 = QPushButton("2) 导入SM2密钥对")
        btn_gen_session = QPushButton("3) 生成并加密会话密钥")

        btn_pick_file = QPushButton("选择待加密文件")
        btn_encrypt = QPushButton("SM4-CBC加密文件")
        btn_decrypt = QPushButton("SM4-CBC解密文件")

        btn_upload = QPushButton("上传加密文件+加密标签")
        btn_search_download = QPushButton("FTP关键词检索并下载")

        btn_gen_sm2.clicked.connect(self.gen_sm2)
        btn_import_sm2.clicked.connect(self.import_sm2)
        btn_gen_session.clicked.connect(self.gen_session)
        btn_pick_file.clicked.connect(self.pick_plain_file)
        btn_encrypt.clicked.connect(self.encrypt_file)
        btn_decrypt.clicked.connect(self.decrypt_file)
        btn_upload.clicked.connect(self.upload_to_ftp)
        btn_search_download.clicked.connect(self.search_and_download)

        grid.addWidget(btn_gen_sm2, 0, 0)
        grid.addWidget(btn_import_sm2, 0, 1)
        grid.addWidget(btn_gen_session, 0, 2)

        grid.addWidget(btn_pick_file, 1, 0)
        grid.addWidget(btn_encrypt, 1, 1)
        grid.addWidget(btn_decrypt, 1, 2)

        grid.addWidget(QLabel("FTP Host"), 2, 0)
        grid.addWidget(QLabel("User"), 2, 1)
        grid.addWidget(QLabel("Password"), 2, 2)

        grid.addWidget(self.ftp_host_input, 3, 0)
        grid.addWidget(self.ftp_user_input, 3, 1)
        grid.addWidget(self.ftp_pwd_input, 3, 2)

        grid.addWidget(btn_upload, 4, 0)
        grid.addWidget(self.search_query_input, 4, 1)
        grid.addWidget(btn_search_download, 4, 2)

        layout.addLayout(grid)
        layout.addWidget(self.progress)
        layout.addWidget(self.log_box)
        root.setLayout(layout)

    def log(self, text: str) -> None:
        self.log_box.append(text)

    def set_progress(self, p: int) -> None:
        self.progress.setValue(p)
        QApplication.processEvents()

    def show_error(self, text: str) -> None:
        QMessageBox.critical(self, "错误", text)

    def show_info(self, text: str) -> None:
        QMessageBox.information(self, "提示", text)

    def gen_sm2(self) -> None:
        self.sm2_keypair = self.key_mgr.generate_sm2_keypair()
        pri, pub = self.key_mgr.export_sm2_keypair(self.sm2_keypair, "default")
        self.log(f"SM2密钥对生成并导出成功: {pri}, {pub}")

    def import_sm2(self) -> None:
        pri, _ = QFileDialog.getOpenFileName(self, "选择SM2私钥")
        if not pri:
            return
        pub, _ = QFileDialog.getOpenFileName(self, "选择SM2公钥")
        if not pub:
            return
        self.sm2_keypair = self.key_mgr.import_sm2_keypair(pri, pub)
        self.log("SM2密钥对导入成功")

    def gen_session(self) -> None:
        if not self.sm2_keypair:
            self.show_error("请先生成/导入SM2密钥对")
            return
        self.session_key = self.key_mgr.generate_sm4_session_key()
        out = self.key_mgr.encrypt_and_store_session_key(
            self.session_key, self.sm2_keypair.public_key, "keys/encrypted_session_key.json"
        )
        self.log(f"SM4会话密钥已生成并通过SM2加密保存: {out}")

    def pick_plain_file(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if f:
            self.selected_file = Path(f)
            self.log(f"已选择: {self.selected_file}")

    def encrypt_file(self) -> None:
        if not self.selected_file or not self.session_key:
            self.show_error("请先选择文件并生成会话密钥")
            return
        out, sm3_before = self.file_crypto.encrypt_file(self.selected_file, self.session_key, self.set_progress)
        self.selected_enc_file = out
        self.log(f"加密成功: {out} | 原文件SM3: {sm3_before}")

    def decrypt_file(self) -> None:
        if not self.session_key:
            self.show_error("请先生成会话密钥")
            return
        if not self.selected_enc_file:
            f, _ = QFileDialog.getOpenFileName(self, "选择.enc文件")
            if not f:
                return
            self.selected_enc_file = Path(f)

        out, h1, h2, ok = self.file_crypto.decrypt_file(self.selected_enc_file, self.session_key, self.set_progress)
        self.log(f"解密成功: {out}")
        self.log(f"SM3加密前: {h1}")
        self.log(f"SM3解密后: {h2}")
        if ok:
            self.log("完整性校验通过: 文件未被篡改")
            self.show_info("完整性校验通过")
        else:
            self.log("完整性校验失败: 哈希不一致")
            QMessageBox.warning(self, "警告", "完整性校验失败")

    def _get_ftp(self) -> FTPManager:
        ftp = FTPManager(self.ftp_host_input.text(), self.ftp_user_input.text(), self.ftp_pwd_input.text())
        ftp.connect()
        self.log("FTP连接成功")
        return ftp

    def upload_to_ftp(self) -> None:
        if not self.selected_enc_file or not self.session_key:
            self.show_error("请先完成文件加密")
            return

        keywords = self.kw_processor.extract_keywords(self.selected_file or self.selected_enc_file)
        enc_keywords = self.kw_processor.encrypt_keywords(keywords, self.session_key)
        file_id = str(uuid.uuid4())
        label_path = Path(f"{file_id}.label.json")
        self.kw_processor.save_labels(file_id, enc_keywords, label_path)

        enc_target = Path(f"{file_id}.enc")
        enc_target.write_bytes(self.selected_enc_file.read_bytes())

        meta_src = self.selected_enc_file.with_suffix(self.selected_enc_file.suffix + ".meta.json")
        meta_dst = Path(f"{file_id}.enc.meta.json")
        if meta_src.exists():
            meta_dst.write_text(meta_src.read_text(encoding="utf-8"), encoding="utf-8")

        ftp = self._get_ftp()
        try:
            files = [enc_target, label_path]
            if meta_dst.exists():
                files.append(meta_dst)
            ftp.upload_files(files)
            self.log(f"已上传加密文件和标签，file_id={file_id}")
            self.show_info("上传成功")
        except Exception as e:
            self.log(str(e))
            self.show_error(f"上传失败: {e}")
        finally:
            ftp.close()

    def search_and_download(self) -> None:
        if not self.session_key:
            self.show_error("请先生成会话密钥")
            return
        ftp = self._get_ftp()
        try:
            matched_ids = ftp.search_by_keyword(self.search_query_input.text(), self.session_key)
            self.log(f"检索结果: {matched_ids}")
            dl_dir = Path("downloads")
            dl_dir.mkdir(exist_ok=True)
            for fid in matched_ids:
                enc_name = f"{fid}.enc"
                local_enc = ftp.download_file(enc_name, dl_dir / enc_name)
                self.selected_enc_file = local_enc
                self.log(f"已下载: {local_enc}")
                meta_name = f"{fid}.enc.meta.json"
                try:
                    ftp.download_file(meta_name, dl_dir / meta_name)
                except Exception:
                    pass
                self.decrypt_file()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"FTP检索/下载失败: {e}")
            self.log(str(e))
        finally:
            ftp.close()


def run() -> None:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    app.exec_()

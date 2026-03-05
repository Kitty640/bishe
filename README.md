# 基于国密算法的文件加密软件

## 功能概览
- **密钥管理**：SM2 密钥对生成/导入/导出，SM4 会话密钥自动生成并通过 SM2 加密持久化。
- **文件加解密**：SM4-CBC 文件加密（生成 `.enc`）与解密（恢复原文件名）。
- **FTP 传输**：上传加密文件+加密标签；关键词检索标签并下载对应文件。
- **关键词处理**：文本文件 TF-IDF 提取关键词，非文本提取属性关键词；关键词经 SM4 加密成标签。
- **完整性校验**：加密前与解密后的 SM3 对比验证完整性。
- **可视化交互**：PyQt5 GUI，一键操作、实时日志、进度条、弹窗提示。

## 项目结构
- `main.py`：程序入口
- `src/gm_file_secure/crypto_manager.py`：SM2/SM4 密钥管理
- `src/gm_file_secure/file_crypto.py`：SM4-CBC 文件加解密 + SM3 校验
- `src/gm_file_secure/ftp_manager.py`：FTP 上传/下载/检索
- `src/gm_file_secure/keyword_processor.py`：关键词提取与标签加密
- `src/gm_file_secure/app.py`：PyQt5 图形界面

## 安装与运行
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python main.py
```

> 注意：FTP 检索使用本地会话密钥解密标签，因此上传与检索应使用同一会话密钥。

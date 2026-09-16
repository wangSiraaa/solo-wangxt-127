"""应用配置：所有路径与连接串来自环境变量，附件目录受控。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PARSER_VERSION = "1.0.0"


@dataclass(frozen=True)
class Settings:
    database_url: str
    attachment_dir: Path
    max_upload_bytes: int
    # 单封邮件内最多为每个大对象保留的字符数（正文落库上限，超出部分落文件）
    inline_text_limit: int

    @staticmethod
    def from_env() -> "Settings":
        db = os.environ.get(
            "DATABASE_URL",
            "postgresql://archive@/emailarchive?host=/tmp",
        )
        raw_dir = os.environ.get("ATTACHMENT_DIR", "/workspace/email_archive/var/attachments")
        attachment_dir = Path(raw_dir).resolve()
        attachment_dir.mkdir(parents=True, exist_ok=True)
        return Settings(
            database_url=db,
            attachment_dir=attachment_dir,
            max_upload_bytes=int(os.environ.get("MAX_UPLOAD_BYTES", 50 * 1024 * 1024)),
            inline_text_limit=int(os.environ.get("INLINE_TEXT_LIMIT", 1_000_000)),
        )


settings = Settings.from_env()

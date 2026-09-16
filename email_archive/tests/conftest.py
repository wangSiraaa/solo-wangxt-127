"""pytest 配置：样例目录与（可选）数据库连接。

纯解析/安全测试不依赖 PostgreSQL；标记 integration 的测试在无数据库时跳过。
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("ATTACHMENT_DIR", "/tmp/eml_archive_test_attachments")
os.environ.setdefault("DATABASE_URL",
                      "postgresql://archive@/emailarchive?host=/tmp")

SAMPLES = Path(__file__).resolve().parent / "samples"


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    if not any(SAMPLES.glob("*.eml")):
        pytest.skip("samples not generated; run tests/sample_gen_*.py")
    return SAMPLES


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

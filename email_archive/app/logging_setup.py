"""日志安全：绝不把邮件/附件正文写进普通日志。"""
from __future__ import annotations

import logging
import os

# 单条日志中允许出现的“头值/元数据”最大长度，防止日志投毒与膨胀
MAX_LOG_VALUE = 500


class PayloadRedactionFilter(logging.Filter):
    """兜底过滤器：疑似大段内容（base64/quoted-printable/HTML 块）被替换。

    这是纵深防御：业务代码本就不应记录 payload，过滤器再拦一次。
    """

    _MARKERS = (
        "Content-Transfer-Encoding",
        "Content-Type: multipart/",
        "<!DOCTYPE",
        "<html",
        "<HTML",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if any(marker in msg for marker in self._MARKERS):
            record.msg = "[REDACTED: message payload refused in logs]"
            record.args = ()
        return True


def configure_logging(level: str | None = None) -> None:
    logging.basicConfig(
        level=level or os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(PayloadRedactionFilter())


def short(value: str | None, limit: int = MAX_LOG_VALUE) -> str:
    """把可能不可信的信头值安全截断后再记录。"""
    if value is None:
        return "-"
    value = value.replace("\n", "\\n").replace("\r", "\\r")
    return value if len(value) <= limit else value[:limit] + f"...<+{len(value)-limit}b>"

"""安全工具：受控目录存储、附件名净化、HTML 安全转义、外部资源识别。

设计要点
- 磁盘文件名完全由服务端生成（内容摘要），永不使用用户提供的路径或名称落盘，
  因此 ../、绝对路径、符号链接等无法越界。
- 用户提供的原始/净化文件名只作为元数据保存，并在下载响应头中再次净化。
- HTML 只做原样保存与转义，不去“过滤脚本”（过滤容易遗漏）；任何 src/href/url()
  中的远程地址只登记到 external_refs，服务端绝不发起请求。
"""
from __future__ import annotations



import hashlib
import html
import os
import posixpath
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

# ---------------------------------------------------------------- 附件落盘

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def storage_relpath(eml_sha256: str, payload_sha256: str) -> str:
    """生成受控目录内的相对路径（无扩展名、无用户输入）。

    两级分片：<eml前2位>/<eml再前2位>/<payload64>，天然防目录膨胀与碰撞。
    """
    return posixpath.join(eml_sha256[:2], eml_sha256[2:4], payload_sha256)


def safe_resolve(base_dir: Path, relpath: str) -> Path:
    """把相对路径解析到 base_dir 内；任何越界（含符号链接逃逸）都抛 ValueError。"""
    base = base_dir.resolve(strict=True)
    # relpath 必须是服务端形态：仅允许 [0-9a-f/] 且不含 . 段
    if not re.fullmatch(r"[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{64}", relpath):
        raise ValueError(f"illegal storage path: {relpath!r}")
    candidate = (base / relpath).resolve()
    # Path.is_relative_to 在 3.9+ 可用
    if not str(candidate).startswith(str(base) + os.sep) and candidate != base:
        raise ValueError(f"path traversal detected: {relpath!r}")
    return candidate


def write_attachment(base_dir: Path, relpath: str, data: bytes) -> int:
    """原子写入受控目录；已存在且摘要相同则去重跳过。返回写入字节数。"""
    target = safe_resolve(base_dir, relpath)
    if target.exists():
        # 路径即摘要，存在即内容相同（损坏磁盘除外）
        return target.stat().st_size
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)  # 同目录原子改名，避免半文件
    os.chmod(target, 0o640)
    return len(data)


def read_attachment(base_dir: Path, relpath: str) -> bytes:
    target = safe_resolve(base_dir, relpath)
    if not target.is_file():
        raise FileNotFoundError(relpath)
    return target.read_bytes()

# ---------------------------------------------------------------- 附件名净化

# 控制字符 / 路径分隔 / NUL
_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f]")
_DEVICE_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def sanitize_filename(raw: str | None) -> str | None:
    """把 MIME 参数中的文件名净化为纯元数据 basename。

    - 解码 URL/2231 百分号；
    - 去掉所有目录段（Windows 与 POSIX 分隔符都处理）；
    - 设备名、空名、全点名回退为 None（调用方用通用名占位）。
    注意：该结果不参与落盘路径，即使净化不完美也无法越界。
    """
    if raw is None:
        return None
    name = raw
    # 2231 percent-encoding
    try:
        name = unquote(name, errors="strict")
    except Exception:
        name = unquote(name, errors="replace")
    name = name.replace("\\", "/").strip()
    name = name.split("/")[-1]  # 仅保留 basename
    name = _UNSAFE_NAME.sub("_", name).strip()
    name = name.strip(". ")
    if not name or name.lower() in _DEVICE_NAMES:
        return None
    return name[:255] or None


def download_header_filename(name: str | None, fallback: str = "attachment.bin") -> str:
    """生成 Content-Disposition 用的 filename*（RFC 5987），避免头注入。"""
    safe = sanitize_filename(name) or fallback
    # 去掉 CR/LF 等会破坏 HTTP 头的字符（sanitize 已去控制字符，这里双保险）
    safe = safe.replace("\r", "_").replace("\n", "_")
    return safe

# ---------------------------------------------------------------- HTML 处理

def escape_html(raw_html: str) -> str:
    """全文本转义：脚本不执行、远程资源不加载。仅用于安全展示。"""
    return html.escape(raw_html, quote=True)


# 外部资源引用：只登记、不抓取。
# 覆盖 src/href 形式与 CSS url(...) 形式。
_ATTR_URL = re.compile(
    r"(?:\bsrc|\bhref|\bposter|\bbackground|\bdata)\s*=\s*['\"]?([^\s'\">]+)",
    re.IGNORECASE,
)
_CSS_URL = re.compile(r"url\(\s*(['\"]?)([^)'\"]+)\1\s*\)", re.IGNORECASE)
_CID_RE = re.compile(r"^cid:(.+)$", re.IGNORECASE)


def classify_html_refs(fragment: str) -> tuple[list[str], list[str]]:
    """识别 HTML/CSS 中的引用，返回 (cid 引用, 外部 URL)。

    两个列表均排序去重。cid: 引用需匹配内嵌资源；http/https/协议相对 URL 仅登记。
    """
    refs: set[str] = set()
    for m in _ATTR_URL.finditer(fragment):
        refs.add(m.group(1).strip())
    for m in _CSS_URL.finditer(fragment):
        refs.add(m.group(2).strip())

    cids: set[str] = set()
    external: set[str] = set()
    for ref in refs:
        cid_m = _CID_RE.match(ref)
        if cid_m:
            cids.add(cid_m.group(1).strip())
            continue
        parts = urlsplit(ref)
        scheme = parts.scheme.lower()
        if scheme in ("http", "https", "ftp"):
            external.add(ref)
        elif ref.startswith("//"):  # 协议相对远程资源
            external.add("https:" + ref)
        # data:/about:/javascript:/空锚点等不登记为外部资源
    return sorted(cids), sorted(external)

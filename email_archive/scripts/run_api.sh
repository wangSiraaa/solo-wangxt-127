#!/usr/bin/env bash
# 启动 API（无前端）。
set -euo pipefail
cd "$(dirname "$0")/.."
export DATABASE_URL="${DATABASE_URL:-postgresql://archive@/emailarchive?host=/tmp}"
export ATTACHMENT_DIR="${ATTACHMENT_DIR:-$(pwd)/var/attachments}"
exec python -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"

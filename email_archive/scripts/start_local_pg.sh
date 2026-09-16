#!/usr/bin/env bash
# 本地开发：启动便携 PostgreSQL（Debian 解包版）。
# 生产环境应使用托管 PostgreSQL，仅通过 DATABASE_URL 指向即可。
set -euo pipefail

PGROOT="${PGROOT:-/tmp/pgroot}"
PGDATA="${PGDATA:-/tmp/pgdata}"
PGSOCK="${PGSOCK:-/tmp}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-archive}"
PGDB="${PGDB:-emailarchive}"

export LD_LIBRARY_PATH="$PGROOT/usr/lib/postgresql/15/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PGBIN="$PGROOT/usr/lib/postgresql/15/bin"

if [ ! -x "$PGBIN/pg_ctl" ]; then
  echo "PostgreSQL binaries not found at $PGBIN" >&2
  exit 1
fi

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  "$PGBIN/initdb" -D "$PGDATA" -U "$PGUSER" --auth=trust --encoding=UTF8 --locale=C
fi

"$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGDATA/server.log" \
  -o "-c unix_socket_directories=$PGSOCK -c listen_addresses=127.0.0.1 -p $PGPORT" start

sleep 1
"$PGBIN/psql" -h "$PGSOCK" -p "$PGPORT" -U "$PGUSER" -d postgres -tc \
  "SELECT 1 FROM pg_database WHERE datname='$PGDB'" | grep -q 1 || \
  "$PGBIN/psql" -h "$PGSOCK" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $PGDB"

echo "PostgreSQL ready: postgresql://$PGUSER@/$PGDB?host=$PGSOCK"

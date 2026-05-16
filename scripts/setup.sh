#!/usr/bin/env bash
# Initialize the SQLite DB, create runtime directories, verify dependencies.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/config/path_monitor.yaml}"

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }
}

need sqlite3
need cmake
need python3

mkdir -p "$ROOT/data" "$ROOT/logs"

DB_PATH="$(python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['database']['path'])" "$CONFIG")"
case "$DB_PATH" in
    /*) ABS_DB="$DB_PATH" ;;
    *)  ABS_DB="$ROOT/$DB_PATH" ;;
esac

mkdir -p "$(dirname "$ABS_DB")"
sqlite3 "$ABS_DB" < "$ROOT/sql/schema.sql"
echo "initialized $ABS_DB"

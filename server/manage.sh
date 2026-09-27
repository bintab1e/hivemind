#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
NODE="$(command -v node || true)"
if [ -z "$NODE" ] || ! "$NODE" -e 'process.exit(process.platform === "linux" && Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)' 2>/dev/null; then
  NODE="$HOME/.local/opt/hivemind-node24/bin/node"
fi
exec "$NODE" "$DIR/manage.mjs" "$@"

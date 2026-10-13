#!/bin/sh
set -eu

agent_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
# The installer still checks that plain HTTP points only to a private LAN host.
HIVEMIND_ALLOW_INSECURE_LAN_HTTP=true
export HIVEMIND_ALLOW_INSECURE_LAN_HTTP
exec bash "$agent_dir/install.sh" "$@"

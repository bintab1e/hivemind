#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${1:-${HIVEMIND_SERVER_URL:-}}"
TRACK="${2:-${HIVEMIND_TRACK:-rc}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${HIVEMIND_AGENT_SOURCE:-$SCRIPT_DIR}"
ROOT="${HIVEMIND_KERNEL_ROOT:-$HOME/workspace/knfsd}"

[[ "$SERVER_URL" =~ ^https?://[^[:space:]]+$ ]] || { echo '서버 URL이 필요합니다 (예: http://<server-ip>:8765).' >&2; exit 1; }
[[ "$TRACK" == rc || "$TRACK" == mainline ]] || { echo '트랙은 rc 또는 mainline이어야 합니다.' >&2; exit 1; }
if [[ "$SERVER_URL" == http://* && "$SERVER_URL" != http://127.0.0.1:* && "$SERVER_URL" != http://localhost:* && "$SERVER_URL" != "http://[::1]:"* ]]; then
  SERVER_HOST="${SERVER_URL#http://}"
  SERVER_HOST="${SERVER_HOST%%[:/]*}"
  if [[ "${HIVEMIND_ALLOW_INSECURE_LAN_HTTP:-false}" != true || ! "$SERVER_HOST" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
    echo '사설망 HTTP는 HIVEMIND_ALLOW_INSECURE_LAN_HTTP=true를 명시해야 합니다.' >&2
    exit 1
  fi
fi
case "$(uname -s)" in
  Linux)
    NODE_PLATFORM=linux
    if ! command -v git >/dev/null || ! command -v tar >/dev/null || ! command -v xz >/dev/null || ! command -v sha256sum >/dev/null || ! command -v curl >/dev/null; then
      if command -v apt-get >/dev/null && command -v sudo >/dev/null; then
        sudo apt-get update
        sudo apt-get install -y git tar xz-utils coreutils ca-certificates curl
      else
        echo 'git, tar, xz, sha256sum, curl을 설치한 뒤 다시 실행하세요.' >&2
        exit 1
      fi
    fi
    ;;
  Darwin)
    NODE_PLATFORM=darwin
    for tool in git tar shasum curl; do
      command -v "$tool" >/dev/null || { echo "$tool이 필요합니다. xcode-select --install을 실행하세요." >&2; exit 1; }
    done
    ;;
  *) echo 'Linux 또는 macOS가 필요합니다. Windows에서는 MANUAL.md를 따르세요.' >&2; exit 1 ;;
esac
curl -fsS "$SERVER_URL/healthz" >/dev/null || { echo "서버에 연결할 수 없습니다: $SERVER_URL" >&2; exit 1; }

if command -v node >/dev/null && node -e 'process.exit(["linux", "darwin"].includes(process.platform) && Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)'; then
  NODE="$(command -v node)"
else
  case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo 'Node.js 24용 x86_64 또는 arm64가 필요합니다.' >&2; exit 1 ;; esac
  if [ "$NODE_PLATFORM" = darwin ]; then
    ARCHIVE_EXT=gz
  else
    ARCHIVE_EXT=xz
  fi
  NODE_DIR="$HOME/.local/opt/hivemind-node24"
  DOWNLOAD="$(mktemp -d)"
  trap 'rm -rf "$DOWNLOAD"' EXIT
  curl -fsS 'https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt' -o "$DOWNLOAD/SHASUMS256.txt"
  ARCHIVE="$(awk -v platform="$NODE_PLATFORM" -v arch="$ARCH" -v ext="$ARCHIVE_EXT" '$2 ~ ("^node-v24[.][0-9]+[.][0-9]+-" platform "-" arch "[.]tar[.]" ext "$") { print $2; exit }' "$DOWNLOAD/SHASUMS256.txt")"
  test -n "$ARCHIVE" || { echo 'Node.js 24 배포 파일을 찾을 수 없습니다.' >&2; exit 1; }
  curl -fsS "https://nodejs.org/dist/latest-v24.x/$ARCHIVE" -o "$DOWNLOAD/$ARCHIVE"
  if [ "$NODE_PLATFORM" = darwin ]; then
    (cd "$DOWNLOAD" && grep -F "  $ARCHIVE" SHASUMS256.txt | shasum -a 256 -c -)
  else
    (cd "$DOWNLOAD" && grep -F "  $ARCHIVE" SHASUMS256.txt | sha256sum -c -)
  fi
  mkdir -p "$NODE_DIR"
  if [ "$NODE_PLATFORM" = darwin ]; then
    tar -xzf "$DOWNLOAD/$ARCHIVE" -C "$NODE_DIR" --strip-components=1
  else
    tar -xJf "$DOWNLOAD/$ARCHIVE" -C "$NODE_DIR" --strip-components=1
  fi
  NODE="$NODE_DIR/bin/node"
  rm -rf "$DOWNLOAD"
  trap - EXIT
fi

TOKEN_FILE="$(mktemp)"
trap 'rm -f "$TOKEN_FILE"' EXIT
if [ -n "${HIVEMIND_TOKEN_FILE:-}" ]; then
  cat < "$HIVEMIND_TOKEN_FILE" > "$TOKEN_FILE"
else
  printf '전달받은 에이전트 토큰: ' >/dev/tty
  IFS= read -rs TOKEN </dev/tty
  printf '\n' >/dev/tty
  printf '%s' "$TOKEN" > "$TOKEN_FILE"
  unset TOKEN
fi
[[ "$(cat "$TOKEN_FILE")" =~ ^[a-fA-F0-9]{64}$ ]] || { echo '64자리 토큰이 필요합니다.' >&2; exit 1; }

read -r VERSION COMMIT < <("$NODE" --input-type=module - "$TOKEN_FILE" "$SERVER_URL" "$TRACK" <<'JS'
import fs from 'node:fs';
const [tokenFile, server, track] = process.argv.slice(2);
const token = fs.readFileSync(tokenFile, 'utf8').trim();
const headers = { Authorization: `Bearer ${token}` };
const health = await fetch(`${server}/v1/sync/health`, { headers });
if (!health.ok) throw new Error(`에이전트 토큰 인증 실패 (${health.status})`);
const response = await fetch(`${server}/mcp`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_versions', arguments: {} } }) });
if (!response.ok) throw new Error(`대상 조회 실패 (${response.status})`);
const payload = await response.json();
const target = payload.result?.structuredContent?.tracks?.find(item => item.track_id === track && item.version_id && item.repo_commit);
if (!target) throw new Error(`${track} 대상이 서버에 등록되지 않았습니다.`);
console.log(target.version_id, target.repo_commit);
JS
)
[[ "$COMMIT" =~ ^[a-fA-F0-9]{40}$ ]] || { echo '서버에서 올바른 커널 커밋을 받지 못했습니다.' >&2; exit 1; }
if [ -z "${HIVEMIND_KERNEL_ROOT:-}" ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ "$(git -C "$ROOT" rev-parse HEAD)" != "$COMMIT" ]; then
  ROOT="$HOME/workspace/knfsd-$TRACK-$VERSION"
fi

if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  test "$(git -C "$ROOT" rev-parse HEAD)" = "$COMMIT" || { echo "기존 커널 체크아웃의 커밋이 $TRACK/$VERSION 과 다릅니다: $ROOT" >&2; exit 1; }
elif [ -e "$ROOT" ] && { [ ! -d "$ROOT" ] || [ -n "$(ls -A "$ROOT")" ]; }; then
  echo "커널 설치 경로에 기존 파일이 있습니다: $ROOT" >&2
  echo "파일을 보존하려면 이 폴더를 다른 이름으로 옮긴 뒤 설치 명령을 다시 실행하세요." >&2
  exit 1
else
  case "$TRACK" in
    rc) KERNEL_SOURCE='https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git' ;;
    mainline) KERNEL_SOURCE='https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' ;;
  esac
  KERNEL_SOURCE="${HIVEMIND_KERNEL_SOURCE:-$KERNEL_SOURCE}"
  mkdir -p "$(dirname "$ROOT")"
  echo "커널 소스 v$VERSION 다운로드 중: $ROOT"
  git clone --depth 1 --branch "v$VERSION" --single-branch "$KERNEL_SOURCE" "$ROOT"
  test "$(git -C "$ROOT" rev-parse HEAD)" = "$COMMIT" || { echo '서버에 등록된 SHA와 내려받은 커널 태그가 다릅니다.' >&2; exit 1; }
fi

EXCLUDE="$(git -C "$ROOT" rev-parse --git-path info/exclude)"
case "$EXCLUDE" in /*) ;; *) EXCLUDE="$ROOT/$EXCLUDE" ;; esac
if ! grep -Fqx '.hivemind/' "$EXCLUDE" 2>/dev/null; then
  printf '\n.hivemind/\n' >> "$EXCLUDE"
fi

AGENT="$ROOT/.hivemind/agent"
if [ -d "$SOURCE" ] && [ -f "$SOURCE/mcp-agent.mjs" ]; then
  if [ ! -e "$AGENT" ]; then
    mkdir -p "$AGENT"
  elif [ ! -f "$AGENT/mcp-agent.mjs" ]; then
    echo "기존 에이전트 폴더에 다른 파일이 있습니다: $AGENT" >&2
    exit 1
  fi
  "$NODE" "$SOURCE/copy-agent.mjs" "$SOURCE" "$AGENT"
elif [[ "$SOURCE" =~ ^https?://|^[^/]+@[^:]+:|^[^/]+:// ]]; then
  if [ -d "$AGENT/.git" ]; then
    git -C "$AGENT" pull --ff-only
  elif [ -e "$AGENT" ]; then
    echo "기존 에이전트 폴더에 다른 파일이 있습니다: $AGENT" >&2
    exit 1
  else
    mkdir -p "$(dirname "$AGENT")"
    git clone --depth 1 "$SOURCE" "$AGENT"
  fi
else
  echo "에이전트 소스를 찾지 못했습니다: $SOURCE" >&2
  exit 1
fi
UV="$AGENT/.local/bin/uv"
if [ ! -x "$UV" ]; then
  mkdir -p "$(dirname "$UV")"
  curl -LsSf 'https://astral.sh/uv/0.12.19/install.sh' | env UV_INSTALL_DIR="$(dirname "$UV")" UV_NO_MODIFY_PATH=1 sh
fi
"$UV" venv --python 3.11 "$AGENT/.venv"
"$UV" pip install --python "$AGENT/.venv/bin/python" -r "$AGENT/requirements.txt"

HIVEMIND_TRACK="$TRACK" "$NODE" "$AGENT/setup.mjs" "$ROOT" "$TOKEN_FILE" "$SERVER_URL"
ID="$(cat "$AGENT/runtime/active-agent-id")"
CONFIG="$AGENT/runtime/agents/$ID.json"
if [ "$NODE_PLATFORM" = darwin ]; then
  PLIST="$HOME/Library/LaunchAgents/org.hivemind.knfsd-agent.plist"
  mkdir -p "$(dirname "$PLIST")"
  "$AGENT/.venv/bin/python" - "$NODE" "$AGENT" "$CONFIG" "$ROOT" "$PLIST" <<'PY'
import os, pathlib, plistlib, sys
node, agent, config, root, plist = sys.argv[1:]
pathlib.Path(plist).write_bytes(plistlib.dumps({
    "Label": "org.hivemind.knfsd-agent",
    "ProgramArguments": [node, f"{agent}/sync-agent.mjs", config],
    "WorkingDirectory": root,
    "RunAtLoad": True,
    "KeepAlive": True,
    "ThrottleInterval": 10,
    "EnvironmentVariables": {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    "StandardOutPath": f"{agent}/runtime/sync.log",
    "StandardErrorPath": f"{agent}/runtime/sync.log",
}))
PY
  launchctl bootout "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  launchctl kickstart -k "gui/$(id -u)/org.hivemind.knfsd-agent"
  echo '동기화 서비스: launchctl print gui/$(id -u)/org.hivemind.knfsd-agent'
elif systemctl --user show-environment >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/hivemind-agent.service" <<EOF
[Unit]
Description=Hivemind analysis agent ($ID)

[Service]
WorkingDirectory=$ROOT
ExecStart=$NODE $AGENT/sync-agent.mjs $CONFIG
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now hivemind-agent
  systemctl --user restart hivemind-agent
  echo '동기화 서비스: systemctl --user status hivemind-agent'
else
  nohup "$NODE" "$AGENT/sync-agent.mjs" "$CONFIG" > "$AGENT/runtime/sync.log" 2>&1 </dev/null &
  echo $! > "$AGENT/runtime/sync.pid"
  echo "동기화 로그: $AGENT/runtime/sync.log (WSL 종료 시 다시 실행 필요)"
fi
echo "완료: $ID / $TRACK / $VERSION / $ROOT"
echo '이 커널 폴더에서 새 Codex/Claude 세션을 여세요.'
echo 'Codex: 프로젝트와 /hooks의 AgentCov PostToolUse 명령을 검토하고 신뢰하세요.'
echo 'Claude: 프로젝트 .mcp.json의 knfsd_hivemind 서버를 검토하고 승인하세요.'

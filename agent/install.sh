#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${HIVEMIND_SERVER_URL:-http://192.168.1.188:8765}"
SOURCE="${HIVEMIND_AGENT_SOURCE:-https://github.com/bintab1e/hivemind-agent.git}"

command -v git >/dev/null || { echo 'git이 필요합니다.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl이 필요합니다.' >&2; exit 1; }
if [ -d "$HOME/workspace/knfsd" ]; then
  ROOT="$(git -C "$HOME/workspace/knfsd" rev-parse --show-toplevel 2>/dev/null)" || { echo '~/workspace/knfsd가 커널 Git 체크아웃이 아닙니다.' >&2; exit 1; }
else
  ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo '커널 Git 체크아웃 안에서 실행하세요.' >&2; exit 1; }
fi
AGENT="$ROOT/.hivemind/agent"
curl -fsS "$SERVER_URL/healthz" >/dev/null || { echo "서버에 연결할 수 없습니다: $SERVER_URL" >&2; exit 1; }

if [ -d "$AGENT/.git" ]; then
  git -C "$AGENT" pull --ff-only
elif [ -e "$AGENT" ]; then
  echo "기존 에이전트 폴더가 있습니다: $AGENT (수동으로 백업하거나 정리하세요)" >&2
  exit 1
else
  mkdir -p "$(dirname "$AGENT")"
  git clone --depth 1 "$SOURCE" "$AGENT"
fi

if command -v node >/dev/null && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)'; then
  NODE="$(command -v node)"
else
  case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo 'Node.js 24용 x86_64 또는 aarch64가 필요합니다.' >&2; exit 1 ;; esac
  NODE_DIR="$AGENT/.local/node24"
  mkdir -p "$NODE_DIR"
  DOWNLOAD="$(mktemp -d)"
  trap 'rm -rf -- "$DOWNLOAD"' EXIT
  curl -fsS 'https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt' -o "$DOWNLOAD/SHASUMS256.txt"
  ARCHIVE="$(awk -v arch="$ARCH" '$2 ~ ("^node-v24[.][0-9]+[.][0-9]+-linux-" arch "[.]tar[.]xz$") { print $2; exit }' "$DOWNLOAD/SHASUMS256.txt")"
  test -n "$ARCHIVE" || { echo 'Node.js 24 배포 파일을 찾을 수 없습니다.' >&2; exit 1; }
  curl -fsS "https://nodejs.org/dist/latest-v24.x/$ARCHIVE" -o "$DOWNLOAD/$ARCHIVE"
  (cd "$DOWNLOAD" && grep -F "  $ARCHIVE" SHASUMS256.txt | sha256sum -c -)
  tar -xJf "$DOWNLOAD/$ARCHIVE" -C "$NODE_DIR" --strip-components=1
  NODE="$NODE_DIR/bin/node"
  rm -rf -- "$DOWNLOAD"
  trap - EXIT
fi

UV="$AGENT/.local/bin/uv"
if [ ! -x "$UV" ]; then
  mkdir -p "$(dirname "$UV")"
  curl -LsSf 'https://astral.sh/uv/0.12.19/install.sh' | env UV_INSTALL_DIR="$(dirname "$UV")" UV_NO_MODIFY_PATH=1 sh
fi
"$UV" venv --python 3.11 "$AGENT/.venv"
"$UV" pip install --python "$AGENT/.venv/bin/python" -r "$AGENT/requirements.txt"

TOKEN_FILE="$(mktemp)"
trap 'rm -f -- "$TOKEN_FILE"' EXIT
printf '전달받은 에이전트 토큰: ' >/dev/tty
IFS= read -rs TOKEN </dev/tty
printf '\n' >/dev/tty
[[ "$TOKEN" =~ ^[a-fA-F0-9]{64}$ ]] || { echo '64자리 토큰이 필요합니다.' >&2; exit 1; }
printf '%s' "$TOKEN" > "$TOKEN_FILE"
unset TOKEN
"$NODE" "$AGENT/setup.mjs" "$ROOT" "$TOKEN_FILE" "$SERVER_URL"

ID="$(cat "$AGENT/runtime/active-agent-id")"
CONFIG="$AGENT/runtime/agents/$ID.json"
if systemctl --user show-environment >/dev/null 2>&1; then
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
echo "완료. $ROOT 에서 새 Codex 세션을 열고 프로젝트와 훅을 신뢰하세요."

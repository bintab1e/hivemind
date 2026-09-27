#!/usr/bin/env bash
set -euo pipefail

REPO="${HIVEMIND_SERVER_DIR:-$HOME/Desktop/workspace/hivemind-server}"
SOURCE="${HIVEMIND_SERVER_SOURCE:-https://github.com/bintab1e/hivemind-server.git}"

if ! command -v git >/dev/null || ! command -v curl >/dev/null || ! command -v xz >/dev/null; then
  if command -v apt-get >/dev/null && command -v sudo >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y ca-certificates git curl xz-utils
  else
    echo 'git, curl, xz를 설치한 뒤 다시 실행하세요.' >&2
    exit 1
  fi
fi
for command in tar sha256sum systemctl; do command -v "$command" >/dev/null || { echo "$command 가 필요합니다." >&2; exit 1; }; done

if [ -d "$REPO/.git" ]; then
  git -C "$REPO" pull --ff-only
elif [ -e "$REPO" ]; then
  echo "이미 다른 파일이 있는 설치 경로입니다: $REPO" >&2
  exit 1
else
  mkdir -p "$(dirname "$REPO")"
  git clone --depth 1 "$SOURCE" "$REPO"
fi

if command -v node >/dev/null && node -e 'process.exit(process.platform === "linux" && Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)'; then
  NODE="$(command -v node)"
else
  case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo 'Node.js 24용 x86_64 또는 aarch64가 필요합니다.' >&2; exit 1 ;; esac
  NODE_DIR="$HOME/.local/opt/hivemind-node24"
  DOWNLOAD="$(mktemp -d)"
  trap 'rm -rf -- "$DOWNLOAD"' EXIT
  curl -fsS 'https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt' -o "$DOWNLOAD/SHASUMS256.txt"
  ARCHIVE="$(awk -v arch="$ARCH" '$2 ~ ("^node-v24[.][0-9]+[.][0-9]+-linux-" arch "[.]tar[.]xz$") { print $2; exit }' "$DOWNLOAD/SHASUMS256.txt")"
  test -n "$ARCHIVE" || { echo 'Node.js 24 배포 파일을 찾을 수 없습니다.' >&2; exit 1; }
  curl -fsS "https://nodejs.org/dist/latest-v24.x/$ARCHIVE" -o "$DOWNLOAD/$ARCHIVE"
  (cd "$DOWNLOAD" && grep -F "  $ARCHIVE" SHASUMS256.txt | sha256sum -c -)
  mkdir -p "$NODE_DIR"
  tar -xJf "$DOWNLOAD/$ARCHIVE" -C "$NODE_DIR" --strip-components=1
  NODE="$NODE_DIR/bin/node"
fi

CONFIG_DIR="$HOME/.config/hivemind"
mkdir -p "$CONFIG_DIR" "$HOME/.config/systemd/user"
chmod 700 "$CONFIG_DIR"
if [ ! -s "$CONFIG_DIR/server.env" ]; then
  umask 077
  printf 'HIVEMIND_DASHBOARD_PASSWORD=%s\n' "$("$NODE" -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('hex'))")" > "$CONFIG_DIR/server.env"
fi
chmod 600 "$CONFIG_DIR/server.env"
cat > "$HOME/.config/systemd/user/hivemind.service" <<EOF
[Unit]
Description=knfsd Hivemind server

[Service]
Type=simple
WorkingDirectory=$REPO/server
ExecStart=$NODE $REPO/server/server.mjs
Environment=HIVEMIND_HOST=0.0.0.0
EnvironmentFile=$CONFIG_DIR/server.env
UMask=0077
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now hivemind
systemctl --user restart hivemind
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:8765/healthz >/dev/null; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8765/healthz >/dev/null || { journalctl --user -u hivemind -n 30 --no-pager >&2; exit 1; }

if command -v loginctl >/dev/null && command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
  sudo loginctl enable-linger "$USER"
fi

LAN_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^192[.]168[.]/ { print; exit }')"
LAN_IP="${LAN_IP:-$(hostname -I 2>/dev/null | awk '{ print $1 }')}"
echo "서버 설치 완료: $REPO"
echo "대시보드: http://${LAN_IP:-SERVER_IP}:8765/ (계정 viewer)"
echo "대시보드 비밀번호: $(sed -n 's/^HIVEMIND_DASHBOARD_PASSWORD=//p' "$CONFIG_DIR/server.env")"
echo "최신 RC·stable 대상 등록: bash '$REPO/server/manage.sh' setup"
echo "분석 PC를 연결할 때만 토큰 발급 (jinpyo를 이름으로 교체): bash '$REPO/server/manage.sh' agent add jinpyo rc"
if ! loginctl show-user "$USER" -p Linger --value 2>/dev/null | grep -qx yes; then
  echo "로그아웃 후에도 유지하려면 한 번 실행: sudo loginctl enable-linger '$USER'"
fi

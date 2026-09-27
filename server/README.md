# Hivemind 중앙 서버 (Linux)

이 `server/` 폴더만 Linux 서버에 복사하면 웹 대시보드, SQLite 저장소, 기록 API가 실행됩니다. **커널 소스와 agentcov는 서버에 설치하지 않습니다.** Node.js 24 이상이 필요하며 npm 설치 단계는 없습니다. 분석 PC 설정은 별도 배포하는 에이전트 패키지의 README를 따릅니다.

준비물: 서버에 접속할 일반 사용자 계정, SSH, `curl`, `tar`, `xz`, `sha256sum`. 아래 명령은 Bash와 systemd가 있는 Linux에서 실행합니다. Debian/Ubuntu에서 `curl`이나 `xz`가 없으면 `sudo apt-get update && sudo apt-get install -y ca-certificates curl xz-utils`로 설치합니다. `server/` 외의 Hivemind 파일은 필요하지 않습니다.

## 0. 받은 폴더와 Node.js 설치

받은 `server/` 폴더가 `~/Downloads/server`에 있다고 가정합니다. 다른 위치라면 첫 줄만 바꿉니다. 이미 `~/hivemind-server`에 놓았다면 복사 명령은 건너뜁니다.

```bash
set -euo pipefail
RECEIVED_SERVER_DIR="$HOME/Downloads/server"
SERVER_DIR="$HOME/hivemind-server"
test -f "$RECEIVED_SERVER_DIR/server.mjs"
mkdir -p "$SERVER_DIR"
cp -a "$RECEIVED_SERVER_DIR/." "$SERVER_DIR/"
cd "$SERVER_DIR"
```

Node.js 24 이상이 없다면 [공식 Linux 바이너리](https://nodejs.org/download/release/latest-v24.x/)를 사용자 홈에 설치합니다. 아래 블록은 glibc Linux의 `x86_64`와 `aarch64` 기준이며, 이미 24 이상이면 건너뜁니다.

```bash
case "$(uname -m)" in x86_64) NODE_ARCH=x64 ;; aarch64) NODE_ARCH=arm64 ;; *) echo '지원하지 않는 CPU: Node.js 24 설치를 확인하세요' >&2; exit 1 ;; esac
NODE_URL='https://nodejs.org/dist/latest-v24.x'
NODE_DOWNLOAD="$HOME/.cache/hivemind-node24"
mkdir -p "$NODE_DOWNLOAD" "$HOME/.local/opt/node24"
cd "$NODE_DOWNLOAD"
curl -fsSLO "$NODE_URL/SHASUMS256.txt"
NODE_ARCHIVE="$(awk -v arch="$NODE_ARCH" '$2 ~ ("^node-v24[.][0-9]+[.][0-9]+-linux-" arch "[.]tar[.]xz$") { print $2; exit }' SHASUMS256.txt)"
test -n "$NODE_ARCHIVE"
curl -fsSLO "$NODE_URL/$NODE_ARCHIVE"
grep -F "  $NODE_ARCHIVE" SHASUMS256.txt | sha256sum -c -
tar -xJf "$NODE_ARCHIVE" -C "$HOME/.local/opt/node24" --strip-components=1
export PATH="$HOME/.local/opt/node24/bin:$PATH"
grep -Fq '.local/opt/node24/bin' "$HOME/.profile" 2>/dev/null || printf '%s\n' 'export PATH="$HOME/.local/opt/node24/bin:$PATH"' >> "$HOME/.profile"
node --version
```

다른 방법으로 설치했다면 위 다운로드 블록을 건너뛰고 다음 실행 명령의 버전 검사를 통과하면 됩니다.

## 1. 서버 시작

같은 SSH 세션에서 실행합니다. 첫 실행 시 `runtime/server/`에 DB와 관리자 토큰이 생성됩니다.

```bash
cd "$HOME/hivemind-server"
node --version                   # v24 이상
node -e 'if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)'
node server.mjs                  # 첫 확인: 이 터미널이 서버를 유지
```

다른 터미널에서 확인합니다.

```bash
curl -fsS http://127.0.0.1:8765/healthz
```

`{"ok":true}`가 나오면 `Ctrl+C`로 임시 서버를 종료하고, 계속 운영할 때는 다음 사용자 systemd 서비스로 실행합니다.

```bash
cd "$HOME/hivemind-server"
NODE_BIN="$(command -v node)"
SERVER_DIR="$(pwd)"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/hivemind.service" <<EOF
[Unit]
Description=knfsd Hivemind

[Service]
Type=simple
WorkingDirectory=$SERVER_DIR
ExecStart=$NODE_BIN $SERVER_DIR/server.mjs
Environment=HIVEMIND_HOST=127.0.0.1
UMask=0077
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now hivemind
curl -fsS http://127.0.0.1:8765/healthz
```

SSH에서 로그아웃한 뒤에도 사용자 서비스를 유지하려면 관리자가 `sudo loginctl enable-linger "$USER"`를 한 번 실행합니다. 로그는 `journalctl --user -u hivemind -f`로 확인합니다. 데이터와 관리자 토큰은 `runtime/server/`에 생기며 이 폴더는 Git에서 제외됩니다. DB를 백업할 때는 `systemctl --user stop hivemind`로 멈춘 뒤 `runtime/server/` 전체를 복사하고 다시 시작합니다. 기본 서버는 `127.0.0.1`에만 바인딩하므로 분석 PC와 대시보드는 SSH 터널을 사용합니다.

같은 사설망에서 터널 없이 쓰려면 서버를 내부망에 바인딩하고 대시보드 비밀번호를 설정합니다. `HIVEMIND_HOST=0.0.0.0`은 서버의 모든 네트워크 인터페이스에서 대기하므로 방화벽에서 8765/tcp를 팀 내부망으로 제한하세요. 공유기 포트 포워딩은 하지 않습니다.

```bash
mkdir -p "$HOME/.config/hivemind" "$HOME/.config/systemd/user/hivemind.service.d"
umask 077
node -e "process.stdout.write('HIVEMIND_DASHBOARD_PASSWORD=' + require('node:crypto').randomBytes(24).toString('hex') + '\n')" > "$HOME/.config/hivemind/server.env"
cat > "$HOME/.config/systemd/user/hivemind.service.d/lan.conf" <<'EOF'
[Service]
Environment=HIVEMIND_HOST=0.0.0.0
EnvironmentFile=%h/.config/hivemind/server.env
EOF
systemctl --user daemon-reload
systemctl --user restart hivemind
hostname -I
```

분석 PC의 에이전트 JSON에는 `server_url`로 `http://서버_내부_IP:8765`, `allow_insecure_lan_http`로 `true`를 설정합니다. 대시보드 로그인 이름은 `viewer`, 비밀번호는 서버의 `~/.config/hivemind/server.env`에 있습니다. HTTP에서는 에이전트 토큰, 대시보드 비밀번호, 분석 내용이 암호화되지 않습니다. 신뢰할 수 없는 네트워크나 인터넷을 통과한다면 HTTPS 또는 SSH 터널을 사용하세요.

## 2. RC·stable 대상 등록

각 대상의 Linux 체크아웃에서 `git rev-parse HEAD`로 구한 **전체 SHA**를 입력합니다. 서버에는 커널 체크아웃이 필요하지 않습니다. 첫 분석 PC가 소스를 받은 뒤 SHA를 관리자에게 전달하면 됩니다. 다음 명령을 `rc`와 `mainline` 각각 한 번 실행합니다. `mainline`은 대시보드에서 stable을 나타내는 내부 ID입니다.

```bash
cd "$HOME/hivemind-server"
ADMIN_TOKEN="$(cat runtime/server/api-token.txt)"
TRACK='rc'                         # stable은 mainline
VERSION='7.3-rc4'                  # 설치할 때 실제 대상 버전으로 변경
COMMIT='FULL_GIT_COMMIT_SHA'       # 분석 PC의 git rev-parse HEAD 결과
[[ "$COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || { echo '40자리 Git SHA가 필요합니다' >&2; exit 1; }
curl -fsS -X PUT "http://127.0.0.1:8765/v1/admin/tracks/$TRACK" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"version_id\":\"$VERSION\",\"repo_commit\":\"$COMMIT\"}"
```

등록 확인:

```bash
curl -fsS http://127.0.0.1:8765/v1/admin/tracks \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

새 릴리스가 나오면 해당 트랙의 버전·SHA를 다시 등록하고 분석 PC는 새 체크아웃으로 옮깁니다.

## 3. 분석 LLM마다 토큰 발급

`AGENT_ID`는 PC와 LLM 조합마다 다르게 정합니다. 토큰은 발급 시 한 번만 반환됩니다. 아래 명령은 서버의 `runtime/agents/`에 해당 에이전트 토큰을 저장합니다.

```bash
set -euo pipefail
cd "$HOME/hivemind-server"
ADMIN_TOKEN="$(cat runtime/server/api-token.txt)"
AGENT_ID='pc01-codex'
mkdir -p runtime/agents
TOKEN_FILE="runtime/agents/$AGENT_ID.token"
test ! -e "$TOKEN_FILE" || { echo '토큰 파일이 이미 있습니다' >&2; exit 1; }
umask 077
TOKEN_JSON="$(curl -fsS -X POST http://127.0.0.1:8765/v1/admin/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AGENT_ID\"}")"
TOKEN="$(printf '%s' "$TOKEN_JSON" | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).token')"
printf '%s' "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
unset TOKEN TOKEN_JSON
```

팀원마다 다른 `AGENT_ID`로 위 블록을 반복합니다. 발급한 **그 팀원 ID의 `.token` 파일 하나**를 안전한 파일 전달 수단으로 해당 팀원에게 보냅니다. 팀원은 토큰을 `~/Downloads/<agent-id>.token`(Windows도 다운로드 폴더) 또는 본인에게만 전달된 `agent/runtime/agents/<agent-id>.token`에 둡니다. **공유 GitHub 저장소의 `agent/`에는 토큰을 넣지 않습니다.** 서버의 SSH 계정을 공유해 토큰을 직접 꺼내게 할 필요는 없습니다. `runtime/server/api-token.txt`는 관리자 토큰이므로 서버에서만 보관합니다. 기존 ID의 토큰 교체는 `PUT /v1/admin/agents/<agent_id>`로 발급한 뒤 팀원의 토큰 파일도 교체합니다.

팀원이 연결한 뒤 마지막 수신 시각을 확인합니다.

```bash
curl -fsS http://127.0.0.1:8765/v1/admin/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## 4. 대시보드 연결

분석 PC 또는 관리자 PC에서 별도 터미널을 열고 유지합니다.

```bash
ssh -N -L 8765:127.0.0.1:8765 user@SERVER_HOST
```

그 PC의 브라우저에서 <http://127.0.0.1:8765/>를 엽니다. 로컬 8765 포트가 사용 중이면 `-L 18765:127.0.0.1:8765`를 쓰고 에이전트의 `server_url`도 `http://127.0.0.1:18765`로 바꿉니다.

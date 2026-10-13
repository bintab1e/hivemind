# Hivemind 서버

`server/`는 대시보드, 에이전트 MCP/API, 코드 열람 커버리지와 취약점 관리 기능을 제공합니다. Node.js **24 이상**의 내장 `node:sqlite`를 사용하며 별도 npm 설치는 필요하지 않습니다.

## 배포 원칙

Git 체크아웃에는 코드만 둡니다. SQLite DB, 과거 첨부파일, AgentCov 전송 기록, 관리자 토큰, 대시보드 인증 파일과 API 키는 **체크아웃 밖의 접근 제한된 데이터 디렉터리**에 보관합니다. 기존 서버를 Git 버전으로 전환할 때 기존 데이터 디렉터리를 복사·초기화하지 말고 서비스의 `HIVEMIND_DATA_DIR`을 현재 경로로 유지하세요. `dashboard reset`은 기존 로그인 정보를 바꾸므로 새 설치 때에만 사용합니다.

새 빈 경로에 저장소를 체크아웃한 다음 서버 코드를 실행합니다.

```bash
git clone git@github.com:bintab1e/hivemind.git /path/to/hivemind
cd /path/to/hivemind
NODE=/absolute/path/to/node24
export HIVEMIND_DATA_DIR=/absolute/private/data-directory
"$NODE" server/manage-local.mjs status
```

새 설치일 때만 데이터 디렉터리를 `0700`으로 만들고 `"$NODE" server/manage-local.mjs dashboard reset`으로 최초 계정을 발급합니다. 이 명령이 화면에 한 번 표시하는 비밀번호는 비밀 관리 도구에 보관하고 셸 기록·Git·이슈에 남기지 마세요. 기존 설치의 `dashboard-auth.env`와 DB는 그대로 사용합니다.

## 서비스 실행

사용자 systemd 서비스에서 다음 값을 실제 절대 경로와 사설망 주소로 바꿔 설정합니다. `EnvironmentFile`은 체크아웃 밖의 기존 `dashboard-auth.env`를 가리킵니다.

```ini
[Unit]
Description=Hivemind server

[Service]
Type=simple
WorkingDirectory=/path/to/hivemind
ExecStart=/absolute/path/to/node24 /path/to/hivemind/server/server.mjs
Environment=HIVEMIND_HOST=SERVER_LAN_IP
Environment=HIVEMIND_PORT=8765
Environment=HIVEMIND_DATA_DIR=/absolute/private/data-directory
EnvironmentFile=/absolute/private/data-directory/dashboard-auth.env
UMask=0077
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

현재 공용 서버는 사용자 서비스 `knfsd-hub`로 운영합니다. 서비스 파일 변경 후 `systemctl --user daemon-reload`와 `systemctl --user restart knfsd-hub`를 실행하고 `curl -fsS http://SERVER_LAN_IP:8765/healthz`로 확인합니다. 인터넷 포트 포워딩은 사용하지 않습니다. 이 배포 절차는 방화벽 설정을 변경하지 않습니다.

## 관리 명령

관리 명령에도 서비스와 같은 `HIVEMIND_DATA_DIR`을 지정해야 합니다. 에이전트 토큰은 PC별로 발급되며 명령 실행 시 한 번만 표시됩니다.

```bash
export HIVEMIND_DATA_DIR=/absolute/private/data-directory
NODE=/absolute/path/to/node24
"$NODE" server/manage-local.mjs status
"$NODE" server/manage-local.mjs track set rc KERNEL_VERSION 40_CHAR_COMMIT_SHA
"$NODE" server/manage-local.mjs agent add pc01
"$NODE" server/manage-local.mjs agent rotate pc01
```

기존 취약점 관리표와 첨부 이관에는 `registry import-history`, `registry reconcile-history`, `registry import-artifacts`, `registry curate-artifacts` 명령이 있습니다. 원본 자료와 스테이징 파일은 Git에 추가하지 마세요. Kimi 정적 검토를 사용할 경우 런타임 환경에서만 `KIMI_API_KEY`를 주입합니다. 키가 없으면 검토는 `unconfigured` 상태로 남습니다. Sashiko 패치 검토는 기본적으로 비활성화되어 있습니다.

## 테스트

```bash
node --test server/*.test.mjs server/public/*.test.mjs
```

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

커버리지 업로드는 기존 전체 줄 LCOV와 열람 줄만 담은 `hivemind-sparse-v1` 형식을 모두 받습니다. 새 형식의 미열람 줄은 파일별 전체 줄 수에서 복원하므로 커버리지 계산은 동일합니다. SQLite에는 에이전트·버전·커밋별 최신 배치와 최신 clean 배치만 남깁니다. 따라서 삭제된 예전 배치 ID의 원본 다운로드는 제공되지 않습니다. 이전 버전에서 이미 저장된 기록은 업로드가 들어온 그룹부터 정리되며, SQLite 파일 크기 회수는 별도의 백업·점검 후 유지보수 시간에 진행해야 합니다.

새 제보의 Codex 정적 검토와 QEMU 2 VM 검증은 별도 `bintable` 사용자 서비스에서 실행합니다. 웹 서버의 전용 Unix 소켓 설정, VM 이미지 설치와 워커 실행 절차는 [검증 워커 배포 문서](verifier/README.md)를 따릅니다. 검증 워커가 준비되지 않았을 때 새 제보는 대기열에 남고 취약점 관리 번호가 발급되지 않습니다.

## 웹에서 ZIP으로 직접 제출

대시보드의 **신규 취약점**에서 제보자 표시명, 취약점 명, 활성 커널 트랙을 선택하고 ZIP을 제출할 수 있습니다. 공유 대시보드 계정을 사용하므로 표시명은 본인이 입력한 이름이며 신원 인증 정보는 아닙니다. 접수된 내용은 **검증 큐**로 이동하고, 승인된 제보만 관리 번호를 받아 신규 취약점과 취약점 관리 표에 나타납니다.

ZIP에는 UTF-8 분석 보고서(`.md`, `.txt`, `.rst`), 독립 실행형 사용자 공간 C PoC, 별도 재현 절차(`.md` 또는 `.sh`), 실제 KASAN/KCSAN `.log`를 포함합니다. 파일명과 원본 구성은 달라도 되지만 Python 단독 PoC는 승인 대상이 아닙니다. 보고서나 증거에는 `fs/nfsd/...` 또는 `net/sunrpc/...`와 같은 커널 소스 경로를 명시해야 합니다. 현재 2 VM 실행기는 C PoC에 서버 IP와 NFS 마운트 경로를 인수로 넘깁니다. 추가 설치 스크립트와 보조 파일은 실행하지 않습니다. KCSAN 로그는 접수할 수 있으나 현재 자동 승인은 서버 VM의 PoC 이후 KASAN read/write 재현과 소스 연계가 필요합니다.

검증에 성공하면 서버는 원본 자료를 보존하면서 `report.md`, `poc.c`, `reproduction.md`, `kasan.log` 네 파일을 표준 결과물로 저장합니다. `report.md`는 `Summary` → `Root cause` → `Reproduction environment` → `PoC` → `Impact analysis` 다섯 절을 쓰고, `Root cause`에 검증한 커널 소스 조각을 포함합니다. 관리 표의 제목·권한·단일 NFS 버전·취약점 유형은 Codex 검토와 2 VM 결과를 대조해 정리합니다. 영향 체크는 독립적으로 관찰된 항목만 기록하며, 한 건에서 여러 항목이 입증되면 모두 표시합니다. 현재 자동 체크 대상은 KASAN Read/Write이고 Controlled Read/Write, LPE, RCE, Info Leak은 주장만으로 체크하지 않습니다.

ZIP은 최대 8 MB이며, 서버는 압축 해제 크기와 정적 검토 입력 크기를 별도로 제한합니다. 경로 탈출, 심볼릭 링크, 암호화·중첩 압축 파일, 지원하지 않는 바이너리 자료는 접수 단계에서 거절합니다. 원본 ZIP은 보관하지 않고 검증에 필요한 텍스트만 기존 비공개 SQLite 제출 큐에 저장합니다.

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

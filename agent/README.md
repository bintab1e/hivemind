# Hivemind 분석 에이전트

Linux·macOS·Windows WSL 분석 PC에서는 이 비공개 저장소의 `agent/`만 받은 다음 설치기를 실행합니다. 팀원별 토큰은 서버 관리자가 따로 발급하며, 설치기가 터미널에서 숨김 입력으로 받습니다. GitHub 인증은 각 PC의 SSH 키 또는 GitHub CLI로 설정하고, 저장소 URL이나 명령줄에 토큰을 넣지 마세요.

```bash
git clone --filter=blob:none --sparse git@github.com:bintab1e/hivemind.git
cd hivemind
git sparse-checkout set agent
HIVEMIND_ALLOW_INSECURE_LAN_HTTP=true sh agent/setup.sh 'http://<server-ip>:8765' rc
```

`<server-ip>`를 운영 서버 주소로 바꾸세요. `mainline` 에이전트는 마지막 인수를 `mainline`으로 사용합니다. 설치 전에 서버 관리자로부터 본인 PC의 에이전트 토큰을 받아야 합니다. 서버 주소는 설치 인자로만 전달하며, 토큰 값은 명령 기록에 남기지 않습니다. HTTP에서는 토큰과 보고서가 암호화되지 않으므로 서버 포트는 팀 사설망에서만 열어야 합니다.

설치기가 Node.js 24, Python 3.11, 고정 버전 AgentCov, 커널 Git 소스와 프로젝트별 Codex MCP·훅을 구성합니다. 커널은 서버에 등록된 공식 태그를 `~/workspace/knfsd`에 내려받고 SHA를 확인합니다. 빈 `knfsd` 폴더는 그대로 사용하고, 기존 체크아웃의 SHA가 다르면 새 버전 전용 폴더에 받습니다. Git 저장소가 아닌 파일이 들어 있는 `knfsd` 폴더는 보존을 위해 설치를 멈춥니다. 사용자가 미리 커널 소스를 내려받거나 JSON 설정을 만들 필요가 없습니다. Ubuntu/WSL에서는 빠진 Git·tar·xz 등도 설치합니다.

설치가 끝나면 출력된 커널 폴더에서 **새 Codex/Claude 세션**을 여세요. Codex에서는 프로젝트와 `/hooks`에 표시되는 AgentCov `PostToolUse` 명령을 확인하고 신뢰해야 실제 열람이 기록됩니다. Claude에서는 프로젝트 `.mcp.json`의 서버를 확인·승인하세요. Claude Code의 코드 열람은 같은 체크아웃의 세션 기록에서 동기화 에이전트가 AgentCov로 가져옵니다. Windows에서 WSL에 설치했다면 Codex/Claude도 **같은 WSL 커널 체크아웃에서 실행**해야 WSL AgentCov에 열람이 잡힙니다. 네이티브 Windows 도구는 [수동 설치](MANUAL.md)가 필요합니다.

stdio MCP의 `submit_vulnerability`는 원본 자료를 서버 검증 대기열로 보냅니다. 분석 에이전트의 **새 제출 규격**은 [`templates/report.md`](templates/report.md)를 채운 `report.md`, 독립 사용자 공간 C PoC `poc.c`, `reproduction.md` 또는 `reproduce.sh`, 실제 수집한 KASAN/KCSAN `.log` 한 개 이상입니다. 보고서의 2단계 제목은 `Summary` → `Root cause` → `Reproduction environment` → `PoC` → `Impact analysis` 순서로 유지합니다. `Root cause`에는 대상 커밋의 실제 C 소스 조각과 경로·함수·줄 번호를 인용합니다. `PoC` 절은 C 코드의 의도와 관찰을 설명하고, 재현 파일에는 두 VM의 조건과 빌드·실행 명령을 적습니다. 로그가 없다면 지어내거나 다른 실행의 로그를 재사용하지 말고 증거를 수집한 뒤 제출하세요.

파일은 커널 체크아웃 또는 에이전트 `runtime/evidence/` 안에 두고 `files`에 `{ "path": "...", "kind": "poc" }` 형식으로 지정합니다. `report.md`는 `report`, `poc.c`는 `poc`, `reproduction.md`/`reproduce.sh`는 `other`, `.log`는 `log`로 지정합니다. 원본 형식이 다른 자료도 서버는 접수해 검증 과정에서 정규화하지만, 분석 에이전트는 위 규격으로 보냅니다. 파일은 최대 20개, 각 2 MB, 보고서 포함 총 8 MB입니다. 전송 실패 시 원본은 로컬 전용 outbox에 남고 동기화 에이전트가 같은 `client_submission_id`로 재전송합니다. 토큰·키·개인 경로는 첨부하지 마세요. 서버 검증과 2 VM 재현이 끝나기 전에는 취약점으로 확정되지 않습니다.

이전 버전에서 `exchange/outbox/`에 작성한 finding Markdown은 자동 제출하지 않고 원본을 보존합니다. 검증에 필요한 PoC·로그를 확인한 뒤 `submit_vulnerability`로 다시 제출하세요.

동기화 에이전트는 `fs/nfsd/`, `fs/nfs/`, `fs/nfs_common/`, `fs/lockd/`, `fs/exportfs/`, `net/sunrpc/`와 로컬 include 의존성 범위의 LCOV와 요약 JSON을 5분마다 보냅니다. 이 범위 외 KNFSD 실행 의존성은 모든 에이전트의 `coverage_prefixes`에 동일하게 추가하세요. 세션 원문·분석 PC의 절대 경로·로컬 자유 형식 진행 메모는 전송하지 않습니다. 로컬 telemetry 배치는 최신 1개만 유지합니다. Linux에서는 `systemctl --user status hivemind-agent`, macOS에서는 `launchctl print gui/$(id -u)/org.hivemind.knfsd-agent`로 동기화 상태를 확인합니다.

`list_findings`와 `get_coverage_gaps`로 기존 보고와 조사 공백을 확인합니다. 신규 후보는 `submit_vulnerability`에 확인한 내용과 위 네 종류의 원본 자료를 보내세요. 제목은 `영향받는 기능 + 원인 + 결과`로 짧고 중립적으로 씁니다. 정정 자료도 새 제출로 보내고 이전 `submission_id`를 보고서 `Summary`에 명시하세요. **코드 열람률은 검증 결과가 아닙니다.**

`metadata`에는 확인한 `file_path`, `code_refs`, `options`, `permission`, `nfs_version`, `vulnerability_type`, `found_date`(YYYY-MM-DD), `reproduction_command`, `vm_environment`, `access_requirements`, `claimed_impacts`를 같은 키로 넣습니다. `claimed_impacts`는 `kasan_read`, `kasan_write`, `controlled_read`, `controlled_write`, `lpe`, `rce`, `info_leak`의 배열이며, 중복으로 입증된 영향은 각각 넣습니다. KASAN 로그만으로 controlled read/write나 LPE/RCE를 추정해 넣지 마세요. 이 값은 제출자의 주장으로 서버 검증 전에는 대시보드 체크가 되지 않습니다. 최종 권한·NFS 버전·유형·영향 체크, 관리 번호와 제보 상태는 서버가 근거에 따라 결정합니다.

네이티브 Windows 수동 설치: [MANUAL.md](MANUAL.md). 중앙 서버 운영: [server/README.md](../server/README.md).

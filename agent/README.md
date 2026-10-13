# Hivemind 분석 에이전트

Linux·macOS·Windows WSL 분석 PC에서는 이 비공개 저장소의 `agent/`만 받은 다음 설치기를 실행합니다. 팀원별 토큰은 서버 관리자가 따로 발급하며, 설치기가 터미널에서 숨김 입력으로 받습니다. GitHub 인증은 각 PC의 SSH 키 또는 GitHub CLI로 설정하고, 저장소 URL이나 명령줄에 토큰을 넣지 마세요.

```bash
git clone --filter=blob:none --sparse git@github.com:bintab1e/hivemind.git
cd hivemind
git sparse-checkout set agent
sh agent/setup.sh 'http://<server-ip>:8765' rc
```

`<server-ip>`를 운영 서버 주소로 바꾸세요. `mainline` 에이전트는 마지막 인수를 `mainline`으로 사용합니다. 설치 전에 서버 관리자로부터 본인 PC의 에이전트 토큰을 받아야 합니다. 서버 주소는 설치 인자로만 전달하며, 토큰 값은 명령 기록에 남기지 않습니다. HTTP에서는 토큰과 보고서가 암호화되지 않으므로 서버 포트는 팀 사설망에서만 열어야 합니다.

설치기가 Node.js 24, Python 3.11, 고정 버전 AgentCov, 커널 Git 소스와 프로젝트별 Codex MCP·훅을 구성합니다. 커널은 서버에 등록된 공식 태그를 `~/workspace/knfsd`에 내려받고 SHA를 확인합니다. 빈 `knfsd` 폴더는 그대로 사용하고, 기존 체크아웃의 SHA가 다르면 새 버전 전용 폴더에 받습니다. Git 저장소가 아닌 파일이 들어 있는 `knfsd` 폴더는 보존을 위해 설치를 멈춥니다. 사용자가 미리 커널 소스를 내려받거나 JSON 설정을 만들 필요가 없습니다. Ubuntu/WSL에서는 빠진 Git·tar·xz 등도 설치합니다.

설치가 끝나면 출력된 커널 폴더에서 **새 Codex/Claude 세션**을 여세요. Codex에서는 프로젝트와 `/hooks`에 표시되는 AgentCov `PostToolUse` 명령을 확인하고 신뢰해야 실제 열람이 기록됩니다. Claude에서는 프로젝트 `.mcp.json`의 서버를 확인·승인하세요. Claude Code의 코드 열람은 같은 체크아웃의 세션 기록에서 동기화 에이전트가 AgentCov로 가져옵니다. Windows에서 WSL에 설치했다면 Codex/Claude도 **같은 WSL 커널 체크아웃에서 실행**해야 WSL AgentCov에 열람이 잡힙니다. 네이티브 Windows 도구는 [수동 설치](MANUAL.md)가 필요합니다.

stdio MCP는 2 VM에서 검증한 취약점 보고서·PoC·KASAN 로그를 즉시 서버로 보내고, 동기화 에이전트는 `fs/nfsd/`, `fs/nfs/`, `fs/nfs_common/`, `fs/lockd/`, `fs/exportfs/`, `net/sunrpc/`와 로컬 include 의존성 범위의 LCOV와 요약 JSON을 5분마다 보냅니다. 이 범위 외 KNFSD 실행 의존성은 모든 에이전트의 `coverage_prefixes`에 동일하게 추가하세요. 세션 원문·분석 PC의 절대 경로·로컬 자유 형식 진행 메모는 전송하지 않습니다. 로컬 telemetry 배치는 최신 1개만 유지합니다. Linux에서는 `systemctl --user status hivemind-agent`, macOS에서는 `launchctl print gui/$(id -u)/org.hivemind.knfsd-agent`로 동기화 상태를 확인합니다.

`list_findings`와 `get_coverage_gaps`로 기존 보고와 조사 공백을 확인합니다. 취약점은 `queue_finding`으로 직접 제출하며 가설 ID가 필요하지 않습니다. 보고에는 두 VM의 역할·커널·연결을 `vm_environment`에 적고, 한국어 분석 보고서, 독립 사용자 공간 C PoC, 실제 KASAN 로그를 포함합니다. `verified_impacts`에는 직접 확인한 영향만 표시합니다. 수정은 `queue_finding_revision`에 기존 `event_id`와 새 전체 자료를 넣어 제출합니다. 토큰·비밀번호·SSH 키·개인 경로를 보고서나 진행도에 넣지 마세요. **코드 열람률은 검증 결과가 아닙니다.**

관리표의 대상·옵션·권한·제보 프로젝트·담당자·NFS 버전·취약점 유형·방법론·발견일·익스플로잇·CVE는 `queue_finding`의 `registry_*` 선택 필드로 전달할 수 있습니다. 확인한 값만 넣고, 관리 번호와 제보 상태는 넣지 않습니다. 제보 상태는 관리자가 관리합니다.

네이티브 Windows 수동 설치: [MANUAL.md](MANUAL.md). 중앙 서버 운영: [server/README.md](../server/README.md).

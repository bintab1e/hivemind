# 네이티브 Windows 수동 설치

Windows에서는 WSL을 켜고 [Linux/WSL 설치기](../README.md)를 실행하는 방법을 권장합니다. **Codex·Claude도 같은 WSL 커널 체크아웃에서 실행해야** WSL에 설치한 AgentCov가 코드 열람을 기록합니다. Windows 경로의 커널과 네이티브 Codex를 쓴다면 아래 절차를 따르세요.

Node.js 24 이상, Python 3.12, Git과 GitHub 비공개 저장소 접근 권한이 필요합니다. 서버 관리자로부터 본인 PC 전용 64자리 토큰 파일과 등록된 커널 버전·Git SHA를 받으세요. 서버 관리자 토큰은 필요하지 않습니다. PowerShell에서 다음 값의 플레이스홀더를 바꿉니다.

```powershell
$checkout = 'C:\work\hivemind-source'
$agentDir = 'C:\work\hivemind-agent'
$kernel = 'C:\work\linux-rc'
$serverUrl = 'http://<server-ip>:8765'
$track = 'rc' # stable 분석은 mainline
$version = '<server-kernel-version>'
$registeredCommit = '<server-kernel-commit-sha>'
$tokenFile = 'C:\work\my-agent.token' # 관리자가 본인에게 발급한 파일
```

`agent/`만 GitHub에서 받고 커널 소스를 독립 체크아웃합니다. 이미 사용 중인 폴더에 덮어쓰지 마세요.

```powershell
New-Item -ItemType Directory -Force 'C:\work' | Out-Null
git clone --filter=blob:none --sparse git@github.com:bintab1e/hivemind.git $checkout
git -C $checkout sparse-checkout set agent
Copy-Item -LiteralPath (Join-Path $checkout 'agent') -Destination $agentDir -Recurse
$kernelGit = if ($track -eq 'rc') { 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git' } else { 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' }
git clone --depth 1 --branch "v$version" --single-branch $kernelGit $kernel
if ((git -C $kernel rev-parse HEAD).Trim() -ne $registeredCommit) { throw '서버 등록 커널 커밋과 다릅니다.' }
```

AgentCov와 프로젝트 설정을 설치합니다. `setup.mjs`는 토큰 파일을 읽어 런타임에 사용자 전용 권한으로 보관하고, Codex 훅·Codex/Claude MCP·5분 동기화 설정을 만듭니다. 토큰 값은 명령 인수나 Git에 넣지 마세요.

```powershell
py -3.12 -m venv (Join-Path $agentDir '.venv')
$python = Join-Path $agentDir '.venv\Scripts\python.exe'
& $python -m pip install -r (Join-Path $agentDir 'requirements.txt')
$env:HIVEMIND_TRACK = $track
$env:HIVEMIND_ALLOW_INSECURE_LAN_HTTP = 'true'
node (Join-Path $agentDir 'setup.mjs') $kernel $tokenFile $serverUrl
```

출력된 커널 폴더에서 새 Codex 세션을 열고 프로젝트와 `/hooks`의 AgentCov `PostToolUse` 명령을 검토·신뢰하세요. Claude Code에서는 프로젝트 `.mcp.json`의 `knfsd_hivemind` 서버를 확인·승인하세요. Claude의 코드 열람은 동기화 에이전트가 해당 체크아웃 세션 기록에서 AgentCov로 가져옵니다.

동기화 프로세스는 분석하는 동안 계속 실행해야 합니다. 별도 PowerShell 창에서 아래를 실행하거나 동일한 명령을 Windows 작업 스케줄러의 로그온 작업에 등록하세요. 스케줄러에는 토큰 문자열을 넣지 않습니다.

```powershell
$agentId = (Get-Content (Join-Path $agentDir 'runtime\active-agent-id') -Raw).Trim()
$config = Join-Path $agentDir "runtime\agents\$agentId.json"
node (Join-Path $agentDir 'sync-agent.mjs') $config
```

코드를 실제로 읽은 뒤 다음 5분 전송에서 웹 대시보드의 해당 에이전트 열람 줄 수를 확인하세요. 커널 폴더에서 `& (Join-Path $agentDir '.venv\Scripts\agentcov.exe') summary`로 로컬 기록도 확인할 수 있습니다. 다른 클라이언트는 AgentCov 지원 세션을 별도 backfill해야 합니다.

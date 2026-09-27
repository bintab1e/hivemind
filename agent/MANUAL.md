# Hivemind 분석 에이전트 (Linux / Windows)

이 `agent/` 폴더만 분석 PC에 복사하면 **stdio MCP 에이전트**(`mcp-agent.mjs`)와 **5분 간격 동기화 에이전트**(`sync-agent.mjs`)를 실행할 수 있습니다. `server/` 폴더와 서버의 DB는 필요하지 않습니다. 각 PC에는 Node.js 24 이상, Git, Python 3.11 이상, 별도 Linux 소스 체크아웃이 필요합니다. [agentcov](https://github.com/trailofbits/agentcov#install)는 **각 분석 PC**에 따로 설치합니다.

서버 운영자에게 **서버 접속 주소(직접 연결 시 내부 IP, 터널 사용 시 SSH 주소와 계정), `agent_id`, `track_id`(`rc` 또는 `mainline`), `version_id`, 등록된 40자리 Git SHA, 그 ID의 `.token` 파일**을 받습니다. 토큰은 별도 파일로 받거나 본인에게만 전달된 `agent/runtime/agents/<agent-id>.token`에 포함돼 있어도 됩니다. 첫 PC라면 소스를 받은 뒤 SHA를 관리자에게 보내고 대상 등록·토큰 발급이 끝난 후 계속합니다. `mainline`은 stable 릴리스의 내부 ID입니다. 다른 LLM과 소스 체크아웃이나 `.agentcov/`를 공유하지 마세요.

## Linux 분석 PC

아래 명령에서 받은 폴더 경로와 서버가 알려 준 ID·버전을 바꿉니다. **같은 터미널 1**에서 순서대로 실행합니다. 받은 `agent/` 폴더만 `~/hivemind-agent`에 복사합니다.

```bash
set -euo pipefail
RECEIVED_AGENT_DIR="$HOME/Downloads/agent"
AGENT_DIR="$HOME/hivemind-agent"
test -f "$RECEIVED_AGENT_DIR/mcp-agent.mjs"
mkdir -p "$AGENT_DIR"
cp -a "$RECEIVED_AGENT_DIR/." "$AGENT_DIR/"
test -f "$AGENT_DIR/sync-agent.mjs"
```

Git, SSH, Python 3.11 이상이 필요합니다. Debian/Ubuntu라면 다음 명령으로 기본 도구를 설치합니다. 다른 배포판에서는 같은 도구를 배포판 패키지 관리자로 설치합니다.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates git openssh-client curl python3 python3-venv python3-pip xz-utils
python3 --version                 # 3.11 이상인지 확인
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
```

Node.js 24 이상이 없다면 [공식 Linux 바이너리](https://nodejs.org/download/release/latest-v24.x/)를 설치합니다. 아래 블록은 glibc Linux의 `x86_64`와 `aarch64` 기준이며, 이미 24 이상이면 건너뜁니다.

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

필수 도구 확인이 끝났다면 아래 값을 설정하고 **대상 소스를 독립 체크아웃**합니다. 새 버전에서는 새 폴더에 다시 받습니다.

```bash
KERNEL_DIR="$HOME/linux-rc-pc01"
AGENT_ID='pc01-codex'
TRACK='rc'                        # stable은 mainline
VERSION='7.3-rc4'                 # 실제 등록 버전
REGISTERED_COMMIT=''              # 첫 PC는 빈 값, 이후는 서버에 등록된 전체 SHA
KERNEL_GIT='https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'
SERVER_URL='http://127.0.0.1:8765' # 사설망 직접 연결: http://서버_IP:8765
ALLOW_INSECURE_LAN_HTTP=false    # 사설망 HTTP 직접 연결일 때만 true
node --version                    # v24 이상
node -e 'if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)'
python3 --version                 # 3.11 이상
git clone --branch "v$VERSION" --single-branch "$KERNEL_GIT" "$KERNEL_DIR"
COMMIT="$(git -C "$KERNEL_DIR" rev-parse HEAD)"
if [ -n "$REGISTERED_COMMIT" ]; then test "$COMMIT" = "$REGISTERED_COMMIT" || { echo '서버 커밋과 다릅니다' >&2; exit 1; }; fi
printf '%s\n' "$COMMIT"           # 첫 PC라면 이 SHA를 서버에 등록
git -C "$KERNEL_DIR" status --short
```

stable은 `KERNEL_GIT='https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'`로 바꿉니다. 등록된 SHA와 다르면 진행하지 않습니다. 새 릴리스에서는 새로운 `KERNEL_DIR`에 체크아웃합니다.

커밋 SHA를 서버 관리자에게 보내 `rc` 또는 `mainline` 대상 등록을 확인하고, 자기 ID의 토큰 파일을 받은 뒤 계속합니다. SSH 터널을 선택했다면 **터미널 2**에서 `user@SERVER_HOST`를 팀원이 사용할 SSH 계정·주소로 바꾸어 터널을 열고 유지합니다. 서버는 기본적으로 외부 포트에 바인딩하지 않습니다.

```bash
ssh -N -o ExitOnForwardFailure=yes -L 8765:127.0.0.1:8765 user@SERVER_HOST
```

PC의 8765 포트가 이미 사용 중이면 `-L 18765:127.0.0.1:8765`로 열고 `SERVER_URL`을 `http://127.0.0.1:18765`로 바꿉니다.

같은 사설망에서 터널 없이 접속할 때는 서버 운영자에게 LAN 바인딩을 요청하고 위의 `SERVER_URL`을 서버 내부 IP로, `ALLOW_INSECURE_LAN_HTTP`를 `true`로 바꿉니다. 이 설정은 `10.*`, `172.16.*`~`172.31.*`, `192.168.*` IPv4 주소에만 적용됩니다. HTTP는 토큰과 분석 기록을 암호화하지 않으므로 신뢰하는 내부망에서만 사용하고 공유기 포트 포워딩을 하지 마세요. HTTPS 주소에는 이 옵션이 필요하지 않습니다.

터미널 1에서 연결을 확인하고 agentcov를 설치합니다.

```bash
curl -fsS "$SERVER_URL/healthz"
python3 -m venv "$AGENT_DIR/.venv"
PYTHON_BIN="$AGENT_DIR/.venv/bin/python"
AGENTCOV="$AGENT_DIR/.venv/bin/agentcov"
"$PYTHON_BIN" -m pip install agentcov
cd "$KERNEL_DIR"
"$AGENTCOV" install-codex-hooks --repo
```

Codex를 쓴다면 훅 명령이 가상 환경의 agentcov를 가리키도록 고정합니다. 설치 프로그램은 기본적으로 `agentcov`라는 명령 이름을 기록하므로, 경로를 고정하지 않으면 Codex의 PATH에 따라 열람 기록이 누락될 수 있습니다.

```bash
"$PYTHON_BIN" - "$KERNEL_DIR/.codex/hooks.json" "$AGENTCOV" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
bin_path = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
for groups in data['hooks'].values():
    for group in groups:
        for handler in group['hooks']:
            command = handler.get('command', '')
            if command.startswith('agentcov hook '):
                handler['command'] = command.replace('agentcov', bin_path, 1)
path.write_text(json.dumps(data, indent=2), encoding='utf-8')
PY
```

관리자에게 받은 **자기 ID 토큰 파일만** 배치합니다. 개인용 `agent/` 폴더 안에 토큰이 이미 있었다면 복사 단계가 생략됩니다. 관리자 토큰은 받지 않습니다.

```bash
cd "$AGENT_DIR"
mkdir -p "runtime/agents" "runtime/telemetry/progress"
if [ ! -s "runtime/agents/$AGENT_ID.token" ]; then
  install -m 600 "$HOME/Downloads/$AGENT_ID.token" "runtime/agents/$AGENT_ID.token"
fi
chmod 600 "runtime/agents/$AGENT_ID.token"
test -s "runtime/agents/$AGENT_ID.token"
```

같은 터미널에서 에이전트 설정과 빈 진행도 파일을 만듭니다. 아래 `coverage_prefixes`는 NFS 서버·클라이언트·공용 코드·잠금·RPC를 포함하며, 동기화 에이전트가 그 파일들의 로컬 `#include` 헤더도 찾아 범위에 넣습니다.

```bash
cat > "runtime/agents/$AGENT_ID.json" <<EOF
{
  "agent_id": "$AGENT_ID",
  "track_id": "$TRACK",
  "version_id": "$VERSION",
  "repo_root": "$KERNEL_DIR",
  "coverage_prefixes": ["fs/nfsd/", "fs/nfs/", "fs/nfs_common/", "fs/lockd/", "net/sunrpc/", "include/uapi/linux/nfsd/"],
  "home": "$AGENT_DIR/runtime",
  "server_url": "$SERVER_URL",
  "allow_insecure_lan_http": $ALLOW_INSECURE_LAN_HTTP,
  "telemetry_interval_seconds": 300,
  "agentcov_bin": "$AGENTCOV"
}
EOF
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "runtime/telemetry/progress/$AGENT_ID.md" <<EOF
---
schema_version: 1
version_id: $VERSION
repo_commit: $COMMIT
updated_at: "$NOW"
---

# 분석 진행 기록

| task_id | status | 확인한 범위·근거 | 관련 가설 | 관련 이벤트 |
| --- | --- | --- | --- | --- |
EOF
```

Codex에서는 **커널 체크아웃의** `.codex/config.toml`에 stdio MCP를 등록합니다. 이미 같은 항목이 있으면 중복 추가하지 말고 그 경로를 고칩니다.

```bash
NODE_BIN="$(command -v node)"
if grep -q '^\[mcp_servers\.knfsd_hivemind\]' "$KERNEL_DIR/.codex/config.toml" 2>/dev/null; then
  echo 'knfsd_hivemind MCP가 이미 등록되어 있습니다. 기존 경로를 확인하세요.' >&2
else
cat >> "$KERNEL_DIR/.codex/config.toml" <<EOF

[mcp_servers.knfsd_hivemind]
command = "$NODE_BIN"
args = ["$AGENT_DIR/mcp-agent.mjs", "$AGENT_DIR/runtime/agents/$AGENT_ID.json"]
cwd = "$AGENT_DIR"
EOF
fi
test -e "$KERNEL_DIR/AGENTS.md" || cp "$AGENT_DIR/knfsd-AGENTS.md" "$KERNEL_DIR/AGENTS.md"
```

기존 `AGENTS.md`가 있으면 `knfsd-AGENTS.md`의 분석·기록 규칙을 그 파일에 합칩니다. 새 Codex 세션을 커널 체크아웃에서 열고 프로젝트와 `/hooks`의 훅을 검토·신뢰합니다. 다른 stdio MCP 클라이언트에는 다음 세 값을 넣습니다.

```text
command: node
args: /home/USER/hivemind-agent/mcp-agent.mjs /home/USER/hivemind-agent/runtime/agents/pc01-codex.json
cwd: /home/USER/hivemind-agent
```

터미널 3에서 동기화 에이전트를 계속 실행합니다.

```bash
AGENT_DIR="$HOME/hivemind-agent"
AGENT_ID='pc01-codex'             # 위에서 설정한 ID
node "$AGENT_DIR/sync-agent.mjs" "$AGENT_DIR/runtime/agents/$AGENT_ID.json"
```

확인 명령:

```bash
cd "$KERNEL_DIR"
"$AGENTCOV" summary
curl -fsS "$SERVER_URL/healthz"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_versions","arguments":{}}}' | node "$AGENT_DIR/mcp-agent.mjs" "$AGENT_DIR/runtime/agents/$AGENT_ID.json"
```

동기화 로그에 `Batch accepted`와 `Coverage scope: ... files`가 나오면 기본 전송이 된 것입니다. 소스를 실제로 읽은 뒤 다음 300초 전송에서 대시보드의 **전체 코드 커버리지 → 해당 에이전트**를 확인합니다. `queue_*` 응답에서는 `accepted: true`와 `event_id`를 확인합니다. 분석하는 동안 동기화 에이전트를 켜 두고, SSH 터널을 선택했다면 터널도 유지합니다.

## Windows 분석 PC

**PowerShell 터미널 1**에서 시작합니다. Node.js 24 이상, Python 3.12, Git이 없다면 WinGet으로 설치한 뒤 PowerShell을 새로 엽니다. 이미 설치했다면 설치 명령은 건너뜁니다. `ssh`는 Windows의 OpenSSH 클라이언트를 사용합니다.

```powershell
winget install --id OpenJS.NodeJS.LTS --exact
winget install --id Python.Python.3.12 --exact
winget install --id Git.Git --exact
```

새 PowerShell에서 버전을 확인합니다. Node.js가 24보다 낮으면 [공식 설치 페이지](https://nodejs.org/en/download)를 통해 24 이상으로 갱신합니다.

```powershell
node --version
if ([int](node -p 'process.versions.node.split(".")[0]') -lt 24) { throw 'Node.js 24 이상이 필요합니다' }
py -3.12 --version
git --version
ssh -V
```

받은 `agent/` 폴더가 다운로드 폴더에 있다고 가정합니다. 다른 위치라면 `$receivedAgentDir`만 바꿉니다. `C:\work\hivemind-agent`에는 이 폴더의 내용만 놓습니다.

```powershell
$agentDir = 'C:\work\hivemind-agent'
$receivedAgentDir = Join-Path $HOME 'Downloads\agent'
$kernel = 'C:\work\linux-rc-pc01'
$agentId = 'pc01-codex'
$track = 'rc'
$version = '7.3-rc4'
$registeredCommit = ''              # 첫 PC는 빈 값, 이후는 서버의 40자리 SHA
$kernelGit = 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'
$serverUrl = 'http://127.0.0.1:8765' # 사설망 직접 연결: http://서버_IP:8765
$allowInsecureLanHttp = $false     # 사설망 HTTP 직접 연결일 때만 $true
New-Item -ItemType Directory -Force 'C:\work' | Out-Null
if (-not (Test-Path (Join-Path $receivedAgentDir 'mcp-agent.mjs'))) { throw "받은 agent 폴더를 찾을 수 없음: $receivedAgentDir" }
if (Test-Path $agentDir) { throw "설치 폴더가 이미 있음: $agentDir" }
Copy-Item -LiteralPath $receivedAgentDir -Destination $agentDir -Recurse -Force
if (-not (Test-Path (Join-Path $agentDir 'sync-agent.mjs'))) { throw 'agent 폴더 복사 실패' }
git clone --branch "v$version" --single-branch $kernelGit $kernel
$commit = (git -C $kernel rev-parse HEAD).Trim()
if ($registeredCommit -and $commit -ne $registeredCommit) { throw "서버 커밋과 다름: $commit" }
$commit                            # 첫 PC라면 이 SHA를 서버에 등록
```

stable은 `$track = 'mainline'`과 `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git`을 사용합니다. 커밋 SHA를 서버 관리자에게 보내 대상 등록을 확인하고, 자기 ID의 토큰 파일을 받은 뒤 계속합니다. SSH 터널을 선택했다면 **PowerShell 터미널 2**에서 `user@SERVER_HOST`를 팀원이 사용할 SSH 계정·주소로 바꾸어 터널을 열어 유지합니다.

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 8765:127.0.0.1:8765 user@SERVER_HOST
```

PC의 8765 포트가 이미 사용 중이면 `-L 18765:127.0.0.1:8765`로 열고 `$serverUrl`을 `http://127.0.0.1:18765`로 바꿉니다. 같은 사설망에서 직접 연결할 때는 서버의 내부 IP를 `$serverUrl`에 넣고 `$allowInsecureLanHttp = $true`로 설정합니다.

터미널 1에서 agentcov를 설치하고 커널 체크아웃에 Codex 훅을 설치합니다. `py -3.12`는 위에서 설치한 Python 3.12를 선택합니다.

```powershell
Invoke-RestMethod "$serverUrl/healthz"
$venv = Join-Path $agentDir '.venv'
py -3.12 -m venv $venv
$pythonBin = Join-Path $venv 'Scripts\python.exe'
$agentcovBin = Join-Path $venv 'Scripts\agentcov.exe'
& $pythonBin -m pip install agentcov
Set-Location $kernel
& $agentcovBin install-codex-hooks --repo
```

Windows의 단순 `Get-Content` 열람은 이 폴더의 `agentcov-windows-hook.py`가 agentcov로 전달합니다. 훅을 가상 환경 경로로 바꿉니다.

```powershell
$hooksPath = Join-Path $kernel '.codex\hooks.json'
$hooks = Get-Content $hooksPath -Raw | ConvertFrom-Json
$bin = $agentcovBin.Replace('\', '/')
$py = $pythonBin.Replace('\', '/')
$adapter = (Join-Path $agentDir 'agentcov-windows-hook.py').Replace('\', '/')
$hooks.hooks.PostToolUse[0].hooks[0].command = "$py $adapter"
$hooks.hooks.PreToolUse[0].hooks[0].command = "$bin hook pre-tool-use"
$hooks.hooks.Stop[0].hooks[0].command = "$bin hook stop"
[IO.File]::WriteAllText($hooksPath, ($hooks | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
```

관리자에게 받은 **이 ID의 토큰 파일**을 다운로드 폴더에서 복사하고 설정 파일을 만듭니다. 서버의 관리자 토큰은 필요하지 않습니다.

```powershell
$runtime = Join-Path $agentDir 'runtime'
$agentsDir = Join-Path $runtime 'agents'
$progressDir = Join-Path $runtime 'telemetry\progress'
New-Item -ItemType Directory -Force $agentsDir, $progressDir | Out-Null
$tokenPath = Join-Path $agentsDir "$agentId.token"
if (-not (Test-Path $tokenPath)) { Copy-Item -LiteralPath (Join-Path $HOME "Downloads\$agentId.token") -Destination $tokenPath }
if (-not (Test-Path $tokenPath)) { throw "토큰 파일을 찾을 수 없음: $tokenPath" }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $tokenPath /inheritance:r /grant:r "${identity}:F"

$configPath = Join-Path $agentsDir "$agentId.json"
$config = Get-Content (Join-Path $agentDir 'agent.example.json') -Raw | ConvertFrom-Json
$config.agent_id = $agentId
$config.track_id = $track
$config.version_id = $version
$config.repo_root = $kernel
$config.home = $runtime
$config.server_url = $serverUrl
$config.allow_insecure_lan_http = $allowInsecureLanHttp
$config.agentcov_bin = $agentcovBin
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))

$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$progress = @"
---
schema_version: 1
version_id: $version
repo_commit: $commit
updated_at: "$now"
---

# 분석 진행 기록

| task_id | status | 확인한 범위·근거 | 관련 가설 | 관련 이벤트 |
| --- | --- | --- | --- | --- |
"@
[IO.File]::WriteAllText((Join-Path $progressDir "$agentId.md"), $progress, [Text.UTF8Encoding]::new($false))
```

Codex MCP 연결을 커널 체크아웃에 등록합니다. 다른 stdio MCP 클라이언트도 같은 Node 실행 파일, `mcp-agent.mjs` 경로, JSON 설정 경로를 사용합니다.

```powershell
$node = (Get-Command node).Source.Replace('\', '/')
$agentPath = $agentDir.Replace('\', '/')
$configFile = $configPath.Replace('\', '/')
$toml = @"

[mcp_servers.knfsd_hivemind]
command = "$node"
args = ["$agentPath/mcp-agent.mjs", "$configFile"]
cwd = "$agentPath"
"@
$tomlPath = Join-Path $kernel '.codex\config.toml'
if ((Test-Path $tomlPath) -and (Select-String -LiteralPath $tomlPath -Pattern '^\[mcp_servers\.knfsd_hivemind\]' -Quiet)) { throw 'knfsd_hivemind MCP가 이미 등록되어 있습니다. 기존 경로를 확인하세요.' }
[IO.File]::AppendAllText($tomlPath, $toml, [Text.UTF8Encoding]::new($false))
if (-not (Test-Path (Join-Path $kernel 'AGENTS.md'))) { Copy-Item (Join-Path $agentDir 'knfsd-AGENTS.md') (Join-Path $kernel 'AGENTS.md') }
```

기존 `AGENTS.md`가 있으면 `knfsd-AGENTS.md`의 분석·기록 규칙을 그 파일에 합칩니다. 새 Codex 세션에서 프로젝트와 `/hooks`의 훅을 검토·신뢰합니다. 이미 같은 MCP 항목이 있으면 중복 추가하지 않습니다. **PowerShell 터미널 3**에서 동기화 에이전트를 계속 실행합니다.

```powershell
$agentDir = 'C:\work\hivemind-agent'
$agentId = 'pc01-codex'
node (Join-Path $agentDir 'sync-agent.mjs') (Join-Path $agentDir "runtime\agents\$agentId.json")
```

PowerShell 터미널 1에서 MCP 조회와 agentcov를 확인합니다. `list_versions` 응답에 서버의 두 트랙이 보여야 합니다.

```powershell
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_versions","arguments":{}}}' | node (Join-Path $agentDir 'mcp-agent.mjs') $configPath
Set-Location $kernel
& $agentcovBin summary
```

브라우저에서 `$serverUrl/?view=coverage`를 엽니다. Codex가 코드를 읽은 뒤 다음 300초 전송에서 해당 에이전트의 읽은 줄 수가 올라가야 합니다. 분석하는 동안 동기화 에이전트를 켜 두고, SSH 터널을 선택했다면 터널도 유지합니다.

## 다른 LLM 클라이언트와 운영

MCP 서버 등록 형식은 클라이언트마다 다르지만 **stdio 명령은 동일**합니다: `node <agent-folder>/mcp-agent.mjs <agent-folder>/runtime/agents/<agent-id>.json`. 다른 LLM의 프로젝트 지침 파일에도 `knfsd-AGENTS.md`의 분석·기록 규칙을 넣습니다. MCP로 쓴 가설·검증·PoC/KASAN 보고는 즉시 전송하고, 실패하면 동기화 에이전트가 로컬 outbox를 재시도합니다. agentcov 커버리지와 진행도는 기본 300초마다 전송합니다.

**MCP 연결만으로 열람률이 생성되지는 않습니다.** Codex 훅 외의 클라이언트는 agentcov가 지원하는 세션을 `agentcov backfill --agent auto --path <session.jsonl>`로 가져오거나 해당 클라이언트에 맞는 훅을 연결해야 합니다. backfill을 실행한 후 다음 동기화 주기에 반영됩니다. 지원되지 않는 열람 명령은 읽었다고 추정하지 않습니다. Codex의 [프로젝트 설정](https://learn.chatgpt.com/docs/config-file/config-basic)과 [훅 신뢰 절차](https://learn.chatgpt.com/docs/hooks)를 참고하세요.

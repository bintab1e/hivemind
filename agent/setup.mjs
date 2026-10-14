import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateConfig, validateServerUrl } from './sync-agent.mjs';
import { defaultCoveragePrefixes } from './coverage-scope.mjs';

const agentDir = path.dirname(fileURLToPath(import.meta.url));

export function secureRuntimeDirectory(runtimeDir) {
  fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    fs.chmodSync(runtimeDir, 0o700);
    return;
  }
  const sid = execFileSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' }).match(/S-1-[\d-]+/)?.[0];
  if (!sid) throw new Error('Cannot determine the current Windows user SID');
  const directories = [runtimeDir];
  for (let index = 0; index < directories.length; index++) {
    const directory = directories[index];
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error('Symlinks are not allowed in agent runtime');
      if (entry.isDirectory()) directories.push(path.join(directory, entry.name));
    }
  }
  const runAcl = args => execFileSync('icacls.exe', [runtimeDir, ...args, '/T'], { stdio: 'pipe' });
  const allowed = [`*${sid}:F`, '*S-1-5-18:F', '*S-1-5-32-544:F'];
  // Keep access while removing inherited ACLs from the whole tree.
  runAcl(['/grant:r', `*${sid}:F`]);
  // Remove inherited permissions on existing reports as well as new descendants.
  runAcl(['/inheritance:r']);
  runAcl(['/remove:g', '*S-1-1-0', '*S-1-5-11', '*S-1-5-32-545', '*S-1-5-32-546']);
  runAcl(['/grant:r', ...allowed]);
  for (const directory of directories) {
    execFileSync('icacls.exe', [directory, '/grant', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], { stdio: 'pipe' });
  }
}

function git(root, ...args) {
  return execFileSync('git', ['-c', `safe.directory=${root}`, '-C', root, ...args], { encoding: 'utf8' }).trim();
}

function ignoreLocalFiles(root) {
  const exclude = path.resolve(root, git(root, 'rev-parse', '--git-path', 'info/exclude'));
  const ignored = new Set((fs.existsSync(exclude) ? fs.readFileSync(exclude, 'utf8') : '').split(/\r?\n/));
  const entries = ['.hivemind/', '.agentcov/', '.codex/', '.mcp.json', 'AGENTS.md'];
  const missing = entries.filter(entry => !ignored.has(entry));
  if (missing.length) fs.appendFileSync(exclude, `\n${missing.join('\n')}\n`);
}

async function getJson(url, token, body) {
  const response = await fetch(url, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body && JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(`서버 연결 실패 (${response.status}): ${result.error || '요청 실패'}`);
  return result;
}

function saveCodexConfig(root, configPath) {
  const file = path.join(root, '.codex', 'config.toml');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const section = `[mcp_servers.knfsd_hivemind]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify([path.join(agentDir, 'mcp-agent.mjs'), configPath])}\ncwd = ${JSON.stringify(agentDir)}\n`;
  const lines = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split(/\r?\n/) : [];
  const start = lines.findIndex(line => line.trim() === '[mcp_servers.knfsd_hivemind]');
  if (start >= 0) {
    let end = start + 1;
    while (end < lines.length && !/^\s*\[/.test(lines[end])) end++;
    lines.splice(start, end - start);
  }
  fs.writeFileSync(file, `${lines.join('\n').trimEnd()}\n\n${section}`);
}

function saveClaudeConfig(root, configPath) {
  const file = path.join(root, '.mcp.json');
  const data = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  if (!data || typeof data !== 'object' || Array.isArray(data) ||
      (data.mcpServers != null && (typeof data.mcpServers !== 'object' || Array.isArray(data.mcpServers)))) {
    throw new Error(`Invalid Claude MCP configuration: ${file}`);
  }
  data.mcpServers ||= {};
  data.mcpServers.knfsd_hivemind = {
    command: process.execPath,
    args: [path.join(agentDir, 'mcp-agent.mjs'), configPath],
  };
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
}

const agentcovHookAction = command => typeof command === 'string'
  ? /(?:^|[/\\])agentcov(?:\.exe)?\s+hook\s+(post-tool-use|pre-tool-use|stop)\s*$/.exec(command.trim())?.[1]
    || /(?:^|[/\\])agentcov-windows-hook\.py(?:['"]|\s|$)/.test(command) && 'post-tool-use'
  : undefined;

export function retainRecordingHook(data, recordingCommand) {
  let recordingHookFound = false;
  for (const [eventName, groups] of Object.entries(data.hooks || {})) {
    if (!Array.isArray(groups)) continue;
    const keptGroups = [];
    for (const group of groups) {
      if (!Array.isArray(group.hooks)) { keptGroups.push(group); continue; }
      const hooks = [];
      for (const hook of group.hooks) {
        const action = agentcovHookAction(hook.command);
        if (!action) { hooks.push(hook); continue; }
        if (eventName !== 'PostToolUse' || action !== 'post-tool-use' || recordingHookFound) continue;
        hooks.push({ ...hook, command: recordingCommand });
        recordingHookFound = true;
      }
      if (hooks.length) keptGroups.push({ ...group, hooks });
    }
    if (keptGroups.length) data.hooks[eventName] = keptGroups;
    else delete data.hooks[eventName];
  }
  if (!recordingHookFound) throw new Error('agentcov PostToolUse hook was not installed');
  return data;
}

function installHooks(root, agentcovBin) {
  execFileSync(agentcovBin, ['install-codex-hooks', '--repo'], { cwd: root, stdio: 'inherit' });
  const file = path.join(root, '.codex', 'hooks.json');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const recordingCommand = process.platform === 'win32'
    ? `powershell.exe -NoProfile -NonInteractive -Command "& '${path.join(agentDir, '.venv', 'Scripts', 'python.exe').replaceAll('\\', '/').replaceAll("'", "''")}' '${path.join(agentDir, 'agentcov-windows-hook.py').replaceAll('\\', '/').replaceAll("'", "''")}'"`
    : `${agentcovBin} hook post-tool-use`;
  fs.writeFileSync(file, `${JSON.stringify(retainRecordingHook(data, recordingCommand), null, 2)}\n`);
  fs.rmSync(path.join(root, '.agentcov', 'coverage.json'), { force: true });
}

export function updateInstructions(root) {
  const file = path.join(root, 'AGENTS.md');
  const content = fs.readFileSync(path.join(agentDir, 'knfsd-AGENTS.md'), 'utf8');
  if (!fs.existsSync(file)) return fs.writeFileSync(file, content);
  const existing = fs.readFileSync(file, 'utf8');
  const marker = '# knfsd Hivemind 분석';
  const start = existing.indexOf(marker);
  if (start < 0) return fs.appendFileSync(file, `\n\n${content}`);
  const nextSection = existing.indexOf('\n# ', start + marker.length);
  const updated = `${existing.slice(0, start)}${content.trimEnd()}${nextSection < 0 ? '\n' : existing.slice(nextSection)}`;
  if (updated !== existing) fs.writeFileSync(file, updated);
}

export async function configure(root, tokenFile, serverUrl = process.env.HIVEMIND_SERVER_URL) {
  const allowInsecureLanHttp = process.env.HIVEMIND_ALLOW_INSECURE_LAN_HTTP === 'true';
  const serverOrigin = validateServerUrl(serverUrl, allowInsecureLanHttp);
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  if (!/^[a-f0-9]{64}$/i.test(token)) throw new Error('64자리 에이전트 토큰이 필요합니다.');
  const commit = git(root, 'rev-parse', 'HEAD');
  ignoreLocalFiles(root);
  const health = await getJson(`${serverOrigin}/v1/sync/health`, token);
  const versions = await getJson(`${serverOrigin}/mcp`, token, {
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_versions', arguments: {} },
  });
  const matches = (versions.result?.structuredContent?.tracks || []).filter(track => track.version_id && track.repo_commit === commit && (!process.env.HIVEMIND_TRACK || track.track_id === process.env.HIVEMIND_TRACK));
  if (matches.length !== 1) throw new Error(`커널 커밋 ${commit}과 일치하는 서버 대상이 없습니다. 서버에 rc/stable 대상 커밋을 등록하세요.`);
  const target = matches[0];
  const id = health.agent_id;
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(id || '')) throw new Error('서버의 agent_id가 올바르지 않습니다.');
  const agentsDir = path.join(agentDir, 'runtime', 'agents');
  const tokenPath = path.join(agentsDir, `${id}.token`);
  const configPath = path.join(agentsDir, `${id}.json`);
  const agentcovBin = path.join(agentDir, '.venv', ...(process.platform === 'win32' ? ['Scripts', 'agentcov.exe'] : ['bin', 'agentcov']));
  if (!fs.existsSync(agentcovBin)) throw new Error('agentcov 설치 파일이 없습니다.');
  secureRuntimeDirectory(path.join(agentDir, 'runtime'));
  fs.mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
  if (fs.existsSync(tokenPath) && fs.readFileSync(tokenPath, 'utf8').trim() !== token) throw new Error(`다른 토큰이 이미 있습니다: ${tokenPath}`);
  fs.writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
  const config = validateConfig({ agent_id: id, track_id: target.track_id, version_id: target.version_id,
    repo_root: root, coverage_prefixes: defaultCoveragePrefixes, home: path.join(agentDir, 'runtime'),
    ...(process.env.HIVEMIND_RESULT_ROOT ? { result_root: process.env.HIVEMIND_RESULT_ROOT } : {}),
    server_url: serverOrigin, allow_insecure_lan_http: allowInsecureLanHttp,
    telemetry_interval_seconds: 300, agentcov_bin: agentcovBin });
  delete config.server;
  if (fs.existsSync(configPath)) {
    const old = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (old.repo_root !== root || old.version_id !== target.version_id) throw new Error('기존 설정의 체크아웃 또는 버전이 다릅니다. 새 작업 폴더를 사용하세요.');
  }
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  const progressDir = path.join(agentDir, 'runtime', 'telemetry', 'progress');
  fs.mkdirSync(progressDir, { recursive: true });
  const progressFile = path.join(progressDir, `${id}.md`);
  if (fs.existsSync(progressFile)) {
    const progress = fs.readFileSync(progressFile, 'utf8');
    if (!progress.includes(`version_id: ${target.version_id}\n`) || !progress.includes(`repo_commit: ${commit}\n`)) throw new Error('기존 진행 기록의 버전 또는 커밋이 다릅니다. 새 작업 폴더를 사용하세요.');
  } else fs.writeFileSync(progressFile, `---\nschema_version: 1\nversion_id: ${target.version_id}\nrepo_commit: ${commit}\nupdated_at: "${new Date().toISOString()}"\n---\n\n# 분석 진행 기록\n\n| task_id | status | 확인한 범위·근거 | 관련 이벤트 |\n| --- | --- | --- | --- |\n`);
  saveCodexConfig(root, configPath);
  saveClaudeConfig(root, configPath);
  installHooks(root, agentcovBin);
  updateInstructions(root);
  fs.writeFileSync(path.join(agentDir, 'runtime', 'active-agent-id'), `${id}\n`, { mode: 0o600 });
  return { id, version: target.version_id, track: target.track_id, configPath };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  configure(path.resolve(process.argv[2] || ''), process.argv[3] || '', process.argv[4] || process.env.HIVEMIND_SERVER_URL).then(result => {
    console.log(`설정 완료: ${result.id} / ${result.track} / ${result.version}`);
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}

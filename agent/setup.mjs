import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateConfig } from './sync-agent.mjs';

const agentDir = path.dirname(fileURLToPath(import.meta.url));
const defaultServerUrl = 'http://192.168.1.188:8765';
const coveragePrefixes = ['fs/nfsd/', 'fs/nfs/', 'fs/nfs_common/', 'fs/lockd/', 'net/sunrpc/', 'include/uapi/linux/nfsd/'];

function git(root, ...args) {
  return execFileSync('git', ['-c', `safe.directory=${root}`, '-C', root, ...args], { encoding: 'utf8' }).trim();
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

function installHooks(root, agentcovBin) {
  execFileSync(agentcovBin, ['install-codex-hooks', '--repo'], { cwd: root, stdio: 'inherit' });
  const file = path.join(root, '.codex', 'hooks.json');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const groups of Object.values(data.hooks)) for (const group of groups) for (const hook of group.hooks) {
    if (hook.command?.startsWith('agentcov hook ')) hook.command = hook.command.replace('agentcov', agentcovBin);
  }
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
}

export async function configure(root, tokenFile, serverUrl = defaultServerUrl) {
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  if (!/^[a-f0-9]{64}$/i.test(token)) throw new Error('64자리 에이전트 토큰이 필요합니다.');
  const commit = git(root, 'rev-parse', 'HEAD');
  const health = await getJson(`${serverUrl}/v1/sync/health`, token);
  const versions = await getJson(`${serverUrl}/mcp`, token, {
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_versions', arguments: {} },
  });
  const matches = (versions.result?.structuredContent?.tracks || []).filter(track => track.version_id && track.repo_commit === commit);
  if (matches.length !== 1) throw new Error(`커널 커밋 ${commit}과 일치하는 서버 대상이 없습니다. 서버에 rc/stable 대상 커밋을 등록하세요.`);
  const target = matches[0];
  const id = health.agent_id;
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(id || '')) throw new Error('서버의 agent_id가 올바르지 않습니다.');
  const agentsDir = path.join(agentDir, 'runtime', 'agents');
  const tokenPath = path.join(agentsDir, `${id}.token`);
  const configPath = path.join(agentsDir, `${id}.json`);
  const agentcovBin = path.join(agentDir, '.venv', 'bin', 'agentcov');
  if (!fs.existsSync(agentcovBin)) throw new Error('agentcov 설치 파일이 없습니다.');
  fs.mkdirSync(agentsDir, { recursive: true, mode: 0o700 });
  if (fs.existsSync(tokenPath) && fs.readFileSync(tokenPath, 'utf8').trim() !== token) throw new Error(`다른 토큰이 이미 있습니다: ${tokenPath}`);
  fs.writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
  const config = validateConfig({ agent_id: id, track_id: target.track_id, version_id: target.version_id,
    repo_root: root, coverage_prefixes: coveragePrefixes, home: path.join(agentDir, 'runtime'),
    server_url: serverUrl, allow_insecure_lan_http: true, telemetry_interval_seconds: 300, agentcov_bin: agentcovBin });
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
  } else fs.writeFileSync(progressFile, `---\nschema_version: 1\nversion_id: ${target.version_id}\nrepo_commit: ${commit}\nupdated_at: "${new Date().toISOString()}"\n---\n\n# 분석 진행 기록\n\n| task_id | status | 확인한 범위·근거 | 관련 가설 | 관련 이벤트 |\n| --- | --- | --- | --- | --- |\n`);
  saveCodexConfig(root, configPath);
  installHooks(root, agentcovBin);
  const instructions = path.join(root, 'AGENTS.md');
  const content = fs.readFileSync(path.join(agentDir, 'knfsd-AGENTS.md'), 'utf8');
  if (!fs.existsSync(instructions)) fs.writeFileSync(instructions, content);
  else if (!fs.readFileSync(instructions, 'utf8').includes('# knfsd Hivemind 분석')) fs.appendFileSync(instructions, `\n\n${content}`);
  const excludePath = git(root, 'rev-parse', '--git-path', 'info/exclude');
  const exclude = path.resolve(root, excludePath);
  const ignored = fs.existsSync(exclude) ? fs.readFileSync(exclude, 'utf8') : '';
  if (!ignored.split(/\r?\n/).includes('.hivemind/')) fs.appendFileSync(exclude, '\n.hivemind/\n.agentcov/\n');
  fs.writeFileSync(path.join(agentDir, 'runtime', 'active-agent-id'), `${id}\n`, { mode: 0o600 });
  return { id, version: target.version_id, track: target.track_id, configPath };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  configure(path.resolve(process.argv[2] || ''), process.argv[3] || '', process.argv[4] || defaultServerUrl).then(result => {
    console.log(`설정 완료: ${result.id} / ${result.track} / ${result.version}`);
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}

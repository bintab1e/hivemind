import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.HIVEMIND_DATA_DIR || path.join(root, 'runtime', 'server');
const sources = {
  rc: 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git',
  mainline: 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git',
};
const base = `http://127.0.0.1:${process.env.HIVEMIND_PORT || 8765}`;

export function latestVersionFromRefs(text, track, wanted) {
  const tags = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([a-f0-9]{40})\trefs\/tags\/v([^\s^]+)(\^\{\})?$/.exec(line);
    if (!match) continue;
    const version = match[2];
    const numbers = track === 'rc' ? /^(\d+)\.(\d+)-rc(\d+)$/.exec(version) : /^(\d+)\.(\d+)(?:\.(\d+))?$/.exec(version);
    if (!numbers || wanted && version !== wanted) continue;
    if (!tags.has(version) || match[3]) tags.set(version, { version_id: version, repo_commit: match[1], rank: numbers.slice(1).map(value => Number(value || 0)) });
  }
  return [...tags.values()].sort((a, b) => b.rank[0] - a.rank[0] || b.rank[1] - a.rank[1] || b.rank[2] - a.rank[2])[0] || null;
}

function target(track, wanted) {
  const refs = execFileSync('git', ['ls-remote', '--tags', sources[track]], { encoding: 'utf8', maxBuffer: 32_000_000, timeout: 120_000 });
  const result = latestVersionFromRefs(refs, track, wanted);
  if (!result) throw new Error(`${track} 태그를 찾지 못했습니다${wanted ? `: v${wanted}` : ''}`);
  return result;
}

async function request(route, method = 'GET', body, token) {
  const response = await fetch(`${base}${route}`, { method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(15_000) });
  const result = await response.json();
  if (!response.ok) throw new Error(`${route}: ${response.status} ${result.error || '요청 실패'}`);
  return result;
}

function lanAddress() {
  const addresses = Object.values(os.networkInterfaces()).flat().filter(item => item?.family === 'IPv4' && !item.internal).map(item => item.address);
  return addresses.find(value => value.startsWith('192.168.')) || addresses.find(value => /^10\./.test(value)) || addresses.find(value => /^172\.(1[6-9]|2\d|3[01])\./.test(value)) || addresses[0] || null;
}

async function registerTrack(token, track, wanted) {
  const { version_id, repo_commit } = target(track, wanted);
  await request(`/v1/admin/tracks/${track}`, 'PUT', { version_id, repo_commit }, token);
  console.log(`${track}: ${version_id} (${repo_commit})`);
}

async function issueAgent(token, id, track) {
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(id)) throw new Error('에이전트 ID는 영숫자, _ 또는 -만 사용할 수 있습니다.');
  if (!sources[track]) throw new Error('트랙은 rc 또는 mainline이어야 합니다.');
  const active = await request('/v1/admin/tracks', 'GET', null, token);
  if (!active.tracks.some(item => item.track_id === track && item.version_id)) throw new Error(`${track} 대상을 먼저 등록하세요.`);
  const directory = path.join(path.dirname(dataDir), 'agents');
  const file = path.join(directory, `${id}.token`);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  let agentToken = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : '';
  const valid = agentToken && await fetch(`${base}/v1/sync/health`, { headers: { Authorization: `Bearer ${agentToken}` }, signal: AbortSignal.timeout(15_000) }).then(async response => response.ok && (await response.json()).agent_id === id).catch(() => false);
  if (!valid) {
    const agents = await request('/v1/admin/agents', 'GET', null, token);
    const exists = agents.agents.some(item => item.agent_id === id);
    const result = exists ? await request(`/v1/admin/agents/${id}`, 'PUT', null, token) : await request('/v1/admin/agents', 'POST', { agent_id: id }, token);
    agentToken = result.token;
    fs.writeFileSync(file, `${agentToken}\n`, { mode: 0o600 });
  }
  const address = lanAddress();
  const serverUrl = process.env.HIVEMIND_SERVER_URL || (address ? `http://${address}:${process.env.HIVEMIND_PORT || 8765}` : 'http://SERVER_IP:8765');
  console.log(`\n${id} 토큰: ${agentToken}`);
  console.log(`분석 PC 설치 명령:\ncurl -fsSL https://raw.githubusercontent.com/bintab1e/hivemind-agent/main/install.sh | bash -s -- ${serverUrl} ${track}`);
  console.log(`토큰 보관 파일: ${file}`);
}

async function main() {
  const [command, first, second, third] = process.argv.slice(2);
  const tokenFile = path.join(dataDir, 'api-token.txt');
  if (!fs.existsSync(tokenFile)) throw new Error('서버를 먼저 설치·시작하세요. 관리자 토큰 파일이 없습니다.');
  const adminToken = fs.readFileSync(tokenFile, 'utf8').trim();
  if (command === 'setup' && !first && !second) {
    await registerTrack(adminToken, 'rc');
    await registerTrack(adminToken, 'mainline');
  } else if (command === 'track' && sources[first]) {
    await registerTrack(adminToken, first, second);
  } else if (command === 'agent' && first === 'add' && second) {
    await issueAgent(adminToken, second, third || 'rc');
  } else if (command === 'status') {
    console.log(JSON.stringify(await request('/v1/admin/tracks', 'GET', null, adminToken), null, 2));
    console.log(JSON.stringify(await request('/v1/admin/agents', 'GET', null, adminToken), null, 2));
  } else {
    console.log('사용법: node manage.mjs setup\n        node manage.mjs agent add <agent_id> [rc|mainline]\n        node manage.mjs track <rc|mainline> [version]\n        node manage.mjs status');
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error.message); process.exitCode = 1; });

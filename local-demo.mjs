import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { startServer } from './server/server.mjs';
import { makeBatch } from './agent/sync-agent.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const demoRoot = path.join(root, 'runtime', 'local-demo');
const runRoot = path.join(demoRoot, `run-${Date.now()}-${randomBytes(3).toString('hex')}`);
const port = Number(process.argv.find(arg => arg.startsWith('--port='))?.slice(7) ?? 8766);
const once = process.argv.includes('--once');
const agentIds = ['demo-a', 'demo-b', 'demo-c', 'demo-d', 'demo-e'];
const refs = ['fs/nfsd/demo.c#demo_open'];

function client(configPath) {
  const child = spawn(process.execPath, [path.join(root, 'agent', 'mcp-agent.mjs'), configPath], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let nextId = 0;
  let stderr = '';
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
  createInterface({ input: child.stdout }).on('line', line => {
    const reply = JSON.parse(line);
    const job = pending.get(reply.id);
    if (!job) return;
    pending.delete(reply.id);
    clearTimeout(job.timer);
    reply.error ? job.reject(new Error(reply.error.message)) : job.resolve(reply.result);
  });
  child.on('exit', code => {
    for (const job of pending.values()) { clearTimeout(job.timer); job.reject(new Error(`MCP exited ${code}: ${stderr}`)); }
    pending.clear();
  });
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`MCP ${method} timed out: ${stderr}`)); }, 20_000);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  return {
    child,
    request,
    async tool(name, args) {
      const result = await request('tools/call', { name, arguments: args });
      if (result.isError) throw new Error(result.content?.[0]?.text || `${name} failed`);
      return result.structuredContent;
    },
  };
}

async function jsonPost(url, token, body, method = 'POST') {
  const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw new Error(`${response.status} ${result.error || url}`);
  return result;
}

async function main() {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid --port');
  await fs.mkdir(runRoot, { recursive: true });
  const repoRoot = path.join(runRoot, 'synthetic-knfsd');
  await fs.mkdir(path.join(repoRoot, 'fs', 'nfsd'), { recursive: true });
  await fs.writeFile(path.join(repoRoot, 'fs', 'nfsd', 'demo.c'), 'int demo_open(int x) {\n  int values[2] = {0, 1};\n  if (x < 0) return -1;\n  return values[x];\n}\n');
  execFileSync('git', ['init', '-q', repoRoot]);
  execFileSync('git', ['-C', repoRoot, 'config', 'core.autocrlf', 'false']);
  execFileSync('git', ['-C', repoRoot, 'add', '.']);
  execFileSync('git', ['-C', repoRoot, '-c', 'user.name=Hivemind Demo', '-c', 'user.email=demo@example.invalid', 'commit', '-qm', 'synthetic demo']);
  const commit = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const { server, db, url, tokenPath } = await startServer({ port, dataDir: path.join(runRoot, 'server') });
  const clients = new Map();
  try {
    const adminToken = (await fs.readFile(tokenPath, 'utf8')).trim();
    await jsonPost(`${url}/v1/admin/tracks/rc`, adminToken, { version_id: 'local-demo', repo_commit: commit }, 'PUT');
    const tokens = new Map();
    for (const agentId of agentIds) {
      const issued = await jsonPost(`${url}/v1/admin/agents`, adminToken, { agent_id: agentId });
      tokens.set(agentId, issued.token);
      const configPath = path.join(runRoot, 'agents', `${agentId}.json`);
      await fs.mkdir(path.dirname(configPath), { recursive: true });
      await fs.writeFile(configPath, JSON.stringify({ agent_id: agentId, track_id: 'rc', version_id: 'local-demo', repo_root: repoRoot, home: path.join(runRoot, 'agent-home'), server_url: url, telemetry_interval_seconds: 300 }, null, 2));
      await fs.writeFile(path.join(path.dirname(configPath), `${agentId}.token`), issued.token, { mode: 0o600 });
      const bridge = client(configPath);
      clients.set(agentId, bridge);
      await bridge.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'local-demo', version: '1' } });
      assert((await bridge.request('tools/list')).tools.some(tool => tool.name === 'queue_hypothesis'));
    }
    const tool = (agentId, name, args) => clients.get(agentId).tool(name, args);
    const hypothesis = (title, claimKey) => ({ title, claim_key: claimKey, verification_plan: 'demo_open의 경계값 분기를 두 방식으로 확인한다', preflight: 'checked', scope: ['fs/nfsd/'], code_refs: refs, angle: 'static-trace', body: '## 주장\ndemo_open의 경계값에서 예상하지 못한 결과가 나올 수 있다.\n\n## 근거\nfs/nfsd/demo.c#demo_open의 분기를 확인했다.\n\n## 검증 계획\n정적 추적과 실행 재현을 비교한다.' });
    const verification = (hypothesisId, method, verdict) => ({ title: `${method} 결과`, scope: ['fs/nfsd/'], code_refs: refs, angle: method, body: `## 수행한 검증\n${method}로 fs/nfsd/demo.c#demo_open을 확인했다.\n\n## 관찰 결과\n${verdict} 근거를 기록한다.`, verification_of: hypothesisId, method, verdict, prior_exposure: 'claim_only', based_on_event_ids: [] });
    const first = await tool('demo-a', 'queue_hypothesis', hypothesis('경계값 처리 가설', 'demo-boundary'));
    assert.equal(first.accepted, true);
    const found = await tool('demo-b', 'search_hypotheses', { version_id: 'local-demo', repo_commit: commit, code_ref: refs[0] });
    assert(found.matches.some(item => item.id === first.hypothesis_id));
    await tool('demo-c', 'search_hypotheses', { version_id: 'local-demo', repo_commit: commit, query: 'demo-boundary' });
    assert.equal((await tool('demo-b', 'queue_verification', verification(first.hypothesis_id, 'static-trace', 'refutes'))).accepted, true);
    assert.equal((await tool('demo-c', 'queue_verification', verification(first.hypothesis_id, 'runtime-reproduction', 'refutes'))).accepted, true);
    assert.equal((await tool('demo-a', 'get_hypothesis', { hypothesis_id: first.hypothesis_id, repo_commit: commit, mode: 'claim_only' })).status, 'retired');
    assert.equal((await tool('demo-d', 'queue_verification', verification(first.hypothesis_id, 'counterexample', 'supports'))).accepted, true);
    assert.equal((await tool('demo-a', 'get_hypothesis', { hypothesis_id: first.hypothesis_id, repo_commit: commit, mode: 'full' })).status, 'contested');
    const second = await tool('demo-e', 'queue_hypothesis', hypothesis('다른 경계값 가설', 'demo-second-boundary'));
    for (const [agentId, method] of [['demo-b', 'static-trace'], ['demo-c', 'runtime-reproduction']]) {
      await tool(agentId, 'search_hypotheses', { version_id: 'local-demo', repo_commit: commit, query: 'demo-second-boundary' });
      assert.equal((await tool(agentId, 'queue_verification', verification(second.hypothesis_id, method, 'refutes'))).accepted, true);
    }
    const duplicate = await tool('demo-a', 'queue_hypothesis', hypothesis('다른 경계값 가설', 'demo-second-boundary'));
    assert.equal(duplicate.queued, false);
    assert(duplicate.possible_matches.some(item => item.id === second.hypothesis_id && item.status === 'retired'));
    const overflow = await tool('demo-a', 'queue_hypothesis', { ...hypothesis('합성 배열 경계 가설', 'demo-array-boundary'), body: '## 주장\ndemo_open에 2를 주면 values[2]를 읽어 배열 경계를 넘는다.\n\n## 검증 계획\n정적 추적과 경계값 입력을 확인한다.' });
    const supportIds = [];
    for (const [agentId, method] of [['demo-b', 'static-trace'], ['demo-c', 'boundary-value']]) {
      const check = await tool(agentId, 'queue_verification', { ...verification(overflow.hypothesis_id, method, 'supports'), body: `## 관찰 결과\n합성 demo_open의 values[2]가 경계를 넘는다. ${method}로 확인했다.` });
      assert.equal(check.accepted, true);
      supportIds.push(check.event_id);
    }
    const evidenceDir = path.join(runRoot, 'agent-home', 'evidence');
    await fs.mkdir(evidenceDir, { recursive: true });
    const pocPath = path.join(evidenceDir, 'demo-poc.c');
    const kasanPath = path.join(evidenceDir, 'demo-kasan.log');
    await fs.writeFile(pocPath, '/* Synthetic demo PoC, not a knfsd exploit. */\nint demo_open(int);\nint main(void) { return demo_open(2); }\n');
    await fs.writeFile(kasanPath, 'SYNTHETIC DEMO LOG — not from a real kernel run\nBUG: KASAN: stack-out-of-bounds in demo_open\nRead of size 4 at values[2]\nCall Trace:\n demo_open\n');
    const finding = await tool('demo-a', 'queue_finding', { title: '합성 데모: 배열 경계 밖 읽기', scope: ['fs/nfsd/'], code_refs: refs, angle: 'boundary-value', body: '## 발견\n합성 demo_open에 2를 넣으면 values[2]를 읽는다. PoC와 KASAN 로그는 UI 시험을 위한 합성 자료이며 실제 knfsd 결과가 아니다.', finding_of: overflow.hypothesis_id, file_path: 'fs/nfsd/demo.c', evidence_event_ids: supportIds, impact: '합성 함수에서 배열 경계 밖 읽기가 발생한다.', poc_path: pocPath, kasan_path: kasanPath, reproduction_command: 'SYNTHETIC DEMO: ./demo-poc' });
    assert.equal(finding.accepted, true);
    for (const [index, agentId] of agentIds.entries()) {
      const read = new Set([[1, 2], [2, 3], [3, 4], [4, 5], [1, 5]][index]);
      const lcov = `TN:\nSF:fs/nfsd/demo.c\n${[1, 2, 3, 4, 5].map(line => `DA:${line},${Number(read.has(line))}`).join('\n')}\nLF:5\nLH:${read.size}\nend_of_record\n`;
      const progressMd = `---\nschema_version: 1\nversion_id: local-demo\nrepo_commit: ${commit}\nupdated_at: "${new Date().toISOString()}"\n---\n\n| task_id | status |\n| --- | --- |\n| ${agentId.replace('-', '')} | done |\n`;
      const batch = makeBatch({ agentId, versionId: 'local-demo', repoRoot, commit, clean: true, generatedAt: new Date().toISOString(), lcov, coverageJson: '{}', progressMd, agentcovConfig: 'synthetic demo' });
      assert.equal((await jsonPost(`${url}/v1/telemetry/batches`, tokens.get(agentId), batch)).accepted, true);
    }
    const dashboard = await (await fetch(`${url}/api/dashboard`)).json();
    assert.equal(dashboard.metrics.agent_count, 5);
    assert.equal(dashboard.metrics.read_lines, 5);
    assert.equal(dashboard.metrics.retired_count, 1);
    assert(dashboard.hypotheses.some(item => item.id === first.hypothesis_id && item.status === 'contested'));
    assert.equal(dashboard.findings[0].file_path, 'fs/nfsd/demo.c');
    assert.match(dashboard.findings[0].kasan_summary, /BUG: KASAN:/);
    const summary = { url, run_dir: runRoot, agents: agentIds, mcp_processes: [...clients.values()].map(bridge => bridge.child.pid), hypothesis_ids: [first.hypothesis_id, second.hypothesis_id, overflow.hypothesis_id], statuses: dashboard.hypotheses.map(item => ({ id: item.id, status: item.status })), coverage: `${dashboard.metrics.read_lines}/${dashboard.metrics.total_lines}`, note: '합성 코드와 합성 agentcov 형식 데이터입니다. 실제 knfsd 분석 결과가 아닙니다.' };
    await fs.writeFile(path.join(runRoot, 'result.json'), JSON.stringify(summary, null, 2));
    if (!once) await fs.writeFile(path.join(demoRoot, 'current.json'), JSON.stringify({ pid: process.pid, ...summary }, null, 2));
    console.log(JSON.stringify(summary));
    if (once) {
      for (const bridge of clients.values()) bridge.child.stdin.end();
      await new Promise(resolve => server.close(resolve));
      db.close();
    }
  } catch (error) {
    for (const bridge of clients.values()) bridge.child.stdin.end();
    await new Promise(resolve => server.close(resolve));
    db.close();
    throw error;
  }
}

main().catch(error => { console.error(error.stack || error); process.exitCode = 1; });

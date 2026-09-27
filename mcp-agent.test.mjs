import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, readdir, rename, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { handleMessage, queueRecord } from './agent/mcp-agent.mjs';
import { startServer } from './server/server.mjs';
import { syncExchange } from './agent/sync-agent.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const commit = 'a'.repeat(40);
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('local MCP queues immutable Markdown, exposes tools over stdio, and forwards reads', async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'hivemind-mcp-'));
  let server, db;
  t.after(async () => { if (server) await new Promise(resolve => server.close(resolve)); db?.close(); await rm(temp, { recursive: true, force: true }); });
  const config = { agent_id: 'pc1', version_id: '7.2.5', repo_root: temp, home: temp, server_url: 'http://127.0.0.1:8765', telemetry_interval_seconds: 300 };
  const args = { title: '경계값 가설', scope: ['fs/nfsd/'], code_refs: ['fs/nfsd/main.c#nfsd_main'], angle: 'static-trace', body: '## 주장\n경계값 처리가 잘못될 수 있다.\n\n## 근거\nfs/nfsd/main.c:10', claim_key: 'boundary', verification_plan: '경계값 입력으로 분기 결과 확인', preflight: 'checked' };
  const first = await queueRecord(config, 'hypothesis', args, commit);
  const second = await queueRecord(config, 'hypothesis', args, commit);
  assert.notEqual(first.file, second.file);
  assert.match(first.event_id, /^[a-f0-9]{64}$/);
  assert.equal(first.hypothesis_id, `H-${first.event_id.slice(0, 12)}`);
  const markdown = await readFile(first.file, 'utf8');
  assert.match(markdown, /kind: "hypothesis"/);
  assert.match(markdown, new RegExp(`repo_commit: "${commit}"`));
  assert.equal(sha256(markdown).length, 64);
  await assert.rejects(queueRecord(config, 'hypothesis', { ...args, body: '' }, commit), /Invalid body/);
  await assert.rejects(queueRecord(config, 'hypothesis', { ...args, code_refs: [] }, commit), /code_refs required/);
  assert.equal((await readdir(path.dirname(first.file))).length, 2);

  const configPath = path.join(temp, 'pc1.json');
  await writeFile(configPath, JSON.stringify(config));
  await writeFile(path.join(temp, 'pc1.token'), 'f'.repeat(64));
  const child = spawn(process.execPath, [path.join(root, 'agent', 'mcp-agent.mjs'), configPath], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', errors = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { errors += chunk; });
  child.stdin.end([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25' } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ].map(item => JSON.stringify(item)).join('\n') + '\n');
  const [code] = await once(child, 'close');
  assert.equal(code, 0, errors);
  const replies = output.trim().split('\n').map(JSON.parse);
  assert.equal(replies.length, 2);
  assert.equal(replies[0].result.serverInfo.name, 'knfsd-hivemind-agent');
  assert(replies[1].result.tools.some(tool => tool.name === 'queue_verification'));
  assert(replies[1].result.tools.some(tool => tool.name === 'queue_finding'));
  assert(replies[1].result.tools.some(tool => tool.name === 'search_hypotheses'));

  await mkdir(path.join(temp, 'server'));
  const running = await startServer({ port: 0, dataDir: path.join(temp, 'server'), apiToken: 'admin' });
  ({ server, db } = running);
  const { url } = running;
  const issued = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer admin', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc1' }) });
  assert.equal(issued.status, 201);
  const { token } = await issued.json();
  const result = await handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_versions', arguments: {} } });
  assert.deepEqual(result.result.structuredContent.versions, []);

  execFileSync('git', ['init', '-q', temp]);
  execFileSync('git', ['-C', temp, 'config', 'core.autocrlf', 'false']);
  await writeFile(path.join(temp, 'source.c'), 'int main(void) { return 0; }\n');
  execFileSync('git', ['-C', temp, 'add', 'source.c']);
  execFileSync('git', ['-C', temp, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'test']);
  const call = () => handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'queue_hypothesis', arguments: args } });
  const queued = (await call()).result.structuredContent;
  assert.equal(queued.queued, true);
  assert.equal(queued.accepted, true);
  assert.deepEqual(queued.possible_matches, []);
  const { hypothesis_id } = queued;
  assert.equal((await readdir(path.join(temp, 'exchange', 'ack', 'pc1'))).length, 1);
  const verification = await handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'queue_verification', arguments: { title: '독립 추적', scope: args.scope, code_refs: args.code_refs, angle: 'static-trace', body: '분기 결과를 확인했다.', verification_of: hypothesis_id, method: '정적 추적', verdict: 'supports', prior_exposure: 'claim_only', based_on_event_ids: [] } } });
  assert.equal(verification.result.structuredContent.accepted, true);
  assert.equal((await readdir(path.join(temp, 'exchange', 'ack', 'pc1'))).length, 2);
  await writeFile(path.join(temp, 'poc.c'), 'int main(void) { return trigger(); }\n');
  await writeFile(path.join(temp, 'kasan.log'), 'BUG: KASAN: out-of-bounds in nfsd_main\nCall Trace:\n nfsd_main\n');
  const findingArgs = { title: '검증된 경계값 취약점 보고', scope: args.scope, code_refs: args.code_refs, angle: 'static-trace', body: '## 발견\n경계값 검증 결과를 보고한다.', finding_of: hypothesis_id, file_path: 'fs/nfsd/main.c', evidence_event_ids: [verification.result.structuredContent.event_id], impact: '특정 경계값에서 예상하지 못한 처리', reproduction_command: './poc', poc_path: 'poc.c', kasan_path: 'kasan.log' };
  const finding = await handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'queue_finding', arguments: findingArgs } });
  assert.equal(finding.result.structuredContent.accepted, true);
  assert.equal((await (await fetch(`${url}/api/dashboard`)).json()).findings[0].file_path, 'fs/nfsd/main.c');
  assert.equal(await (await fetch(`${url}/api/events/${finding.result.structuredContent.event_id}/poc`)).text(), 'int main(void) { return trigger(); }\n');
  await writeFile(path.join(temp, 'kasan.log'), 'No sanitizer report\n');
  const invalidFinding = await handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'queue_finding', arguments: findingArgs } });
  assert.equal(invalidFinding.result.isError, true);
  const repeated = (await call()).result.structuredContent;
  assert.equal(repeated.queued, false);
  assert.equal(repeated.possible_matches[0].id, hypothesis_id);
  assert.deepEqual(repeated.possible_matches[0].code_refs, args.code_refs);
  const distinct = await handleMessage({ ...config, server: url }, token, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'queue_hypothesis', arguments: { ...args, related_hypothesis_id: hypothesis_id, body: `${args.body}\n\n기존 가설과 조건이 다르다.` } } });
  assert.equal(distinct.result.structuredContent.queued, true);
  assert.equal(distinct.result.structuredContent.accepted, true);

  const offline = { ...config, server: 'http://127.0.0.1:65534' };
  const offlineCall = (name, arguments_) => handleMessage(offline, token, { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name, arguments: arguments_ } }).then(reply => reply.result.structuredContent);
  const pendingHypothesis = await offlineCall('queue_hypothesis', { ...args, title: '오프라인 가설', claim_key: 'offline-boundary' });
  assert.equal(pendingHypothesis.accepted, false);
  assert.match(pendingHypothesis.hypothesis_id, /^H-/);
  const pendingVerification = await offlineCall('queue_verification', { title: '오프라인 검증', scope: args.scope, code_refs: args.code_refs, angle: 'runtime-reproduction', body: '별도의 재현으로 지지했다.', verification_of: pendingHypothesis.hypothesis_id, method: '런타임 재현', verdict: 'supports', prior_exposure: 'none', based_on_event_ids: [] });
  assert.equal(pendingVerification.accepted, false);
  assert.match(pendingVerification.event_id, /^[a-f0-9]{64}$/);
  await writeFile(path.join(temp, 'kasan.log'), 'BUG: KASAN: out-of-bounds in nfsd_main\nCall Trace:\n nfsd_main\n');
  const pendingFinding = await offlineCall('queue_finding', { ...findingArgs, title: '오프라인 취약점 보고', finding_of: pendingHypothesis.hypothesis_id, evidence_event_ids: [pendingVerification.event_id] });
  assert.equal(pendingFinding.accepted, false);
  for (const item of [pendingHypothesis, pendingVerification, pendingFinding]) await utimes(item.file, 0, 0);

  await rename(pendingHypothesis.file, `${pendingHypothesis.file}.hold`);
  await syncExchange({ ...config, server: url }, token);
  assert.equal(db.prepare('SELECT 1 FROM events WHERE id = ?').get(pendingVerification.event_id), undefined);
  await rename(`${pendingHypothesis.file}.hold`, pendingHypothesis.file);
  await syncExchange({ ...config, server: url }, token);
  await syncExchange({ ...config, server: url }, token);
  for (const item of [pendingHypothesis, pendingVerification, pendingFinding]) assert(db.prepare('SELECT 1 FROM events WHERE id = ?').get(item.event_id));
});

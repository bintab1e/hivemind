import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { hash, userspacePocError, validateEvent } from './contract.mjs';
import { handleMessage } from './mcp-agent.mjs';

test('local MCP sends a direct PoC/KASAN finding without a support event', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'hivemind-mcp-'));
  const home = path.join(root, '.hivemind', 'agent', 'runtime');
  await mkdir(home, { recursive: true });
  await writeFile(path.join(root, 'poc.c'), 'int main(void) { return 0; }\n');
  await writeFile(path.join(root, 'kasan.log'), 'BUG: KASAN: use-after-free in nfsd4_open\nWrite of size 8 at addr deadbeef\n');
  execFileSync('git', ['init', root], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, 'add', 'poc.c'], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, '-c', 'user.name=test', '-c', 'user.email=test@example.com', 'commit', '-m', 'source'], { stdio: 'ignore' });
  const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const received = [];
  let findingRevisions = true;
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/sync/health') return res.end(JSON.stringify({ ok: true, exchange: { finding_revisions: findingRevisions } }));
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (req.url === '/mcp') return res.end(JSON.stringify({ result: { structuredContent: { matches: [] } } }));
    const event = validateEvent(body);
    received.push(event.data);
    const eventId = hash(`${event.data.version_id}\0pc1\0${body.source_path}`);
    res.end(JSON.stringify({ event_id: eventId }));
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  const config = { agent_id: 'pc1', track_id: 'rc', version_id: '7.3-rc4', repo_root: root, home, server: `http://127.0.0.1:${server.address().port}` };
  const invoke = (name, args) => handleMessage(config, 'a'.repeat(64), { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  const listed = await handleMessage(config, 'a'.repeat(64), { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert(!listed.result.tools.some(tool => /hypothesis|verification|correction|review_gaps/.test(tool.name)));
  assert(listed.result.tools.some(tool => tool.name === 'queue_finding_revision'));
  assert(listed.result.tools.find(tool => tool.name === 'queue_finding').inputSchema.required.includes('vm_environment'));
  assert.equal(listed.result.tools.find(tool => tool.name === 'queue_finding').inputSchema.properties.registry_report_status, undefined);
  const common = { title: 'NFSD boundary handling', scope: ['fs/nfsd/'], code_refs: ['fs/nfsd/nfs4proc.c#nfsd4_open'], angle: 'runtime-reproduction', body: '## 근거\n동일 커밋에서 재현했다.' };
  const findingArgs = { ...common, file_path: 'fs/nfsd/nfs4proc.c', access_requirements: ['auth_null'], verified_impacts: ['kasan_write'], impact: '메모리 오류를 확인했으며 코드 실행은 확인하지 못했다.', vm_environment: '서버 VM: KASAN 커널과 knfsd. 클라이언트 VM: NFS 요청을 보내는 별도 VM.', reproduction_command: 'cc -o poc poc.c && ./poc', poc_path: 'poc.c', kasan_path: 'kasan.log', registry_target: 'knfsd', registry_option: 'NFSv4.1', registry_privilege: 'AUTH_NONE', registry_report_project: 'Linux kernel', registry_owner: '테스터', registry_nfs_version: '4.1', registry_vulnerability_type: 'Race, UAF', registry_methodology: 'LLM', registry_found_date: '2026-10-12', registry_exploit: 'LPE', registry_cve: 'CVE-2026-1234' };
  const finding = (await invoke('queue_finding', findingArgs)).result.structuredContent;
  assert.equal(finding.accepted, true);
  assert.equal(finding.hypothesis_id, undefined);
  if (process.platform !== 'win32') {
    assert.equal((await stat(path.dirname(finding.file))).mode & 0o777, 0o700);
    assert.equal((await stat(finding.file)).mode & 0o777, 0o600);
  }
  const english = { ...common, body: '## Evidence\nObserved the same code path.' };
  const invalidFinding = (await invoke('queue_finding', { ...findingArgs, ...english, impact: 'Memory corruption' })).result;
  assert.equal(invalidFinding.isError, true);
  assert.match(invalidFinding.content[0].text, /한국어/);
  const missingVms = (await invoke('queue_finding', { ...findingArgs, vm_environment: '' })).result;
  assert.equal(missingVms.isError, true);
  assert.match(missingVms.content[0].text, /vm_environment/);
  const nfsFinding = (await invoke('queue_finding', { ...findingArgs, file_path: 'fs/nfs/main.c', scope: ['fs/nfs/'], code_refs: ['fs/nfs/main.c#nfs_call'] })).result.structuredContent;
  assert.equal(nfsFinding.accepted, true);
  const unsafePath = (await invoke('queue_finding', { ...findingArgs, file_path: '../fs/nfs/main.c' })).result;
  assert.equal(unsafePath.isError, true);
  assert.match(unsafePath.content[0].text, /file_path/);
  const unclassified = (await invoke('queue_finding', { ...findingArgs, verified_impacts: [] })).result;
  assert.equal(unclassified.isError, true);
  assert.match(unclassified.content[0].text, /verified_impacts/);
  for (const [key, value] of [['registry_target', 'NFS-Ganesha'], ['registry_found_date', '12.10'], ['registry_cve', 'not-a-cve'], ['registry_owner', 'bad\nowner'], ['registry_owner', 'a'.repeat(101)], ['registry_report_status', '제보 완료']]) {
    const invalidRegistry = (await invoke('queue_finding', { ...findingArgs, [key]: value })).result;
    assert.equal(invalidRegistry.isError, true, key);
    assert.match(invalidRegistry.content[0].text, new RegExp(key), key);
  }
  await writeFile(path.join(root, 'kernel-patch.c'), 'diff --git a/fs/nfsd/nfs4proc.c b/fs/nfsd/nfs4proc.c\n--- a/fs/nfsd/nfs4proc.c\n+++ b/fs/nfsd/nfs4proc.c\n@@ -1 +1 @@\n');
  const patchFinding = (await invoke('queue_finding', { ...findingArgs, reproduction_command: 'git apply kernel-patch.c && make', poc_path: 'kernel-patch.c' })).result;
  assert.equal(patchFinding.isError, true);
  assert.match(patchFinding.content[0].text, /커널 패치가 아닌 독립 실행형/);
  await writeFile(path.join(root, 'poc.c'), 'int main(void) { return 1; }\n');
  const dirtyFinding = (await invoke('queue_finding', findingArgs)).result;
  assert.equal(dirtyFinding.isError, true);
  assert.match(dirtyFinding.content[0].text, /깨끗한 커널 소스/);
  execFileSync('git', ['-C', root, 'restore', 'poc.c']);
  await writeFile(path.join(root, 'poc-v2.c'), 'int main(void) { return 2; }\n');
  await writeFile(path.join(root, 'kasan-v2.log'), 'BUG: KASAN: use-after-free in nfsd4_open\nWrite of size 4 at addr deadbeef\n');
  const revision = (await invoke('queue_finding_revision', { ...findingArgs, title: 'NFSD corrected finding', body: '## 정정 근거\nPoC와 보고 원문을 다시 확인했다.', corrects_event_id: finding.event_id, reproduction_command: '/usr/bin/gcc -o poc-v2 poc-v2.c && ./poc-v2', poc_path: 'poc-v2.c', kasan_path: 'kasan-v2.log' })).result.structuredContent;
  assert.equal(revision.accepted, true);
  assert.equal(revision.corrects_event_id, finding.event_id);
  findingRevisions = false;
  const unsupportedRevision = (await invoke('queue_finding_revision', { ...findingArgs, corrects_event_id: revision.event_id, poc_path: 'poc-v2.c', kasan_path: 'kasan-v2.log' })).result;
  assert.equal(unsupportedRevision.isError, true);
  assert.match(unsupportedRevision.content[0].text, /서버를 먼저 업데이트/);
  assert.deepEqual(received.map(item => item.kind), ['finding', 'finding', 'finding']);
  assert.equal(received[0].evidence_event_ids, undefined);
  assert.equal(received[0].finding_of, undefined);
  assert.deepEqual(received[0].access_requirements, ['auth_null']);
  assert.deepEqual(received[0].verified_impacts, ['kasan_write']);
  for (const key of ['registry_target', 'registry_option', 'registry_privilege', 'registry_report_project', 'registry_owner', 'registry_nfs_version', 'registry_vulnerability_type', 'registry_methodology', 'registry_found_date', 'registry_exploit', 'registry_cve']) assert.equal(received[0][key], findingArgs[key], key);
  assert.equal(received[0].registry_report_status, undefined);
  assert.equal(received[1].file_path, 'fs/nfs/main.c');
  assert.equal(received[2].corrects_event_id, finding.event_id);
  assert.equal(received[2].registry_cve, findingArgs.registry_cve);
  assert.match(await readFile(finding.file, 'utf8'), /BUG: KASAN:/);
  assert.match(await readFile(revision.file, 'utf8'), /return 2/);
});

test('standalone PoC validation accepts common compiler and build-tool forms', () => {
  const source = 'int main(void) { return 0; }\n';
  for (const command of [
    '/usr/bin/gcc -o poc poc.c && ./poc',
    'x86_64-linux-gnu-gcc -o poc poc.c && ./poc',
    'CC=clang make poc && ./poc',
    'cmake --build build && ./build/poc',
    'ninja -C build poc && ./build/poc',
  ]) assert.equal(userspacePocError(source, command), null, command);
  assert.match(userspacePocError(source, './poc'), /컴파일/);
});

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { handleMessage } from './mcp-agent.mjs';
import { buildSubmission, queueSubmission, syncSubmissions } from './submissions.mjs';

test('strengthened submission carries a validated existing management ID', async () => {
  const config = { repo_root: '/unused', home: '/unused', version_id: '7.3-rc4', track_id: 'rc' };
  const args = { report: 'Strengthened primitive evidence', existing_management_id: 'A-005' };
  const body = await buildSubmission(config, args, 'a'.repeat(40));
  assert.equal(body.metadata.existing_management_id, 'A-005');
  assert.equal(body.existing_management_id, undefined);
  await assert.rejects(buildSubmission(config, { ...args, existing_management_id: 'B-005' }, 'a'.repeat(40)), /Invalid existing_management_id/);
  await assert.rejects(buildSubmission(config, { ...args, metadata: { existing_management_id: 'A-999' } }, 'a'.repeat(40)), /top level/);
});

test('raw MCP submission accepts varied files without KASAN and retries with one ID', async t => {
  const base = await mkdtemp(path.join(tmpdir(), 'hivemind-submission-'));
  const root = path.join(base, 'linux');
  const home = path.join(base, 'runtime');
  await mkdir(root);
  await mkdir(path.join(home, 'evidence'), { recursive: true });
  await writeFile(path.join(root, 'poc.c'), 'int main(void) { return 0; }\n');
  await writeFile(path.join(root, 'notes.md'), '# 원본 분석\n');
  await writeFile(path.join(root, 'reproduction.md'), '# VM 절차\n');
  await writeFile(path.join(home, 'evidence', 'repro.py'), 'print("repro")\n');
  await writeFile(path.join(home, 'pc1.token'), 'private token');
  execFileSync('git', ['init', root], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, 'add', 'poc.c'], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, '-c', 'user.name=test', '-c', 'user.email=test@example.com', 'commit', '-m', 'kernel'], { stdio: 'ignore' });
  const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  let unavailable = false;
  let reject = false;
  const received = [];
  const server = createServer(async (req, res) => {
    assert.equal(req.url, '/v1/submissions');
    assert.equal(req.headers.authorization, `Bearer ${'a'.repeat(64)}`);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    received.push(body);
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = unavailable ? 503 : reject ? 413 : 202;
    res.end(unavailable ? '{"error":"temporarily unavailable"}' : reject ? '{"error":"rejected"}' : JSON.stringify({ submission_id: `server-${received.length}`, status: 'pending', replayed: false }));
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(base, { recursive: true, force: true }); });
  const config = { agent_id: 'pc1', track_id: 'rc', version_id: '7.3-rc4', repo_root: root, home, server: `http://127.0.0.1:${server.address().port}` };
  const invoke = args => handleMessage(config, 'a'.repeat(64), { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'submit_vulnerability', arguments: args } });
  const listed = await handleMessage(config, 'a'.repeat(64), { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert(listed.result.tools.some(tool => tool.name === 'submit_vulnerability'));

  const args = { title: 'Potential knfsd issue', report: 'Observed suspicious path', metadata: { nfs_version: '4.1', repo_commit: 'forged' }, files: [
    { path: 'poc.c' }, { path: 'notes.md', kind: 'report' }, { path: 'reproduction.md' }, { path: path.join(home, 'evidence', 'repro.py') },
  ] };
  const first = (await invoke(args)).result.structuredContent;
  assert.equal(first.delivered, true);
  assert.equal(first.status, 'pending');
  assert.equal(received[0].project, 'knfsd');
  assert.equal(received[0].metadata.repo_commit, commit);
  assert.equal(received[0].metadata.nfs_version, '4.1');
  assert.deepEqual(received[0].files.map(file => file.kind), ['poc', 'report', 'other', 'poc']);
  assert.equal(Buffer.from(received[0].files[0].content_base64, 'base64').toString('utf8'), 'int main(void) { return 0; }\n');
  assert(!JSON.stringify(received[0]).includes(root));
  assert(!JSON.stringify(received[0]).includes('private token'));
  assert.equal((await readdir(path.join(home, 'submissions', 'outbox', 'pc1'))).length, 0);
  const ack = JSON.parse(await readFile(path.join(home, 'submissions', 'ack', 'pc1', `${first.client_submission_id}.json`), 'utf8'));
  assert.equal(ack.result.submission_id, first.submission_id);

  const replay = (await invoke({ ...args, client_submission_id: first.client_submission_id })).result.structuredContent;
  assert.equal(replay.replayed, true);
  assert.equal(received.length, 1);

  unavailable = true;
  const pending = (await invoke({ report: 'No log yet', files: [{ path: 'poc.c' }] })).result.structuredContent;
  assert.equal(pending.status, 'local_pending');
  const pendingPath = path.join(home, 'submissions', 'outbox', 'pc1', `${pending.client_submission_id}.json`);
  const stale = new Date(Date.now() - 3000);
  await utimes(pendingPath, stale, stale);
  unavailable = false;
  await syncSubmissions(config, 'a'.repeat(64));
  assert.equal(received[1].client_submission_id, received[2].client_submission_id);
  assert.equal((await readdir(path.dirname(pendingPath))).length, 0);

  reject = true;
  const refused = (await invoke({ report: 'Rejected sample', files: [] })).result;
  assert.equal(refused.isError, true);
  assert.equal(refused.structuredContent.status, 'local_rejected');
  const rejectedId = refused.structuredContent.client_submission_id;
  const rejectedFile = path.join(path.dirname(pendingPath), `${rejectedId}.json`);
  assert.equal(JSON.parse(await readFile(rejectedFile, 'utf8')).report, 'Rejected sample');
  const rejectedMarker = path.join(home, 'submissions', 'ack', 'pc1', `${rejectedId}.rejected.json`);
  assert.match(await readFile(rejectedMarker, 'utf8'), /rejected/);
});

test('raw MCP submission rejects path traversal, hidden files and symlinks', async t => {
  const base = await mkdtemp(path.join(tmpdir(), 'hivemind-submission-paths-'));
  const root = path.join(base, 'linux');
  const home = path.join(base, 'runtime');
  await mkdir(root);
  await mkdir(home);
  await writeFile(path.join(root, 'poc.c'), 'int main(void) { return 0; }\n');
  await writeFile(path.join(root, '.secret'), 'secret');
  await writeFile(path.join(base, 'outside.log'), 'outside');
  await symlink(path.join(root, 'poc.c'), path.join(root, 'link.c'));
  await symlink(root, path.join(root, 'linked-directory'));
  execFileSync('git', ['init', root], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, 'add', 'poc.c'], { stdio: 'ignore' });
  execFileSync('git', ['-C', root, '-c', 'user.name=test', '-c', 'user.email=test@example.com', 'commit', '-m', 'kernel'], { stdio: 'ignore' });
  t.after(() => rm(base, { recursive: true, force: true }));
  const config = { agent_id: 'pc1', track_id: 'rc', version_id: '7.3-rc4', repo_root: root, home, server: 'http://127.0.0.1:1' };
  const invoke = file => handleMessage(config, 'a'.repeat(64), { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'submit_vulnerability', arguments: { files: [{ path: file }] } } });
  for (const file of [path.join(base, 'outside.log'), '../outside.log', '.secret', 'link.c', 'linked-directory/poc.c', path.join(home, 'pc1.token')]) {
    const result = (await invoke(file)).result;
    assert.equal(result.isError, true, file);
  }
});

test('queue publishes complete JSON atomically and an ID collision cannot overwrite it', async t => {
  const home = await mkdtemp(path.join(tmpdir(), 'hivemind-queue-atomic-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const config = { home, agent_id: 'pc1' };
  const first = { project: 'knfsd', client_submission_id: 'same-0001', report: 'first', metadata: {}, files: [] };
  const second = { ...first, report: 'second' };
  const results = await Promise.allSettled([queueSubmission(config, first), queueSubmission(config, second)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter(result => result.status === 'rejected').length, 1);
  const winner = results[0].status === 'fulfilled' ? first : second;
  const folder = path.join(home, 'submissions', 'outbox', 'pc1');
  assert.deepEqual(await readdir(folder), ['same-0001.json']);
  assert.deepEqual(JSON.parse(await readFile(path.join(folder, 'same-0001.json'), 'utf8')), winner);
});

test('sync preserves a malformed old payload and continues with later valid submissions', async t => {
  const home = await mkdtemp(path.join(tmpdir(), 'hivemind-queue-malformed-'));
  const received = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    res.setHeader('Content-Type', 'application/json');
    res.end('{"submission_id":"server-valid","status":"pending"}');
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(home, { recursive: true, force: true }); });
  const config = { home, agent_id: 'pc1', server: `http://127.0.0.1:${server.address().port}` };
  const folder = path.join(home, 'submissions', 'outbox', 'pc1');
  await mkdir(folder, { recursive: true });
  const corrupt = path.join(folder, 'aaaaaaaa.json');
  await writeFile(corrupt, '{"project":"knfsd",', { mode: 0o600 });
  const valid = { project: 'knfsd', client_submission_id: 'zzzzzzzz', report: 'valid', metadata: {}, files: [] };
  await queueSubmission(config, valid);
  const stale = new Date(Date.now() - 3000);
  await Promise.all([utimes(corrupt, stale, stale), utimes(path.join(folder, 'zzzzzzzz.json'), stale, stale)]);
  await syncSubmissions(config, 'a'.repeat(64));
  assert.deepEqual(received, [valid]);
  assert.equal(await readFile(corrupt, 'utf8'), '{"project":"knfsd",');
  assert.deepEqual(await readdir(folder), ['aaaaaaaa.json']);
  assert.match(await readFile(path.join(home, 'submissions', 'ack', 'pc1', 'aaaaaaaa.malformed.json'), 'utf8'), /Malformed queued submission/);
  await syncSubmissions(config, 'a'.repeat(64));
  assert.equal(received.length, 1);
});

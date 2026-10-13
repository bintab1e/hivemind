import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { availablePrimitiveSources, primitiveConfiguration, primitiveWorkerId, runPrimitiveOnce } from './primitive-worker.mjs';

const commit = 'a'.repeat(40);
const findingId = 'b'.repeat(64);
const leaseToken = 'c'.repeat(64);
const config = { socketPath: '/tmp/verifier.sock', cliPath: '/usr/bin/codex',
  workRoot: '/tmp/primitive-work', sourceDirs: ['/trusted/kernel-stable', '/trusted/kernel-rc'] };
const job = { finding_id: findingId, lease_token: leaseToken, management_id: 'A-043',
  title: 'NFSv4 boundary read', repo_commit: commit, file_path: 'fs/nfsd/nfs4proc.c',
  code_refs: ['fs/nfsd/nfs4proc.c:1'], nfs_version: '4.2', privilege: 'AUTH_SYS',
  verified_impacts: ['kasan_read'], report: '## Summary\nA read was observed.',
  poc_source: 'int main(void) { return 0; }\n', kasan_log: 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n' };

test('primitive worker configuration and identity are stable per service', () => {
  assert.deepEqual(primitiveConfiguration({ HIVEMIND_VERIFIER_SOCKET: config.socketPath,
    HIVEMIND_CODEX_CLI: config.cliPath, HIVEMIND_PRIMITIVE_WORK_ROOT: config.workRoot,
    HIVEMIND_PRIMITIVE_KERNEL_SOURCES: config.sourceDirs.join(':') }), config);
  assert.throws(() => primitiveConfiguration({}), /not_configured/);
  assert.match(primitiveWorkerId(config, 'host-a'), /^[a-f0-9]{32}$/);
  assert.equal(primitiveWorkerId(config, 'host-a'), primitiveWorkerId({ ...config }, 'host-a'));
  assert.notEqual(primitiveWorkerId(config, 'host-a'), primitiveWorkerId(config, 'host-b'));
});

test('primitive worker advertises only clean pinned kernel checkouts', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'primitive-kernel-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim();
  git('init', '-q');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.invalid');
  fs.writeFileSync(path.join(directory, 'source.c'), 'int source;\n');
  git('add', '.');
  git('commit', '-qm', 'fixture');
  const head = git('rev-parse', 'HEAD');
  assert.deepEqual([...availablePrimitiveSources({ ...config, sourceDirs: [directory] })], [[head, directory]]);
  fs.writeFileSync(path.join(directory, 'untracked.txt'), 'dirty');
  assert.equal(availablePrimitiveSources({ ...config, sourceDirs: [directory] }).size, 0);
});

test('primitive worker reviews only claimed approved evidence and submits a separate opinion', async () => {
  const calls = [];
  const transport = async (socket, endpoint, body) => {
    calls.push({ socket, endpoint, body });
    return endpoint === '/primitive/claim' ? { job } : {};
  };
  const trustedSource = { commit, files: [{ path: job.file_path, lines: [{ number: 1, text: 'int nfsd4_proc_compound(void) { return 0; }' }] }] };
  const result = await runPrimitiveOnce({ config, workerId: 'd'.repeat(32), transport,
    sourceDiscovery: () => new Map([[commit, '/trusted/kernel-rc']]),
    sourceLoader: (directory, sourceCommit, submission) => {
      assert.equal(directory, '/trusted/kernel-rc');
      assert.equal(sourceCommit, commit);
      assert.equal(submission.metadata.file_path, job.file_path);
      return trustedSource;
    },
    reviewer: (received, options) => {
      assert.equal(received, job);
      assert.equal(options.trustedSource, trustedSource);
      return { summary: 'Controlled Read 가능성 — 소스의 길이 처리 추가 검토 권장.' };
    } });
  assert.equal(result, true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/primitive/heartbeat', '/primitive/claim',
    '/primitive/heartbeat', '/primitive/complete', '/primitive/heartbeat']);
  assert.deepEqual(calls.find(call => call.endpoint === '/primitive/claim').body,
    { worker_id: 'd'.repeat(32), supported_commits: [commit] });
  assert.deepEqual(calls.find(call => call.endpoint === '/primitive/complete').body,
    { finding_id: findingId, lease_token: leaseToken, summary: 'Controlled Read 가능성 — 소스의 길이 처리 추가 검토 권장.' });
});

test('primitive worker completes with no added opinion when no high-value direction is grounded', async () => {
  const calls = [];
  const transport = async (_, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/primitive/claim' ? { job } : {};
  };
  await runPrimitiveOnce({ config, transport, sourceDiscovery: () => new Map([[commit, '/trusted/kernel-rc']]),
    sourceLoader: () => ({ commit, files: [] }), reviewer: () => ({ summary: null }) });
  assert.equal(calls.find(call => call.endpoint === '/primitive/complete').body.summary, null);
  assert.equal(calls.some(call => call.endpoint === '/primitive/fail'), false);
});

test('primitive worker records review failure without exposing submitted evidence', async () => {
  const calls = [];
  const transport = async (_, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/primitive/claim' ? { job } : {};
  };
  await runPrimitiveOnce({ config, transport, sourceDiscovery: () => new Map([[commit, '/trusted/kernel-rc']]),
    sourceLoader: () => ({ commit, files: [] }), reviewer: () => { throw new Error('sensitive report text'); } });
  assert.deepEqual(calls.find(call => call.endpoint === '/primitive/fail').body,
    { finding_id: findingId, lease_token: leaseToken, reason: 'primitive_review_failed' });
});

test('primitive worker runs lease cleanup but does not claim work when no clean kernel checkout exists', async () => {
  const calls = [];
  const worked = await runPrimitiveOnce({ config, sourceDiscovery: () => new Map(),
    transport: async (_, endpoint, body) => {
      calls.push({ endpoint, body });
      return endpoint === '/primitive/claim' ? { job: null } : {};
    } });
  assert.equal(worked, false);
  assert.deepEqual(calls.map(call => call.endpoint), ['/primitive/heartbeat', '/primitive/claim']);
  assert.deepEqual(calls[1].body.supported_commits, []);
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CodexReviewError, VerifierUnavailableError } from './codex.mjs';
import { postJson, runWorkerOnce, stableWorkerId } from './worker.mjs';

const commit = 'a'.repeat(40);
const id = 'b'.repeat(64);
const leaseToken = 'c'.repeat(64);
const source = 'int main(void) { return 0; }\n';
const trustedSource = { commit, files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [{ number: 1, text: 'int nfsd4_proc_compound(void) { return 0; }' }] }] };
const sourceLoader = async () => trustedSource;
const job = {
  submission_id: id, lease_token: leaseToken, agent_id: 'pc1', project: 'knfsd', title: 'candidate', report: 'Untrusted report',
  metadata: { repo_commit: commit, version_id: '7.3', nfs_version: '4.2', reproduction_command: 'touch /host/never' },
  files: [
    { name: 'fallback.py', kind: 'poc', content_base64: Buffer.from('print("test")\n').toString('base64') },
    { name: 'arbitrary-name.c', kind: 'poc', content_base64: Buffer.from(source).toString('base64') },
    { name: 'report.txt', kind: 'report', content_base64: Buffer.from('BUG: KASAN: test\nRead of size 4\n').toString('base64') },
  ],
};

function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-worker-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const kernelInfoPath = path.join(dir, 'kernel-info.json');
  const vmlinuxImage = path.join(dir, 'vmlinux');
  fs.writeFileSync(vmlinuxImage, 'trusted-symbol-image');
  fs.writeFileSync(kernelInfoPath, JSON.stringify({ sourceCommit: commit,
    vmlinuxSha256: createHash('sha256').update('trusted-symbol-image').digest('hex') }));
  return { dir, config: { socketPath: path.join(dir, 'verifier.sock'), cliPath: '/usr/bin/codex', kernelImage: '/trusted/bzImage', vmlinuxImage,
    kernelInfoPath, kernelSource: '/trusted/linux', rootfsImage: '/trusted/rootfs.raw', workRoot: dir } };
}

test('worker identity is stable across restarts and distinct per service target', t => {
  const { config, dir } = setup(t);
  const first = stableWorkerId(config, 'verifier-host');
  assert.match(first, /^[a-f0-9]{32}$/);
  assert.equal(stableWorkerId({ ...config }, 'verifier-host'), first);
  assert.notEqual(stableWorkerId(config, 'another-host'), first);
  assert.notEqual(stableWorkerId({ ...config, workRoot: path.join(dir, 'another-work-root') }, 'verifier-host'), first);
  const otherKernelInfoPath = path.join(dir, 'other-kernel-info.json');
  fs.copyFileSync(config.kernelInfoPath, otherKernelInfoPath);
  assert.notEqual(stableWorkerId({ ...config, kernelInfoPath: otherKernelInfoPath }, 'verifier-host'), first);
  fs.writeFileSync(config.kernelInfoPath, JSON.stringify({ sourceCommit: 'f'.repeat(40) }));
  assert.notEqual(stableWorkerId(config, 'verifier-host'), first);
});

test('uses exact original C PoC and fixed guest manifest, sends only post-PoC server evidence', async t => {
  const { dir, config } = setup(t);
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/claim' ? { job } : { status: 'needs_review' };
  };
  const reviewer = async (submission, options) => {
    assert.equal(submission.files[1].content, source);
    assert.equal(submission.report, 'Untrusted report');
    assert.equal(options.trustedSource, trustedSource);
    return {
      verdict: 'likely', reason: 'Plausible only', model: 'test',
      grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1, text: trustedSource.files[0].lines[0].text }] },
      normalized: { title: 'Candidate', report: '정적 검토', file_path: 'fs/nfsd/nfs4proc.c', nfs_version: '4.2',
        poc: { source_index: 1, source, original_name: 'arbitrary-name.c', filename: 'poc.c', language: 'c', build_command: 'touch /host/never', run_command: 'touch /host/never' },
        logs: [{ filename: 'evidence-1.log', original_name: 'report.txt', source_index: 2, content: 'Large raw log remains in submission artifacts' }] },
    };
  };
  const runner = async ({ bundleDir, outputDir }) => {
    assert.equal(fs.readFileSync(path.join(bundleDir, 'poc.c'), 'utf8'), source);
    const manifest = JSON.parse(fs.readFileSync(path.join(bundleDir, 'manifest.json'), 'utf8'));
    assert.deepEqual(Object.keys(manifest).sort(), ['expected', 'files', 'mount', 'nfsVersion', 'poc', 'project', 'schemaVersion', 'targetCommit'].sort());
    assert.equal(manifest.targetCommit, commit);
    assert.equal(manifest.poc, 'poc.c');
    fs.mkdirSync(outputDir);
    const prefix = '부팅 전\nBUG: KASAN: unrelated\n';
    const serverSerialPath = path.join(outputDir, 'server.serial.log');
    fs.writeFileSync(serverSerialPath, `${prefix}BUG: KASAN: slab-out-of-bounds\nRead of size 4\n nfsd4_proc_compound+0x4/0x20\n`);
    return { status: 'observed', reason: 'observed', kernelCommit: commit,
      observation: { guestCompleted: true, targetCommitMatch: true, pocStarted: true, baselineClean: true, serverEvidenceAfterPoc: true, serverEvidenceStartOffset: Buffer.byteLength(prefix) },
      evidence: { serverSerialPath } };
  };
  const symbolizer = async ({ serverSerial, vmlinuxPath, kernelInfo, sourceDir }) => {
    assert.match(serverSerial, /nfsd4_proc_compound\+0x4\/0x20/);
    assert.equal(vmlinuxPath, config.vmlinuxImage);
    assert.equal(sourceDir, config.kernelSource);
    assert.match(kernelInfo.vmlinuxSha256, /^[a-f0-9]{64}$/);
    return [{ trace_line: 'nfsd4_proc_compound+0x4/0x20', locations: [{ path: 'fs/nfsd/nfs4proc.c', line: 17 }] }];
  };
  const relevanceReviewer = async ({ review, serverSerial, pocSource, trustedSource: context, symbolizedFrames }) => {
    assert.equal(review.grounding.source_commit, commit);
    assert.equal(context, trustedSource);
    assert.equal(pocSource, source);
    assert.match(serverSerial, /nfsd4_proc_compound\+0x4\/0x20/);
    assert.equal(symbolizedFrames[0].locations[0].line, 17);
    return { verdict: 'supports', reason: 'Matching KASAN frame', trace_line: 'nfsd4_proc_compound+0x4/0x20', source_path: 'fs/nfsd/nfs4proc.c', source_line: 1, poc_line: 1 };
  };
  assert.equal(await runWorkerOnce({ config, transport, reviewer, sourceLoader, relevanceReviewer, symbolizer, runner,
    workerId: 'd'.repeat(32) }), true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/claim', '/heartbeat', '/progress', '/progress', '/progress', '/progress', '/complete', '/heartbeat']);
  assert.deepEqual(calls[0].body, { target_commit: commit });
  assert.deepEqual(calls.filter(call => call.endpoint === '/progress').map(call => call.body.phase),
    ['static_review', 'qemu_reproduction', 'trace_review', 'finalizing']);
  assert.equal(calls[1].body.submission_id, id);
  assert.equal(calls.at(-1).body.submission_id, null);
  const completed = calls.find(call => call.endpoint === '/complete').body;
  assert.equal(completed.submission_id, id);
  assert.equal(completed.lease_token, leaseToken);
  assert.match(completed.result.server_serial, /^BUG: KASAN: slab-out-of-bounds/);
  assert.doesNotMatch(completed.result.server_serial, /unrelated|부팅 전/);
  assert.equal(completed.result.reproduction.evidence, undefined);
  assert.equal(completed.result.review.relevance.verdict, 'supports');
  assert.equal(completed.result.review.relevance.symbolized_path, 'fs/nfsd/nfs4proc.c');
  assert.equal(completed.result.review.relevance.symbolized_line, 17);
  assert.deepEqual(completed.result.review.normalized.logs, [{ filename: 'evidence-1.log', original_name: 'report.txt', source_index: 2 }]);
  assert.equal(fs.readdirSync(dir).some(name => name.startsWith('hv-')), false);
});

test('malformed PoC text fails closed and still completes the leased job', async t => {
  const { config } = setup(t);
  const calls = [];
  const bad = { ...job, files: [{ name: 'poc.c', kind: 'poc', content_base64: Buffer.from([0xff, 0xfe]).toString('base64') }] };
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/claim' ? { job: bad } : {};
  };
  assert.equal(await runWorkerOnce({ config, transport, sourceLoader, reviewer: () => { throw new Error('must not review'); }, runner: () => { throw new Error('must not run'); } }), true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/claim', '/complete']);
  assert.deepEqual([calls[1].body.result.review.verdict, calls[1].body.result.reproduction.status], ['uncertain', 'inconclusive']);
  assert.equal(calls[1].body.result.server_serial, '');
});

test('enhancement with a different root cause stops before 2VM reproduction', async t => {
  const { config } = setup(t);
  let completed;
  const enhancement = { ...job, metadata: { ...job.metadata, existing_management_id: 'A-005' },
    existing_finding: { management_id: 'A-005', title: 'Old flaw', file_path: 'fs/nfsd/nfs4proc.c',
      report: 'An earlier root cause.' } };
  const transport = async (_socket, endpoint, body) => endpoint === '/claim' ? { job: enhancement } :
    (endpoint === '/complete' ? (completed = body, {}) : {});
  await runWorkerOnce({ config, transport, sourceLoader,
    reviewer: async () => ({ verdict: 'likely', reason: 'Plausible', model: 'test',
      grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1,
        text: trustedSource.files[0].lines[0].text }] },
      normalized: { file_path: 'fs/nfsd/nfs4proc.c', report: 'A new root cause.' } }),
    sameRootReviewer: async () => ({ verdict: 'different', reason: 'Different source invariant' }),
    runner: async () => { throw new Error('2VM must not run'); } });
  assert.equal(completed.result.review.same_root_cause.verdict, 'different');
  assert.equal(completed.result.reproduction.status, 'inconclusive');
});

test('missing or changed trusted kernel source prevents static review and VM execution', async t => {
  const { config } = setup(t);
  let completed;
  const transport = async (_socket, endpoint, body) => endpoint === '/claim' ? { job } : (completed = body, {});
  await runWorkerOnce({ config, transport,
    sourceLoader: () => { throw new Error('source commit changed'); },
    reviewer: () => { throw new Error('must not review'); },
    runner: () => { throw new Error('must not run'); } });
  assert.equal(completed.result.review.verdict, 'uncertain');
  assert.equal(completed.result.reproduction.status, 'inconclusive');
});

test('failed completion is retried then explicitly fails the lease', async t => {
  const { config } = setup(t);
  const endpoints = [];
  const bodies = [];
  const transport = async (_socket, endpoint, body) => {
    endpoints.push(endpoint);
    bodies.push(body);
    if (endpoint === '/claim') return { job };
    if (endpoint === '/complete') { const error = new Error('unprocessable'); error.status = 422; throw error; }
    return { status: 'error' };
  };
  await assert.rejects(runWorkerOnce({ config, transport, sourceLoader, reviewer: () => { throw new Error('offline'); } }), /completion_delivery_failed/);
  assert.deepEqual(endpoints, ['/claim', '/complete', '/fail']);
  assert.equal(bodies[1].lease_token, leaseToken);
  assert.equal(bodies[2].lease_token, leaseToken);
});

test('observed KASAN remains inconclusive when post-QEMU relevance is uncertain', async t => {
  const { config } = setup(t);
  let completed;
  const transport = async (_socket, endpoint, body) => {
    if (endpoint === '/claim') return { job };
    completed = body;
    return {};
  };
  const reviewer = async () => ({ verdict: 'likely', reason: 'Plausible', model: 'test',
    grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1, text: trustedSource.files[0].lines[0].text }] },
    normalized: { file_path: 'fs/nfsd/nfs4proc.c', nfs_version: '4.2',
      poc: { source_index: 1, source, original_name: 'arbitrary-name.c', filename: 'poc.c', language: 'c' } } });
  const runner = async ({ outputDir }) => {
    fs.mkdirSync(outputDir);
    const serverSerialPath = path.join(outputDir, 'server.serial.log');
    fs.writeFileSync(serverSerialPath, 'BUG: KASAN: test\nframe fs/nfsd/nfs4proc.c:1\n');
    return { status: 'observed', kernelCommit: commit, observation: { guestCompleted: true, targetCommitMatch: true, pocStarted: true,
      baselineClean: true, serverEvidenceAfterPoc: true, serverEvidenceStartOffset: 0 }, evidence: { serverSerialPath } };
  };
  const relevanceReviewer = async () => ({ verdict: 'uncertain', reason: 'Trace does not establish the claimed fault',
    trace_line: null, source_path: null, source_line: null, poc_line: null });
  await runWorkerOnce({ config, transport, reviewer, sourceLoader, relevanceReviewer, symbolizer: async () => [], runner });
  assert.equal(completed.result.review.relevance.verdict, 'uncertain');
  assert.equal(completed.result.reproduction.status, 'inconclusive');
});

test('transient completion error is retried without releasing a successful lease', async t => {
  const { config } = setup(t);
  const endpoints = [];
  let attempts = 0;
  const transport = async (_socket, endpoint) => {
    endpoints.push(endpoint);
    if (endpoint === '/claim') return { job };
    if (endpoint === '/complete' && attempts++ === 0) { const error = new Error('temporary'); error.status = 500; throw error; }
    return { status: 'needs_review' };
  };
  assert.equal(await runWorkerOnce({ config, transport, sourceLoader, reviewer: () => { throw new Error('offline'); } }), true);
  assert.deepEqual(endpoints, ['/claim', '/complete', '/complete']);
});

test('IPC client sends JSON only to the local Unix socket', async t => {
  const { config } = setup(t);
  const server = http.createServer(async (request, response) => {
    assert.equal(request.url, '/claim');
    assert.equal(request.method, 'POST');
    let body = '';
    for await (const chunk of request) body += chunk;
    assert.deepEqual(JSON.parse(body), { target_commit: commit });
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ job: null }));
  });
  await new Promise(resolve => server.listen(config.socketPath, resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.deepEqual(await postJson(config.socketPath, '/claim', { target_commit: commit }), { job: null });
  assert.throws(() => postJson(config.socketPath, '/patch/claim', {}), error => error.code === 'invalid_request');
});

test('duplicate worker IPC routes are available on the same local socket', async t => {
  const { config } = setup(t);
  const routes = [];
  const server = http.createServer(async (request, response) => {
    routes.push(request.url);
    assert.equal(request.method, 'POST');
    let body = '';
    for await (const chunk of request) body += chunk;
    assert.deepEqual(JSON.parse(body), {});
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(request.url.endsWith('candidates') ? { candidates: [] } : { status_changed: false }));
  });
  await new Promise(resolve => server.listen(config.socketPath, resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.deepEqual(await postJson(config.socketPath, '/duplicate/candidates', {}), { candidates: [] });
  assert.deepEqual(await postJson(config.socketPath, '/duplicate/result', {}), { status_changed: false });
  assert.deepEqual(await postJson(config.socketPath, '/duplicate/internal-candidates', {}), { candidates: [] });
  assert.deepEqual(await postJson(config.socketPath, '/duplicate/internal-result', {}), { status_changed: false });
  assert.deepEqual(routes, ['/duplicate/candidates', '/duplicate/result', '/duplicate/internal-candidates', '/duplicate/internal-result']);
});

test('worker does not claim a job without a pinned full kernel commit', async t => {
  const { config } = setup(t);
  fs.writeFileSync(config.kernelInfoPath, JSON.stringify({ sourceCommit: 'main' }));
  await assert.rejects(runWorkerOnce({ config, transport: () => { throw new Error('claim must not happen'); } }),
    error => error.code === 'kernel_commit_unavailable');
});

test('static-review failures expose only typed error codes', async t => {
  const { config } = setup(t);
  for (const [failure, reviewReason, runReason] of [
    [new CodexReviewError('runtime_failure'), 'runtime_failure', 'runtime_failure'],
    [new Error('private submitted evidence'), 'Static review unavailable', 'Verifier environment unavailable'],
  ]) {
    let completed;
    const transport = async (_socket, endpoint, body) => {
      if (endpoint === '/claim') return { job };
      if (endpoint === '/complete') completed = body.result;
      return {};
    };
    const reviewer = async () => { throw failure; };
    assert.equal(await runWorkerOnce({ config, transport, reviewer, sourceLoader }), true);
    assert.equal(completed.review.reason, reviewReason);
    assert.equal(completed.reproduction.reason, runReason);
    assert.equal(completed.server_serial, '');
    assert.doesNotMatch(JSON.stringify(completed), /private submitted evidence/);
  }
});

test('persistent verifier infrastructure failures mark the lease error without running a PoC', async t => {
  const { config } = setup(t);
  for (const failure of [new CodexReviewError('network_connection_reset'), new CodexReviewError('cli_nonzero_exit'),
    new CodexReviewError('turn_failed'), new CodexReviewError('turn_incomplete'),
    new CodexReviewError('cli_output_too_large'), new VerifierUnavailableError()]) {
    const calls = [];
    const transport = async (_socket, endpoint, body) => {
      calls.push({ endpoint, body });
      return endpoint === '/claim' ? { job } : {};
    };
    const reviewer = async () => { throw failure; };
    const runner = async () => { throw new Error('PoC must not run'); };
    assert.equal(await runWorkerOnce({ config, transport, reviewer, sourceLoader, runner }), true);
    assert.deepEqual(calls.map(call => call.endpoint), ['/claim', '/fail']);
    assert.deepEqual(calls.at(-1).body, { submission_id: id, lease_token: leaseToken, reason: `Verifier ${failure.code}` });
    assert.equal(calls.some(call => call.endpoint === '/complete'), false);
  }
});

test('infrastructure failure includes only bounded diagnostic enums in the queue reason', async t => {
  const { config } = setup(t);
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/claim' ? { job } : {};
  };
  const reviewer = async () => { throw new CodexReviewError('cli_nonzero_exit', {
    exit_code: 'one', signal: 'none', stderr_size: 'short', json_error_events: 'turn_failed',
    json_error_keys: ['error.message', 'PRIVATE_EVIDENCE'], hints: ['schema_error', 'PRIVATE_EVIDENCE'],
    secret: 'PRIVATE_EVIDENCE',
  }); };
  assert.equal(await runWorkerOnce({ config, transport, reviewer, sourceLoader }), true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/claim', '/fail']);
  assert.match(calls.at(-1).body.reason, /^Verifier cli_nonzero_exit \{/);
  assert.match(calls.at(-1).body.reason, /"schema_error"/);
  assert.doesNotMatch(calls.at(-1).body.reason, /PRIVATE_EVIDENCE|secret/);
});

test('worker emits only allowlisted diagnostic enums for a failed Codex CLI', async t => {
  const { config } = setup(t);
  let completed;
  const transport = async (_socket, endpoint, body) => {
    if (endpoint === '/claim') return { job };
    if (endpoint === '/complete') completed = body.result;
    return {};
  };
  const diagnostic = { exit_code: 'one', signal: 'none', stderr_size: 'short', json_error_events: 'turn_failed',
    json_error_keys: ['error.message', 'PRIVATE_EVIDENCE'], hints: ['invalid_request', 'PRIVATE_EVIDENCE'], secret: 'PRIVATE_EVIDENCE' };
  const reviewer = async () => { throw new CodexReviewError('invalid_request', diagnostic); };
  assert.equal(await runWorkerOnce({ config, transport, reviewer, sourceLoader }), true);
  assert.match(completed.review.reason, /^invalid_request \{/);
  assert.match(completed.review.reason, /"exit_code":"one"/);
  assert.match(completed.review.reason, /"invalid_request"/);
  assert.equal(completed.reproduction.reason, 'invalid_request');
  assert.doesNotMatch(JSON.stringify(completed), /PRIVATE_EVIDENCE|secret/);
});

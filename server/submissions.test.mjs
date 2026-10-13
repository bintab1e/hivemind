import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack, startServer } from './server.mjs';
import { claimSubmission, completeSubmission, getSubmission, getVerifiedArtifact, heartbeatWorker, listVerificationQueue, listVerifiedArtifacts, progressSubmission, submitSubmission } from './submissions.mjs';
import { listRegistry } from './registry.mjs';
import { postJson } from './verifier/worker.mjs';

const commit = 'a'.repeat(40);
const source = 'int main(void) { return 0; }\n';
const serial = 'boot complete\nBUG: KASAN: slab-out-of-bounds in nfsd_test\nRead of size 8 at addr deadbeef\n nfsd_test+0x12/0x30\n';
const trace = serial.slice(serial.indexOf('BUG: KASAN:')).trim();
const report = `## Summary\n\nA server-side NFS request reaches the reviewed bounds error.\n\n## Root cause\n\nfs/nfsd/nfs4proc.c:42\n\n\`\`\`c\nreturn nfsd_test(rqstp);\n\`\`\`\n\n## Reproduction environment\n\nTwo QEMU VMs, NFS 4.2, kernel ${commit}.\n\n## PoC\n\nThe C client sends the request.\n\n## Impact analysis\n\nThe server KASAN trace confirms a read; no other impact was proven.\n`;
const raw = client_submission_id => ({
  project: 'knfsd', client_submission_id, title: 'NFS boundary issue',
  report: 'The submitted report has no KASAN log yet.',
  metadata: { version_id: '7.3-rc7', repo_commit: commit, nfs_version: '4.2' },
  files: [{ name: 'arbitrary-source.c', kind: 'poc', content_base64: Buffer.from(source).toString('base64') }],
});
const verdict = (status = 'observed', evidence = serial) => ({
  review: {
    verdict: 'likely', reason: 'Source and report identify a reachable bounds error',
    grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 42, text: 'return nfsd_test(rqstp);' }] },
    relevance: { verdict: 'supports', reason: 'The server trace names the same function after the PoC ran',
      trace_line: 'nfsd_test+0x12/0x30', source_path: 'fs/nfsd/nfs4proc.c', source_line: 42,
      symbolized_path: 'fs/nfsd/nfs4proc.c', symbolized_line: 44, poc_line: 1 },
    normalized: {
      title: 'NFS boundary issue', report: 'A 2VM NFS request triggers the server KASAN trace.',
      file_path: 'fs/nfsd/nfs4proc.c', code_refs: ['fs/nfsd/nfs4proc.c#nfsd_test'],
      permission: 'AUTH_SYS', nfs_version: '4.2', vulnerability_type: 'OOB Read',
      poc: { filename: 'poc.c', original_name: 'arbitrary-source.c', source_index: 0, source, language: 'c' },
    },
  },
  reproduction: {
    status, kernelCommit: commit, nfsVersion: '4.2', reason: status === 'observed' ? 'KASAN in server guest' : 'No KASAN in server guest',
    observation: { guestCompleted: true, targetCommitMatch: true, baselineClean: true, pocStarted: true, serverEvidenceAfterPoc: true },
  },
  server_serial: evidence,
  artifacts: {
    report: { filename: 'report.md', content: report },
    poc: { filename: 'poc.c', source_index: 0, source },
    reproduction: { filename: 'reproduction.md', content: `Two QEMU VMs, NFS 4.2, kernel ${commit}.` },
    log: { filename: 'kasan.log', content: evidence.includes('BUG: KASAN:') ? trace : 'No KASAN evidence' },
  },
});

test('unstructured submission stays out of registry until independent 2VM evidence promotes it once', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-submissions-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const accepted = submitSubmission(db, raw('case-1'), 'pc01');
  assert.equal(accepted.status, 'pending');
  assert.equal(submitSubmission(db, raw('case-1'), 'pc01').replayed, true);
  assert.equal(listRegistry(db).length, 0);
  const claimed = claimSubmission(db);
  assert.equal(claimed.submission_id, accepted.submission_id);
  assert.equal(claimed.files.length, 1);
  const approved = completeSubmission(db, accepted.submission_id, verdict(), claimed.lease_token);
  assert.equal(approved.status, 'approved');
  assert.equal(approved.management_id, 'A-043');
  assert.equal(completeSubmission(db, accepted.submission_id, verdict()).management_id, 'A-043');
  const findings = listRegistry(db);
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].verified_impacts, ['kasan_read']);
  assert.equal(findings[0].management_id, 'A-043');
  assert.equal(findings[0].review_provider, 'codex_qemu');
  assert.equal(findings[0].privilege, 'AUTH_SYS');
  assert.equal(findings[0].nfs_version, '4.2');
  assert.equal(findings[0].vulnerability_type, 'OOB Read');
  assert.match(findings[0].reproduction_command, /\/tmp\/hivemind-poc 10\.77\.0\.1 \/mnt\/nfs/);
  assert.deepEqual(listVerifiedArtifacts(db, findings[0].event_id).map(item => item.name), ['report.md', 'poc.c', 'reproduction.md', 'kasan.log']);
  assert.equal(getVerifiedArtifact(db, findings[0].event_id, 'report.md').toString(), report);
  assert.equal(getVerifiedArtifact(db, findings[0].event_id, 'poc.c').toString(), source);
  assert.equal(getVerifiedArtifact(db, findings[0].event_id, 'kasan.log').toString(), trace);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
});

test('inconsistent metadata or missing canonical files never receives a management number', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-format-gates-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const cases = [
    ['tested-version', result => { result.reproduction.nfsVersion = '3'; }],
    ['submitted-version', result => { result.review.normalized.nfs_version = '4.1'; }],
    ['unknown-permission', result => { result.review.normalized.permission = 'root maybe'; }],
    ['unknown-type', result => { result.review.normalized.vulnerability_type = 'possible problem'; }],
    ['report-section', result => { result.artifacts.report.content = result.artifacts.report.content.replace('## Impact analysis', '## Conclusions'); }],
    ['untrusted-snippet', result => { result.artifacts.report.content = result.artifacts.report.content.replace('return nfsd_test(rqstp);', 'invented source'); }],
    ['no-reproduction', result => { delete result.artifacts.reproduction; }],
    ['no-c-poc', result => { result.review.normalized.poc.language = 'python'; }],
    ['unsupported-impact', result => { result.review.normalized.claimed_impacts = ['lpe', 'rce']; }],
  ];
  for (const [name, change] of cases) {
    const id = submitSubmission(db, raw(`gate-${name}`), 'pc01').submission_id;
    const claimed = claimSubmission(db, commit);
    const result = verdict();
    change(result);
    const outcome = completeSubmission(db, id, result, claimed.lease_token);
    if (name === 'unsupported-impact') {
      assert.equal(outcome.status, 'approved');
      assert.deepEqual(listRegistry(db).find(row => row.management_id === outcome.management_id).verified_impacts, ['kasan_read']);
    } else assert.equal(outcome.status, 'needs_review', name);
  }
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
});

test('KASAN evidence selects the relevant later block and supports multiple observed flags', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-multiple-traces-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const id = submitSubmission(db, raw('multi-trace'), 'pc01').submission_id;
  const claimed = claimSubmission(db, commit);
  const result = verdict();
  const relevant = 'BUG: KASAN: slab-out-of-bounds in nfsd_test\nRead of size 8 at addr deadbeef\nWrite of size 8 at addr deadbeef\n nfsd_test+0x12/0x30';
  result.server_serial = `BUG: KASAN: slab-out-of-bounds in unrelated_driver\nRead of size 8 at addr aaa\n unrelated_driver+0x1/0x2\n${relevant}\n`;
  result.artifacts.log.content = relevant;
  const outcome = completeSubmission(db, id, result, claimed.lease_token);
  assert.equal(outcome.status, 'approved');
  assert.deepEqual(listRegistry(db)[0].verified_impacts, ['kasan_read', 'kasan_write']);
  assert.equal(getVerifiedArtifact(db, listRegistry(db)[0].event_id, 'kasan.log').toString(), relevant);
});

test('verified manual upload carries its validated reporter into the registry owner', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-manual-owner-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const input = raw('manual-owner');
  input.metadata.reporter = '이진표';
  const accepted = submitSubmission(db, input, 'web:reporter', 'manual_upload');
  const claimed = claimSubmission(db, commit);
  assert.equal(completeSubmission(db, accepted.submission_id, verdict(), claimed.lease_token).status, 'approved');
  assert.equal(listRegistry(db)[0].owner, '이진표');
});

test('non-reproduction and missing server KASAN never allocate a management number', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-reject-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const rejected = submitSubmission(db, raw('case-rejected'), 'pc01').submission_id;
  const rejectedClaim = claimSubmission(db);
  assert.equal(completeSubmission(db, rejected, verdict('not_observed', ''), rejectedClaim.lease_token).status, 'rejected');
  const rejectedQueue = listVerificationQueue(db);
  assert.equal(rejectedQueue.counts.blocked, 1);
  assert.equal(rejectedQueue.blocked[0].submission_id, rejected);
  assert.equal(rejectedQueue.blocked[0].status, 'rejected');
  assert.match(rejectedQueue.blocked[0].reason, /No KASAN in server guest/);
  const unsupported = submitSubmission(db, raw('case-no-kasan'), 'pc01').submission_id;
  const unsupportedClaim = claimSubmission(db);
  assert.equal(completeSubmission(db, unsupported, verdict('observed', 'server boot only'), unsupportedClaim.lease_token).status, 'needs_evidence');
  assert.equal(listRegistry(db).length, 0);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 42);
});

test('submission names and idempotency are checked before storing evidence', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-unsafe-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  assert.throws(() => submitSubmission(db, { ...raw('bad'), files: [{ name: '../poc.c', content_base64: Buffer.from(source).toString('base64') }] }, 'pc01'), /Unsafe/);
  submitSubmission(db, raw('same-id'), 'pc01');
  assert.throws(() => submitSubmission(db, { ...raw('same-id'), title: 'changed' }, 'pc01'), /reused/);
});

test('a pinned verifier claims only submissions for its full kernel commit', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-commit-claims-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  const otherCommit = 'b'.repeat(40);
  const first = submitSubmission(db, raw('first-commit'), 'pc01').submission_id;
  const second = submitSubmission(db, { ...raw('second-commit'), metadata: {
    ...raw('second-commit').metadata, repo_commit: otherCommit,
  } }, 'pc02').submission_id;
  assert.throws(() => claimSubmission(db, commit.toUpperCase()), /Invalid target_commit/);
  assert.throws(() => claimSubmission(db, otherCommit.slice(0, 39)), /Invalid target_commit/);
  assert.equal(claimSubmission(db, otherCommit).submission_id, second);
  assert.equal(getSubmission(db, first).status, 'pending');
  assert.equal(claimSubmission(db, otherCommit), null);
  assert.equal(claimSubmission(db, commit).submission_id, first);
});

test('queue reports persisted stages, compatible workers, lease activity and interrupted work truthfully', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-queue-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  const first = submitSubmission(db, raw('queue-first'), 'pc01').submission_id;
  const second = submitSubmission(db, raw('queue-second'), 'pc02').submission_id;
  const unmatched = submitSubmission(db, { ...raw('queue-unmatched'), metadata: { version_id: 'unknown' } }, 'pc03').submission_id;
  for (const [index, id] of [first, second, unmatched].entries()) {
    db.prepare('UPDATE submissions SET submitted_at = ? WHERE id = ?').run(`2026-10-13T00:00:0${index}.000Z`, id);
  }
  const workerId = 'd'.repeat(32);
  let queue = listVerificationQueue(db);
  assert.deepEqual(queue.counts, { processing: 0, pending: 3, blocked: 0 });
  assert.deepEqual(queue.pending.map(row => row.position), [1, 2, 3]);
  assert.equal(queue.pending.find(row => row.submission_id === unmatched).target_commit, null);
  const claimed = claimSubmission(db, commit);
  assert.equal(claimed.submission_id, first);
  assert.throws(() => progressSubmission(db, first, 'static_review', '0'.repeat(64)), /lease/);
  assert.throws(() => progressSubmission(db, first, 'invented_phase', claimed.lease_token), /progress/);
  progressSubmission(db, first, 'static_review', claimed.lease_token);
  assert.throws(() => heartbeatWorker(db, { worker_id: workerId, target_commit: commit, submission_id: first, lease_token: '0'.repeat(64) }), /lease/);
  heartbeatWorker(db, { worker_id: workerId, target_commit: commit, submission_id: first, lease_token: claimed.lease_token });
  queue = listVerificationQueue(db);
  assert.equal(queue.active[0].phase, 'static_review');
  assert.equal(queue.active[0].stale, false);
  assert.equal(queue.workers[0].status, 'busy');
  assert.equal(queue.workers[0].current_submission_id, first);
  assert.equal(queue.active[0].lease_token, undefined);
  assert.equal(queue.active[0].report, undefined);
  db.prepare('UPDATE submissions SET last_activity_at = ? WHERE id = ?').run(new Date(Date.now() - 120_000).toISOString(), first);
  assert.equal(listVerificationQueue(db).active[0].stale, true);
  assert.equal(claimSubmission(db, commit).submission_id, second);
  assert.equal(getSubmission(db, first).status, 'processing');
  heartbeatWorker(db, { worker_id: workerId, target_commit: commit, submission_id: first, lease_token: claimed.lease_token });
  assert.equal(listVerificationQueue(db).active.find(row => row.submission_id === first).stale, false);
  heartbeatWorker(db, { worker_id: workerId, target_commit: commit });
  assert.equal(listVerificationQueue(db).workers[0].status, 'idle');
  db.prepare('UPDATE verifier_workers SET last_seen_at = ? WHERE worker_id = ?').run('2000-01-01T00:00:00.000Z', workerId);
  assert.equal(listVerificationQueue(db).workers.length, 0);
  db.prepare('UPDATE submissions SET last_activity_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', first);
  assert.equal(listVerificationQueue(db).active.find(row => row.submission_id === first).stale, true);
  const reclaimed = claimSubmission(db, commit);
  assert.equal(reclaimed.submission_id, first);
  assert.notEqual(reclaimed.lease_token, claimed.lease_token);
  assert.throws(() => progressSubmission(db, first, 'static_review', claimed.lease_token), /lease/);
  assert.equal(listVerificationQueue(db).active.find(row => row.submission_id === first).phase, 'preparing');
});

test('queue hides superseded worker sessions while retaining one offline card per kernel', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-worker-sessions-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  const stableCommit = 'b'.repeat(40);
  const oldRc = '1'.repeat(32);
  const newRc = '2'.repeat(32);
  const oldStable = '3'.repeat(32);
  const newStable = '4'.repeat(32);
  heartbeatWorker(db, { worker_id: oldRc, target_commit: commit });
  heartbeatWorker(db, { worker_id: oldStable, target_commit: stableCommit });
  db.prepare('UPDATE verifier_workers SET last_seen_at = ?').run(new Date(Date.now() - 5 * 60_000).toISOString());
  heartbeatWorker(db, { worker_id: newRc, target_commit: commit });
  heartbeatWorker(db, { worker_id: newStable, target_commit: stableCommit });

  let workers = listVerificationQueue(db).workers;
  assert.deepEqual(new Set(workers.map(row => row.worker_id)), new Set([newRc, newStable]));
  assert.ok(workers.every(row => row.status === 'idle'));

  db.prepare('UPDATE verifier_workers SET last_seen_at = ? WHERE worker_id = ?')
    .run(new Date(Date.now() - 2 * 60_000).toISOString(), newStable);
  workers = listVerificationQueue(db).workers;
  assert.deepEqual(new Set(workers.map(row => row.worker_id)), new Set([newRc, newStable]));
  assert.equal(workers.find(row => row.worker_id === newStable).status, 'offline');

  const parallelRc = '5'.repeat(32);
  heartbeatWorker(db, { worker_id: parallelRc, target_commit: commit });
  workers = listVerificationQueue(db).workers;
  assert.deepEqual(new Set(workers.map(row => row.worker_id)), new Set([newRc, parallelRc, newStable]));
});

test('expired leases, unregistered targets, and unrelated traces cannot approve a submission', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-gates-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  const first = submitSubmission(db, raw('no-track'), 'pc01').submission_id;
  const firstClaim = claimSubmission(db);
  assert.throws(() => completeSubmission(db, first, verdict(), '0'.repeat(64)), /lease/);
  assert.equal(completeSubmission(db, first, verdict(), firstClaim.lease_token).status, 'needs_evidence');

  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const second = submitSubmission(db, raw('dirty-baseline'), 'pc01').submission_id;
  const secondClaim = claimSubmission(db);
  const dirty = verdict();
  dirty.reproduction.observation.baselineClean = false;
  assert.equal(completeSubmission(db, second, dirty, secondClaim.lease_token).status, 'needs_evidence');

  const third = submitSubmission(db, raw('unrelated-trace'), 'pc01').submission_id;
  const thirdClaim = claimSubmission(db);
  const unrelated = verdict('observed', 'BUG: KASAN: slab-out-of-bounds in unrelated_driver\nRead of size 8 at addr deadbeef\n');
  assert.equal(completeSubmission(db, third, unrelated, thirdClaim.lease_token).status, 'needs_evidence');
  const fourth = submitSubmission(db, raw('wrong-symbolized-path'), 'pc01').submission_id;
  const fourthClaim = claimSubmission(db);
  const wrongPath = verdict();
  wrongPath.review.relevance.symbolized_path = 'net/sunrpc/svc.c';
  assert.equal(completeSubmission(db, fourth, wrongPath, fourthClaim.lease_token).status, 'needs_review');
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 42);
});

test('same kernel crash location is held for duplicate review before allocating another number', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-duplicate-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const first = submitSubmission(db, raw('same-bug-1'), 'pc01').submission_id;
  assert.equal(completeSubmission(db, first, verdict(), claimSubmission(db).lease_token).management_id, 'A-043');
  const second = submitSubmission(db, raw('same-bug-2'), 'pc02').submission_id;
  const held = completeSubmission(db, second, verdict(), claimSubmission(db).lease_token);
  assert.equal(held.status, 'needs_review');
  assert.match(held.reason, /A-043/);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
});

test('agent HTTP intake and status require its token; verifier socket is local', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-http-submission-'));
  const socketPath = path.join(directory, 'verifier.sock');
  const { server, verifierServer, db, url } = await startServer({ port: 0, dataDir: directory, verifierSocketPath: socketPath,
    dashboardPassword: 'queue-test-password' });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    if (verifierServer?.listening) await new Promise(resolve => verifierServer.close(resolve));
    db.close(); rmSync(directory, { recursive: true, force: true });
  });
  const body = JSON.stringify(raw('http-1'));
  assert.equal((await fetch(`${url}/api/verification-queue`)).status, 401);
  assert.equal((await fetch(`${url}/v1/submissions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body })).status, 401);
  const { issueAgentToken } = await import('./server.mjs');
  const { token } = issueAgentToken(db, 'pc01');
  const posted = await fetch(`${url}/v1/submissions`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body });
  assert.equal(posted.status, 202, await posted.text());
  const id = (await (await fetch(`${url}/v1/submissions`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body })).json()).submission_id;
  assert.equal((await fetch(`${url}/v1/submissions/${id}`, { headers: { Authorization: `Bearer ${token}` } })).status, 200);
  assert.equal(getSubmission(db, id).status, 'pending');
  assert.equal(Boolean(verifierServer?.listening), true);
  await assert.rejects(postJson(socketPath, '/claim', { target_commit: commit.toUpperCase() }), error => error.status === 400);
  await assert.rejects(postJson(socketPath, '/claim', { target_commit: [commit] }), error => error.status === 400);
  assert.equal(getSubmission(db, id).status, 'pending');
  assert.equal((await postJson(socketPath, '/claim', { target_commit: 'b'.repeat(40) })).job, null);
  const claimed = (await postJson(socketPath, '/claim', { target_commit: commit })).job;
  assert.equal(claimed.submission_id, id);
  await assert.rejects(postJson(socketPath, '/progress', { submission_id: id, lease_token: '0'.repeat(64), phase: 'static_review' }), error => error.status === 409);
  assert.equal((await postJson(socketPath, '/progress', { submission_id: id, lease_token: claimed.lease_token, phase: 'static_review' })).phase, 'static_review');
  await postJson(socketPath, '/heartbeat', { worker_id: 'd'.repeat(32), target_commit: commit, submission_id: id, lease_token: claimed.lease_token });
  const auth = { Authorization: `Basic ${Buffer.from('viewer:queue-test-password').toString('base64')}` };
  const queue = await (await fetch(`${url}/api/verification-queue`, { headers: auth })).json();
  assert.equal(queue.active[0].phase, 'static_review');
  assert.equal(queue.workers[0].status, 'busy');
  assert.equal(JSON.stringify(queue).includes(claimed.lease_token), false);
  assert.equal(JSON.stringify(queue).includes(source), false);
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const approved = completeSubmission(db, id, verdict(), claimed.lease_token);
  assert.equal(approved.status, 'approved');
  const finding = listRegistry(db).find(row => row.management_id === approved.management_id);
  const base = `${url}/api/events/${finding.event_id}/artifacts`;
  const artifacts = await (await fetch(base, { headers: auth })).json();
  assert.deepEqual(artifacts.artifacts.map(file => file.name), ['report.md', 'poc.c', 'reproduction.md', 'kasan.log']);
  assert.equal(await (await fetch(`${base}/report.md`, { headers: auth })).text(), report);
  assert.equal(await (await fetch(`${base}/poc.c`, { headers: auth })).text(), source);
  assert.equal((await fetch(`${base}/poc.py`, { headers: auth })).status, 404);
});

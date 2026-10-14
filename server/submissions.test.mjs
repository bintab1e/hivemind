import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack, startServer } from './server.mjs';
import { claimPrimitiveReview, claimSubmission, completePrimitiveReview, completeSubmission, failPrimitiveReview, getSubmission,
  getVerifiedArtifact, heartbeatPrimitiveWorker, heartbeatWorker, listVerificationQueue,
  listVerifiedArtifacts, progressSubmission, submitSubmission } from './submissions.mjs';
import { listRegistry } from './registry.mjs';
import { importHistoryArtifacts, listHistoryArtifacts, openHistoryArtifact } from './history-artifacts.mjs';
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

function socketPost(socketPath, endpoint, body) {
  return new Promise((resolve, reject) => {
    const encoded = JSON.stringify(body);
    const request = http.request({ socketPath, path: endpoint, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(encoded) } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const result = JSON.parse(Buffer.concat(chunks).toString());
        if (response.statusCode !== 200) reject(Object.assign(new Error(result.error), { status: response.statusCode }));
        else resolve(result);
      });
    });
    request.on('error', reject);
    request.end(encoded);
  });
}

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

test('grounded pre-auth 2VM evidence is registered without a fabricated NFS version', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-preauth-submissions-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const input = raw('preauth-accepted');
  input.metadata.nfs_version = 'Transport pre-authentication; no decoded NFS version';
  const id = submitSubmission(db, input, 'pc01').submission_id;
  const claimed = claimSubmission(db, commit);
  const result = verdict();
  result.review.normalized.nfs_version = null;
  result.review.normalized.permission = 'Pre-auth';
  result.review.normalized.pre_auth = { source_path: 'fs/nfsd/nfs4proc.c', source_line: 42, poc_line: 1 };
  result.reproduction.nfsVersion = null;
  result.reproduction.mount = false;
  result.artifacts.report.content = report.replace('NFS 4.2', 'direct pre-auth request without NFS mount');
  result.artifacts.reproduction.content = `Two QEMU VMs, direct pre-auth request without NFS mount, kernel ${commit}.`;
  const approved = completeSubmission(db, id, result, claimed.lease_token);
  assert.equal(approved.status, 'approved');
  const finding = listRegistry(db).find(item => item.management_id === approved.management_id);
  assert.equal(finding.nfs_version, null);
  assert.equal(finding.privilege, 'Pre-auth');
  assert.deepEqual(finding.access_requirements, ['pre_auth']);
  assert.match(finding.vm_environment, /without NFS mount/);
  assert.doesNotMatch(finding.reproduction_command, /\/mnt\/nfs|vers=/);
});

test('pre-auth metadata alone, false permission, or mismatched VM mode cannot assign a number', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-preauth-gates-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  for (const [label, mutate] of [
    ['metadata-only', result => { result.review.normalized.pre_auth = null; }],
    ['wrong-permission', result => { result.review.normalized.permission = 'AUTH_NONE'; }],
    ['mounted-vm', result => { result.reproduction.mount = true; }],
    ['invented-version', result => { result.reproduction.nfsVersion = '4.2'; }],
    ['missing-source-proof', result => { result.review.normalized.pre_auth.source_line = 99; }],
  ]) {
    const input = raw(`preauth-${label}`);
    input.metadata.nfs_version = 'Transport pre-authentication; no decoded NFS version';
    const id = submitSubmission(db, input, 'pc01').submission_id;
    const claimed = claimSubmission(db, commit);
    const result = verdict();
    result.review.normalized.nfs_version = null;
    result.review.normalized.permission = 'Pre-auth';
    result.review.normalized.pre_auth = { source_path: 'fs/nfsd/nfs4proc.c', source_line: 42, poc_line: 1 };
    result.reproduction.nfsVersion = null;
    result.reproduction.mount = false;
    mutate(result);
    assert.equal(completeSubmission(db, id, result, claimed.lease_token).status, 'needs_review', label);
  }
  assert.equal(listRegistry(db).length, 0);
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

test('verified enhancement of a historical A finding keeps its ID, archive and later revision', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-historical-enhancement-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  db.prepare(`INSERT INTO registry_history(management_id, number, title, target, report_status, imported_at)
    VALUES ('A-005', 5, 'Original flaw', 'knfsd', '제보 완료', ?)`).run(new Date().toISOString());
  const sourceDir = path.join(directory, 'source');
  mkdirSync(sourceDir);
  const originalReport = 'Same nfsd_test bounds error in fs/nfsd/nfs4proc.c:42';
  writeFileSync(path.join(sourceDir, 'original.md'), originalReport +
    'x'.repeat(29_999 - Buffer.byteLength(originalReport)) + '한');
  importHistoryArtifacts(db, directory, sourceDir, [{ management_id: 'A-005', kind: 'report',
    source_path: 'original.md', display_name: 'original.md' }]);
  const input = raw('history-enhancement-1');
  input.metadata.existing_management_id = 'A-005';
  const id = submitSubmission(db, input, 'pc01').submission_id;
  const claimed = claimSubmission(db, commit, directory);
  assert.equal(claimed.existing_finding.management_id, 'A-005');
  assert.match(claimed.existing_finding.report, /Same nfsd_test/);
  const result = verdict();
  result.review.same_root_cause = { verdict: 'same', reason: 'Same bounds operation' };
  assert.equal(completeSubmission(db, id, result, claimed.lease_token).management_id, 'A-005');
  assert.deepEqual(JSON.parse(db.prepare('SELECT verification_json FROM submissions WHERE id = ?').get(id).verification_json)
    .same_root_cause, { verdict: 'same', reason: 'Same bounds operation' });
  assert.deepEqual(listRegistry(db).map(item => item.management_id), ['A-005']);
  assert.equal(listRegistry(db)[0].report_status, '제보 완료');
  assert.equal(listRegistry(db)[0].registration_status, 'verified');
  assert.deepEqual(listRegistry(db)[0].verified_impacts, ['kasan_read']);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 42);
  const files = listHistoryArtifacts(db, 'A-005');
  assert.equal(files[0].name, 'report.md');
  assert.ok(files.some(item => item.name === 'original.md'));
  assert.equal(openHistoryArtifact(db, directory, 'A-005', files[0].id).content.toString(), report);
  const secondInput = raw('history-enhancement-2');
  secondInput.metadata.existing_management_id = 'A-005';
  const second = submitSubmission(db, secondInput, 'pc02').submission_id;
  const secondClaim = claimSubmission(db, commit, directory);
  assert.match(secondClaim.existing_finding.report, /## Summary/);
  const secondResult = verdict();
  secondResult.review.same_root_cause = { verdict: 'same', reason: 'Same bounds operation' };
  secondResult.artifacts.report.content = report.replace('A server-side', 'An independently verified server-side');
  assert.equal(completeSubmission(db, second, secondResult, secondClaim.lease_token).management_id, 'A-005');
  assert.equal(listRegistry(db).length, 1);
  assert.equal(listHistoryArtifacts(db, 'A-005').filter(item => item.name === 'report.md').length, 1);
  assert.equal(db.prepare('SELECT count(*) AS n FROM finding_revision_audit').get().n, 2);
  assert.equal(db.prepare("SELECT count(*) AS n FROM submissions WHERE status = 'approved' AND management_id = 'A-005'").get().n, 2);
});

test('live enhancement needs same-root review and retains newest report plus all verified impacts', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-live-enhancement-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const original = submitSubmission(db, raw('live-original'), 'pc01').submission_id;
  const first = completeSubmission(db, original, verdict(), claimSubmission(db, commit).lease_token);
  assert.equal(first.management_id, 'A-043');
  const previous = listRegistry(db)[0];
  const unmatched = raw('live-unmatched');
  unmatched.metadata.existing_management_id = 'A-043';
  const wrongId = submitSubmission(db, unmatched, 'pc02').submission_id;
  const wrongResult = verdict();
  wrongResult.review.same_root_cause = { verdict: 'different', reason: 'A different flaw' };
  assert.equal(completeSubmission(db, wrongId, wrongResult, claimSubmission(db, commit).lease_token).status, 'needs_review');
  assert.deepEqual(JSON.parse(db.prepare('SELECT verification_json FROM submissions WHERE id = ?').get(wrongId).verification_json)
    .same_root_cause, { verdict: 'different', reason: 'A different flaw' });
  assert.equal(getVerifiedArtifact(db, previous.event_id, 'report.md').toString(), report);
  const older = raw('live-older');
  older.metadata.existing_management_id = 'A-043';
  const newer = raw('live-newer');
  newer.metadata.existing_management_id = 'A-043';
  const oldId = submitSubmission(db, older, 'pc02').submission_id;
  const newId = submitSubmission(db, newer, 'pc03').submission_id;
  const oldClaim = claimSubmission(db, commit);
  const newClaim = claimSubmission(db, commit);
  assert.equal(oldClaim.submission_id, oldId);
  assert.equal(newClaim.submission_id, newId);
  const newestResult = verdict();
  newestResult.review.same_root_cause = { verdict: 'same', reason: 'Same source invariant' };
  newestResult.artifacts.report.content = report.replace('A server-side', 'Newest server-side');
  assert.equal(completeSubmission(db, newId, newestResult, newClaim.lease_token).management_id, 'A-043');
  const writeLog = 'BUG: KASAN: slab-out-of-bounds in nfsd_test\nWrite of size 8 at addr deadbeef\n nfsd_test+0x12/0x30';
  const olderResult = verdict();
  olderResult.review.same_root_cause = { verdict: 'same', reason: 'Same source invariant' };
  olderResult.server_serial = writeLog;
  olderResult.artifacts.log.content = writeLog;
  olderResult.artifacts.report.content = report.replace('A server-side', 'Older server-side');
  assert.equal(completeSubmission(db, oldId, olderResult, oldClaim.lease_token).management_id, 'A-043');
  assert.equal(listRegistry(db).length, 1);
  assert.deepEqual(new Set(listRegistry(db)[0].verified_impacts), new Set(['kasan_read', 'kasan_write']));
  assert.equal(getVerifiedArtifact(db, previous.event_id, 'report.md').toString(), newestResult.artifacts.report.content);
  assert.equal(listVerifiedArtifacts(db, previous.event_id).length, 4);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
  assert.equal(db.prepare('SELECT count(*) AS n FROM finding_revision_audit').get().n, 2);
  assert.equal(db.prepare("SELECT count(*) AS n FROM submissions WHERE status = 'approved' AND management_id = 'A-043'").get().n, 3);
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
  const primitiveWorker = 'e'.repeat(32);
  await assert.rejects(socketPost(socketPath, '/primitive/claim', { worker_id: primitiveWorker }), error => error.status === 400);
  await assert.rejects(socketPost(socketPath, '/primitive/claim', {
    worker_id: primitiveWorker, supported_commits: [commit], extra: true,
  }), error => error.status === 400);
  const primitive = (await socketPost(socketPath, '/primitive/claim', {
    worker_id: primitiveWorker, supported_commits: [commit],
  })).job;
  assert.equal(primitive.management_id, approved.management_id);
  assert.equal(primitive.report, report);
  assert.equal(primitive.poc_source, source);
  assert.deepEqual(primitive.verified_impacts, ['kasan_read']);
  await assert.rejects(socketPost(socketPath, '/primitive/complete', {
    finding_id: primitive.finding_id, lease_token: '0'.repeat(64), summary: 'Potential further impact requires testing.',
  }), error => error.status === 409);
  await socketPost(socketPath, '/primitive/heartbeat', {
    worker_id: primitiveWorker, finding_id: primitive.finding_id, lease_token: primitive.lease_token,
  });
  const primitiveQueue = await (await fetch(`${url}/api/verification-queue`, { headers: auth })).json();
  assert.equal(primitiveQueue.primitive.counts.processing, 1);
  assert.equal(primitiveQueue.workers.find(worker => worker.role === 'primitive')?.current_management_id, approved.management_id);
  assert.equal(JSON.stringify(primitiveQueue).includes(primitive.lease_token), false);
  await socketPost(socketPath, '/primitive/complete', {
    finding_id: primitive.finding_id, lease_token: primitive.lease_token,
    summary: 'KASAN Read is verified; controlled access needs more evidence.',
  });
  assert.equal(listRegistry(db)[0].primitive_review_status, 'complete');
  assert.match(listRegistry(db)[0].primitive_review_summary, /controlled access/);
  assert.deepEqual(listRegistry(db)[0].verified_impacts, ['kasan_read']);
});

test('primitive review jobs follow approved submissions, survive restart, and retry expired leases', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-primitive-'));
  const file = path.join(directory, 'db.sqlite3');
  let db = openDatabase(file);
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  assert.equal(claimPrimitiveReview(db, 'a'.repeat(32), [commit]), null);
  const first = submitSubmission(db, raw('primitive-first'), 'pc01').submission_id;
  assert.equal(completeSubmission(db, first, verdict(), claimSubmission(db).lease_token).status, 'approved');
  const second = submitSubmission(db, raw('primitive-second'), 'pc01').submission_id;
  const secondSerial = serial.replace('slab-out-of-bounds', 'use-after-free');
  const secondVerdict = verdict('observed', secondSerial);
  secondVerdict.artifacts.log.content = secondSerial.slice(secondSerial.indexOf('BUG: KASAN:')).trim();
  assert.equal(completeSubmission(db, second, secondVerdict, claimSubmission(db).lease_token).status, 'approved');
  const before = db.prepare('SELECT finding_id, requested_at FROM primitive_reviews ORDER BY requested_at, finding_id').all();
  assert.equal(before.length, 2);
  db.prepare('UPDATE primitive_reviews SET requested_at = ? WHERE finding_id = ?').run('2026-01-01T00:00:00.000Z', before[0].finding_id);
  db.prepare('UPDATE primitive_reviews SET requested_at = ? WHERE finding_id = ?').run('2026-01-02T00:00:00.000Z', before[1].finding_id);
  const old = claimPrimitiveReview(db, 'a'.repeat(32), [commit]);
  assert.equal(old.finding_id, before[0].finding_id);
  assert.equal(listVerificationQueue(db).primitive.counts.pending, 1);
  db.prepare('UPDATE primitive_reviews SET last_activity_at = ? WHERE finding_id = ?')
    .run('2000-01-01T00:00:00.000Z', old.finding_id);
  const noCandidate = claimPrimitiveReview(db, 'c'.repeat(32), [commit]);
  assert.equal(noCandidate.finding_id, before[1].finding_id);
  db.prepare('UPDATE primitive_reviews SET retry_after = ? WHERE finding_id = ?')
    .run('2000-01-01T00:00:00.000Z', old.finding_id);
  const retried = claimPrimitiveReview(db, 'b'.repeat(32), [commit]);
  assert.equal(retried.finding_id, old.finding_id);
  assert.notEqual(retried.lease_token, old.lease_token);
  assert.throws(() => completePrimitiveReview(db, old.finding_id, 'Outdated review', old.lease_token), /lease/);
  heartbeatPrimitiveWorker(db, { worker_id: 'b'.repeat(32), finding_id: retried.finding_id,
    lease_token: retried.lease_token });
  assert.equal(listVerificationQueue(db).workers.find(worker => worker.role === 'primitive').status, 'busy');
  const summary = 'KASAN Read confirmed. Controlled Read and LPE are hypotheses requiring independent reproduction.';
  assert.equal(completePrimitiveReview(db, retried.finding_id, summary, retried.lease_token).status, 'complete');
  assert.equal(completePrimitiveReview(db, retried.finding_id, summary, retried.lease_token).replayed, true);
  assert.throws(() => completePrimitiveReview(db, retried.finding_id, 'Different claim', retried.lease_token), /different content/);
  assert.deepEqual(listRegistry(db).find(row => row.event_id === retried.finding_id).verified_impacts, ['kasan_read']);
  assert.equal(claimPrimitiveReview(db, 'c'.repeat(32), [commit]), null);
  assert.equal(completePrimitiveReview(db, noCandidate.finding_id, null, noCandidate.lease_token).status, 'complete');
  assert.equal(completePrimitiveReview(db, noCandidate.finding_id, '', noCandidate.lease_token).replayed, true);
  assert.equal(listRegistry(db).find(row => row.event_id === noCandidate.finding_id).primitive_review_summary, null);
  assert.equal(listRegistry(db).find(row => row.event_id === noCandidate.finding_id).primitive_review_status, 'complete');
  db.prepare('DELETE FROM primitive_reviews WHERE finding_id = ?').run(retried.finding_id);
  db.close();
  db = openDatabase(file);
  assert.equal(db.prepare('SELECT status FROM primitive_reviews WHERE finding_id = ?').get(retried.finding_id).status, 'pending');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM primitive_reviews').get().count, 2);
});

test('primitive reviewer skips older unsupported commits and backs off transient failures', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-primitive-compat-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const first = submitSubmission(db, raw('primitive-incompatible'), 'pc01').submission_id;
  const firstApproved = completeSubmission(db, first, verdict(), claimSubmission(db).lease_token);
  assert.equal(firstApproved.status, 'approved');
  const second = submitSubmission(db, raw('primitive-compatible'), 'pc01').submission_id;
  const secondSerial = serial.replace('slab-out-of-bounds', 'use-after-free');
  const secondVerdict = verdict('observed', secondSerial);
  secondVerdict.artifacts.log.content = secondSerial.slice(secondSerial.indexOf('BUG: KASAN:')).trim();
  const secondApproved = completeSubmission(db, second, secondVerdict, claimSubmission(db).lease_token);
  assert.equal(secondApproved.status, 'approved');
  const otherCommit = 'b'.repeat(40);
  // Model an older approved finding from a different kernel track.
  db.prepare('UPDATE events SET repo_commit = ? WHERE id = ?').run(otherCommit, firstApproved.finding_id);
  db.prepare('UPDATE primitive_reviews SET requested_at = ? WHERE finding_id = ?')
    .run('2026-01-01T00:00:00.000Z', firstApproved.finding_id);
  db.prepare('UPDATE primitive_reviews SET requested_at = ? WHERE finding_id = ?')
    .run('2026-01-02T00:00:00.000Z', secondApproved.finding_id);
  assert.equal(claimPrimitiveReview(db, 'd'.repeat(32), []), null);
  assert.throws(() => claimPrimitiveReview(db, 'd'.repeat(32), null), /supported_commits/);
  assert.throws(() => claimPrimitiveReview(db, 'd'.repeat(32), [commit, commit]), /supported_commits/);
  assert.throws(() => claimPrimitiveReview(db, 'd'.repeat(32), [commit.toUpperCase()]), /supported_commits/);
  const compatible = claimPrimitiveReview(db, 'd'.repeat(32), [commit]);
  assert.equal(compatible.finding_id, secondApproved.finding_id);
  assert.equal(db.prepare('SELECT status FROM primitive_reviews WHERE finding_id = ?').get(firstApproved.finding_id).status, 'pending');
  assert.equal(completePrimitiveReview(db, compatible.finding_id, null, compatible.lease_token).status, 'complete');
  const older = claimPrimitiveReview(db, 'd'.repeat(32), [otherCommit]);
  assert.equal(older.finding_id, firstApproved.finding_id);
  const originalRequest = db.prepare('SELECT requested_at FROM primitive_reviews WHERE finding_id = ?').get(older.finding_id).requested_at;
  const firstFailure = failPrimitiveReview(db, older.finding_id, 'Temporary Codex failure', older.lease_token);
  assert.equal(firstFailure.status, 'pending');
  assert.ok(Date.parse(firstFailure.retry_after) > Date.now());
  assert.equal(claimPrimitiveReview(db, 'd'.repeat(32), [otherCommit]), null);
  assert.equal(db.prepare('SELECT requested_at FROM primitive_reviews WHERE finding_id = ?').get(older.finding_id).requested_at, originalRequest);
  db.prepare('UPDATE primitive_reviews SET retry_after = ? WHERE finding_id = ?').run('2000-01-01T00:00:00.000Z', older.finding_id);
  const secondAttempt = claimPrimitiveReview(db, 'd'.repeat(32), [otherCommit]);
  const secondFailure = failPrimitiveReview(db, older.finding_id, 'Temporary Codex failure', secondAttempt.lease_token);
  assert.equal(secondFailure.status, 'pending');
  assert.ok(Date.parse(secondFailure.retry_after) > Date.parse(firstFailure.retry_after));
  db.prepare('UPDATE primitive_reviews SET retry_after = ? WHERE finding_id = ?').run('2000-01-01T00:00:00.000Z', older.finding_id);
  const thirdAttempt = claimPrimitiveReview(db, 'd'.repeat(32), [otherCommit]);
  assert.equal(failPrimitiveReview(db, older.finding_id, 'Codex failed after retries', thirdAttempt.lease_token).status, 'error');
  assert.equal(claimPrimitiveReview(db, 'd'.repeat(32), [otherCommit]), null);
  assert.equal(db.prepare('SELECT attempts FROM primitive_reviews WHERE finding_id = ?').get(older.finding_id).attempts, 3);
});

test('empty primitive support list reaps stale leases without claiming new jobs', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-primitive-reap-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const id = submitSubmission(db, raw('primitive-reap'), 'pc01').submission_id;
  const approved = completeSubmission(db, id, verdict(), claimSubmission(db).lease_token);
  assert.equal(approved.status, 'approved');
  assert.equal(claimPrimitiveReview(db, 'f'.repeat(32), []), null);
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const claimed = claimPrimitiveReview(db, 'f'.repeat(32), [commit]);
    assert.equal(claimed.finding_id, approved.finding_id);
    db.prepare('UPDATE primitive_reviews SET last_activity_at = ? WHERE finding_id = ?')
      .run('2000-01-01T00:00:00.000Z', approved.finding_id);
    assert.equal(claimPrimitiveReview(db, 'f'.repeat(32), []), null);
    const row = db.prepare('SELECT status, retry_after, attempts FROM primitive_reviews WHERE finding_id = ?')
      .get(approved.finding_id);
    assert.equal(row.attempts, attempt);
    assert.equal(row.status, attempt < 3 ? 'pending' : 'error');
    if (attempt < 3) {
      assert.ok(Date.parse(row.retry_after) > Date.now());
      db.prepare('UPDATE primitive_reviews SET retry_after = ? WHERE finding_id = ?')
        .run('2000-01-01T00:00:00.000Z', approved.finding_id);
    } else assert.equal(row.retry_after, null);
  }
});

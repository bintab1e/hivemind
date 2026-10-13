import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack, startServer } from './server.mjs';
import { claimSubmission, completeSubmission, getSubmission, submitSubmission } from './submissions.mjs';
import { listRegistry } from './registry.mjs';
import { postJson } from './verifier/worker.mjs';

const commit = 'a'.repeat(40);
const source = 'int main(void) { return 0; }\n';
const serial = 'boot complete\nBUG: KASAN: slab-out-of-bounds in nfsd_test\nRead of size 8 at addr deadbeef\n nfsd_test+0x12/0x30\n';
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
    status, kernelCommit: commit, reason: status === 'observed' ? 'KASAN in server guest' : 'No KASAN in server guest',
    observation: { guestCompleted: true, targetCommitMatch: true, baselineClean: true, pocStarted: true, serverEvidenceAfterPoc: true },
  },
  server_serial: evidence,
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
  assert.match(findings[0].reproduction_command, /\/tmp\/hivemind-poc 10\.77\.0\.1 \/mnt\/nfs/);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
});

test('non-reproduction and missing server KASAN never allocate a management number', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hivemind-reject-'));
  const db = openDatabase(path.join(directory, 'db.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const rejected = submitSubmission(db, raw('case-rejected'), 'pc01').submission_id;
  const rejectedClaim = claimSubmission(db);
  assert.equal(completeSubmission(db, rejected, verdict('not_observed', ''), rejectedClaim.lease_token).status, 'rejected');
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
  const { server, verifierServer, db, url } = await startServer({ port: 0, dataDir: directory, verifierSocketPath: socketPath });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    if (verifierServer?.listening) await new Promise(resolve => verifierServer.close(resolve));
    db.close(); rmSync(directory, { recursive: true, force: true });
  });
  const body = JSON.stringify(raw('http-1'));
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
  assert.equal((await postJson(socketPath, '/claim', { target_commit: commit })).job.submission_id, id);
});

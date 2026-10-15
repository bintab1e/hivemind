import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack } from './server.mjs';
import { hash, readFrontMatter } from './contract.mjs';
import { importHistoryArtifacts } from './history-artifacts.mjs';
import { claimPrimitiveReview, claimSubmission, completeSubmission, getVerifiedArtifact,
  heartbeatWorker, listVerificationQueue, listVerifiedArtifacts, purgeFinishedSubmissions, submitSubmission } from './submissions.mjs';
import { listRegistry } from './registry.mjs';

const commit = 'a'.repeat(40);
const entryLine = 'int nfsd4_proc_compound(const char *buffer, unsigned int count) {';
const line = 'if (count > available) return -EINVAL;';
const poc = 'int main(void) { return 0; }\n';
const log = 'BUG: KASAN: submitted claim\nRead of size 4\n';
const report = `## Summary\n요청 길이 검사 후보입니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:42\n\`\`\`c\n${line}\n\`\`\`\n\n## Reproduction environment\n서버 검증은 제출 자료의 정적 검토만 수행했습니다.\n\n## PoC\n원본 C 요청입니다.\n\n## Impact analysis\n제출 로그는 미재현 주장입니다.`;
const artifact = (name, kind, content) => ({ name, kind, content_base64: Buffer.from(content).toString('base64') });
const sourceProof = { path: 'fs/nfsd/nfs4proc.c', line: 42,
  explanation: 'The reviewed source line is part of the claimed request path.' };
const proof = { entry: { path: 'fs/nfsd/nfs4proc.c', line: 41,
  explanation: 'This entry point receives the input from the caller.' },
  flaw: sourceProof, impact: sourceProof, defenses: sourceProof,
  poc: { line: 1, explanation: 'The original C source line constructs the submitted request.' },
  log: { index: 1, line: 1, explanation: 'The submitted diagnostic line names the claimed failure.' } };
const proofReview = { verdict: 'supports', admin_action_required: false,
  reason: 'All required static links were independently challenged',
  checks: { reachability: 'supported', flaw: 'supported', poc: 'supported', log: 'supported',
    defenses: 'supported', admin_action: 'supported' } };
const raw = (id, metadata = {}) => ({ project: 'knfsd', client_submission_id: id, title: 'NFS request length error',
  report, metadata: { version_id: '7.3-rc7', repo_commit: commit, nfs_version: '4.2', ...metadata },
  files: [artifact('source.c', 'poc', poc), artifact('submitted.log', 'log', log)] });
const verdict = ({ integrity = 'clear', existingId = null, anchorLine = 42 } = {}) => ({
  review: { verdict: 'likely', integrity: { verdict: integrity, admin_action_required: false,
    reason: integrity === 'clear' ? 'No artificial conditions' : 'Kernel delay added' },
    reason: 'Source and original C PoC support a plausible static candidate',
    proof, proof_review: proofReview,
    grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: anchorLine, text: line },
      { path: 'fs/nfsd/nfs4proc.c', line: 41, text: entryLine }] },
    ...(existingId ? { same_root_cause: { verdict: 'same', management_id: existingId, reason: 'Same faulty invariant' } } : {}),
    normalized: { title: 'NFS request length error', report, file_path: 'fs/nfsd/nfs4proc.c',
      code_refs: ['fs/nfsd/nfs4proc.c:42'], nfs_version: '4.2', permission: 'AUTH_SYS',
      vulnerability_type: 'OOB Read', claimed_impacts: ['kasan_read'],
      poc: { filename: 'poc.c', original_name: 'source.c', source_index: 0, source: poc, language: 'c' },
      logs: [{ filename: 'evidence-1.log', original_name: 'submitted.log', source_index: 1 }] } },
  reproduction: { status: 'not_run', reason: 'Static screening only' },
  artifacts: { report: { filename: 'report.md', content: report },
    poc: { filename: 'poc.c', source_index: 0, source: poc },
    reproduction: { filename: 'reproduction.md', content: 'No server VM or PoC execution occurred.\n' },
    log: { filename: 'evidence.log', content: log } },
});

function setup(t) {
  const directory = mkdtempSync(path.join(tmpdir(), 'hv-static-submission-'));
  const db = openDatabase(path.join(directory, 'data.sqlite3'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  return db;
}

function submit(db, id, metadata = {}) { return submitSubmission(db, raw(id, metadata), 'analyst').submission_id; }
function approve(db, id, result = verdict()) { return completeSubmission(db, id, result, claimSubmission(db, commit).lease_token); }

test('static-screened submission receives a number without fabricated dynamic impacts or VM evidence', t => {
  const db = setup(t);
  const id = submitSubmission(db, raw('one'), 'jinpyo').submission_id;
  const result = verdict();
  result.review.normalized.code_refs = [];
  const accepted = approve(db, id, result);
  assert.equal(accepted.management_id, 'A-043');
  const record = listRegistry(db).find(row => row.management_id === 'A-043');
  assert.equal(record.owner, '이진표');
  assert.equal(record.review_provider, 'codex_static');
  assert.equal(record.dynamic_status, 'not_run');
  assert.deepEqual(record.verified_impacts, []);
  assert.deepEqual(record.claimed_impacts, ['kasan_read']);
  assert.deepEqual(listVerifiedArtifacts(db, accepted.finding_id).map(file => file.name),
    ['report.md', 'poc.c', 'reproduction.md', 'evidence.log']);
  assert.equal(getVerifiedArtifact(db, accepted.finding_id, 'evidence.log').toString(), log);
  const data = readFrontMatter(db.prepare('SELECT markdown FROM events WHERE id = ?').get(accepted.finding_id).markdown).data;
  assert.equal(data.angle, 'codex-static-screening');
  assert.equal(data.dynamic_status, 'not_run');
  assert.equal(data.evidence_sha256, hash(log));
  assert.equal(data.kasan_sha256, undefined);
  assert.deepEqual(data.code_refs, ['fs/nfsd/nfs4proc.c:42']);
});

test('daily cleanup removes finished blocked submissions and blobs but preserves active work and approved evidence', t => {
  const db = setup(t);
  const approvedId = submit(db, 'approved');
  const approved = approve(db, approvedId);
  const old = ['needs_evidence', 'needs_review', 'error', 'rejected'].map(status => {
    const id = submit(db, `old-${status}`);
    db.prepare('UPDATE submissions SET status = ?, completed_at = ? WHERE id = ?')
      .run(status, status === 'error' ? null : '2026-10-14T20:00:00.000Z', id);
    return id;
  });
  const future = submit(db, 'future');
  db.prepare('UPDATE submissions SET status = ?, completed_at = ? WHERE id = ?')
    .run('rejected', '2026-10-14T21:00:01.000Z', future);
  const pending = submit(db, 'pending');
  const processing = submit(db, 'processing');
  db.prepare('UPDATE submissions SET status = ? WHERE id = ?').run('processing', processing);
  const cutoff = '2026-10-14T21:00:00.000Z';
  assert.deepEqual(purgeFinishedSubmissions(db, cutoff), { deleted: 4 });
  for (const id of old) {
    assert.equal(db.prepare('SELECT 1 FROM submissions WHERE id = ?').get(id), undefined);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM submission_artifacts WHERE submission_id = ?').get(id).n, 0);
  }
  for (const id of [approvedId, future, pending, processing]) {
    assert.ok(db.prepare('SELECT 1 FROM submissions WHERE id = ?').get(id));
  }
  assert.equal(getVerifiedArtifact(db, approved.finding_id, 'report.md').toString(), report);
  assert.equal(listRegistry(db).find(row => row.management_id === 'A-043').title, 'NFS request length error');
  assert.equal(listVerificationQueue(db).counts.blocked, 1);
  assert.deepEqual(purgeFinishedSubmissions(db, cutoff), { deleted: 0 });
  assert.throws(() => purgeFinishedSubmissions(db, '2099-99-99T00:00:00.000Z'), TypeError);
});

test('NFS/RDMA findings can be anchored in the InfiniBand source they traverse', t => {
  const db = setup(t);
  const source = 'drivers/infiniband/sw/siw/siw_cm.c';
  const id = submitSubmission(db, {
    ...raw('rdma-driver', { file_path: source, code_refs: [`${source}:42`] }),
    report: report.replaceAll('fs/nfsd/nfs4proc.c', source),
  }, 'analyst').submission_id;
  const result = JSON.parse(JSON.stringify(verdict()).replaceAll('fs/nfsd/nfs4proc.c', source));
  const accepted = approve(db, id, result);
  assert.equal(accepted.status, 'approved');
  assert.equal(listRegistry(db).find(row => row.management_id === accepted.management_id).file_path, source);
});

test('suspicious shortcuts, uncertain screening and forged 2VM results never receive a number', t => {
  const db = setup(t);
  const suspect = submit(db, 'suspect');
  assert.equal(approve(db, suspect, verdict({ integrity: 'suspect' })).status, 'rejected');
  const uncertain = submit(db, 'uncertain');
  assert.equal(approve(db, uncertain, verdict({ integrity: 'uncertain' })).status, 'needs_review');
  const forged = submit(db, 'forged');
  const claimed = claimSubmission(db, commit);
  assert.throws(() => completeSubmission(db, forged, { ...verdict(), reproduction: { status: 'observed' } }, claimed.lease_token), /Dynamic evidence/);
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('missing or disputed static proof never receives a management number', t => {
  const db = setup(t);
  for (const [name, change] of [
    ['missing-proof', result => { delete result.review.proof; }],
    ['no-second-review', result => { delete result.review.proof_review; }],
    ['contradiction', result => { result.review.proof_review = { ...proofReview, verdict: 'refutes' }; }],
    ['missing-poc-anchor', result => { result.review.proof = { ...proof, poc: { ...proof.poc, line: 99 } }; }],
    ['missing-log-anchor', result => { result.review.proof = { ...proof, log: { ...proof.log, line: 99 } }; }],
  ]) {
    const id = submit(db, name);
    const result = verdict();
    change(result);
    assert.equal(approve(db, id, result).status, 'needs_review', name);
  }
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('plausible grounded flaw is accepted despite unresolved ancillary proof checks', t => {
  const db = setup(t);
  const id = submit(db, 'ancillary-uncertain');
  const result = verdict();
  result.review.proof_review = { ...proofReview, checks: { ...proofReview.checks,
    reachability: 'uncertain', poc: 'uncertain', log: 'uncertain', defenses: 'uncertain' } };
  assert.equal(approve(db, id, result).status, 'approved');

  const contradictedId = submit(db, 'ancillary-contradicted');
  const contradicted = verdict();
  contradicted.review.proof_review = { ...proofReview, checks: { ...proofReview.checks,
    reachability: 'contradicted' } };
  assert.equal(approve(db, contradictedId, contradicted).status, 'needs_review');
});

test('first static uncertainty keeps its own reason when independent review was not reached', t => {
  const db = setup(t);
  const id = submit(db, 'first-review-uncertain');
  const result = verdict();
  result.review.verdict = 'uncertain';
  result.review.reason = 'Original C PoC does not establish the required entry path';
  delete result.review.proof_review;
  const held = approve(db, id, result);
  assert.equal(held.status, 'needs_review');
  assert.equal(held.reason, result.review.reason);
  const summary = JSON.parse(db.prepare('SELECT verification_json FROM submissions WHERE id = ?').get(id).verification_json);
  assert.equal(summary.admin_action_required, null);
  assert.equal(summary.proof_review, null);

  const missingSecondId = submit(db, 'likely-without-second-review');
  const likely = verdict();
  delete likely.review.proof_review;
  const missingSecond = approve(db, missingSecondId, likely);
  assert.equal(missingSecond.status, 'needs_review');
  assert.match(missingSecond.reason, /Administrator action requirement is unresolved/);
});

test('unanchored administrator claims and unknown prerequisites are held', t => {
  const db = setup(t);
  for (const [name, change, expected] of [
    ['primary-admin', result => { result.review.integrity.admin_action_required = true;
      result.review.integrity.reason = 'Original PoC requires sudo mount'; }, 'needs_review'],
    ['secondary-admin', result => { result.review.proof_review = { ...proofReview,
      admin_action_required: true, verdict: 'refutes', reason: 'Target administrator must change a kernel setting' }; }, 'needs_review'],
    ['primary-unknown', result => { result.review.integrity.admin_action_required = null; }, 'needs_review'],
    ['secondary-unknown', result => { result.review.proof_review = { ...proofReview,
      admin_action_required: null, verdict: 'uncertain' }; }, 'needs_review'],
    ['missing-primary-flag', result => { delete result.review.integrity.admin_action_required; }, 'needs_review'],
    ['missing-second-flag', result => { result.review.proof_review = { ...proofReview };
      delete result.review.proof_review.admin_action_required; }, 'needs_review'],
  ]) {
    const id = submit(db, name);
    const result = verdict();
    change(result);
    assert.equal(approve(db, id, result).status, expected, name);
  }
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('only original non-port privileged trigger anchors cause administrator rejection', t => {
  const db = setup(t);
  const cases = [
    { name: 'client-reserved-port', source: 'int main(void) { return connect_reserved(); }\n',
      trigger: { file_index: 0, line: 1, operation: 'connect_reserved' }, status: 'needs_review' },
    { name: 'sudo-client-wrapper', source: poc, script: 'sudo ./poc\n',
      trigger: { file_index: 2, line: 1, operation: 'sudo' }, status: 'needs_review' },
    { name: 'commented-c-mount', source: 'int main(void) { /* mount(0); */ return 0; }\n',
      trigger: { file_index: 0, line: 1, operation: 'mount' }, status: 'needs_review' },
    { name: 'string-c-mount', source: 'int main(void) { puts("mount(0)"); return 0; }\n',
      trigger: { file_index: 0, line: 1, operation: 'mount' }, status: 'needs_review' },
    { name: 'real-c-mount', source: 'int main(void) { return mount("x", "y", "z", 0, 0); }\n',
      trigger: { file_index: 0, line: 1, operation: 'mount' }, status: 'rejected' },
    { name: 'real-shell-exportfs', source: poc, script: 'sudo exportfs -ra\n',
      trigger: { file_index: 2, line: 1, operation: 'exportfs' }, status: 'rejected' },
  ];
  for (const sample of cases) {
    const input = raw(sample.name);
    input.files[0] = artifact('source.c', 'poc', sample.source);
    if (sample.script) input.files.push(artifact('trigger.sh', 'other', sample.script));
    const id = submitSubmission(db, input, 'analyst').submission_id;
    const result = verdict();
    result.review.integrity = { verdict: 'suspect', admin_action_required: true,
      admin_trigger: sample.trigger, reason: 'Claimed privileged trigger' };
    const completed = approve(db, id, result);
    assert.equal(completed.status, sample.status, sample.name);
    const stored = JSON.parse(db.prepare('SELECT verification_json FROM submissions WHERE id = ?').get(id).verification_json);
    assert.equal(stored.admin_action_required, sample.status === 'rejected' ? true : null, sample.name);
  }
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('independent proof reviewer needs an original privileged trigger anchor', t => {
  const db = setup(t);
  for (const [name, script, expected] of [
    ['shell-comment', '# sudo exportfs -ra\n', 'needs_review'],
    ['shell-narrative', 'echo sudo exportfs -ra\n', 'needs_review'],
    ['shell-trigger', 'sudo exportfs -ra\n', 'rejected'],
  ]) {
    const input = raw(name);
    input.files.push(artifact('trigger.sh', 'other', script));
    const id = submitSubmission(db, input, 'analyst').submission_id;
    const result = verdict();
    result.review.proof_review = { ...proofReview, verdict: 'refutes',
      admin_action_required: true, admin_trigger: { file_index: 2, line: 1, operation: 'exportfs' },
      reason: 'Original shell trigger changes exports' };
    assert.equal(approve(db, id, result).status, expected, name);
  }
});

test('valid long static-review reasons are stored without failing completion', t => {
  const db = setup(t);
  const approvedId = submit(db, 'long-review-reason');
  const approvedResult = verdict();
  approvedResult.review.reason = '검증'.repeat(600);
  const approved = approve(db, approvedId, approvedResult);
  assert.equal(approved.status, 'approved');
  assert.ok(Buffer.byteLength(approved.reason) <= 1000);
  assert.ok(approved.reason.startsWith('검증'));

  const suspectId = submit(db, 'long-integrity-reason');
  const suspectResult = verdict({ integrity: 'suspect' });
  suspectResult.review.integrity.reason = 'Admin-only trigger is absent from the claimed attack path. '.repeat(30);
  const rejected = approve(db, suspectId, suspectResult);
  assert.equal(rejected.status, 'rejected');
  assert.ok(Buffer.byteLength(rejected.reason) <= 1000);

  const adminInput = raw('long-admin-reason');
  adminInput.files[0] = artifact('source.c', 'poc', 'int main(void) { return mount("x", "y", "z", 0, 0); }\n');
  const adminId = submitSubmission(db, adminInput, 'analyst').submission_id;
  const adminResult = verdict();
  adminResult.review.integrity.admin_action_required = true;
  adminResult.review.integrity.admin_trigger = { file_index: 0, line: 1, operation: 'mount' };
  adminResult.review.integrity.reason = '관리자 권한이 필요한 마운트 작업입니다. '.repeat(60);
  const adminRejected = approve(db, adminId, adminResult);
  assert.equal(adminRejected.status, 'rejected');
  assert.ok(Buffer.byteLength(adminRejected.reason) <= 1000);
});

test('overlong option metadata is held instead of turning a completed review into an error', t => {
  const db = setup(t);
  const id = submit(db, 'long-option');
  const result = verdict();
  result.review.normalized.options = 'pNFS '.repeat(60);
  const held = approve(db, id, result);
  assert.equal(held.status, 'needs_review');
  assert.match(held.reason, /option metadata/i);
  assert.equal(held.management_id, null);
});

test('invalid source-path metadata is held instead of failing result delivery', t => {
  const db = setup(t);
  const id = submit(db, 'long-source-path');
  const result = verdict();
  result.review.normalized.file_path = `fs/nfsd/${'가'.repeat(110)}.c`;
  const held = approve(db, id, result);
  assert.equal(held.status, 'needs_review');
  assert.match(held.reason, /source path/i);
  assert.equal(held.management_id, null);
});

test('ambiguous same-root candidates cannot fall through to a new management ID', t => {
  const db = setup(t);
  const id = submit(db, 'ambiguous');
  const result = verdict();
  result.review.same_root_cause = { verdict: 'uncertain', reason: 'Multiple candidates' };
  assert.equal(approve(db, id, result).status, 'needs_review');
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('the same rooted enhancement retains one management ID and its earlier revisions', t => {
  const db = setup(t);
  const first = approve(db, submit(db, 'first'));
  const second = submit(db, 'second', { existing_management_id: first.management_id });
  const next = approve(db, second, verdict({ existingId: first.management_id }));
  assert.equal(next.management_id, first.management_id);
  assert.equal(db.prepare("SELECT count(*) AS count FROM submissions WHERE management_id = ? AND status = 'approved'").get(first.management_id).count, 2);
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 43);
});

test('same-root comparison receives the complete canonical live report or holds oversized evidence', t => {
  const db = setup(t);
  const firstReport = `${report}\n${'근거'.repeat(13_000)}\nLATE_ROOT_CAUSE_ANCHOR`;
  assert.ok(Buffer.byteLength(firstReport) < 90_000);
  const firstResult = verdict();
  firstResult.review.normalized.report = firstReport;
  firstResult.artifacts.report.content = firstReport;
  const first = approve(db, submit(db, 'first'), firstResult);
  submit(db, 'second', { existing_management_id: first.management_id });
  const comparison = claimSubmission(db, commit);
  assert.equal(comparison.existing_finding.report, firstReport);
  assert.match(comparison.existing_finding.report, /LATE_ROOT_CAUSE_ANCHOR$/);

  const oversized = `${report}\n${'근거'.repeat(16_000)}`;
  assert.ok(oversized.length < 90_000 && Buffer.byteLength(oversized) > 90_000);
  db.prepare('UPDATE submission_artifacts SET content = ?, size = ? WHERE submission_id = ? AND ordinal = 1000')
    .run(Buffer.from(oversized), Buffer.byteLength(oversized), first.submission_id);
  submit(db, 'third', { existing_management_id: first.management_id });
  assert.equal(claimSubmission(db, commit).existing_finding.report, null);
});

test('historical same-root comparison never passes a truncated archive report', t => {
  const db = setup(t);
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hv-existing-report-'));
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  const sourceDir = path.join(dataDir, 'source');
  mkdirSync(sourceDir);
  const complete = `${report}\n${'근거'.repeat(13_000)}\nHISTORICAL_TAIL_ANCHOR`;
  const oversized = `${report}\n${'근거'.repeat(16_000)}`;
  for (const [managementId, filename, content] of [
    ['A-001', 'complete.md', complete], ['A-002', 'oversized.md', oversized],
  ]) {
    db.prepare('INSERT INTO registry_history(management_id, number, title, target, imported_at) VALUES (?, ?, ?, ?, ?)')
      .run(managementId, Number(managementId.slice(2)), 'Historical issue', 'knfsd', new Date().toISOString());
    writeFileSync(path.join(sourceDir, filename), content);
  }
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-001', kind: 'report', source_path: 'complete.md', display_name: 'report.md' },
    { management_id: 'A-002', kind: 'report', source_path: 'oversized.md', display_name: 'report.md' },
  ]);
  submit(db, 'historical-complete', { existing_management_id: 'A-001' });
  assert.equal(claimSubmission(db, commit, dataDir).existing_finding.report, complete);
  submit(db, 'historical-oversized', { existing_management_id: 'A-002' });
  assert.equal(claimSubmission(db, commit, dataDir).existing_finding.report, null);
});

test('historical revision reports static screening without fabricated 2VM observation', t => {
  const db = setup(t);
  db.prepare(`INSERT INTO registry_history(management_id, number, title, target, imported_at)
    VALUES ('A-001', 1, 'Historical NFS issue', 'knfsd', ?)`)
    .run(new Date().toISOString());
  const historical = db.prepare('SELECT management_id FROM registry_history ORDER BY management_id LIMIT 1').get();
  assert.ok(historical);
  const id = submit(db, 'historical-revision', { existing_management_id: historical.management_id });
  const approved = approve(db, id, verdict({ existingId: historical.management_id }));
  assert.equal(approved.management_id, historical.management_id);
  const record = listRegistry(db).find(row => row.management_id === historical.management_id);
  assert.equal(record.review_provider, 'codex_static');
  assert.equal(record.latest_verification.result, 'static_screened');
  assert.equal(record.latest_verification.reproduction_status, 'not_run');
  assert.deepEqual(record.latest_verification.observed_impacts, []);
});

test('concurrent same-path submissions are held for root comparison before a second number', t => {
  const db = setup(t);
  const first = submit(db, 'first');
  const second = submit(db, 'second');
  const firstLease = claimSubmission(db, commit);
  const secondLease = claimSubmission(db, commit);
  assert.equal(completeSubmission(db, first, verdict(), firstLease.lease_token).management_id, 'A-043');
  const secondResult = verdict({ anchorLine: 43 });
  secondResult.review.grounding.evidence[0].text = line;
  assert.equal(completeSubmission(db, second, secondResult, secondLease.lease_token).status, 'needs_review');
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 43);
});

test('pooled claim picks oldest compatible target and idle heartbeats expose no fixed commit', t => {
  const db = setup(t);
  const first = submit(db, 'rc-one');
  const other = 'b'.repeat(40);
  const second = submit(db, 'stable-two', { repo_commit: other, version_id: 'stable' });
  assert.equal(claimSubmission(db, [other, commit]).submission_id, first);
  assert.equal(claimSubmission(db, [other, commit]).submission_id, second);
  const workerId = 'e'.repeat(32);
  heartbeatWorker(db, { worker_id: workerId, target_commit: null });
  const card = listVerificationQueue(db).workers.find(worker => worker.worker_id === workerId);
  assert.equal(card.target_commit, null);
  assert.equal(card.status, 'idle');
});

test('queue shows only the two current pooled verifiers while legacy cards age out', t => {
  const db = setup(t);
  const oldRc = '1'.repeat(32), oldStable = '2'.repeat(32);
  heartbeatWorker(db, { worker_id: oldRc, target_commit: commit });
  heartbeatWorker(db, { worker_id: oldStable, target_commit: 'b'.repeat(40) });
  db.prepare('UPDATE verifier_workers SET last_seen_at = ? WHERE worker_id IN (?, ?)')
    .run(new Date(Date.now() - 60 * 60_000).toISOString(), oldRc, oldStable);
  const poolOne = '3'.repeat(32), poolTwo = '4'.repeat(32);
  heartbeatWorker(db, { worker_id: poolOne, target_commit: null });
  heartbeatWorker(db, { worker_id: poolTwo, target_commit: null });
  assert.deepEqual(listVerificationQueue(db).workers.filter(worker => worker.role === 'verifier')
    .map(worker => worker.worker_id).sort(), [poolOne, poolTwo]);
});

test('blocked queue exposes all records so each UI column can paginate independently', t => {
  const db = setup(t);
  for (let index = 0; index < 51; index++) {
    const id = submit(db, `blocked-${index}`);
    completeSubmission(db, id, verdict({ integrity: 'suspect' }), claimSubmission(db, commit).lease_token);
  }
  const queue = listVerificationQueue(db);
  assert.equal(queue.counts.blocked, 51);
  assert.equal(queue.blocked.length, 51);
  assert.equal(queue.blocked_has_more, false);
});

test('primitive follow-up sees submitted evidence as static-only and no verified impacts', t => {
  const db = setup(t);
  const approved = approve(db, submit(db, 'one'));
  const job = claimPrimitiveReview(db, 'f'.repeat(32), [commit]);
  assert.equal(job.management_id, approved.management_id);
  assert.equal(job.evidence_status, 'submitted_static');
  assert.deepEqual(job.verified_impacts, []);
  assert.equal(job.kasan_log, log);
});

test('legacy approved KASAN log downloads remain available', t => {
  const db = setup(t);
  const approved = approve(db, submit(db, 'legacy-log'));
  db.prepare("UPDATE submission_artifacts SET name = 'kasan.log' WHERE submission_id = ? AND ordinal = 1003").run(approved.submission_id);
  assert.equal(getVerifiedArtifact(db, approved.finding_id, 'kasan.log').toString(), log);
});

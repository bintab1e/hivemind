import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack } from './server.mjs';
import { hash, readFrontMatter } from './contract.mjs';
import { importHistoryArtifacts } from './history-artifacts.mjs';
import { claimDuplicateReview, claimPrimitiveReview, claimSubmission, completeDuplicateReview,
  completePrimitiveReview, completeSubmission, failDuplicateReview, failPrimitiveReview,
  getVerifiedArtifact, heartbeatWorker, initializeSubmissions,
  listVerificationQueue, listVerifiedArtifacts, purgeFinishedSubmissions, retrySubmission,
  submitSubmission } from './submissions.mjs';
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
function approve(db, id, result = verdict(), duplicateReview = {
  verdict: 'new', matched_management_id: null, reason: 'Different root cause from registered findings',
}) {
  const screened = completeSubmission(db, id, result, claimSubmission(db, commit).lease_token);
  if (screened.status !== 'duplicate_pending') return screened;
  const job = claimDuplicateReview(db);
  assert.equal(job.submission_id, id);
  return completeDuplicateReview(db, id, duplicateReview, job.lease_token);
}

const sameFinding = managementId => ({ verdict: 'duplicate', matched_management_id: managementId,
  reason: 'Same source path, reachable call chain and faulty invariant' });

test('static-screened submission receives a number only after duplicate review, without fabricated dynamic evidence', t => {
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

test('grounded review corrects submitted NFS version and preserves a proven pre-auth path', t => {
  const db = setup(t);
  const corrected = approve(db, submit(db, 'corrected-version', { nfs_version: '3' }));
  assert.equal(corrected.status, 'approved');
  assert.equal(listRegistry(db).find(row => row.management_id === corrected.management_id).nfs_version, '4.2');

  const id = submit(db, 'pre-auth', { nfs_version: '4.2' });
  const result = verdict();
  result.review.normalized.nfs_version = null;
  result.review.normalized.permission = 'Pre-auth';
  result.review.normalized.pre_auth = { source_path: 'fs/nfsd/nfs4proc.c', source_line: 41, poc_line: 1 };
  const accepted = approve(db, id, result);
  assert.equal(accepted.status, 'approved');
  const row = listRegistry(db).find(item => item.management_id === accepted.management_id);
  assert.equal(row.privilege, 'Pre-auth');
  assert.equal(row.nfs_version, null);
});

test('authorization bypass is normalized while unknown types remain unset', t => {
  const db = setup(t);
  const valid = verdict();
  valid.review.normalized.vulnerability_type = 'Access Control Bypass';
  const accepted = approve(db, submit(db, 'authz-bypass'), valid);
  assert.equal(accepted.status, 'approved');
  assert.equal(listRegistry(db).find(row => row.management_id === accepted.management_id).vulnerability_type,
    'Authorization Bypass');

  const invalid = verdict();
  invalid.review.normalized.vulnerability_type = 'Unknown Bypass';
  const reviewed = approve(db, submit(db, 'unknown-type'), invalid);
  assert.equal(reviewed.status, 'approved');
  assert.equal(listRegistry(db).find(row => row.management_id === reviewed.management_id).vulnerability_type,
    null);
});

test('formatting or missing optional metadata does not hold a source-grounded flaw', t => {
  const db = setup(t);
  for (const [label, change, field, expected] of [
    ['title', finding => { finding.normalized.title = 'short'; }, 'title',
      'NFS source flaw in fs/nfsd/nfs4proc.c'],
    ['NFS version', finding => { finding.normalized.nfs_version = null; }, 'nfs_version', null],
    ['permission', finding => { finding.normalized.permission = null; }, 'privilege', null],
  ]) {
    const result = verdict();
    change(result.review);
    const reviewed = approve(db, submit(db, `bad-${label.replaceAll(' ', '-')}`), result);
    assert.equal(reviewed.status, 'approved');
    assert.equal(listRegistry(db).find(row => row.management_id === reviewed.management_id)[field], expected);
  }
});

test('static screening stages evidence without registering or numbering the finding', t => {
  const db = setup(t);
  const id = submit(db, 'staged');
  const screened = completeSubmission(db, id, verdict(), claimSubmission(db, commit).lease_token);
  assert.equal(screened.status, 'duplicate_pending');
  assert.equal(screened.management_id, null);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 42);
  assert.equal(listRegistry(db).some(row => row.title === 'NFS request length error'), false);
  const queue = listVerificationQueue(db);
  assert.equal(queue.duplicate.counts.pending, 1);
  assert.equal(queue.duplicate.pending[0].submission_id, id);
  const job = claimDuplicateReview(db);
  assert.equal(job.submission_id, id);
  assert.equal(job.candidate.title, 'NFS request length error');
  assert.equal(job.candidate.poc_excerpt, poc);
  assert.equal(listVerificationQueue(db).duplicate.active[0].submission_id, id);
  assert.equal(completeDuplicateReview(db, id,
    { verdict: 'new', matched_management_id: null, reason: 'No matching root cause or entry path' },
    job.lease_token).management_id, 'A-043');
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
  result.review.proof_review = { ...proofReview, verdict: 'uncertain', checks: { ...proofReview.checks,
    reachability: 'uncertain', defenses: 'uncertain' } };
  assert.equal(approve(db, id, result).status, 'approved');

  const uncertainLog = verdict();
  uncertainLog.review.proof_review = { ...proofReview, verdict: 'uncertain', checks: { ...proofReview.checks,
    log: 'uncertain' } };
  assert.equal(approve(db, submit(db, 'uncertain-log'), uncertainLog).status, 'approved');

  const uncertainFlaw = verdict();
  uncertainFlaw.review.proof_review = { ...proofReview, verdict: 'uncertain', checks: { ...proofReview.checks,
    flaw: 'uncertain', poc: 'uncertain', log: 'uncertain' } };
  assert.equal(approve(db, submit(db, 'uncertain-secondary-excerpt'), uncertainFlaw).status, 'approved');

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
  assert.equal(approved.reason, approvedResult.review.reason);

  const suspectId = submit(db, 'long-integrity-reason');
  const suspectResult = verdict({ integrity: 'suspect' });
  suspectResult.review.integrity.reason = 'Admin-only trigger is absent from the claimed attack path. '.repeat(30);
  const rejected = approve(db, suspectId, suspectResult);
  assert.equal(rejected.status, 'rejected');
  assert.equal(rejected.reason, suspectResult.review.integrity.reason.trim());

  const adminInput = raw('long-admin-reason');
  adminInput.files[0] = artifact('source.c', 'poc', 'int main(void) { return mount("x", "y", "z", 0, 0); }\n');
  const adminId = submitSubmission(db, adminInput, 'analyst').submission_id;
  const adminResult = verdict();
  adminResult.review.integrity.admin_action_required = true;
  adminResult.review.integrity.admin_trigger = { file_index: 0, line: 1, operation: 'mount' };
  adminResult.review.integrity.reason = '관리자 권한이 필요한 마운트 작업입니다. '.repeat(60);
  const adminRejected = approve(db, adminId, adminResult);
  assert.equal(adminRejected.status, 'rejected');
  assert.equal(adminRejected.reason, adminResult.review.integrity.reason.trim());

  const challengedId = submit(db, 'long-independent-reason');
  const challengedResult = verdict();
  const explanation = '소스 경로의 전제 조건을 확인해야 합니다. '.repeat(65);
  challengedResult.review.verdict = 'uncertain';
  challengedResult.review.proof_review = { ...proofReview, verdict: 'refutes', reason: explanation };
  challengedResult.review.reason = `Independent static challenge did not confirm the claim: ${explanation}`;
  const challenged = approve(db, challengedId, challengedResult);
  assert.equal(challenged.status, 'needs_review');
  assert.equal(challenged.reason, challengedResult.review.reason.trim());
  const summary = JSON.parse(db.prepare('SELECT verification_json FROM submissions WHERE id = ?')
    .get(challengedId).verification_json);
  assert.equal(summary.proof_review.reason, explanation.trim());
});

test('reviewed options keep build settings and short NFS features, omitting runtime prose', t => {
  for (const [name, rawOption, expected] of [
    ['build', 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y; listener on TCP port 2049', 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y'],
    ['feature', 'RPC/RDMA', 'RPC/RDMA'],
    ['runtime', 'iWARP listener on TCP port 20049; max_block_size=1048576', null],
  ]) {
    const db = setup(t);
    const result = verdict();
    result.review.normalized.options = rawOption;
    const completed = approve(db, submit(db, name), result);
    assert.equal(completed.status, 'approved', name);
    assert.equal(listRegistry(db).find(row => row.management_id === completed.management_id).option, expected, name);
  }
});

test('long build option metadata stays visible without blocking a source-grounded flaw', t => {
  const db = setup(t);
  const id = submit(db, 'long-option');
  const result = verdict();
  const options = Array.from({ length: 20 }, (_, index) => `CONFIG_NFSD_FEATURE_${index}=y`).join(', ');
  result.review.normalized.options = options;
  const reviewed = approve(db, id, result);
  assert.equal(reviewed.status, 'approved');
  assert.equal(listRegistry(db).find(row => row.management_id === reviewed.management_id).option, options);
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

test('uncertain duplicate comparison is held without assigning a management ID', t => {
  const db = setup(t);
  const id = submit(db, 'ambiguous');
  const held = approve(db, id, verdict(),
    { verdict: 'uncertain', matched_management_id: null, reason: 'Multiple candidates share the same path' });
  assert.equal(held.status, 'duplicate_needs_review');
  assert.equal(held.reason, 'Multiple candidates share the same path');
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
});

test('the same rooted enhancement retains one management ID and its earlier revisions', t => {
  const db = setup(t);
  const first = approve(db, submit(db, 'first'));
  const second = submit(db, 'second', { existing_management_id: first.management_id });
  const next = approve(db, second, verdict(), sameFinding(first.management_id));
  assert.equal(next.management_id, first.management_id);
  assert.equal(db.prepare("SELECT count(*) AS count FROM submissions WHERE management_id = ? AND status = 'approved'").get(first.management_id).count, 2);
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 43);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM finding_revision_audit WHERE management_id = ?').get(first.management_id).n, 1);
  assert.equal(getVerifiedArtifact(db, next.finding_id, 'report.md').toString(), report);
});

test('a first submission issues a lasting vulnerability ID for pending and purged follow-ups', t => {
  const db = setup(t);
  const input = raw('first-case');
  const first = submitSubmission(db, input, 'analyst');
  assert.match(first.vulnerability_id, /^V-\d{6,}$/);
  assert.equal(first.management_id, undefined);
  assert.equal(submitSubmission(db, input, 'analyst').vulnerability_id, first.vulnerability_id);
  db.prepare("UPDATE submissions SET status = 'rejected', completed_at = ? WHERE id = ?")
    .run('2026-10-14T20:00:00.000Z', first.submission_id);
  assert.equal(purgeFinishedSubmissions(db, '2026-10-14T21:00:00.000Z').deleted, 1);
  const enhanced = submitSubmission(db, raw('enhanced-case',
    { existing_vulnerability_id: first.vulnerability_id }), 'analyst');
  assert.equal(enhanced.vulnerability_id, first.vulnerability_id);
  assert.equal(listVerificationQueue(db).pending[0].vulnerability_id, first.vulnerability_id);
  assert.equal(listVerificationQueue(db).pending[0].existing_vulnerability_id, first.vulnerability_id);
  assert.equal(approve(db, enhanced.submission_id).management_id, 'A-043');
  assert.equal(db.prepare('SELECT management_id FROM finding_cases WHERE id = ?')
    .get(Number(first.vulnerability_id.slice(2))).management_id, 'A-043');
  assert.throws(() => submitSubmission(db, raw('unknown-case',
    { existing_vulnerability_id: 'V-999999' }), 'analyst'), /Existing vulnerability not found/);
});

test('a cited vulnerability never becomes a new number or a different finding without review', t => {
  const db = setup(t);
  const firstReceipt = submitSubmission(db, raw('first-case'), 'analyst');
  const first = approve(db, firstReceipt.submission_id);
  const independent = approve(db, submit(db, 'independent-case'));
  const id = firstReceipt.vulnerability_id;
  const unlinked = approve(db, submit(db, 'unexpected-new', { existing_vulnerability_id: id }));
  assert.equal(unlinked.status, 'duplicate_needs_review');
  assert.equal(unlinked.management_id, null);
  assert.match(unlinked.reason, /linked to A-043/);
  const wrong = approve(db, submit(db, 'wrong-match', { existing_vulnerability_id: id }),
    verdict(), sameFinding(independent.management_id));
  assert.equal(wrong.status, 'duplicate_needs_review');
  assert.equal(wrong.management_id, null);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 44);
  const merged = approve(db, submit(db, 'same-case', { existing_vulnerability_id: id }),
    verdict(), sameFinding(first.management_id));
  assert.equal(merged.status, 'approved');
  assert.equal(merged.management_id, first.management_id);
  assert.equal(merged.vulnerability_id, id);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 44);
});

test('legacy approved revisions backfill to one vulnerability ID', t => {
  const db = setup(t);
  const first = approve(db, submit(db, 'legacy-first'));
  approve(db, submit(db, 'legacy-second', { existing_management_id: first.management_id }),
    verdict(), sameFinding(first.management_id));
  db.prepare('UPDATE submissions SET case_id = NULL WHERE management_id = ?').run(first.management_id);
  db.prepare('DELETE FROM finding_cases WHERE management_id = ?').run(first.management_id);
  initializeSubmissions(db);
  const cases = db.prepare("SELECT DISTINCT case_id FROM submissions WHERE management_id = ?")
    .all(first.management_id);
  assert.equal(cases.length, 1);
  assert.equal(db.prepare('SELECT management_id FROM finding_cases WHERE id = ?').get(cases[0].case_id).management_id,
    first.management_id);
});

test('an uncertain metadata field in a strengthening submission preserves existing registry values', t => {
  const db = setup(t);
  const firstReview = verdict();
  firstReview.review.normalized.options = 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y';
  const first = approve(db, submit(db, 'first-with-options'), firstReview);
  const secondReview = verdict();
  Object.assign(secondReview.review.normalized, { options: null, permission: null,
    nfs_version: null, vulnerability_type: null });
  const second = approve(db, submit(db, 'second-without-options',
    { existing_management_id: first.management_id }), secondReview, sameFinding(first.management_id));
  const record = listRegistry(db).find(row => row.management_id === first.management_id);
  assert.equal(second.management_id, first.management_id);
  assert.equal(record.option, 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y');
  assert.equal(record.privilege, 'AUTH_SYS');
  assert.equal(record.nfs_version, '4.2');
  assert.equal(record.vulnerability_type, 'OOB Read');
});

test('the static verifier does not receive an existing report; duplicate worker receives the reference', t => {
  const db = setup(t);
  const first = approve(db, submit(db, 'first'));
  const second = submit(db, 'second', { existing_management_id: first.management_id });
  const screening = claimSubmission(db, commit);
  assert.equal(Object.hasOwn(screening, 'existing_finding'), false);
  assert.equal(completeSubmission(db, second, verdict(), screening.lease_token).status, 'duplicate_pending');
  const duplicateJob = claimDuplicateReview(db);
  const reference = duplicateJob.references.find(item => item.management_id === first.management_id);
  assert.ok(reference);
  assert.match(reference.report_excerpt, /## Root cause/);
});

test('historical A records are available only to the duplicate reviewer', t => {
  const db = setup(t);
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hv-existing-report-'));
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  const sourceDir = path.join(dataDir, 'source');
  mkdirSync(sourceDir);
  db.prepare('INSERT INTO registry_history(management_id, number, title, target, imported_at) VALUES (?, ?, ?, ?, ?)')
    .run('A-001', 1, 'Historical issue', 'knfsd', new Date().toISOString());
  writeFileSync(path.join(sourceDir, 'complete.md'), report);
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-001', kind: 'report', source_path: 'complete.md', display_name: 'report.md' },
  ]);
  const id = submit(db, 'historical-complete', { existing_management_id: 'A-001' });
  const screening = claimSubmission(db, commit, dataDir);
  assert.equal(Object.hasOwn(screening, 'existing_finding'), false);
  assert.equal(completeSubmission(db, id, verdict(), screening.lease_token).status, 'duplicate_pending');
  const duplicateJob = claimDuplicateReview(db, dataDir);
  assert.match(duplicateJob.references.find(item => item.management_id === 'A-001').report_excerpt, /## Root cause/);
});

test('historical revision reports static screening without fabricated 2VM observation', t => {
  const db = setup(t);
  db.prepare(`INSERT INTO registry_history(management_id, number, title, target, imported_at)
    VALUES ('A-001', 1, 'Historical NFS issue', 'knfsd', ?)`)
    .run(new Date().toISOString());
  const historical = db.prepare('SELECT management_id FROM registry_history ORDER BY management_id LIMIT 1').get();
  assert.ok(historical);
  const id = submit(db, 'historical-revision', { existing_management_id: historical.management_id });
  const approved = approve(db, id, verdict(), sameFinding(historical.management_id));
  assert.equal(approved.management_id, historical.management_id);
  const record = listRegistry(db).find(row => row.management_id === historical.management_id);
  assert.equal(record.review_provider, 'codex_static');
  assert.equal(record.latest_verification.result, 'static_screened');
  assert.equal(record.latest_verification.reproduction_status, 'not_run');
  assert.deepEqual(record.latest_verification.observed_impacts, []);
});

test('concurrent same-path submissions wait for duplicate comparison before any number', t => {
  const db = setup(t);
  const first = submit(db, 'first');
  const second = submit(db, 'second');
  const firstLease = claimSubmission(db, commit);
  const secondLease = claimSubmission(db, commit);
  assert.equal(completeSubmission(db, first, verdict(), firstLease.lease_token).status, 'duplicate_pending');
  assert.equal(completeSubmission(db, second, verdict(), secondLease.lease_token).status, 'duplicate_pending');
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
  const firstJob = claimDuplicateReview(db);
  assert.equal(firstJob.submission_id, first);
  assert.equal(claimDuplicateReview(db), null);
  assert.equal(completeDuplicateReview(db, first, { verdict: 'new', matched_management_id: null,
    reason: 'No matching root cause' }, firstJob.lease_token).management_id, 'A-043');
  const secondJob = claimDuplicateReview(db);
  assert.equal(secondJob.submission_id, second);
  assert.ok(secondJob.references.some(item => item.management_id === 'A-043'));
  assert.equal(completeDuplicateReview(db, second, { verdict: 'uncertain', matched_management_id: null,
    reason: 'Same source file but root cause differs in an unresolved way' }, secondJob.lease_token).status, 'duplicate_needs_review');
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 43);
});

test('changed A/B/C references force a fresh duplicate comparison before new numbering', t => {
  const db = setup(t);
  const first = approve(db, submit(db, 'first'));
  const second = submit(db, 'second');
  assert.equal(completeSubmission(db, second, verdict(), claimSubmission(db, commit).lease_token).status, 'duplicate_pending');
  const oldJob = claimDuplicateReview(db);
  db.prepare('UPDATE finding_registry SET revision = revision + 1 WHERE management_id = ?').run(first.management_id);
  assert.equal(completeDuplicateReview(db, second, { verdict: 'new', matched_management_id: null,
    reason: 'No matching cause in the old snapshot' }, oldJob.lease_token).status, 'duplicate_pending');
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 43);
  assert.equal(claimDuplicateReview(db).submission_id, second);
});

test('a duplicate-review hold stays in its own queue and survives daily cleanup', t => {
  const db = setup(t);
  const id = submit(db, 'held-duplicate');
  assert.equal(completeSubmission(db, id, verdict(), claimSubmission(db, commit).lease_token).status, 'duplicate_pending');
  const job = claimDuplicateReview(db);
  assert.equal(completeDuplicateReview(db, id, { verdict: 'uncertain', matched_management_id: null,
    reason: 'A historical report lacks a comparable causal path' }, job.lease_token).status, 'duplicate_needs_review');
  const queue = listVerificationQueue(db);
  assert.equal(queue.counts.blocked, 0);
  assert.equal(queue.duplicate.counts.error, 1);
  assert.equal(queue.duplicate.errors[0].submission_id, id);
  purgeFinishedSubmissions(db, '9999-12-31T00:00:00.000Z');
  assert.equal(db.prepare('SELECT status FROM submissions WHERE id = ?').get(id).status, 'duplicate_needs_review');
  assert.equal(retrySubmission(db, id).status, 'duplicate_pending');
});

test('duplicate-review failures retry, then expose an error without consuming a number', t => {
  const db = setup(t);
  const id = submit(db, 'duplicate-failure');
  assert.equal(completeSubmission(db, id, verdict(), claimSubmission(db, commit).lease_token).status, 'duplicate_pending');
  for (let attempt = 1; attempt <= 3; attempt++) {
    const job = claimDuplicateReview(db);
    assert.equal(job.submission_id, id);
    const failed = failDuplicateReview(db, id, `Comparison failed ${attempt}`, job.lease_token);
    assert.equal(failed.status, attempt < 3 ? 'duplicate_pending' : 'duplicate_error');
    assert.equal(failed.management_id, null);
    if (attempt < 3) db.prepare('UPDATE submissions SET duplicate_retry_after = ? WHERE id = ?')
      .run('2000-01-01T00:00:00.000Z', id);
  }
  assert.equal(listVerificationQueue(db).duplicate.counts.error, 1);
  assert.equal(db.prepare("SELECT last_number FROM registry_sequences WHERE target = 'knfsd'").get().last_number, 42);
  assert.equal(retrySubmission(db, id).status, 'duplicate_pending');
  const retry = claimDuplicateReview(db);
  assert.equal(retry.submission_id, id);
  assert.equal(completeDuplicateReview(db, id, { verdict: 'new', matched_management_id: null,
    reason: 'Independent comparison found no matching root cause' }, retry.lease_token).management_id, 'A-043');
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

test('primitive opinions and failures cannot change approved findings', t => {
  for (const outcome of ['complete', 'fail']) {
    const db = setup(t);
    const approved = approve(db, submit(db, `primitive-${outcome}`));
    const job = claimPrimitiveReview(db, 'f'.repeat(32), [commit]);
    if (outcome === 'complete') completePrimitiveReview(db, approved.finding_id, '추가 검토 방향입니다.', job.lease_token);
    else failPrimitiveReview(db, approved.finding_id, 'Opinion generation unavailable', job.lease_token);
    assert.equal(db.prepare('SELECT status FROM submissions WHERE id = ?').get(approved.submission_id).status,
      'approved');
    assert.equal(db.prepare('SELECT finding_id FROM finding_registry WHERE management_id = ?')
      .get(approved.management_id).finding_id, approved.finding_id);
  }
});

test('legacy approved KASAN log downloads remain available', t => {
  const db = setup(t);
  const approved = approve(db, submit(db, 'legacy-log'));
  db.prepare("UPDATE submission_artifacts SET name = 'kasan.log' WHERE submission_id = ? AND ordinal = 1003").run(approved.submission_id);
  assert.equal(getVerifiedArtifact(db, approved.finding_id, 'kasan.log').toString(), log);
});

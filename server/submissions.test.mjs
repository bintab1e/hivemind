import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, setActiveTrack } from './server.mjs';
import { hash, readFrontMatter } from './contract.mjs';
import { claimPrimitiveReview, claimSubmission, completeSubmission, getVerifiedArtifact,
  heartbeatWorker, listVerificationQueue, listVerifiedArtifacts, submitSubmission } from './submissions.mjs';
import { listRegistry } from './registry.mjs';

const commit = 'a'.repeat(40);
const line = 'if (count > available) return -EINVAL;';
const poc = 'int main(void) { return 0; }\n';
const log = 'BUG: KASAN: submitted claim\nRead of size 4\n';
const report = `## Summary\n요청 길이 검사 후보입니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:42\n\`\`\`c\n${line}\n\`\`\`\n\n## Reproduction environment\n서버 검증은 제출 자료의 정적 검토만 수행했습니다.\n\n## PoC\n원본 C 요청입니다.\n\n## Impact analysis\n제출 로그는 미재현 주장입니다.`;
const artifact = (name, kind, content) => ({ name, kind, content_base64: Buffer.from(content).toString('base64') });
const raw = (id, metadata = {}) => ({ project: 'knfsd', client_submission_id: id, title: 'NFS request length error',
  report, metadata: { version_id: '7.3-rc7', repo_commit: commit, nfs_version: '4.2', ...metadata },
  files: [artifact('source.c', 'poc', poc), artifact('submitted.log', 'log', log)] });
const verdict = ({ integrity = 'clear', existingId = null, anchorLine = 42 } = {}) => ({
  review: { verdict: 'likely', integrity: { verdict: integrity, reason: integrity === 'clear' ? 'No artificial conditions' : 'Kernel delay added' },
    reason: 'Source and original C PoC support a plausible static candidate',
    grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: anchorLine, text: line }] },
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
  const id = submit(db, 'one');
  const result = verdict();
  result.review.normalized.code_refs = [];
  const accepted = approve(db, id, result);
  assert.equal(accepted.management_id, 'A-043');
  const record = listRegistry(db).find(row => row.management_id === 'A-043');
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

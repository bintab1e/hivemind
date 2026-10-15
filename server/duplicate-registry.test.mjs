import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, startServer } from './server.mjs';
import { importRegistryHistory, listRegistry, registerFinding, updateRegistryRow } from './registry.mjs';
import { listDuplicateCandidates, listInternalDuplicateReferences, recordDuplicateResult,
  recordInternalDuplicateResult } from './duplicate-registry.mjs';

const findingId = 'a'.repeat(64);
const submissionId = 'b'.repeat(64);
const historicalArtifactId = 'c'.repeat(64);
const historicalPocId = 'e'.repeat(64);
const kernelCommit = 'd'.repeat(40);
const checkedAt = '2026-10-13T06:00:00.000Z';
const lore = 'https://lore.kernel.org/linux-nfs/20261013-example%40example.org/';
const branch = `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${kernelCommit}`;

function historicalRows() {
  return [['A', 'knfsd', 42], ['B', 'NFS-Ganesha', 21], ['C', 'libnfs', 1]]
    .flatMap(([prefix, target, last]) => Array.from({ length: last }, (_, index) => ({
      management_id: `${prefix}-${String(index + 1).padStart(3, '0')}`,
      title: `${target} historical issue ${index + 1}`,
      target,
      report_status: prefix === 'A' && index === 0 || prefix === 'B' && index === 0 ? '미제보' :
        prefix === 'A' && index === 2 ? null : '제보 완료',
    })));
}

function fixture(t, existing = null) {
  const dataDir = existing ?? fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-duplicate-'));
  const db = openDatabase(path.join(dataDir, 'hivemind.sqlite3'));
  t.after(() => { db.close(); if (!existing) fs.rmSync(dataDir, { recursive: true, force: true }); });
  importRegistryHistory(db, historicalRows());
  const report = '# Existing analysis\n\nRoot cause in nfsd4_proc_compound.\n';
  fs.mkdirSync(path.join(dataDir, 'history-artifacts'), { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'history-artifacts', historicalArtifactId), report);
  db.prepare(`INSERT INTO history_artifacts (id, management_id, kind, name, sha256, size, imported_at)
    VALUES (?, 'A-001', 'report', 'report.md', 'hash', ?, ?)`)
    .run(historicalArtifactId, Buffer.byteLength(report), checkedAt);
  const oldPoc = '#include <stdio.h>\nint main(void) { puts("old PoC"); return 0; }\n';
  fs.writeFileSync(path.join(dataDir, 'history-artifacts', historicalPocId), oldPoc);
  db.prepare(`INSERT INTO history_artifacts (id, management_id, kind, name, sha256, size, imported_at)
    VALUES (?, 'A-001', 'poc', 'poc.c', 'hash', ?, ?)`)
    .run(historicalPocId, Buffer.byteLength(oldPoc), checkedAt);
  const markdown = `---\nschema_version: 1\nkind: finding\nfile_path: fs/nfsd/nfs4proc.c\ncode_refs:\n  - fs/nfsd/nfs4proc.c:123\n---\nUncurated event body with private PoC`;
  db.prepare(`INSERT INTO events
    (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES (?, 'agent-1', 'finding.md', 'hash', 'finding', 'v1', ?, 'Submitted title', '[]', ?, ?, ?)`)
    .run(findingId, kernelCommit, checkedAt, checkedAt, markdown);
  registerFinding(db, findingId, {}, checkedAt);
  db.prepare("UPDATE finding_registry SET management_id = 'A-043', number = 43, approved_at = ? WHERE finding_id = ?")
    .run(checkedAt, findingId);
  db.prepare(`INSERT INTO submissions
    (id, agent_id, project, title, report, metadata_json, raw_sha256, status, submitted_at,
     completed_at, finding_id, management_id)
    VALUES (?, 'agent-1', 'knfsd', 'Submitted title', 'raw', '{}', 'hash', 'approved', ?, ?, ?, 'A-043')`)
    .run(submissionId, checkedAt, checkedAt, findingId);
  const canonical = '## Summary\nObserved in 2 VM.\n## Root cause\nChecked source expression.\n';
  db.prepare(`INSERT INTO submission_artifacts
    (submission_id, ordinal, name, kind, sha256, size, content)
    VALUES (?, 1000, 'report.md', 'report', 'hash', ?, ?)`)
    .run(submissionId, Buffer.byteLength(canonical), Buffer.from(canonical));
  const livePoc = '#include <stdio.h>\nint main(void) { puts("new PoC"); return 0; }\n';
  db.prepare(`INSERT INTO submission_artifacts
    (submission_id, ordinal, name, kind, sha256, size, content)
    VALUES (?, 1001, 'poc.c', 'poc', 'hash', ?, ?)`)
    .run(submissionId, Buffer.byteLength(livePoc), Buffer.from(livePoc));
  return { db, dataDir };
}

function result(rowId, revision = 0, overrides = {}) {
  return {
    row_id: rowId, revision, verdict: 'duplicate', reason: 'Same root cause and affected code path in upstream report.',
    evidence: [{ url: lore, kind: 'mail', title: 'Earlier linux-nfs report' }],
    sources_checked: { mail: true, branch: true }, checked_at: checkedAt, ...overrides,
  };
}

function internalResult(rowId, revision = 0, overrides = {}) {
  return { row_id: rowId, revision, verdict: 'duplicate', reason: 'Same root cause and affected code path in both private reports.',
    matched_management_id: 'A-001', checked_at: checkedAt, ...overrides };
}

test('daily candidates include bounded canonical and historical PoC evidence', t => {
  const { db, dataDir } = fixture(t);
  const candidates = listDuplicateCandidates(db, dataDir);
  assert.deepEqual(candidates.map(item => item.row_id), ['history:A-001', 'history:A-003', 'history:B-001', findingId]);
  assert.match(candidates[0].report_excerpt, /Root cause in nfsd4_proc_compound/);
  assert.equal(candidates[1].report_status, null);
  assert.equal(candidates[3].management_id, 'A-043');
  assert.equal(candidates[3].file_path, 'fs/nfsd/nfs4proc.c');
  assert.deepEqual(candidates[3].code_refs, ['fs/nfsd/nfs4proc.c:123']);
  assert.match(candidates[3].report_excerpt, /Observed in 2 VM/);
  assert.match(candidates[0].poc_excerpt, /old PoC/);
  assert.match(candidates[3].poc_excerpt, /new PoC/);
  assert.doesNotMatch(JSON.stringify(candidates), /private PoC/);
});

test('internal references include all A/B/C registry rows, including reported findings', t => {
  const { db, dataDir } = fixture(t);
  const references = listInternalDuplicateReferences(db, dataDir);
  assert.equal(references.length, 65);
  assert.deepEqual(references.filter(row => ['A-001', 'B-021', 'C-001', 'A-043'].includes(row.management_id))
    .map(row => [row.management_id, row.report_status]), [
      ['A-001', '미제보'], ['B-021', '제보 완료'], ['C-001', '제보 완료'], ['A-043', '미제보'],
    ]);
  assert.doesNotMatch(JSON.stringify(references), /private PoC/);
  assert.match(references.find(row => row.management_id === 'A-001').poc_excerpt, /old PoC/);
  assert.match(references.find(row => row.management_id === 'A-043').poc_excerpt, /new PoC/);
});

test('confirmed internal duplicate changes only the later eligible row and records separate audit', t => {
  const { db, dataDir } = fixture(t);
  const result = recordInternalDuplicateResult(db, internalResult(findingId), dataDir);
  assert.equal(result.outcome, 'changed');
  assert.equal(db.prepare('SELECT report_status FROM finding_registry WHERE finding_id = ?').get(findingId).report_status, '중복');
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'A-001'").get().report_status, '미제보');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM duplicate_reviews').get().n, 0);
  assert.deepEqual(listRegistry(db).find(row => row.management_id === 'A-043').internal_duplicate_review, {
    verdict: 'duplicate', reason: 'Same root cause and affected code path in both private reports.',
    matched_management_id: 'A-001', checked_at: checkedAt, outcome: 'changed',
  });
  assert.throws(() => db.prepare("DELETE FROM internal_duplicate_reviews WHERE row_id = ?").run(findingId), /append-only/);
});

test('internal duplicate never auto-tags self, later, missing-report, completed or manually restored rows', t => {
  const { db, dataDir } = fixture(t);
  assert.throws(() => recordInternalDuplicateResult(db, internalResult('history:A-001'), dataDir), /cannot match itself/);
  assert.equal(recordInternalDuplicateResult(db, internalResult('history:A-001', 0,
    { matched_management_id: 'A-043' }), dataDir).outcome, 'ineligible_reference');
  assert.equal(recordInternalDuplicateResult(db, internalResult('history:B-001', 0,
    { matched_management_id: 'A-001' }), dataDir).outcome, 'insufficient_reports');
  assert.equal(recordInternalDuplicateResult(db, internalResult('history:A-001', 0,
    { matched_management_id: 'C-001' }), dataDir).outcome, 'insufficient_reports');
  assert.throws(() => recordInternalDuplicateResult(db, internalResult(findingId, 0,
    { matched_management_id: 'A-999' }), dataDir), /Matched finding not found/);
  updateRegistryRow(db, 'history:A-001', { revision: 0, report_status: '제보 완료' }, 'human');
  assert.equal(recordInternalDuplicateResult(db, internalResult('history:A-001', 0,
    { matched_management_id: 'A-043' }), dataDir).outcome, 'stale');
  assert.equal(recordInternalDuplicateResult(db, internalResult('history:A-001', 1,
    { matched_management_id: 'A-043' }), dataDir).outcome, 'ineligible');
  assert.equal(recordInternalDuplicateResult(db, internalResult(findingId, 0), dataDir).outcome, 'changed');
  updateRegistryRow(db, findingId, { revision: 1, report_status: '미제보' }, 'human');
  assert.equal(recordInternalDuplicateResult(db, internalResult(findingId, 2), dataDir).outcome, 'manual_override');
});

test('internal no-match stores only a review date and cannot mutate status', t => {
  const { db, dataDir } = fixture(t);
  const output = recordInternalDuplicateResult(db, internalResult('history:B-001', 0,
    { verdict: 'no_match', matched_management_id: null, reason: 'No matching private finding.' }), dataDir);
  assert.equal(output.status_changed, false);
  assert.equal(listRegistry(db).find(row => row.management_id === 'B-001').internal_duplicate_review.checked_at, checkedAt);
  assert.throws(() => recordInternalDuplicateResult(db, internalResult(findingId, 0,
    { verdict: 'no_match' }), dataDir), /matched_management_id/);
});

test('already duplicate or withdrawn references cannot cause another automatic duplicate', t => {
  const { db, dataDir } = fixture(t);
  updateRegistryRow(db, 'history:A-001', { revision: 0, report_status: '중복' }, 'human');
  assert.equal(recordInternalDuplicateResult(db, internalResult(findingId), dataDir).outcome, 'ineligible_reference');
  updateRegistryRow(db, 'history:A-001', { revision: 1, report_status: '철회' }, 'human');
  assert.equal(recordInternalDuplicateResult(db, internalResult(findingId), dataDir).outcome, 'ineligible_reference');
  assert.equal(db.prepare('SELECT report_status FROM finding_registry WHERE finding_id = ?').get(findingId).report_status, '미제보');
});

test('confirmed duplicates update both registry tables and leave immutable evidence and edit trail', t => {
  const { db } = fixture(t);
  const history = recordDuplicateResult(db, result('history:A-001'));
  assert.deepEqual({ outcome: history.outcome, status_changed: history.status_changed, report_status: history.report_status },
    { outcome: 'changed', status_changed: true, report_status: '중복' });
  assert.equal(db.prepare("SELECT report_status, revision FROM registry_history WHERE management_id = 'A-001'").get().revision, 1);
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'A-001'").get().report_status, '중복');
  const live = recordDuplicateResult(db, result(findingId, 0, {
    evidence: [{ url: branch, kind: 'branch', title: 'Maintainer branch commit' }],
  }));
  assert.equal(live.status_changed, true);
  assert.equal(db.prepare('SELECT report_status FROM finding_registry WHERE finding_id = ?').get(findingId).report_status, '중복');
  assert.deepEqual(db.prepare('SELECT row_id, actor FROM registry_edits ORDER BY id').all().map(({ row_id, actor }) => ({ row_id, actor })), [
    { row_id: 'history:A-001', actor: 'duplicate-agent' }, { row_id: findingId, actor: 'duplicate-agent' },
  ]);
  assert.deepEqual(db.prepare('SELECT row_id, verdict, outcome FROM duplicate_reviews ORDER BY id').all().map(({ row_id, verdict, outcome }) => ({ row_id, verdict, outcome })), [
    { row_id: 'history:A-001', verdict: 'duplicate', outcome: 'changed' },
    { row_id: findingId, verdict: 'duplicate', outcome: 'changed' },
  ]);
  assert.deepEqual(listRegistry(db).find(item => item.event_id === 'history:A-001').duplicate_review.evidence,
    [{ url: lore, kind: 'mail', title: 'Earlier linux-nfs report' }]);
  assert.throws(() => db.prepare("UPDATE duplicate_reviews SET reason = 'changed' WHERE id = 1").run(), /append-only/);
});

test('completed, stale and unknown historical statuses never change automatically', t => {
  const { db } = fixture(t);
  const before = listDuplicateCandidates(db).find(item => item.row_id === 'history:A-001');
  updateRegistryRow(db, 'history:A-001', { revision: before.revision, report_status: '제보 완료' }, 'human');
  assert.equal(recordDuplicateResult(db, result('history:A-001', before.revision)).outcome, 'stale');
  assert.equal(recordDuplicateResult(db, result('history:A-001', 1)).outcome, 'ineligible');
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'A-001'").get().report_status, '제보 완료');
  const unknown = recordDuplicateResult(db, result('history:A-003'));
  assert.equal(unknown.outcome, 'review_only');
  assert.equal(unknown.report_status, null);
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'A-003'").get().report_status, null);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM registry_edits WHERE actor = ?').get('duplicate-agent').n, 0);
});

test('a human reversal of an automatic duplicate label is respected on later runs', t => {
  const { db } = fixture(t);
  assert.equal(recordDuplicateResult(db, result('history:A-001')).status_changed, true);
  updateRegistryRow(db, 'history:A-001', { revision: 1, report_status: '미제보' }, 'human');
  const repeated = recordDuplicateResult(db, result('history:A-001', 2));
  assert.equal(repeated.outcome, 'manual_override');
  assert.equal(repeated.status_changed, false);
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'A-001'").get().report_status, '미제보');
});

test('a duplicate verdict needs both source checks and an official matching source URL', t => {
  const { db } = fixture(t);
  assert.throws(() => recordDuplicateResult(db, result('history:A-001', 0, {
    sources_checked: { mail: true, branch: false },
  })), /both source checks/);
  assert.throws(() => recordDuplicateResult(db, result('history:A-001', 0, {
    evidence: [{ url: 'https://github.com/unrelated/repo/commit/' + kernelCommit, kind: 'branch', title: 'Unrelated' }],
  })), /official public source/);
  assert.throws(() => recordDuplicateResult(db, result('history:B-001', 0, {
    evidence: [{ url: lore, kind: 'mail', title: 'Wrong project' }],
  })), /official public source/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM duplicate_reviews').get().n, 0);
  const checked = recordDuplicateResult(db, result('history:B-001', 0, {
    verdict: 'no_match', evidence: [], reason: 'No prior matching report or maintainer commit.',
  }));
  assert.equal(checked.status_changed, false);
  assert.equal(db.prepare("SELECT report_status FROM registry_history WHERE management_id = 'B-001'").get().report_status, '미제보');
});

test('project mailing-list links are accepted only for their corresponding project', t => {
  const { db } = fixture(t);
  const ganeshaMail = 'https://lists.nfs-ganesha.org/archives/list/devel@lists.nfs-ganesha.org/thread/ABC123/';
  assert.equal(recordDuplicateResult(db, result('history:B-001', 0, {
    evidence: [{ url: ganeshaMail, kind: 'mail', title: 'Earlier Ganesha report' }],
  })).status_changed, true);
  updateRegistryRow(db, 'history:C-001', { revision: 0, report_status: '미제보' }, 'human');
  const libnfsMail = 'https://groups.google.com/g/libnfs/c/ABC123';
  assert.equal(recordDuplicateResult(db, result('history:C-001', 1, {
    evidence: [{ url: libnfsMail, kind: 'mail', title: 'Earlier libnfs report' }],
  })).status_changed, true);
  assert.throws(() => recordDuplicateResult(db, result('history:A-001', 0, {
    evidence: [{ url: libnfsMail, kind: 'mail', title: 'Wrong project' }],
  })), /official public source/);
});

function postSocket(socketPath, endpoint, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({ socketPath, path: endpoint, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test('duplicate review is available through verifier IPC and not through the public HTTP API', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-duplicate-ipc-'));
  const socketPath = path.join(dataDir, 'verifier.sock');
  const running = await startServer({ port: 0, dataDir, verifierSocketPath: socketPath, apiToken: 'test-admin' });
  t.after(async () => {
    await new Promise(resolve => running.server.close(resolve));
    running.db.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  importRegistryHistory(running.db, historicalRows());
  const candidates = await postSocket(socketPath, '/duplicate/candidates', {});
  assert.equal(candidates.status, 200);
  assert.equal(candidates.body.candidates.some(item => item.row_id === 'history:A-001'), true);
  const recorded = await postSocket(socketPath, '/duplicate/result', result('history:A-001'));
  assert.equal(recorded.status, 200);
  assert.equal(recorded.body.status_changed, true);
  const publicResult = await fetch(`${running.url}/duplicate/candidates`, { method: 'POST' });
  assert.equal(publicResult.status, 404);
  const internal = await postSocket(socketPath, '/duplicate/internal-candidates', {});
  assert.equal(internal.status, 200);
  assert.equal(internal.body.references.length, 64);
  assert.equal(internal.body.references.some(row => row.management_id === 'C-001'), true);
  const internalResult = await postSocket(socketPath, '/duplicate/internal-result', {
    row_id: 'history:B-001', revision: 0, verdict: 'no_match', reason: 'No matching private finding.',
    matched_management_id: null, checked_at: checkedAt,
  });
  assert.equal(internalResult.status, 200);
  assert.equal(internalResult.body.status_changed, false);
  assert.equal((await fetch(`${running.url}/duplicate/internal-candidates`, { method: 'POST' })).status, 404);
});

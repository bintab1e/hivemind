import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { importHistoryArtifacts, initializeHistoryArtifacts } from './history-artifacts.mjs';
import { sameRootCandidates } from './same-root-candidates.mjs';

function fixture(t) {
  const db = new DatabaseSync(':memory:');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-candidates-'));
  db.exec(`
    CREATE TABLE events (id TEXT PRIMARY KEY, title TEXT NOT NULL, markdown TEXT NOT NULL);
    CREATE TABLE finding_registry (finding_id TEXT PRIMARY KEY, management_id TEXT, target TEXT,
      title_override TEXT, approved_at TEXT, superseded_by TEXT);
    CREATE TABLE registry_history (management_id TEXT PRIMARY KEY, title TEXT NOT NULL, target TEXT NOT NULL);
    CREATE TABLE submissions (id TEXT PRIMARY KEY, management_id TEXT, finding_id TEXT, status TEXT, submitted_at TEXT);
    CREATE TABLE submission_artifacts (submission_id TEXT, ordinal INTEGER, name TEXT, size INTEGER, sha256 TEXT, content BLOB);
  `);
  initializeHistoryArtifacts(db);
  t.after(() => { db.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  return { db, dataDir };
}

function live(db, id, filePath, { approved = true, superseded = false, title = 'Same title', codeRef = null,
  body = `${filePath}:42` } = {}) {
  const report = `---\nfile_path: ${filePath}\ncode_refs:\n  - ${codeRef || `${filePath}#function`}\n---\n## Root cause\n${body}\n`;
  db.prepare('INSERT INTO events VALUES (?, ?, ?)').run(id, title, report);
  db.prepare('INSERT INTO finding_registry VALUES (?, ?, ?, ?, ?, ?)').run(
    id, id, 'knfsd', null, approved ? '2026-10-14' : null, superseded ? 'later' : null);
}

test('shortlists only active approved source-path/code-ref matches, never title-only matches', t => {
  const { db } = fixture(t);
  live(db, 'A-043', 'fs/nfsd/nfs4proc.c');
  live(db, 'A-044', 'fs/nfsd/other.c');
  live(db, 'A-045', 'fs/nfsd/nfs4proc.c', { approved: false });
  live(db, 'A-046', 'fs/nfsd/nfs4proc.c', { superseded: true });
  live(db, 'A-047', 'fs/nfsd/helper.c', { codeRef: 'fs/nfsd/nfs4proc.c#nfsd_test' });
  const input = { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c',
    codeRefs: ['fs/nfsd/nfs4proc.c#nfsd_test'] };
  const result = sameRootCandidates(db, input);
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-043', 'A-047']);
  assert.equal(result.truncated, false);
  assert.match(result.candidates[0].report, /Root cause/);
  assert.deepEqual(sameRootCandidates(db, { ...input, existingManagementId: 'A-043' })
    .candidates.map(item => item.management_id), ['A-047']);
  assert.throws(() => sameRootCandidates(db, { ...input, filePath: '../etc/passwd' }), TypeError);
});

test('recalls a cross-file root-cause candidate from exact report paths or C function identifiers', t => {
  const { db } = fixture(t);
  const other = 'fs/nfsd/other.c';
  const path = 'fs/nfsd/nfs4proc.c';
  live(db, 'A-043', other, { body: `The faulty operation also reaches ${path}:42.` });
  live(db, 'A-044', other, { body: `${path}.bak describes an unrelated test fixture.` });
  live(db, 'A-045', other, { body: 'The nfsd4_proc_compound() boundary check is faulty.' });
  live(db, 'A-046', other, { body: 'The nfsd4_proc_compound_extra() helper is unrelated.' });
  live(db, 'A-047', other, { body: 'The my_nfsd4_proc_compound() wrapper is unrelated.' });
  live(db, 'A-048', other, { body: `The X${path} mention is not a source path.` });
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: path,
    codeRefs: [`${path}:nfsd4_proc_compound`] });
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-043', 'A-045']);
  assert.equal(result.truncated, false);
  const fromRef = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/entry.c',
    codeRefs: [`${path}:nfsd4_proc_compound`] });
  assert.deepEqual(fromRef.candidates.map(item => item.management_id), ['A-043', 'A-045']);
});

test('does not shortlist a generic code-ref word merely because it appears in a report', t => {
  const { db } = fixture(t);
  live(db, 'A-043', 'fs/nfsd/other.c', { body: 'main() invokes a different code path.' });
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c',
    codeRefs: ['fs/nfsd/nfs4proc.c:main'] });
  assert.deepEqual(result.candidates, []);
});

test('shortlists imported historical records from archived report source paths', t => {
  const { db, dataDir } = fixture(t);
  const sourceDir = path.join(dataDir, 'source');
  fs.mkdirSync(sourceDir);
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-005', 'Old imported report', 'knfsd');
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-006', 'Old imported report', 'knfsd');
  fs.writeFileSync(path.join(sourceDir, 'matching.md'), '## Root cause\nfs/nfsd/nfs4proc.c:42\n');
  fs.writeFileSync(path.join(sourceDir, 'other.md'), '## Root cause\nfs/nfsd/other.c:42\n');
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-005', kind: 'report', source_path: 'matching.md', display_name: 'report.md' },
    { management_id: 'A-006', kind: 'report', source_path: 'other.md', display_name: 'report.md' },
  ]);
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c', dataDir });
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-005']);
  assert.equal(result.candidates[0].file_path, null);
  assert.equal(result.truncated, false);
});

test('recalls an archived cross-file cause by its exact C function name', t => {
  const { db, dataDir } = fixture(t);
  const sourceDir = path.join(dataDir, 'source');
  fs.mkdirSync(sourceDir);
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-005', 'Old imported report', 'knfsd');
  fs.writeFileSync(path.join(sourceDir, 'matching.md'),
    '## Root cause\nThe nfsd4_proc_compound() operation loses its bounds check in a helper.\n');
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-005', kind: 'report', source_path: 'matching.md', display_name: 'report.md' },
  ]);
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c',
    codeRefs: ['fs/nfsd/nfs4proc.c:nfsd4_proc_compound'], dataDir });
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-005']);
  assert.equal(result.truncated, false);
});

test('scans complete historical reports beyond the candidate excerpt before deciding relevance', t => {
  const { db, dataDir } = fixture(t);
  const sourceDir = path.join(dataDir, 'source');
  fs.mkdirSync(sourceDir);
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-037', 'Unrelated long report', 'knfsd');
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-038', 'Related long report', 'knfsd');
  fs.writeFileSync(path.join(sourceDir, 'unrelated.md'), `## Root cause\n${'x'.repeat(31_000)}\nfs/nfsd/other.c`);
  fs.writeFileSync(path.join(sourceDir, 'related.md'), `## Root cause\n${'x'.repeat(31_000)}\ndrivers/infiniband/core/iwcm.c:42`);
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-037', kind: 'report', source_path: 'unrelated.md', display_name: 'report.md' },
    { management_id: 'A-038', kind: 'report', source_path: 'related.md', display_name: 'report.md' },
  ]);
  const result = sameRootCandidates(db, {
    project: 'knfsd', filePath: 'drivers/infiniband/core/iwcm.c', dataDir,
  });
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-038']);
  assert.match(result.candidates[0].report, /drivers\/infiniband\/core\/iwcm\.c:42/);
  assert.equal(result.truncated, false);
});

test('limits candidate count and tells caller when matching is incomplete', t => {
  const { db } = fixture(t);
  for (let n = 43; n <= 52; n++) live(db, `A-${n}`, 'fs/nfsd/nfs4proc.c');
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c' });
  assert.equal(result.candidates.length, 8);
  assert.equal(result.truncated, true);
});

test('flags an unreadable historical report so an incomplete shortlist cannot auto-link', t => {
  const { db, dataDir } = fixture(t);
  live(db, 'A-043', 'fs/nfsd/nfs4proc.c');
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-005', 'Missing archive', 'knfsd');
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c', dataDir });
  assert.deepEqual(result.candidates.map(item => item.management_id), ['A-043']);
  assert.equal(result.truncated, true);
});

test('retains the incomplete-shortlist guard when a historical report exceeds the review limit', t => {
  const { db, dataDir } = fixture(t);
  const sourceDir = path.join(dataDir, 'source');
  fs.mkdirSync(sourceDir);
  db.prepare('INSERT INTO registry_history VALUES (?, ?, ?)').run('A-037', 'Oversized report', 'knfsd');
  fs.writeFileSync(path.join(sourceDir, 'large.md'), `${'x'.repeat(90_001)}\nfs/nfsd/nfs4proc.c`);
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-037', kind: 'report', source_path: 'large.md', display_name: 'report.md' },
  ]);
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c', dataDir });
  assert.deepEqual(result.candidates, []);
  assert.equal(result.truncated, true);
});

test('holds an oversized live report instead of comparing a truncated cause', t => {
  const { db } = fixture(t);
  live(db, 'A-043', 'fs/nfsd/nfs4proc.c', {
    body: `fs/nfsd/nfs4proc.c:42\n${'x'.repeat(90_001)}`,
  });
  const result = sameRootCandidates(db, { project: 'knfsd', filePath: 'fs/nfsd/nfs4proc.c' });
  assert.deepEqual(result.candidates, []);
  assert.equal(result.truncated, true);
});

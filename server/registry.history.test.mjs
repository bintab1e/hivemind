import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase } from './server.mjs';
import { importRegistryHistory, listRegistry, reconcileRegistryHistory, registrySequences } from './registry.mjs';

const floors = [['A', 'knfsd', 42], ['B', 'NFS-Ganesha', 21], ['C', 'libnfs', 1]];
const rows = () => floors.flatMap(([prefix, target, last]) => Array.from({ length: last }, (_, index) => ({
  management_id: `${prefix}-${String(index + 1).padStart(3, '0')}`,
  title: `Historical ${prefix}-${index + 1}`,
  target,
  report_status: null,
})));

test('historical registry imports exact IDs without inventing finding events or changing new-ID floors', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hivemind-history-'));
  const file = path.join(dir, 'hivemind.sqlite3');
  let db = openDatabase(file);
  t.after(() => { db?.close(); rmSync(dir, { recursive: true, force: true }); });
  assert.deepEqual(importRegistryHistory(db, rows()), { total: 64, added: 64 });
  assert.deepEqual(importRegistryHistory(db, rows()), { total: 64, added: 0 });
  const listed = listRegistry(db);
  assert.equal(listed.length, 64);
  assert.equal(listed[0].origin, 'history');
  assert.equal(listed[0].event_id, 'history:A-001');
  assert.equal(listed[0].management_id, 'A-001');
  assert.equal(listed[0].report_status, null);
  assert.equal(listed.at(-1).management_id, 'C-001');
  assert.deepEqual(listed[0].verified_impacts, []);
  assert.equal(db.prepare('SELECT count(*) AS n FROM events').get().n, 0);
  assert.deepEqual(registrySequences(db).map(row => row.next_id), ['A-043', 'B-022', 'C-002']);
  db.close();
  db = null;
  db = openDatabase(file);
  assert.equal(listRegistry(db).length, 64);
});

test('historical import rejects gaps, edits, and unexpected operational fields atomically', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hivemind-history-reject-'));
  const db = openDatabase(path.join(dir, 'hivemind.sqlite3'));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  assert.throws(() => importRegistryHistory(db, rows().slice(1)), /64 rows/);
  assert.throws(() => importRegistryHistory(db, rows().map(row => row.management_id === 'B-021' ? { ...row, management_id: 'B-022' } : row)), /Missing, duplicate, or out-of-range/);
  assert.throws(() => importRegistryHistory(db, rows().map(row => row.management_id === 'A-001' ? { ...row, poc_source: 'secret' } : row)), /Invalid historical registry fields/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM registry_history').get().n, 0);
  importRegistryHistory(db, rows());
  assert.throws(() => importRegistryHistory(db, rows().map(row => row.management_id === 'A-002' ? { ...row, title: 'Changed title' } : row)), /differs from already imported/);
  assert.equal(db.prepare("SELECT title FROM registry_history WHERE management_id = 'A-002'").get().title, 'Historical A-2');
});

test('historical reconciliation updates only existing management metadata and is idempotent', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hivemind-history-reconcile-'));
  const db = openDatabase(path.join(dir, 'hivemind.sqlite3'));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  importRegistryHistory(db, rows());
  db.prepare(`INSERT INTO events
    (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES ('live-1', 'agent-1', 'finding.md', 'hash', 'finding', 'v1', 'commit', 'Live finding', '[]', '2026-01-01', '2026-01-01', '# Live finding')`).run();
  db.prepare("INSERT INTO finding_registry (finding_id, target, report_status, updated_at) VALUES ('live-1', 'knfsd', '미제보', '2026-01-01')").run();
  const changed = rows().map(row => row.management_id === 'A-001' ? {
    ...row, title: 'Updated title', owner: 'Owner', found_date: '9.07', report_status: '제보 완료',
  } : row);
  assert.deepEqual(reconcileRegistryHistory(db, changed), { total: 64, updated: 1 });
  assert.deepEqual(reconcileRegistryHistory(db, changed), { total: 64, updated: 0 });
  assert.deepEqual({ ...db.prepare("SELECT title, owner, found_date, report_status FROM registry_history WHERE management_id = 'A-001'").get() }, {
    title: 'Updated title', owner: 'Owner', found_date: '9.07', report_status: '제보 완료',
  });
  assert.equal(db.prepare('SELECT count(*) AS n FROM registry_history').get().n, 64);
  assert.equal(db.prepare("SELECT report_status FROM finding_registry WHERE finding_id = 'live-1'").get().report_status, '미제보');
  assert.deepEqual(registrySequences(db).map(row => row.next_id), ['A-043', 'B-022', 'C-002']);
});

test('historical reconciliation rejects incomplete or unexpected input without partial updates', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hivemind-history-reconcile-reject-'));
  const db = openDatabase(path.join(dir, 'hivemind.sqlite3'));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  importRegistryHistory(db, rows());
  const changed = rows().map(row => row.management_id === 'A-001' ? { ...row, title: 'Changed' } : row);
  assert.throws(() => reconcileRegistryHistory(db, changed.slice(1)), /64 rows/);
  assert.throws(() => reconcileRegistryHistory(db, changed.map(row => row.management_id === 'C-001' ? { ...row, management_id: 'C-002' } : row)), /Missing, duplicate, or out-of-range/);
  assert.throws(() => reconcileRegistryHistory(db, changed.map(row => row.management_id === 'B-021' ? { ...row, kasan_log: 'secret' } : row)), /Invalid historical registry fields/);
  assert.throws(() => reconcileRegistryHistory(db, changed.map(row => row.management_id === 'B-021' ? { ...row, found_date: '13.01' } : row)), /Invalid historical found_date/);
  db.prepare("DELETE FROM registry_history WHERE management_id = 'C-001'").run();
  assert.throws(() => reconcileRegistryHistory(db, changed), /does not match 64 expected IDs/);
  assert.equal(db.prepare("SELECT title FROM registry_history WHERE management_id = 'A-001'").get().title, 'Historical A-1');
});

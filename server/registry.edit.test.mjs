import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, startServer } from './server.mjs';
import { importRegistryHistory, reconcileRegistryHistory, registerFinding } from './registry.mjs';

const historyRows = () => [['A', 'knfsd', 42], ['B', 'NFS-Ganesha', 21], ['C', 'libnfs', 1]]
  .flatMap(([prefix, target, last]) => Array.from({ length: last }, (_, index) => ({
    management_id: `${prefix}-${String(index + 1).padStart(3, '0')}`,
    title: `Original ${prefix}-${index + 1}`,
    target,
    report_status: null,
  })));

test('dashboard edit mode persists historical and live table fields without changing source events or identifiers', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-registry-edit-'));
  const file = path.join(dataDir, 'hivemind.sqlite3');
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'admin', dashboardPassword: 'test-password' });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });
  importRegistryHistory(db, historyRows());
  const liveId = 'a'.repeat(64);
  const markdown = '---\nschema_version: 1\nkind: finding\n---\n\nOriginal report';
  db.prepare(`INSERT INTO events
    (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES (?, 'agent-1', 'exchange/outbox/agent-1/finding.md', 'hash', 'finding', 'v1', 'a', 'Submitted title', '[]',
      '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z', ?)`).run(liveId, markdown);
  registerFinding(db, liveId, {}, '2026-10-12T00:00:00Z');

  const basic = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}`, 'Content-Type': 'application/json' };
  const historyUrl = `${url}/api/registry/rows/history%3AA-001`;
  const liveUrl = `${url}/api/registry/rows/${liveId}`;
  const patch = (endpoint, body, headers = basic) => fetch(endpoint, { method: 'PATCH', headers, body: JSON.stringify(body) });
  const find = async eventId => (await (await fetch(`${url}/api/registry`, { headers: basic })).json()).findings.find(item => item.event_id === eventId);

  assert.equal((await patch(historyUrl, { revision: 0, owner: 'No auth' }, { 'Content-Type': 'application/json' })).status, 401);
  assert.equal((await patch(historyUrl, { revision: 0, owner: 'Cross-site' }, { ...basic, Origin: 'http://untrusted.example' })).status, 403);
  assert.equal((await patch(historyUrl, { revision: 0, owner: 'Wrong MIME' }, { ...basic, 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await patch(historyUrl, { revision: 0, management_id: 'A-999' })).status, 400);
  assert.equal((await patch(historyUrl, { revision: 0, target: 'libnfs' })).status, 400);
  assert.equal((await patch(historyUrl, { revision: 0, verified_impacts: ['rce'] })).status, 400);
  assert.equal((await patch(historyUrl, { revision: 0, found_date: '13.01' })).status, 400);
  assert.equal((await patch(historyUrl, { revision: 0, cve: 'fake' })).status, 400);

  let response = await patch(historyUrl, {
    revision: 0, title: 'Curated title', owner: 'Researcher', report_status: '제보 완료',
    found_date: '9.07', option: '',
  }, { ...basic, Origin: new URL(url).origin });
  assert.equal(response.status, 200, await response.text());
  let row = await find('history:A-001');
  assert.equal(row.title, 'Curated title');
  assert.equal(row.owner, 'Researcher');
  assert.equal(row.report_status, '제보 완료');
  assert.equal(row.found_date, '9.07');
  assert.equal(row.option, null);
  assert.equal(row.management_id, 'A-001');
  assert.equal(row.revision, 1);
  assert.equal((await patch(historyUrl, { revision: 0, owner: 'Lost edit' })).status, 409);
  assert.equal((await patch(historyUrl, { revision: 1, report_status: null })).status, 200);
  row = await find('history:A-001');
  assert.equal(row.report_status, null);
  assert.equal(row.revision, 2);
  assert.equal(db.prepare("SELECT count(*) AS n FROM registry_edits WHERE row_id = 'history:A-001'").get().n, 2);
  const firstEdit = JSON.parse(db.prepare("SELECT changes_json FROM registry_edits WHERE row_id = 'history:A-001' ORDER BY id LIMIT 1").get().changes_json);
  assert.deepEqual(firstEdit.title, { before: 'Original A-1', after: 'Curated title' });
  assert.deepEqual(firstEdit.owner, { before: null, after: 'Researcher' });
  assert.equal(db.prepare("SELECT actor FROM registry_edits WHERE row_id = 'history:A-001' ORDER BY id LIMIT 1").get().actor, 'viewer');
  assert.deepEqual(importRegistryHistory(db, historyRows()), { total: 64, added: 0 });
  assert.throws(() => importRegistryHistory(db, historyRows().map(item => item.management_id === 'A-001'
    ? { ...item, privilege: 'AUTH_SYS' } : item)), /differs from already imported/);

  const reconciled = historyRows().map(item => item.management_id === 'A-001'
    ? { ...item, title: 'Import title', owner: 'Import owner', option: 'NFSv4.2' }
    : item);
  assert.deepEqual(reconcileRegistryHistory(db, reconciled), { total: 64, updated: 1 });
  row = await find('history:A-001');
  assert.equal(row.title, 'Curated title');
  assert.equal(row.owner, 'Researcher');
  assert.equal(row.option, 'NFSv4.2');
  assert.equal(row.report_status, null);
  assert.equal(row.revision, 3);
  assert.equal((await patch(historyUrl, { revision: 2, owner: 'Stale after reconciliation' })).status, 409);

  response = await patch(liveUrl, { revision: 0, title: 'Displayed title', owner: 'Analyst', found_date: '2026-10-12' });
  assert.equal(response.status, 200, await response.text());
  row = await find(liveId);
  assert.equal(row.title, 'Displayed title');
  assert.equal(row.owner, 'Analyst');
  assert.equal(row.revision, 1);
  assert.equal(db.prepare('SELECT title FROM events WHERE id = ?').get(liveId).title, 'Submitted title');
  assert.equal((await patch(liveUrl, { revision: 1, found_date: '9.07' })).status, 400);
  assert.equal((await patch(liveUrl, { revision: 1, title: '' })).status, 400);
  assert.equal((await patch(liveUrl, { revision: 0, owner: 'Lost edit' })).status, 409);
  assert.equal((await patch(liveUrl, { revision: 1, owner: '' })).status, 200);
  assert.equal((await find(liveId)).owner, null);
  const adminResponse = await fetch(`${url}/v1/admin/registry/${liveId}`, {
    method: 'PATCH', headers: { Authorization: 'Bearer admin', 'Content-Type': 'application/json' },
    body: JSON.stringify({ revision: 2, report_status: '제보 완료' }),
  });
  assert.equal(adminResponse.status, 200, await adminResponse.text());
  assert.equal((await find(liveId)).report_status, '제보 완료');
  assert.equal(db.prepare('SELECT count(*) AS n FROM registry_edits WHERE row_id = ?').get(liveId).n, 3);

  const reopened = openDatabase(file);
  try {
    assert.equal(reopened.prepare("SELECT title, revision FROM registry_history WHERE management_id = 'A-001'").get().revision, 3);
    assert.equal(reopened.prepare("SELECT title_override FROM finding_registry WHERE finding_id = ?").get(liveId).title_override, 'Displayed title');
  } finally { reopened.close(); }
});

test('dashboard mutation requires configured login even on loopback', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-registry-noauth-'));
  const { server, db, url } = await startServer({ port: 0, dataDir });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });
  const response = await fetch(`${url}/api/registry/rows/history%3AA-001`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ revision: 0, owner: 'test' }),
  });
  assert.equal(response.status, 403);
});

test('existing registry database gains edit columns and audit table on restart', t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-registry-migration-'));
  const file = path.join(dataDir, 'hivemind.sqlite3');
  let db = openDatabase(file);
  t.after(() => { db?.close(); rmSync(dataDir, { recursive: true, force: true }); });
  db.exec(`ALTER TABLE finding_registry DROP COLUMN title_override;
    ALTER TABLE registry_history DROP COLUMN updated_at;
    ALTER TABLE registry_history DROP COLUMN revision;
    ALTER TABLE registry_history DROP COLUMN manual_overrides_json;
    DROP TABLE registry_edits;`);
  db.close();
  db = openDatabase(file);
  const liveColumns = new Set(db.prepare('PRAGMA table_info(finding_registry)').all().map(column => column.name));
  const historyColumns = new Set(db.prepare('PRAGMA table_info(registry_history)').all().map(column => column.name));
  assert.equal(liveColumns.has('title_override'), true);
  for (const column of ['updated_at', 'revision', 'manual_overrides_json']) assert.equal(historyColumns.has(column), true);
  assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name = 'registry_edits'").get().name, 'registry_edits');
  importRegistryHistory(db, historyRows());
  assert.equal(db.prepare("SELECT revision FROM registry_history WHERE management_id = 'A-001'").get().revision, 0);
});

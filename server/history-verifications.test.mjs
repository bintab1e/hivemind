import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { startServer } from './server.mjs';
import { importRegistryHistory, registrySequences } from './registry.mjs';

const commit = 'a'.repeat(40);
const reportId = 'b'.repeat(64);
const pocId = 'c'.repeat(64);
const otherReportId = 'd'.repeat(64);
const rows = () => [['A', 'knfsd', 42], ['B', 'NFS-Ganesha', 21], ['C', 'libnfs', 1]]
  .flatMap(([prefix, target, count]) => Array.from({ length: count }, (_, index) => ({
    management_id: `${prefix}-${String(index + 1).padStart(3, '0')}`,
    title: `Historical ${prefix}-${index + 1}`, target,
    report_status: prefix === 'A' && index === 0 ? '제보 완료' : null,
  })));

test('historical two-VM verification appends an independent result without changing original management data', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-history-verification-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'admin', dashboardPassword: 'test-pass' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  importRegistryHistory(db, rows());
  const insertArtifact = db.prepare(`INSERT INTO history_artifacts
    (id, management_id, kind, name, sha256, size, imported_at) VALUES (?, ?, ?, ?, ?, 1, ?)`);
  insertArtifact.run(reportId, 'A-001', 'report', 'report.md', reportId, '2026-10-12T00:00:00Z');
  insertArtifact.run(pocId, 'A-001', 'poc', 'poc.c', pocId, '2026-10-12T00:00:00Z');
  insertArtifact.run(otherReportId, 'A-002', 'report', 'other.md', otherReportId, '2026-10-12T00:00:00Z');

  const endpoint = `${url}/v1/admin/history-verifications`;
  const basic = { Authorization: `Basic ${Buffer.from('viewer:test-pass').toString('base64')}`, 'Content-Type': 'application/json' };
  const admin = { Authorization: 'Bearer admin', 'Content-Type': 'application/json' };
  const write = (body, headers = admin) => fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
  const initial = {
    management_id: 'A-001', result: 'inconclusive', static_verdict: 'likely', reproduction_status: 'inconclusive',
    kernel_commit: commit, report_artifact_id: reportId, poc_artifact_id: pocId,
    observed_impacts: [], evidence: { observation: { guestCompleted: false }, diagnostic: 'Guest timed out' },
    reason: 'Guest did not complete the PoC; no vulnerability verdict',
  };
  assert.equal((await write(initial, basic)).status, 401);
  assert.equal((await write({ ...initial, management_id: 'B-001' })).status, 404);
  assert.equal((await write({ ...initial, report_artifact_id: otherReportId })).status, 400);
  assert.equal((await write({ ...initial, kernel_commit: 'short' })).status, 400);
  assert.equal((await write({ ...initial, report_artifact_id: null })).status, 400);
  assert.equal((await write({ ...initial, poc_artifact_id: null })).status, 400);
  assert.equal((await write({ ...initial, result: 'verified', reproduction_status: 'observed', observed_impacts: ['kasan_read'] })).status, 400);
  assert.equal((await write({ ...initial, result: 'verified', reproduction_status: 'observed', observed_impacts: ['kasan_read'],
    evidence: { static_grounded: true, trace_grounded: true, observation: {
      guestCompleted: true, targetCommitMatch: true, baselineClean: true,
      pocStarted: true, serverEvidenceAfterPoc: true,
    } },
  })).status, 400);
  assert.equal((await write({ ...initial, result: 'not_reproduced', reproduction_status: 'not_observed' })).status, 400);
  assert.equal((await write({ ...initial, observed_impacts: ['kasan_read'] })).status, 400);

  let response = await write(initial);
  assert.equal(response.status, 201, await response.clone().text());
  const first = await response.json();
  assert.equal(first.management_id, 'A-001');
  assert.equal(first.result, 'inconclusive');
  assert.deepEqual(first.observed_impacts, []);
  const find = async () => (await (await fetch(`${url}/api/registry`, { headers: basic })).json()).findings.find(item => item.management_id === 'A-001');
  let listed = await find();
  assert.equal(listed.latest_verification.id, first.id);
  assert.equal(listed.report_status, '제보 완료');
  assert.equal(listed.registration_status, 'history');

  const retry = {
    ...initial, reproduction_status: 'not_observed',
    evidence: { observation: { guestCompleted: true, targetCommitMatch: true }, diagnostic: 'No relevant KASAN trace' },
    reason: 'No relevant KASAN trace; reproduction remains inconclusive',
  };
  response = await write(retry);
  assert.equal(response.status, 201, await response.clone().text());
  const second = await response.json();
  assert.ok(second.id > first.id);
  listed = await find();
  assert.equal(listed.latest_verification.id, second.id);
  assert.equal(listed.latest_verification.result, 'inconclusive');
  assert.deepEqual(listed.latest_verification.observed_impacts, []);
  assert.equal(listed.report_status, '제보 완료');
  assert.equal(db.prepare("SELECT revision, report_status FROM registry_history WHERE management_id = 'A-001'").get().revision, 0);
  assert.deepEqual(registrySequences(db).map(row => row.next_id), ['A-043', 'B-022', 'C-002']);
  assert.equal(db.prepare('SELECT count(*) AS n FROM history_verification_runs').get().n, 2);
  assert.throws(() => db.prepare('UPDATE history_verification_runs SET reason = ? WHERE id = ?').run('changed', first.id), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM history_verification_runs WHERE id = ?').run(first.id), /append-only/);
});

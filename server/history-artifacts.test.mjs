import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { startServer } from './server.mjs';
import { importRegistryHistory } from './registry.mjs';
import { importHistoryArtifacts, curateHistoryArtifacts, listHistoryArtifacts } from './history-artifacts.mjs';

const history = () => [['A', 'knfsd', 42], ['B', 'NFS-Ganesha', 21], ['C', 'libnfs', 1]]
  .flatMap(([prefix, target, last]) => Array.from({ length: last }, (_, index) => ({
    management_id: `${prefix}-${String(index + 1).padStart(3, '0')}`,
    title: `${prefix} historical ${index + 1}`,
    target,
  })));

test('historical reports, PoCs, and optional KASAN stay private and are listed by management ID', async t => {
  const base = mkdtempSync(path.join(tmpdir(), 'hivemind-artifact-test-'));
  const dataDir = path.join(base, 'data');
  const sourceDir = path.join(base, 'selected');
  mkdirSync(path.join(sourceDir, 'A-001'), { recursive: true });
  mkdirSync(path.join(sourceDir, 'B-001'), { recursive: true });
  const report = '<html><script>alert(1)</script></html>\n';
  const poc = 'int main(void) { return 0; }\n';
  const kasan = 'BUG: KASAN: use-after-free in nfsd_test\n';
  const binary = Buffer.from([0, 1, 2, 3]);
  writeFileSync(path.join(sourceDir, 'A-001', 'analysis.html'), report);
  writeFileSync(path.join(sourceDir, 'A-001', 'poc.c'), poc);
  writeFileSync(path.join(sourceDir, 'B-001', 'kasan.stderr'), kasan);
  writeFileSync(path.join(sourceDir, 'B-001', 'archive.bin'), binary);
  const manifest = [
    { management_id: 'A-001', kind: 'report', source_path: 'A-001/analysis.html', display_name: "분석's.html" },
    { management_id: 'A-001', kind: 'poc', source_path: 'A-001/poc.c', display_name: 'poc.c' },
    { management_id: 'B-001', kind: 'kasan', source_path: 'B-001/kasan.stderr', display_name: 'kasan.stderr' },
    { management_id: 'B-001', kind: 'report', source_path: 'B-001/archive.bin', display_name: 'archive.bin' },
  ];
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(base, { recursive: true, force: true }); });
  importRegistryHistory(db, history());
  assert.deepEqual(importHistoryArtifacts(db, dataDir, sourceDir, manifest), {
    total: 4, added: 4, bytes: Buffer.byteLength(report) + Buffer.byteLength(poc) + Buffer.byteLength(kasan) + binary.length,
  });
  assert.equal(importHistoryArtifacts(db, dataDir, sourceDir, manifest).added, 0);
  assert.equal(listHistoryArtifacts(db, 'A-001').length, 2);
  assert.deepEqual(listHistoryArtifacts(db, 'C-001'), []);
  assert.equal(db.prepare('SELECT count(*) AS n FROM events').get().n, 0);
  const listUrl = `${url}/api/registry/history/A-001/artifacts`;
  assert.equal((await fetch(listUrl)).status, 401);
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` };
  const response = await fetch(listUrl, { headers: auth });
  assert.equal(response.status, 200);
  const listed = (await response.json()).artifacts;
  assert.equal(listed.length, 2);
  assert.equal(listed[0].kind, 'report');
  assert.equal(listed[0].previewable, true);
  assert.equal(listed[0].name, "분석's.html");
  assert.equal(Object.hasOwn(listed[0], 'source_path'), false);
  const reportResponse = await fetch(`${listUrl}/${listed[0].id}`, { headers: auth });
  assert.equal(reportResponse.status, 200);
  assert.equal(reportResponse.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(reportResponse.headers.get('x-content-type-options'), 'nosniff');
  assert.match(reportResponse.headers.get('content-security-policy'), /sandbox/);
  assert.match(reportResponse.headers.get('content-disposition'), /%27s\.html/);
  assert.equal(await reportResponse.text(), report);
  const otherList = (await (await fetch(`${url}/api/registry/history/B-001/artifacts`, { headers: auth })).json()).artifacts;
  assert.equal(otherList.length, 2);
  assert.equal(otherList[0].previewable, false);
  const binaryResponse = await fetch(`${url}/api/registry/history/B-001/artifacts/${otherList[0].id}`, { headers: auth });
  assert.equal(binaryResponse.headers.get('content-type'), 'application/octet-stream');
  assert.match(binaryResponse.headers.get('content-disposition'), /^attachment;/);
  assert.deepEqual(Buffer.from(await binaryResponse.arrayBuffer()), binary);
  assert.equal(otherList[1].kind, 'verification');
  assert.equal(otherList[1].previewable, true);
  assert.equal(await (await fetch(`${url}/api/registry/history/B-001/artifacts/${otherList[1].id}`, { headers: auth })).text(), kasan);
  assert.equal((await fetch(`${listUrl}/${otherList[0].id}`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/api/registry/history/A-002/artifacts`, { headers: auth })).status, 200);
  assert.equal((await fetch(`${url}/api/registry/history/A-999/artifacts`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/api/registry/history/A-001/artifacts/../../../../healthz`, { headers: auth })).status, 404);
});

test('historical curation shows essential files under corrected tabs without deleting originals', async t => {
  const base = mkdtempSync(path.join(tmpdir(), 'hivemind-artifact-curate-'));
  const dataDir = path.join(base, 'data');
  const sourceDir = path.join(base, 'selected');
  mkdirSync(path.join(sourceDir, 'A-001'), { recursive: true });
  mkdirSync(path.join(sourceDir, 'B-001'), { recursive: true });
  for (const [name, content] of [
    ['A-001/summary.md', 'metadata only'],
    ['A-001/report.md', 'full report'],
    ['A-001/poc.py', 'print(1)'],
    ['A-001/kmsan.log', 'BUG: KMSAN'],
    ['B-001/report.md', 'second report'],
  ]) writeFileSync(path.join(sourceDir, name), content);
  const manifest = [
    { management_id: 'A-001', kind: 'report', source_path: 'A-001/summary.md', display_name: 'summary.md' },
    { management_id: 'A-001', kind: 'report', source_path: 'A-001/report.md', display_name: 'report.md' },
    { management_id: 'A-001', kind: 'poc', source_path: 'A-001/poc.py', display_name: 'poc.py' },
    { management_id: 'A-001', kind: 'report', source_path: 'A-001/kmsan.log', display_name: 'kmsan.log' },
    { management_id: 'B-001', kind: 'report', source_path: 'B-001/report.md', display_name: 'report.md' },
  ];
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(base, { recursive: true, force: true }); });
  importRegistryHistory(db, history());
  importHistoryArtifacts(db, dataDir, sourceDir, manifest);
  const raw = db.prepare('SELECT id, management_id, name FROM history_artifacts').all();
  const entry = (management_id, name, kind, label) => ({
    management_id, artifact_id: raw.find(row => row.management_id === management_id && row.name === name).id, kind, label, download_name: name,
  });
  const plan = [
    entry('A-001', 'report.md', 'report', '분석 보고서.md'),
    entry('A-001', 'poc.py', 'poc', '재현 PoC.py'),
    entry('A-001', 'kmsan.log', 'verification', 'KMSAN 검증 로그.log'),
    entry('B-001', 'report.md', 'report', '분석 보고서.md'),
  ];
  assert.throws(() => curateHistoryArtifacts(db, plan.slice(0, 3)), /retain a report for every finding/);
  assert.deepEqual(curateHistoryArtifacts(db, plan), { total: 4, changed: 1, hidden: 1 });
  assert.deepEqual(curateHistoryArtifacts(db, plan), { total: 4, changed: 0, hidden: 1 });
  assert.throws(() => curateHistoryArtifacts(db, [...plan, plan[0]]), /Duplicate historical artifact curation/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM history_artifacts').get().n, 5);
  const listed = listHistoryArtifacts(db, 'A-001');
  assert.deepEqual(listed.map(row => [row.kind, row.name]), [
    ['report', '분석 보고서.md'], ['poc', '재현 PoC.py'], ['verification', 'KMSAN 검증 로그.log'],
  ]);
  assert.equal(listed[0].original_name, 'report.md');
  assert.equal(listed[1].download_name, 'poc.py');
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` };
  const endpoint = `${url}/api/registry/history/A-001/artifacts`;
  assert.equal((await fetch(endpoint)).status, 401);
  assert.equal((await (await fetch(endpoint, { headers: auth })).json()).artifacts.length, 3);
  assert.equal((await fetch(`${endpoint}/${entry('A-001', 'summary.md', 'report', 'unused').artifact_id}`, { headers: auth })).status, 404);
  const logResponse = await fetch(`${endpoint}/${listed[2].id}`, { headers: auth });
  assert.match(logResponse.headers.get('content-disposition'), /KMSAN|kmsan\.log/);
  assert.equal(await logResponse.text(), 'BUG: KMSAN');
});

test('large QEMU serial logs and cpio init scripts preview as inert text while extensionless binary PoCs download', async t => {
  const base = mkdtempSync(path.join(tmpdir(), 'hivemind-artifact-serial-'));
  const dataDir = path.join(base, 'data');
  const sourceDir = path.join(base, 'selected');
  mkdirSync(path.join(sourceDir, 'A-027'), { recursive: true });
  const serial = 'Booting Linux\nBUG: KASAN: slab-out-of-bounds\n'.padEnd(4_984_926, 'x');
  const initScript = '#!/bin/sh\necho boot\n';
  const binaryPoc = Buffer.from([0, 1, 2, 3]);
  writeFileSync(path.join(sourceDir, 'A-027', 'qemu.serial'), serial);
  writeFileSync(path.join(sourceDir, 'A-027', 'init'), initScript);
  writeFileSync(path.join(sourceDir, 'A-027', 'poc'), binaryPoc);
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(base, { recursive: true, force: true }); });
  importRegistryHistory(db, history());
  importHistoryArtifacts(db, dataDir, sourceDir, [
    { management_id: 'A-027', kind: 'kasan', source_path: 'A-027/qemu.serial', display_name: 'third-level · qemu.serial' },
    { management_id: 'A-027', kind: 'poc', source_path: 'A-027/init', display_name: 'cpio · init' },
    { management_id: 'A-027', kind: 'poc', source_path: 'A-027/poc', display_name: 'poc' },
  ]);
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` };
  const baseUrl = `${url}/api/registry/history/A-027/artifacts`;
  const listed = (await (await fetch(baseUrl, { headers: auth })).json()).artifacts;
  const log = listed.find(artifact => artifact.name.endsWith('qemu.serial'));
  const init = listed.find(artifact => artifact.name.endsWith('init'));
  const binary = listed.find(artifact => artifact.name === 'poc');
  assert.equal(log.size, 4_984_926);
  assert.equal(log.previewable, true);
  assert.equal(init.previewable, true);
  assert.equal(binary.previewable, false);
  const logResponse = await fetch(`${baseUrl}/${log.id}`, { headers: auth });
  assert.equal(logResponse.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(logResponse.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(await logResponse.text(), serial);
  const initResponse = await fetch(`${baseUrl}/${init.id}`, { headers: auth });
  assert.equal(initResponse.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(initResponse.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(await initResponse.text(), initScript);
  const binaryResponse = await fetch(`${baseUrl}/${binary.id}`, { headers: auth });
  assert.equal(binaryResponse.headers.get('content-type'), 'application/octet-stream');
  assert.match(binaryResponse.headers.get('content-disposition'), /^attachment;/);
  assert.deepEqual(Buffer.from(await binaryResponse.arrayBuffer()), binaryPoc);
});

test('artifact import rejects path traversal, unknown IDs, symlinks, oversized files and conflicting revisions', async t => {
  const base = mkdtempSync(path.join(tmpdir(), 'hivemind-artifact-reject-'));
  const dataDir = path.join(base, 'data');
  const sourceDir = path.join(base, 'selected');
  mkdirSync(path.join(sourceDir, 'A-001'), { recursive: true });
  writeFileSync(path.join(sourceDir, 'A-001', 'report.md'), 'safe report');
  const { server, db } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(base, { recursive: true, force: true }); });
  importRegistryHistory(db, history());
  const entry = { management_id: 'A-001', kind: 'report', source_path: 'A-001/report.md', display_name: 'report.md' };
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, source_path: '../outside.md' }]), /source path/);
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, source_path: 'A-001\\report.md' }]), /source path/);
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, management_id: 'D-001' }]), /Unknown historical/);
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, display_name: '../../x.html' }]), /display name/);
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [entry, entry]), /Duplicate/);
  const outside = path.join(base, 'outside.md');
  writeFileSync(outside, 'outside');
  let linked = false;
  try { symlinkSync(outside, path.join(sourceDir, 'A-001', 'linked.md')); linked = true; } catch { /* unavailable on host */ }
  if (linked) assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, source_path: 'A-001/linked.md' }]), /symlink/);
  const overLimit = path.join(sourceDir, 'A-001', 'huge.md');
  const fd = await import('node:fs').then(fs => fs.openSync(overLimit, 'w'));
  try { await import('node:fs').then(fs => fs.ftruncateSync(fd, 129 * 1024 * 1024)); }
  finally { await import('node:fs').then(fs => fs.closeSync(fd)); }
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [{ ...entry, source_path: 'A-001/huge.md' }]), /file limit/);
  assert.equal(importHistoryArtifacts(db, dataDir, sourceDir, [entry]).added, 1);
  writeFileSync(path.join(sourceDir, 'A-001', 'report.md'), 'changed report');
  assert.throws(() => importHistoryArtifacts(db, dataDir, sourceDir, [entry]), /differs from existing record/);
  assert.equal(listHistoryArtifacts(db, 'A-001').length, 1);
  assert.equal(readFileSync(path.join(sourceDir, 'A-001', 'report.md'), 'utf8'), 'changed report');
});

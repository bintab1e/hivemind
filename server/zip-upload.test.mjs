import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setActiveTrack, startServer } from './server.mjs';
import { readZip } from './zip-upload.mjs';

const commit = 'a'.repeat(40);
const report = 'Analysis of fs/nfsd/nfs4proc.c:42 and a reproducible NFS request.\n';
const poc = '#include <stdio.h>\nint main(int argc, char **argv) { return argc < 3; }\n';
const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}`, 'Content-Type': 'application/json' };

function crc32(bytes) {
  let crc = -1;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ -1) >>> 0;
}

function zip(files) {
  const locals = [], central = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name);
    const source = Buffer.from(file.content || '');
    const content = file.store ? source : deflateRawSync(source);
    const checksum = crc32(source);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(file.encrypted ? 1 : 0x0800, 6);
    local.writeUInt16LE(file.store ? 0 : 8, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(source.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, content);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(0x0314, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(file.encrypted ? 1 : 0x0800, 8);
    header.writeUInt16LE(file.store ? 0 : 8, 10);
    header.writeUInt32LE(checksum, 16);
    header.writeUInt32LE(content.length, 20);
    header.writeUInt32LE(source.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt32LE(((file.mode || 0o100644) << 16) >>> 0, 38);
    header.writeUInt32LE(offset, 42);
    central.push(header, name);
    offset += local.length + name.length + content.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

const bundle = () => zip([
  { name: 'finding/분석 보고서.md', content: report },
  { name: 'finding/PoC.c', content: poc },
  { name: 'finding/VM-steps.md', content: 'cc -o poc PoC.c\n./poc 10.77.0.1 /mnt/nfs\n' },
  { name: 'finding/kasan.log', content: 'BUG: KASAN: slab-out-of-bounds in nfsd_test\nRead of size 8\n' },
]);

test('manual ZIP upload uses active kernel target and enters verifier queue without approving', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-upload-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const input = { project: 'knfsd', title: 'NFS source boundary', reporter: '이진표', track_id: 'rc',
    nfs_version: '4.2', zip_base64: bundle().toString('base64') };
  assert.equal((await fetch(`${url}/api/submissions/upload-targets`)).status, 401);
  const targets = await (await fetch(`${url}/api/submissions/upload-targets`, { headers: auth })).json();
  assert.equal(targets.targets[0].repo_commit, commit);
  assert.equal((await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) })).status, 401);
  assert.equal((await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: { ...auth, Origin: 'http://evil.example' }, body: JSON.stringify(input) })).status, 403);
  const posted = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: { ...auth, Origin: url }, body: JSON.stringify(input) });
  const postedText = await posted.text();
  assert.equal(posted.status, 202, postedText);
  const accepted = JSON.parse(postedText);
  assert.equal(accepted.status, 'pending');
  assert.equal(accepted.replayed, false);
  assert.match(accepted.vulnerability_id, /^V-\d{6,}$/);
  db.prepare("UPDATE submissions SET status = 'rejected', reason = 'PoC did not reproduce', completed_at = ? WHERE id = ?").run(new Date().toISOString(), accepted.submission_id);
  const retry = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth, body: JSON.stringify(input) });
  assert.equal(retry.status, 202);
  const repeated = await retry.json();
  assert.equal(repeated.status, 'pending');
  assert.equal(repeated.replayed, false);
  assert.notEqual(repeated.submission_id, accepted.submission_id);
  assert.notEqual(repeated.vulnerability_id, accepted.vulnerability_id);
  const row = db.prepare('SELECT agent_id, origin, report, metadata_json, status FROM submissions WHERE id = ?').get(repeated.submission_id);
  assert.equal(row.origin, 'manual_upload');
  assert.match(row.agent_id, /^web:/);
  assert.equal(row.status, 'pending');
  assert.equal(row.report, report.trim());
  assert.deepEqual(JSON.parse(row.metadata_json), { version_id: '7.3-rc7', repo_commit: commit, track_id: 'rc', reporter: '이진표', nfs_version: '4.2' });
  const files = db.prepare('SELECT name, kind FROM submission_artifacts WHERE submission_id = ? ORDER BY ordinal').all(repeated.submission_id);
  assert.deepEqual(files.map(file => ({ ...file })), [{ name: 'source-02.c', kind: 'poc' }, { name: 'document-03.md', kind: 'other' }, { name: 'evidence-04.log', kind: 'log' }]);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM finding_registry').get().n, 0);
  const queue = await (await fetch(`${url}/api/verification-queue`, { headers: auth })).json();
  assert.equal(queue.pending[0].submission_id, repeated.submission_id);
  assert.equal(queue.pending[0].vulnerability_id, repeated.vulnerability_id);
  assert.equal(queue.pending[0].origin, 'manual_upload');
  assert.equal(queue.pending[0].reporter, '이진표');
  assert.equal(queue.blocked[0].submission_id, accepted.submission_id);
  assert.equal((await fetch(`${url}/api/submissions/uploaded`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/api/submissions/upload/${accepted.submission_id}`, { headers: auth })).status, 404);
  const pythonOnly = zip([{ name: 'report.md', content: report }, { name: 'poc.py', content: 'import sys\nprint(sys.argv[1:])\n' },
    { name: 'run.sh', content: 'python3 poc.py\n' }, { name: 'kcsan.log', content: 'BUG: KCSAN: data-race in nfsd_test\n' }]);
  const python = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth,
    body: JSON.stringify({ ...input, title: 'Python fallback', zip_base64: pythonOnly.toString('base64') }) });
  assert.equal(python.status, 400, await python.clone().text());
  const kcsanBundle = zip([{ name: 'case/analysis.txt', content: report }, { name: 'case/trigger.c', content: poc },
    { name: 'case/replay.sh', content: 'cc -o trigger trigger.c\n./trigger 10.77.0.1 /mnt/nfs\n' },
    { name: 'case/race.log', content: 'BUG: KCSAN: data-race in nfsd_test\n' }]);
  const kcsan = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth,
    body: JSON.stringify({ ...input, title: 'KCSAN candidate', zip_base64: kcsanBundle.toString('base64') }) });
  assert.equal(kcsan.status, 202, await kcsan.clone().text());
  const unnamedReport = zip([{ name: 'reproduction.md', content: 'cc -o trigger trigger.c\n./trigger 10.77.0.1 /mnt/nfs\n' },
    { name: 'notes.md', content: report }, { name: 'trigger.c', content: poc },
    { name: 'trace.log', content: 'BUG: KCSAN: data-race in nfsd_test\n' }]);
  const unnamed = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth,
    body: JSON.stringify({ ...input, title: 'Arbitrary report name', zip_base64: unnamedReport.toString('base64') }) });
  assert.equal(unnamed.status, 202, await unnamed.clone().text());
  assert.equal(db.prepare('SELECT report FROM submissions WHERE id = ?').get((await unnamed.json()).submission_id).report, report.trim());
});

test('manual ZIP strengthening targets an existing management ID without changing its record', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-upload-strengthen-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  db.prepare(`INSERT INTO registry_history(management_id, number, title, target, report_status, imported_at)
    VALUES ('A-005', 5, 'Prior verified finding', 'knfsd', '미제보', ?)`).run(new Date().toISOString());
  const input = { project: 'knfsd', title: 'Stronger primitive', reporter: 'tester', track_id: 'rc',
    existing_management_id: 'A-005', zip_base64: bundle().toString('base64') };
  const post = body => fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth, body: JSON.stringify(body) });
  const accepted = await post(input);
  assert.equal(accepted.status, 202, await accepted.clone().text());
  const { submission_id: submissionId, vulnerability_id: vulnerabilityId } = await accepted.json();
  assert.match(vulnerabilityId, /^V-\d{6,}$/);
  const row = db.prepare('SELECT metadata_json, status, management_id FROM submissions WHERE id = ?').get(submissionId);
  assert.equal(JSON.parse(row.metadata_json).existing_management_id, 'A-005');
  assert.equal(row.status, 'pending');
  assert.equal(row.management_id, null);
  const queue = await (await fetch(`${url}/api/verification-queue`, { headers: auth })).json();
  assert.equal(queue.pending[0].existing_management_id, 'A-005');
  assert.equal(queue.pending[0].vulnerability_id, vulnerabilityId);
  const registry = await (await fetch(`${url}/api/registry`, { headers: auth })).json();
  assert.equal(registry.findings.find(item => item.management_id === 'A-005').vulnerability_id, vulnerabilityId);
  const viaV = await post({ ...input, existing_management_id: undefined,
    existing_vulnerability_id: vulnerabilityId });
  assert.equal(viaV.status, 202, await viaV.clone().text());
  const followUp = await viaV.json();
  assert.equal(followUp.vulnerability_id, vulnerabilityId);
  assert.equal(db.prepare("SELECT json_extract(metadata_json, '$.existing_vulnerability_id') AS id FROM submissions WHERE id = ?")
    .get(followUp.submission_id).id, vulnerabilityId);
  const aliasNumber = Number(db.prepare("INSERT INTO finding_cases(project, management_id, created_at) VALUES ('knfsd', 'A-005', ?)")
    .run(new Date().toISOString()).lastInsertRowid);
  const withAlias = await (await fetch(`${url}/api/registry`, { headers: auth })).json();
  assert.deepEqual(withAlias.findings.find(item => item.management_id === 'A-005').vulnerability_aliases,
    [`V-${String(aliasNumber).padStart(6, '0')}`]);
  assert.equal(db.prepare("SELECT title FROM registry_history WHERE management_id = 'A-005'").get().title, 'Prior verified finding');
  assert.equal((await post({ ...input, existing_management_id: 'B-001' })).status, 400);
  assert.equal((await post({ ...input, existing_management_id: 'A-999' })).status, 404);
});

test('malformed, unsafe and oversized ZIP entries fail before queue insertion', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-upload-bad-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const request = bytes => fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth,
    body: JSON.stringify({ project: 'knfsd', title: 'candidate', reporter: 'tester', track_id: 'rc', zip_base64: bytes.toString('base64') }) });
  for (const [name, entry] of [
    ['traversal', { name: '../poc.c', content: poc }],
    ['symlink', { name: 'link.c', content: poc, mode: 0o120777 }],
    ['encrypted', { name: 'poc.c', content: poc, encrypted: true }],
    ['nested ZIP', { name: 'nested.zip', content: 'zip' }],
    ['binary', { name: 'report.pdf', content: Buffer.from([0, 255, 0]) }],
  ]) {
    const response = await request(zip([{ name: 'report.md', content: report }, entry]));
    assert.ok([400, 413].includes(response.status), `${name}: ${response.status} ${await response.text()}`);
  }
  const noPoc = await request(zip([{ name: 'report.md', content: report }]));
  assert.equal(noPoc.status, 400);
  const noReproduction = await request(zip([{ name: 'report.md', content: report }, { name: 'poc.c', content: poc },
    { name: 'kasan.log', content: 'BUG: KASAN: out-of-bounds\n' }]));
  assert.equal(noReproduction.status, 400);
  const noLog = await request(zip([{ name: 'report.md', content: report }, { name: 'poc.c', content: poc },
    { name: 'steps.sh', content: 'cc -o poc poc.c\n./poc\n' }]));
  assert.equal(noLog.status, 400);
  const irrelevantLog = await request(zip([{ name: 'report.md', content: report }, { name: 'poc.c', content: poc },
    { name: 'steps.sh', content: 'cc -o poc poc.c\n./poc\n' }, { name: 'run.log', content: 'No kernel sanitizer output\n' }]));
  assert.equal(irrelevantLog.status, 400);
  const duplicate = await request(zip([{ name: 'report.md', content: report }, { name: 'PoC.c', content: poc }, { name: 'poc.c', content: poc }]));
  assert.equal(duplicate.status, 400);
  const noSource = await request(zip([{ name: 'report.md', content: 'No path' }, { name: 'poc.c', content: poc },
    { name: 'steps.sh', content: 'cc -o poc poc.c\n./poc\n' }, { name: 'kasan.log', content: 'BUG: KASAN: out-of-bounds\n' }]));
  assert.equal(noSource.status, 400);
  const huge = await request(zip([{ name: 'report.md', content: report }, { name: 'poc.c', content: poc },
    { name: 'steps.sh', content: 'cc -o poc poc.c\n./poc\n' }, { name: 'large.log', content: 'BUG: KASAN:\n' + 'x'.repeat(600_001) }]));
  assert.equal(huge.status, 413);
  const longReport = await request(zip([{ name: 'report.md', content: report + 'x'.repeat(150_000) }, { name: 'poc.c', content: poc },
    { name: 'steps.sh', content: 'cc -o poc poc.c\n./poc\n' }, { name: 'kasan.log', content: 'BUG: KASAN: out-of-bounds\n' }]));
  assert.equal(longReport.status, 413);
  const checksum = bundle();
  checksum[35] ^= 1;
  assert.throws(() => readZip(checksum), /checksum|ZIP/);
  const localMismatch = bundle();
  localMismatch[14] ^= 1;
  assert.throws(() => readZip(localMismatch), /local header/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM submissions').get().n, 0);
});

test('repeated manual uploads remain bounded by the existing per-reporter queue cap', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-upload-cap-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const body = JSON.stringify({ project: 'knfsd', title: 'Repeated candidate', reporter: 'same tester', track_id: 'rc',
    zip_base64: bundle().toString('base64') });
  const ids = new Set();
  for (let index = 0; index < 30; index += 1) {
    const response = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth, body });
    assert.equal(response.status, 202, `upload ${index + 1}`);
    ids.add((await response.json()).submission_id);
  }
  assert.equal(ids.size, 30);
  const overLimit = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth, body });
  assert.equal(overLimit.status, 429);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE status = 'pending'").get().n, 30);
});

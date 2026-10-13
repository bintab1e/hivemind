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
  db.prepare("UPDATE submissions SET status = 'rejected', reason = 'PoC did not reproduce', completed_at = ? WHERE id = ?").run(new Date().toISOString(), accepted.submission_id);
  const retry = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth, body: JSON.stringify(input) });
  assert.equal(retry.status, 202);
  const repeated = await retry.json();
  assert.equal(repeated.status, 'pending');
  assert.equal(repeated.replayed, false);
  assert.notEqual(repeated.submission_id, accepted.submission_id);
  const row = db.prepare('SELECT agent_id, origin, report, metadata_json, status FROM submissions WHERE id = ?').get(repeated.submission_id);
  assert.equal(row.origin, 'manual_upload');
  assert.match(row.agent_id, /^web:/);
  assert.equal(row.status, 'pending');
  assert.equal(row.report, report.trim());
  assert.deepEqual(JSON.parse(row.metadata_json), { version_id: '7.3-rc7', repo_commit: commit, track_id: 'rc', reporter: '이진표', nfs_version: '4.2' });
  const files = db.prepare('SELECT name, kind FROM submission_artifacts WHERE submission_id = ? ORDER BY ordinal').all(repeated.submission_id);
  assert.deepEqual(files.map(file => ({ ...file })), [{ name: 'source-02.c', kind: 'poc' }, { name: 'evidence-03.log', kind: 'log' }]);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM finding_registry').get().n, 0);
  const queue = await (await fetch(`${url}/api/verification-queue`, { headers: auth })).json();
  assert.equal(queue.pending[0].submission_id, repeated.submission_id);
  assert.equal(queue.pending[0].origin, 'manual_upload');
  assert.equal(queue.pending[0].reporter, '이진표');
  assert.equal(queue.blocked[0].submission_id, accepted.submission_id);
  assert.equal((await fetch(`${url}/api/submissions/uploaded`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/api/submissions/upload/${accepted.submission_id}`, { headers: auth })).status, 404);
  const pythonOnly = zip([{ name: 'report.md', content: report }, { name: 'poc.py', content: 'import sys\nprint(sys.argv[1:])\n' }]);
  const python = await fetch(`${url}/api/submissions/upload`, { method: 'POST', headers: auth,
    body: JSON.stringify({ ...input, title: 'Python fallback', zip_base64: pythonOnly.toString('base64') }) });
  assert.equal(python.status, 202, await python.clone().text());
  const pythonId = (await python.json()).submission_id;
  assert.equal(db.prepare("SELECT name FROM submission_artifacts WHERE submission_id = ? AND kind = 'poc'").get(pythonId).name, 'source-02.py');
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
  const duplicate = await request(zip([{ name: 'report.md', content: report }, { name: 'PoC.c', content: poc }, { name: 'poc.c', content: poc }]));
  assert.equal(duplicate.status, 400);
  const noSource = await request(zip([{ name: 'report.md', content: 'No path' }, { name: 'poc.c', content: poc }]));
  assert.equal(noSource.status, 400);
  const huge = await request(zip([{ name: 'report.md', content: report }, { name: 'poc.c', content: poc }, { name: 'large.log', content: 'x'.repeat(600_001) }]));
  assert.equal(huge.status, 413);
  const longReport = await request(zip([{ name: 'report.md', content: report + 'x'.repeat(150_000) }, { name: 'poc.c', content: poc }]));
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

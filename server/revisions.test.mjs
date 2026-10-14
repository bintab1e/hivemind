import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { getRevisionArtifact, listApprovedRevisions, listRevisionArtifacts } from './revisions.mjs';
import { startServer } from './server.mjs';

test('revision artifacts belong only to approved submissions of the selected management ID', () => {
  const db = new DatabaseSync(':memory:');
  const approved = 'a'.repeat(64), older = 'b'.repeat(64), rejected = 'c'.repeat(64), other = 'd'.repeat(64);
  db.exec(`CREATE TABLE submissions (id TEXT, management_id TEXT, status TEXT, title TEXT, completed_at TEXT);
    CREATE TABLE submission_artifacts (submission_id TEXT, ordinal INTEGER, name TEXT, kind TEXT, sha256 TEXT, size INTEGER, content BLOB);`);
  const insert = db.prepare('INSERT INTO submissions VALUES (?, ?, ?, ?, ?)');
  insert.run(approved, 'A-005', 'approved', 'new', '2026-10-14T01:00:00Z');
  insert.run(older, 'A-005', 'approved', 'old', '2026-10-13T01:00:00Z');
  insert.run(rejected, 'A-005', 'rejected', 'unverified', '2026-10-14T02:00:00Z');
  insert.run(other, 'A-006', 'approved', 'other finding', '2026-10-14T03:00:00Z');
  const file = db.prepare('INSERT INTO submission_artifacts VALUES (?, 1000, ?, ?, ?, ?, ?)');
  for (const [id, content] of [[approved, 'latest report'], [older, 'earlier report'], [rejected, 'rejected report'], [other, 'other report']]) {
    file.run(id, 'report.md', 'report', 'hash', content.length, Buffer.from(content));
  }
  db.prepare('INSERT INTO submission_artifacts VALUES (?, 1003, ?, ?, ?, ?, ?)')
    .run(older, 'evidence.log', 'log', 'hash', 12, Buffer.from('claimed log\n'));
  assert.deepEqual(listApprovedRevisions(db, 'A-005').map(item => item.submission_id), [approved, older]);
  assert.deepEqual(listRevisionArtifacts(db, 'A-005', older).map(item => item.name), ['report.md', 'evidence.log']);
  assert.equal(getRevisionArtifact(db, 'A-005', older, 'report.md').toString(), 'earlier report');
  assert.equal(getRevisionArtifact(db, 'A-005', older, 'evidence.log').toString(), 'claimed log\n');
  for (const id of [rejected, other]) {
    assert.throws(() => listRevisionArtifacts(db, 'A-005', id), error => error.status === 404);
    assert.throws(() => getRevisionArtifact(db, 'A-005', id, 'report.md'), error => error.status === 404);
  }
  assert.throws(() => getRevisionArtifact(db, 'A-005', approved, '../report.md'), error => error.status === 404);
  db.close();
});

test('revision routes require dashboard login and reject cross-finding artifact access', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-revisions-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardUser: 'guest', dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const approved = 'a'.repeat(64), rejected = 'b'.repeat(64);
  const insert = db.prepare(`INSERT INTO submissions
    (id, agent_id, project, title, report, metadata_json, raw_sha256, status, submitted_at, completed_at, management_id)
    VALUES (?, 'agent', 'knfsd', 'example', 'report', '{}', 'hash', ?, '2026-10-14T00:00:00Z', '2026-10-14T01:00:00Z', 'A-005')`);
  insert.run(approved, 'approved');
  insert.run(rejected, 'rejected');
  db.prepare(`INSERT INTO submission_artifacts VALUES (?, 1000, 'report.md', 'report', 'hash', 14, ?)`)
    .run(approved, Buffer.from('earlier report'));
  db.prepare(`INSERT INTO submission_artifacts VALUES (?, 1003, 'evidence.log', 'log', 'hash', 12, ?)`)
    .run(approved, Buffer.from('claimed log\n'));
  const base = `${url}/api/registry/A-005/revisions`;
  const auth = { Authorization: `Basic ${Buffer.from('guest:test-password').toString('base64')}` };
  assert.equal((await fetch(base)).status, 401);
  assert.equal((await (await fetch(base, { headers: auth })).json()).revisions.length, 1);
  assert.equal((await (await fetch(`${base}/${approved}/artifacts/report.md`, { headers: auth })).text()), 'earlier report');
  assert.equal((await (await fetch(`${base}/${approved}/artifacts/evidence.log`, { headers: auth })).text()), 'claimed log\n');
  assert.equal((await fetch(`${base}/${rejected}/artifacts/report.md`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/api/registry/A-006/revisions/${approved}/artifacts/report.md`, { headers: auth })).status, 404);
});

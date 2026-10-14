import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setActiveTrack, startServer } from './server.mjs';
import { claimPatchReview, completePatchReview, failPatchReview, getPatchReview,
  submitPatchReview, validatePatchFile } from './patch-reviews.mjs';

const commit = 'a'.repeat(40);
const patch = 'diff --git a/fs/nfsd/nfs4proc.c b/fs/nfsd/nfs4proc.c\n--- a/fs/nfsd/nfs4proc.c\n+++ b/fs/nfsd/nfs4proc.c\n@@ -1 +1 @@\n-old\n+new\n';
const payload = (managementId = 'A-001', content = patch) => ({ management_id: managementId, track_id: 'rc',
  filename: 'fix.patch', content_base64: Buffer.from(content).toString('base64') });

function postSocket(socketPath, endpoint, body) {
  const encoded = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path: endpoint, method: 'POST', headers: {
      'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(encoded),
    } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(encoded);
  });
}

test('patch review upload, dedupe, lease recovery, and Sashiko result are available to the right callers', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-patch-reviews-'));
  const socketPath = path.join(dataDir, 'verifier.sock');
  const { server, verifierServer, db, url } = await startServer({ port: 0, dataDir, verifierSocketPath: socketPath,
    dashboardPassword: 'test-password' });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    if (verifierServer?.listening) await new Promise(resolve => verifierServer.close(resolve));
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });
  db.prepare("INSERT INTO registry_history (management_id, number, title, target, imported_at) VALUES ('A-001', 1, 'Test finding', 'knfsd', ?)").run(new Date().toISOString());
  db.prepare("INSERT INTO registry_history (management_id, number, title, target, imported_at) VALUES ('B-001', 1, 'Other project', 'NFS-Ganesha', ?)").run(new Date().toISOString());
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` };
  const submit = (body, headers = auth) => fetch(`${url}/api/patch-reviews`, { method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  assert.equal((await submit(payload(), {})).status, 401);
  assert.equal((await submit(payload(), { ...auth, Origin: 'http://untrusted.example' })).status, 403);
  assert.equal((await submit(payload(), { ...auth, 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await submit(payload('B-001'))).status, 422);
  assert.equal((await submit(payload('A-999'))).status, 404);
  assert.equal((await submit(payload('A-001', patch.replaceAll('fs/nfsd/nfs4proc.c', '../outside.c')))).status, 400);

  const response = await submit(payload());
  assert.equal(response.status, 201, await response.clone().text());
  const created = await response.json();
  assert.equal(created.management_id, 'A-001');
  assert.equal(created.base_commit, commit);
  assert.equal(created.status, 'pending');
  const replay = await (await submit(payload())).json();
  assert.equal(replay.id, created.id);
  assert.equal(replay.replayed, true);

  const list = await (await fetch(`${url}/api/patch-reviews`, { headers: auth })).json();
  assert.equal(list.reviews.length, 1);
  assert.equal(JSON.stringify(list).includes('diff --git'), false);
  const reviewPage = `${url}/patch-reviews/${created.id}`;
  assert.equal((await fetch(reviewPage)).status, 401);
  assert.equal((await fetch(`${url}/patch-review.js`)).status, 401);
  assert.equal((await fetch(`${url}/patch-reviews/${'b'.repeat(64)}`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/patch-reviews/${created.id}/extra`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${url}/patch-reviews/%2e%2e%2fapp.js`, { headers: auth })).status, 404);
  const page = await fetch(reviewPage, { headers: auth });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /^text\/html/);
  assert.match(await page.text(), /<html\b/i);
  const reviewScript = await fetch(`${url}/patch-review.js`, { headers: auth });
  assert.equal(reviewScript.status, 200);
  assert.match(reviewScript.headers.get('content-type'), /^text\/javascript/);
  const file = await fetch(`${url}/api/patch-reviews/${created.id}/file`, { headers: auth });
  assert.match(file.headers.get('content-disposition'), /attachment; filename="fix.patch"/);
  assert.equal(await file.text(), patch);
  assert.equal((await postSocket(socketPath, '/patch/claim', { worker_id: 'worker-1', supported_commits: ['b'.repeat(40)] })).body.job, null);

  const first = (await postSocket(socketPath, '/patch/claim', { worker_id: 'worker-1', supported_commits: [commit] })).body.job;
  assert.equal(first.review_id, created.id);
  assert.equal(first.patch, patch);
  assert.equal((await postSocket(socketPath, '/patch/claim', { worker_id: 'worker-2', supported_commits: [commit] })).body.job, null);
  db.prepare('UPDATE patch_reviews SET claimed_at = ? WHERE id = ?').run(new Date(Date.now() - 119 * 60_000).toISOString(), created.id);
  assert.equal((await postSocket(socketPath, '/patch/claim', { worker_id: 'worker-2', supported_commits: [commit] })).body.job, null);
  db.prepare('UPDATE patch_reviews SET claimed_at = ? WHERE id = ?').run(new Date(Date.now() - 121 * 60_000).toISOString(), created.id);
  const second = (await postSocket(socketPath, '/patch/claim', { worker_id: 'worker-2', supported_commits: [commit] })).body.job;
  assert.notEqual(second.lease_token, first.lease_token);
  assert.equal((await postSocket(socketPath, '/patch/complete', { review_id: created.id,
    lease_token: first.lease_token, status: 'reviewed', result: { patches: [] } })).status, 409);
  const result = { exit_code: 1, sashiko: { patches: [{ status: 'applied' }], findings: [{ title: 'Missing lock' }] } };
  const completed = await postSocket(socketPath, '/patch/complete', { review_id: created.id,
    lease_token: second.lease_token, status: 'findings', result });
  assert.equal(completed.status, 200);
  const detail = await (await fetch(`${url}/api/patch-reviews/${created.id}`, { headers: auth })).json();
  assert.equal(detail.review.status, 'findings');
  assert.deepEqual(detail.review.result, result);
  assert.equal(JSON.stringify(detail).includes(second.lease_token), false);
  assert.equal((await postSocket(socketPath, '/patch/complete', { review_id: created.id,
    lease_token: second.lease_token, status: 'reviewed', result })).status, 409);
});

test('patch review execution failures retain a short reason without exposing a result', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-patch-failure-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  db.prepare("INSERT INTO registry_history (management_id, number, title, target, imported_at) VALUES ('A-001', 1, 'Test finding', 'knfsd', ?)").run(new Date().toISOString());
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}`, 'Content-Type': 'application/json' };
  const response = await fetch(`${url}/api/patch-reviews`, { method: 'POST', headers: auth, body: JSON.stringify(payload()) });
  assert.equal(response.status, 201);
  const created = await response.json();
  const claim = claimPatchReview(db, 'worker-1', [commit]);
  assert.equal(failPatchReview(db, created.id, claim.lease_token, 'sashiko_unavailable').status, 'error');
  assert.equal(getPatchReview(db, created.id).reason, 'sashiko_unavailable');
  assert.equal(getPatchReview(db, created.id).result, null);
  const retryResponse = await fetch(`${url}/api/patch-reviews`, { method: 'POST', headers: auth, body: JSON.stringify(payload()) });
  assert.equal(retryResponse.status, 201);
  const retry = await retryResponse.json();
  assert.equal(retry.id, created.id);
  assert.equal(retry.status, 'pending');
  assert.equal(retry.replayed, false);
  assert.equal(retry.retried, true);
  const restarted = getPatchReview(db, created.id);
  assert.equal(restarted.reason, null);
  assert.equal(restarted.result, null);
  assert.equal(restarted.claimed_at, null);
  assert.equal(restarted.completed_at, null);
  assert.equal(restarted.worker_id, null);
  assert.equal(claimPatchReview(db, 'worker-2', [commit]).review_id, created.id);
});

test('patch validation rejects mode changes and symlinks', () => {
  for (const header of [
    'old mode 100644', 'new mode 100755', 'new file mode 100644',
    'deleted file mode 100644', 'index 1111111..2222222 120000',
    'index 1111111..2222222 160000', 'index 1111111..2222222 120000\r',
  ]) {
    assert.throws(() => validatePatchFile(payload('A-001', `${patch}${header}\n`)),
      error => error.status === 400 && /mode-changing|symlink/.test(error.message), header);
  }
});

test('patch review storage and active queue caps include retries without double-counting patch bytes', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-patch-limits-'));
  const { server, db } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  db.prepare("INSERT INTO registry_history (management_id, number, title, target, imported_at) VALUES ('A-001', 1, 'Test finding', 'knfsd', ?)").run(new Date().toISOString());
  setActiveTrack(db, 'rc', { version_id: '7.3-rc7', repo_commit: commit });
  const first = submitPatchReview(db, payload(), { maxActiveReviews: 1 });
  const other = payload('A-001', patch.replace('-old', '-different'));
  assert.equal(submitPatchReview(db, payload(), { maxActiveReviews: 1 }).replayed, true);
  assert.throws(() => submitPatchReview(db, other, { maxActiveReviews: 1 }), error => error.status === 429);
  const firstClaim = claimPatchReview(db, 'worker-1', [commit]);
  failPatchReview(db, first.id, firstClaim.lease_token, 'temporary error');
  const second = submitPatchReview(db, other, { maxActiveReviews: 1 });
  assert.throws(() => submitPatchReview(db, payload(), { maxActiveReviews: 1 }), error => error.status === 429);
  const secondClaim = claimPatchReview(db, 'worker-2', [commit]);
  completePatchReview(db, second.id, secondClaim.lease_token, 'reviewed', { exit_code: 0 });
  assert.equal(submitPatchReview(db, payload(), { maxActiveReviews: 1, maxStoredBytes: 1 }).retried, true);
  const third = payload('A-001', patch.replace('+new', '+another'));
  const stored = db.prepare('SELECT SUM(length(CAST(patch AS BLOB))) AS bytes FROM patch_reviews').get().bytes;
  assert.throws(() => submitPatchReview(db, third, { maxStoredBytes: stored }), error => error.status === 413);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM patch_reviews').get().count, 2);
});

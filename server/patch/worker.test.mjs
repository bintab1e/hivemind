import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runPatchWorkerOnce } from './worker.mjs';

function repository(dir) {
  mkdirSync(dir);
  execFileSync('git', ['init', '-q', dir]);
  writeFileSync(path.join(dir, 'code.c'), 'int value = 1;\n');
  execFileSync('git', ['-C', dir, 'add', 'code.c']);
  execFileSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-qm', 'base']);
  return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

test('patch worker sends a selected kernel patch to Sashiko and stores its actual result', async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hivemind-patch-worker-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rc = path.join(root, 'rc');
  const mainline = path.join(root, 'mainline');
  const rcCommit = repository(rc);
  repository(mainline);
  const config = { socketPath: path.join(root, 'verifier.sock'), cliPath: path.join(root, 'sashiko-cli'),
    configDir: root, workRoot: root, repos: { rc, mainline } };
  const job = { review_id: 'a'.repeat(64), lease_token: 'b'.repeat(64), track_id: 'rc', base_commit: rcCommit,
    patch: 'diff --git a/code.c b/code.c\n' };
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/patch/claim' ? { job } : {};
  };
  const reviewer = async input => {
    assert.equal(input.patch, job.patch);
    assert.equal(input.baseCommit, rcCommit);
    assert.equal(input.repoPath, rc);
    return { status: 'findings', exit_code: 0, result: { status: 'issues_found', findings: [{ title: 'Missing check' }] } };
  };
  assert.equal(await runPatchWorkerOnce({ config, transport, reviewer, workerId: 'patch-worker' }), true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/patch/claim', '/patch/complete']);
  assert.deepEqual(calls[0].body.supported_commits.length, 2);
  assert.equal(calls[1].body.review_id, job.review_id);
  assert.equal(calls[1].body.status, 'findings');
  assert.equal(calls[1].body.result.findings[0].title, 'Missing check');
});

test('patch worker records apply or Sashiko failures without a false clean verdict', async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hivemind-patch-fail-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rc = path.join(root, 'rc');
  const commit = repository(rc);
  const config = { socketPath: path.join(root, 'verifier.sock'), cliPath: path.join(root, 'sashiko-cli'),
    configDir: root, workRoot: root, repos: { rc, mainline: rc } };
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/patch/claim' ? { job: { review_id: 'c'.repeat(64), lease_token: 'd'.repeat(64),
      track_id: 'rc', base_commit: commit, patch: 'patch' } } : {};
  };
  await runPatchWorkerOnce({ config, transport, reviewer: async () => { throw new Error('patch_does_not_apply'); } });
  assert.deepEqual(calls.map(call => call.endpoint), ['/patch/claim', '/patch/fail']);
  assert.equal(calls[1].body.reason, 'patch_does_not_apply');
});

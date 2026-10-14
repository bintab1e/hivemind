import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { reviewPatchWithSashiko } from './integrations.mjs';

function setup(t, result, exitCode = 0) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'hivemind-sashiko-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repoPath = path.join(root, 'kernel');
  const configDir = path.join(root, 'config');
  const dataDir = path.join(root, 'work');
  mkdirSync(repoPath);
  mkdirSync(configDir);
  mkdirSync(dataDir);
  execFileSync('git', ['init', '-q', repoPath]);
  writeFileSync(path.join(repoPath, 'nfsd.c'), 'int check(void) { return 0; }\n');
  execFileSync('git', ['-C', repoPath, 'add', 'nfsd.c']);
  execFileSync('git', ['-C', repoPath, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-qm', 'base']);
  const baseCommit = execFileSync('git', ['-C', repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const cliPath = path.join(root, 'sashiko-cli');
  writeFileSync(path.join(configDir, 'Settings.toml'), '[ai]\nprovider = "codex-cli"\n');
  writeFileSync(cliPath, `#!/bin/sh\nprintf '%s\\n' "$@" > "${cliPath}.args"\npwd > "${cliPath}.cwd"\nprintf '%s\\n' "$SASHIKO_CONFIG" > "${cliPath}.config"\nprintf '%s\\n' '${JSON.stringify(result)}'\nexit ${exitCode}\n`, { mode: 0o700 });
  const patch = 'diff --git a/nfsd.c b/nfsd.c\n--- a/nfsd.c\n+++ b/nfsd.c\n@@ -1 +1 @@\n-int check(void) { return 0; }\n+int check(void) { return 1; }\n';
  return { root, repoPath, configDir, dataDir, baseCommit, cliPath, patch };
}

test('uploaded patch runs actual Sashiko CLI in an isolated worktree with structured JSON output', async t => {
  const item = setup(t, { status: 'clean', findings: [], concerns: [], patches: [] });
  const answer = await reviewPatchWithSashiko(item);
  assert.equal(answer.status, 'reviewed');
  const args = readFileSync(`${item.cliPath}.args`, 'utf8').trim().split('\n');
  assert.deepEqual(args.slice(0, 5), ['--format', 'json', 'local', 'HEAD', '--repo']);
  assert.match(args[5], new RegExp(`^${item.dataDir}/jobs/sashiko-[^/]+/tree$`));
  assert.deepEqual(args.slice(6), ['--baseline', item.baseCommit, '--force-local', '--agent']);
  assert.equal(readFileSync(`${item.cliPath}.cwd`, 'utf8').trim(), args[5]);
  assert.equal(readFileSync(`${item.cliPath}.config`, 'utf8').trim(), path.join(item.configDir, 'Settings.toml'));
  assert.deepEqual(readdirSync(path.join(item.dataDir, 'jobs')), []);
  assert.equal(readFileSync(path.join(item.repoPath, 'nfsd.c'), 'utf8'), 'int check(void) { return 0; }\n');
});

test('Sashiko findings remain findings when CLI exits zero', async t => {
  const item = setup(t, { status: 'issues_found', findings: [{ title: 'Race condition', severity: 'medium' }], concerns: [] });
  const answer = await reviewPatchWithSashiko(item);
  assert.equal(answer.status, 'findings');
  assert.equal(answer.result.findings[0].title, 'Race condition');
});

test('Sashiko stderr-only failure keeps an actionable reason without exposing raw output', async t => {
  const item = setup(t, { status: 'clean' });
  writeFileSync(item.cliPath, '#!/bin/sh\necho "Authentication failed: private-marker" >&2\nexit 3\n', { mode: 0o700 });
  await assert.rejects(reviewPatchWithSashiko(item), error => {
    assert.match(error.message, /Sashiko AI authentication failed/);
    assert.doesNotMatch(error.message, /private-marker/);
    return true;
  });
  assert.deepEqual(readdirSync(path.join(item.dataDir, 'jobs')), []);
});

test('Sashiko timeout is reported even when the process emits partial output', async t => {
  const item = setup(t, { status: 'clean' });
  writeFileSync(item.cliPath, '#!/bin/sh\necho partial\nexec sleep 2\n', { mode: 0o700 });
  await assert.rejects(reviewPatchWithSashiko({ ...item, timeoutMs: 50 }), /Sashiko review timed out/);
  assert.deepEqual(readdirSync(path.join(item.dataDir, 'jobs')), []);
});

test('a patch cannot make Sashiko read a symlink outside the kernel worktree', async t => {
  const item = setup(t, { status: 'clean', findings: [], concerns: [] });
  symlinkSync('/etc/passwd', path.join(item.repoPath, 'linked'));
  execFileSync('git', ['-C', item.repoPath, 'add', 'linked']);
  execFileSync('git', ['-C', item.repoPath, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-qm', 'symlink']);
  item.baseCommit = execFileSync('git', ['-C', item.repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  item.patch = 'diff --git a/linked b/linked\n--- a/linked\n+++ b/linked\n@@ -1 +1 @@\n-/etc/passwd\n+/etc/shadow\n';
  await assert.rejects(reviewPatchWithSashiko(item), /regular files inside the kernel worktree/);
  assert.deepEqual(readdirSync(path.join(item.dataDir, 'jobs')), []);
});

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openDatabase, startServer } from './server.mjs';

test('database startup preserves the verifier traversal ACL', async t => {
  if (process.platform !== 'linux' || spawnSync('setfacl', ['--version']).status !== 0 ||
      spawnSync('getfacl', ['--version']).status !== 0) return t.skip('POSIX ACL tools unavailable');
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-acl-'));
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  execFileSync('setfacl', ['-m', 'u:65534:x', dataDir]);
  const assertAcl = () => {
    const acl = execFileSync('getfacl', ['-ncp', dataDir], { encoding: 'utf8' });
    assert.match(acl, /^user:65534:--x$/m);
    assert.match(acl, /^mask::--x$/m);
    assert.equal(statSync(dataDir).mode & 0o777, 0o710);
  };
  assertAcl();

  const db = openDatabase(path.join(dataDir, 'hivemind.sqlite3'));
  db.close();
  assertAcl();

  const running = await startServer({
    port: 0, dataDir, apiToken: 'test-token',
    verifierSocketPath: path.join(dataDir, 'verifier.sock'), verifierUser: 'nobody',
  });
  t.after(async () => {
    await new Promise(resolve => running.server.close(resolve));
    running.db.close();
  });
  assertAcl();
  assert.equal((await (await fetch(`${running.url}/healthz`)).json()).ok, true);
});

test('database startup removes broad directory permissions', t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-mode-'));
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  chmodSync(dataDir, 0o777);
  const db = openDatabase(path.join(dataDir, 'hivemind.sqlite3'));
  db.close();
  const mode = statSync(dataDir).mode & 0o777;
  assert.equal(mode & 0o700, 0o700);
  assert.equal(mode & 0o067, 0);
});

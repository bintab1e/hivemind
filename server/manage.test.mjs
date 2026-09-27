import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { latestVersionFromRefs } from './manage.mjs';
import { startServer } from './server.mjs';

const run = promisify(execFile);

test('latest kernel tags use the commit behind annotated tags', () => {
  const refs = [
    `${'a'.repeat(40)}\trefs/tags/v7.2-rc4`,
    `${'b'.repeat(40)}\trefs/tags/v7.3-rc1`,
    `${'c'.repeat(40)}\trefs/tags/v7.3-rc1^{}`,
    `${'d'.repeat(40)}\trefs/tags/v7.2.5`,
    `${'e'.repeat(40)}\trefs/tags/v7.2.6`,
    `${'f'.repeat(40)}\trefs/tags/v6.20.99`,
  ].join('\n');
  assert.deepEqual(latestVersionFromRefs(refs, 'rc')?.repo_commit, 'c'.repeat(40));
  assert.deepEqual(latestVersionFromRefs(refs, 'mainline')?.version_id, '7.2.6');
  assert.deepEqual(latestVersionFromRefs(refs, 'rc', '7.2-rc4')?.repo_commit, 'a'.repeat(40));
});

test('management command issues a reusable token and an agent install command', async t => {
  const temp = mkdtempSync(path.join(tmpdir(), 'hivemind-manage-'));
  const dataDir = path.join(temp, 'server');
  const { server, db, url, tokenPath } = await startServer({ port: 0, dataDir });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(temp, { recursive: true, force: true }); });
  const adminToken = readFileSync(tokenPath, 'utf8').trim();
  const active = await fetch(`${url}/v1/admin/tracks/rc`, { method: 'PUT', headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ version_id: '7.3-rc4', repo_commit: 'a'.repeat(40) }) });
  assert.equal(active.status, 200);
  const env = { ...process.env, HIVEMIND_DATA_DIR: dataDir, HIVEMIND_PORT: new URL(url).port, HIVEMIND_SERVER_URL: 'http://192.168.1.188:8765' };
  const command = [path.join(path.dirname(fileURLToPath(import.meta.url)), 'manage.mjs'), 'agent', 'add', 'jinpyo', 'rc'];
  const first = await run(process.execPath, command, { env });
  const token = readFileSync(path.join(temp, 'agents', 'jinpyo.token'), 'utf8').trim();
  assert.match(token, /^[a-f0-9]{64}$/);
  assert(first.stdout.includes('bash -s -- http://192.168.1.188:8765 rc'));
  const second = await run(process.execPath, command, { env });
  assert(second.stdout.includes(token));
});

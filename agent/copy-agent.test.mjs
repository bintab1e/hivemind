import assert from 'node:assert/strict';
import { lstat, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { agentSourceFiles, copyAgentSource } from './copy-agent.mjs';

test('agent source copy excludes local secrets and preserves installed runtime', async t => {
  const base = await mkdtemp(path.join(tmpdir(), 'hivemind-copy-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const source = path.join(base, 'source');
  const target = path.join(base, 'target');
  for (const dir of [source, target, path.join(source, 'runtime'), path.join(source, '.venv'), path.join(source, '.git'), path.join(target, 'runtime')]) {
    await mkdir(dir, { recursive: true });
  }
  for (const file of agentSourceFiles) {
    await mkdir(path.dirname(path.join(source, file)), { recursive: true });
    await writeFile(path.join(source, file), `new ${file}`);
  }
  await writeFile(path.join(source, 'runtime', 'agents.token'), 'source secret');
  await writeFile(path.join(source, '.venv', 'key'), 'source key');
  await writeFile(path.join(source, '.git', 'config'), 'source remote');
  await writeFile(path.join(source, '.env'), 'source env secret');
  await writeFile(path.join(source, 'auth.json'), 'source auth secret');
  await writeFile(path.join(target, 'runtime', 'agents.token'), 'existing secret');

  copyAgentSource(source, target);
  assert.equal(await readFile(path.join(target, 'mcp-agent.mjs'), 'utf8'), 'new mcp-agent.mjs');
  assert.equal(await readFile(path.join(target, 'runtime', 'agents.token'), 'utf8'), 'existing secret');
  for (const name of ['.venv', '.git', '.env', 'auth.json']) await assert.rejects(lstat(path.join(target, name)), { code: 'ENOENT' });
  assert.throws(() => copyAgentSource(base, target), /inside its source/);
});

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { cp, chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

test('token configures the matching kernel checkout and project hooks', { skip: process.platform === 'win32' }, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'hivemind-install-'));
  const root = path.join(temp, 'linux');
  const agent = path.join(root, '.hivemind', 'agent');
  await mkdir(root, { recursive: true });
  await cp(path.dirname(fileURLToPath(import.meta.url)), agent, { recursive: true });
  await mkdir(path.join(agent, '.venv', 'bin'), { recursive: true });
  const agentcov = path.join(agent, '.venv', 'bin', 'agentcov');
  await writeFile(agentcov, '#!/bin/sh\nmkdir -p .codex\nprintf \'{"hooks":{"PostToolUse":[{"hooks":[{"command":"agentcov hook post-tool-use"}]}]}}\' > .codex/hooks.json\n');
  await chmod(agentcov, 0o755);
  execFileSync('git', ['init', root]);
  await writeFile(path.join(root, 'README'), 'kernel\n');
  execFileSync('git', ['-C', root, 'add', 'README']);
  execFileSync('git', ['-C', root, '-c', 'user.name=test', '-c', 'user.email=test@example.com', 'commit', '-m', 'kernel']);
  const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const token = 'a'.repeat(64);
  const tokenFile = path.join(temp, 'token');
  await writeFile(tokenFile, token);
  const server = createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${token}`);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(req.url === '/v1/sync/health'
      ? { agent_id: 'jinpyo' }
      : { result: { structuredContent: { tracks: [{ track_id: 'rc', version_id: '7.3-rc4', repo_commit: commit }] } } }));
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(temp, { recursive: true, force: true }); });
  const { configure } = await import(pathToFileURL(path.join(agent, 'setup.mjs')).href);
  const result = await configure(root, tokenFile, `http://127.0.0.1:${server.address().port}`);
  assert.equal(result.id, 'jinpyo');
  const config = JSON.parse(await readFile(result.configPath, 'utf8'));
  assert.equal(config.repo_root, root);
  assert.equal(config.version_id, '7.3-rc4');
  assert.match(await readFile(path.join(root, '.codex', 'config.toml'), 'utf8'), /mcp_servers\.knfsd_hivemind/);
  const hooks = await readFile(path.join(root, '.codex', 'hooks.json'), 'utf8');
  assert(hooks.includes(agentcov));
  assert.equal((await readFile(path.join(agent, 'runtime', 'agents', 'jinpyo.token'), 'utf8')).trim(), token);
});

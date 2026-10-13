import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { cp, chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

test('setup rejects private-LAN HTTP before sending an agent token', async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'hivemind-url-policy-'));
  const tokenFile = path.join(temp, 'token');
  await writeFile(tokenFile, 'a'.repeat(64));
  const originalFetch = globalThis.fetch;
  const originalAllow = process.env.HIVEMIND_ALLOW_INSECURE_LAN_HTTP;
  let requests = 0;
  globalThis.fetch = async () => { requests++; throw new Error('Token was sent'); };
  delete process.env.HIVEMIND_ALLOW_INSECURE_LAN_HTTP;
  t.after(async () => {
    globalThis.fetch = originalFetch;
    if (originalAllow === undefined) delete process.env.HIVEMIND_ALLOW_INSECURE_LAN_HTTP;
    else process.env.HIVEMIND_ALLOW_INSECURE_LAN_HTTP = originalAllow;
    await rm(temp, { recursive: true, force: true });
  });
  const { configure } = await import('./setup.mjs');
  await assert.rejects(configure(temp, tokenFile, 'http://10.1.2.3:8765'), /Private-LAN HTTP requires/);
  assert.equal(requests, 0);
  const { validateServerUrl } = await import('./sync-agent.mjs');
  assert.equal(validateServerUrl('http://10.1.2.3:8765', true), 'http://10.1.2.3:8765');
  assert.throws(() => validateServerUrl('http://8.8.8.8:8765', true), /other network connections require HTTPS/);
});

test('Windows setup restricts existing runtime files to the user and system administrators', { skip: process.platform !== 'win32' }, async t => {
  const runtime = await mkdtemp(path.join(tmpdir(), 'hivemind-runtime-acl-'));
  t.after(() => rm(runtime, { recursive: true, force: true }));
  const nested = path.join(runtime, 'exchange', 'outbox');
  await mkdir(nested, { recursive: true });
  const report = path.join(nested, 'finding.md');
  await writeFile(report, 'BUG: KASAN: local test\n');
  const { secureRuntimeDirectory } = await import('./setup.mjs');
  secureRuntimeDirectory(runtime);
  const future = path.join(nested, 'future.md');
  await writeFile(future, 'later report\n');
  const currentUser = execFileSync('whoami.exe', { encoding: 'utf8' }).trim();
  for (const target of [runtime, nested, report, future]) {
    const output = execFileSync('icacls.exe', [target], { encoding: 'utf8' });
    const permissions = output.replace(target, '').split(/\r?\n/).map(line => line.trim()).filter(line => /:\(/.test(line));
    const principals = new Set(permissions.map(line => line.match(/^(.+?):\(/)?.[1]?.toLowerCase()));
    assert.equal(principals.size, 3, output);
    assert(principals.has(currentUser.toLowerCase()), output);
    assert(permissions.every(line => /\(F\)$/.test(line)), output);
  }
});

test('reinstall keeps one AgentCov read hook and leaves custom hooks intact', async () => {
  const { retainRecordingHook } = await import('./setup.mjs');
  const hooks = { hooks: {
    PostToolUse: [{ hooks: [
      { command: 'agentcov hook post-tool-use' },
      { command: '"C:/agent/python.exe" "C:/agent/agentcov-windows-hook.py"' },
      { command: 'powershell.exe -NoProfile -NonInteractive -Command "& \'C:/agent/python.exe\' \'C:/agent/agentcov-windows-hook.py\'"' },
      { command: 'echo custom' },
    ] }],
    Stop: [{ hooks: [{ command: 'agentcov hook stop' }, { command: 'echo keep-stop' }] }],
  } };
  const command = 'powershell.exe -NoProfile -NonInteractive -Command "& \'C:/agent/python.exe\' \'C:/agent/agentcov-windows-hook.py\'"';
  retainRecordingHook(hooks, command);
  assert.deepEqual(hooks.hooks.PostToolUse[0].hooks.map(item => item.command), [
    command, 'echo custom',
  ]);
  assert.deepEqual(hooks.hooks.Stop[0].hooks.map(item => item.command), ['echo keep-stop']);
});

test('reinstall removes obsolete analysis instructions and keeps project guidance', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'hivemind-instructions-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'AGENTS.md'), '# knfsd Hivemind 분석\n\n- 공유할 가설이 구체화되면 예전 규칙\n- 공유할 가설·분석·검증·정정은 queue_analysis 사용\n\n# 팀 규칙\n기존 지침 유지\n');
  const { updateInstructions } = await import('./setup.mjs');
  updateInstructions(root);
  const result = await readFile(path.join(root, 'AGENTS.md'), 'utf8');
  assert.match(result, /queue_finding/);
  assert.doesNotMatch(result, /queue_analysis/);
  assert.doesNotMatch(result, /공유할 가설/);
  assert.match(result, /vm_environment/);
  assert.match(result, /기존 지침 유지/);
});

test('token configures the matching kernel checkout and project hooks', { skip: process.platform === 'win32' }, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'hivemind-install-'));
  const root = path.join(temp, 'linux');
  const agent = path.join(root, '.hivemind', 'agent');
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, '.mcp.json'), JSON.stringify({ mcpServers: { existing: { command: 'existing-tool' } } }));
  const source = path.dirname(fileURLToPath(import.meta.url));
  const localOnly = new Set(['.git', '.local', '.venv', '__pycache__', 'runtime']);
  await cp(source, agent, { recursive: true, filter: entry => !localOnly.has(path.relative(source, entry).split(path.sep)[0]) });
  await mkdir(path.join(root, '.agentcov'), { recursive: true });
  await writeFile(path.join(root, '.agentcov', 'coverage.json'), '{"obsolete":true}\n');
  await writeFile(path.join(root, '.agentcov', 'events.jsonl'), '{"event":"keep"}\n');
  await mkdir(path.join(agent, '.venv', 'bin'), { recursive: true });
  const agentcov = path.join(agent, '.venv', 'bin', 'agentcov');
  await writeFile(agentcov, '#!/bin/sh\nmkdir -p .codex\nprintf \'{"hooks":{"PostToolUse":[{"hooks":[{"command":"agentcov hook post-tool-use"}]}],"PreToolUse":[{"hooks":[{"command":"agentcov hook pre-tool-use"}]}],"Stop":[{"hooks":[{"command":"agentcov hook stop"},{"command":"echo keep-custom-stop"}]}]}}\' > .codex/hooks.json\n');
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
  const codexConfig = await readFile(path.join(root, '.codex', 'config.toml'), 'utf8');
  assert.match(codexConfig, /mcp_servers\.knfsd_hivemind/);
  assert.doesNotMatch(codexConfig, /NODE_EXTRA_CA_CERTS/);
  const claudeConfig = JSON.parse(await readFile(path.join(root, '.mcp.json'), 'utf8'));
  assert.equal(claudeConfig.mcpServers.existing.command, 'existing-tool');
  assert.deepEqual(claudeConfig.mcpServers.knfsd_hivemind, {
    command: process.execPath,
    args: [path.join(agent, 'mcp-agent.mjs'), result.configPath],
  });
  const hooks = JSON.parse(await readFile(path.join(root, '.codex', 'hooks.json'), 'utf8'));
  const hookCommands = Object.values(hooks.hooks).flatMap(groups => groups.flatMap(group => group.hooks.map(hook => hook.command)));
  assert.deepEqual(hookCommands.filter(command => command.includes('agentcov')), [`${agentcov} hook post-tool-use`]);
  assert.equal(hooks.hooks.PreToolUse, undefined);
  assert(hookCommands.includes('echo keep-custom-stop'));
  await assert.rejects(readFile(path.join(root, '.agentcov', 'coverage.json')), { code: 'ENOENT' });
  assert.equal(await readFile(path.join(root, '.agentcov', 'events.jsonl'), 'utf8'), '{"event":"keep"}\n');
  assert.equal((await readFile(path.join(agent, 'runtime', 'agents', 'jinpyo.token'), 'utf8')).trim(), token);
  const exclude = await readFile(path.join(root, '.git', 'info', 'exclude'), 'utf8');
  for (const entry of ['.hivemind/', '.agentcov/', '.codex/', '.mcp.json', 'AGENTS.md']) assert(exclude.includes(entry));
});

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startServer } from './server/server.mjs';
import { startSyncAgent } from './agent/sync-agent.mjs';

const agentcov = process.env.AGENTCOV_BIN;
if (!agentcov) throw new Error('Set AGENTCOV_BIN to the installed agentcov executable');
const parent = path.join(tmpdir(), 'hivemind-smoke');
await mkdir(parent, { recursive: true });
const temp = await mkdtemp(path.join(parent, 'run-'));
let running;
const syncs = [];
try {
  const repo = path.join(temp, 'linux');
  const home = path.join(temp, 'home');
  await mkdir(path.join(repo, 'fs', 'nfsd'), { recursive: true });
  await writeFile(path.join(repo, 'fs', 'nfsd', 'demo.c'), 'int nfsd_demo(void) {\n  return 1;\n}\n');
  execFileSync('git', ['init', '-q', repo]);
  execFileSync('git', ['-C', repo, 'config', 'core.autocrlf', 'false']);
  execFileSync('git', ['-C', repo, 'add', 'fs/nfsd/demo.c']);
  execFileSync('git', ['-C', repo, '-c', 'user.name=Smoke', '-c', 'user.email=smoke@example.invalid', 'commit', '-qm', 'synthetic source']);
  const commit = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const agents = [
    ['smoke-a', repo, 'Get-Content -LiteralPath fs/nfsd/demo.c -TotalCount 2', 2],
    ['smoke-b', path.join(temp, 'linux-b'), 'Get-Content -LiteralPath fs/nfsd/demo.c | Select-Object -Skip 2 -First 1', 1],
    ['smoke-c', path.join(temp, 'linux-c'), 'Get-Content -LiteralPath fs/nfsd/demo.c | Select-Object -First 1', 1],
    ['smoke-d', path.join(temp, 'linux-d'), 'Get-Content -LiteralPath fs/nfsd/demo.c | Select-Object -Skip 1 -First 1', 1],
    ['smoke-e', path.join(temp, 'linux-e'), 'Get-Content -LiteralPath fs/nfsd/demo.c | Select-Object -Skip 2 -First 1', 1],
  ];
  for (const [agentId, checkout, command, expectedRead] of agents) {
    if (checkout !== repo) execFileSync('git', ['clone', '-q', repo, checkout]);
    const hook = spawnSync(path.join(path.dirname(agentcov), process.platform === 'win32' ? 'python.exe' : 'python'), [path.join(import.meta.dirname, 'agent', 'agentcov-windows-hook.py')], {
      cwd: checkout, encoding: 'utf8', input: JSON.stringify({ cwd: checkout, session_id: agentId, tool_name: 'Bash', tool_input: { cmd: command }, tool_response: 'synthetic source read' }),
    });
    assert.equal(hook.status, 0, hook.stderr);
    const partial = path.join(temp, `${agentId}.json`);
    const report = spawnSync(agentcov, ['report', '--format', 'json', '--out', partial], { cwd: checkout, encoding: 'utf8' });
    assert.equal(report.status, 0, report.stderr);
    assert.equal(JSON.parse(await readFile(partial, 'utf8')).files['fs/nfsd/demo.c'].read_lines, expectedRead);
  }

  running = await startServer({ port: 0, dataDir: path.join(temp, 'server'), apiToken: 'admin' });
  const post = async (route, body, method = 'POST', token = 'admin') => {
    const response = await fetch(`${running.url}${route}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`${route}: ${response.status} ${await response.text()}`);
    return response.json();
  };
  await post('/v1/admin/tracks/rc', { version_id: 'smoke', repo_commit: commit }, 'PUT');
  await mkdir(path.join(home, 'telemetry', 'progress'), { recursive: true });
  for (const [agentId, checkout] of agents) {
    const { token } = await post('/v1/admin/agents', { agent_id: agentId });
    await writeFile(path.join(home, 'telemetry', 'progress', `${agentId}.md`), `---\nschema_version: 1\nversion_id: smoke\nrepo_commit: ${commit}\nupdated_at: "${new Date().toISOString()}"\n---\n\n# Synthetic smoke\n`);
    syncs.push(await startSyncAgent({ agent_id: agentId, track_id: 'rc', version_id: 'smoke', repo_root: checkout, home, server_url: running.url, telemetry_interval_seconds: 300, coverage_prefixes: ['fs/nfsd/'], agentcov_bin: agentcov }, token));
  }
  const dashboard = await (await fetch(`${running.url}/api/dashboard?track_id=rc`)).json();
  assert.equal(dashboard.files.length, 1);
  assert.equal(dashboard.metrics.total_lines, 3);
  assert.equal(dashboard.metrics.read_lines, 3);
  assert.equal(dashboard.metrics.agent_count, 5);
  assert.deepEqual(dashboard.coverage_agents.map(agent => agent.read_lines).sort(), [1, 1, 1, 1, 2]);
  for (const sync of syncs) sync.stop();
  syncs.length = 0;
  await new Promise(resolve => running.server.close(resolve));
  running.db.close();
  running = await startServer({ port: 0, dataDir: path.join(temp, 'server'), apiToken: 'admin' });
  const restored = await (await fetch(`${running.url}/api/dashboard?track_id=rc`)).json();
  assert.equal(restored.metrics.agent_count, 5);
  assert.equal(restored.metrics.read_lines, 3);
  console.log(JSON.stringify({ agentcov: 'installed binary', agents: 5, sync: 'accepted', observed: `${dashboard.metrics.read_lines}/${dashboard.metrics.total_lines}`, restart: 'persisted', server: 'isolated' }));
} finally {
  for (const sync of syncs) sync.stop();
  if (running) { await new Promise(resolve => running.server.close(resolve)); running.db.close(); }
  if (!temp.startsWith(`${parent}${path.sep}`)) throw new Error('Unexpected smoke directory');
  await rm(temp, { recursive: true, force: true });
}

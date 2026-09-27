import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const root = path.dirname(fileURLToPath(import.meta.url));

test('server/ and agent/ run from separate copies', async t => {
  const folder = await mkdtemp(path.join(tmpdir(), 'hivemind-packages-'));
  let server, db;
  t.after(async () => { if (server) await new Promise(resolve => server.close(resolve)); db?.close(); await rm(folder, { recursive: true, force: true }); });
  const serverDir = path.join(folder, 'server-host', 'server');
  const agentDir = path.join(folder, 'analysis-pc', 'agent');
  await Promise.all([
    cp(path.join(root, 'server'), serverDir, { recursive: true }),
    cp(path.join(root, 'agent'), agentDir, { recursive: true }),
  ]);
  assert.equal(
    await readFile(path.join(serverDir, 'contract.mjs'), 'utf8'),
    await readFile(path.join(agentDir, 'contract.mjs'), 'utf8'),
  );

  const { startServer } = await import(pathToFileURL(path.join(serverDir, 'server.mjs')).href);
  const { handleMessage } = await import(pathToFileURL(path.join(agentDir, 'mcp-agent.mjs')).href);
  const { validateConfig } = await import(pathToFileURL(path.join(agentDir, 'sync-agent.mjs')).href);
  const connection = { agent_id: 'pc01', version_id: '7.3-rc4', repo_root: folder, home: folder, telemetry_interval_seconds: 300 };
  assert.throws(() => validateConfig({ ...connection, server_url: 'http://192.168.1.188:8765' }), /allow_insecure_lan_http/);
  assert.equal(validateConfig({ ...connection, server_url: 'http://192.168.1.188:8765', allow_insecure_lan_http: true }).server, 'http://192.168.1.188:8765');
  assert.throws(() => validateConfig({ ...connection, server_url: 'http://8.8.8.8:8765', allow_insecure_lan_http: true }), /Use HTTPS/);
  const running = await startServer({ port: 0, dataDir: path.join(folder, 'data'), apiToken: 'admin' });
  ({ server, db } = running);
  const { url } = running;
  const health = await fetch(`${url}/healthz`);
  assert.equal(health.status, 200);
  await health.text();
  const dashboard = await fetch(url);
  assert.equal(dashboard.status, 200);
  await dashboard.text();
  const response = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer admin', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc01' }) });
  const { token } = await response.json();
  const config = { agent_id: 'pc01', version_id: '7.3-rc4', repo_root: folder, home: folder, server: url };
  const listed = await handleMessage(config, token, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert(listed.result.tools.some(tool => tool.name === 'queue_hypothesis'));
  assert(listed.result.tools.some(tool => tool.name === 'search_hypotheses'));
  const versions = await handleMessage(config, token, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_versions', arguments: {} } });
  assert.deepEqual(versions.result.structuredContent.versions, []);
});

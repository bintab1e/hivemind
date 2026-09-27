import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { makeBatch } from './agent/sync-agent.mjs';
import { startServer } from './server/server.mjs';

const source = process.env.HIVEMIND_BATCH_DIR;
if (!source) throw new Error('Set HIVEMIND_BATCH_DIR to an existing full-scope batch directory');
const [manifest, lcov, coverageJson, progressMd] = await Promise.all([
  readFile(path.join(source, 'manifest.json'), 'utf8').then(JSON.parse),
  readFile(path.join(source, 'agentcov.info'), 'utf8'),
  readFile(path.join(source, 'coverage.json'), 'utf8'),
  readFile(path.join(source, 'progress.md'), 'utf8'),
]);
const allRead = process.argv.includes('--all-read');
const measuredLcov = allRead
  ? lcov.replace(/^DA:(\d+),\d+(?:,.*)?$/gm, 'DA:$1,1').replace(/^LF:(\d+)\r?\nLH:\d+$/gm, 'LF:$1\nLH:$1')
  : lcov;
let measuredJson = coverageJson;
if (allRead) {
  const report = JSON.parse(coverageJson);
  for (const file of Object.values(report.files)) file.read_lines = file.line_count;
  report.summary.read_lines = report.summary.total_lines;
  measuredJson = JSON.stringify(report);
}
const temp = await mkdtemp(path.join(tmpdir(), 'hivemind-scale-'));
let running;
try {
  running = await startServer({ port: 0, dataDir: temp, apiToken: 'admin' });
  const post = async (route, body, token = 'admin', method = 'POST') => {
    const response = await fetch(`${running.url}${route}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`${route}: ${response.status} ${await response.text()}`);
    return response.json();
  };
  await post('/v1/admin/tracks/rc', { version_id: manifest.version_id, repo_commit: manifest.repo_commit }, 'admin', 'PUT');
  const uploads = [];
  for (let index = 1; index <= 5; index++) {
    const agentId = `scale-${index}`;
    const { token } = await post('/v1/admin/agents', { agent_id: agentId });
    const batch = makeBatch({ agentId, versionId: manifest.version_id, repoRoot: manifest.repo_root, commit: manifest.repo_commit, clean: true, generatedAt: new Date().toISOString(), lcov: measuredLcov, coverageJson: measuredJson, progressMd, agentcovConfig: '' });
    uploads.push({ batch, token });
  }
  const uploadStart = performance.now();
  const results = await Promise.all(uploads.map(({ batch, token }) => post('/v1/telemetry/batches', batch, token)));
  assert(results.every(result => result.accepted));
  const uploadMs = Math.round(performance.now() - uploadStart);
  const start = performance.now();
  const response = await fetch(`${running.url}/api/dashboard?track_id=rc`);
  assert.equal(response.status, 200);
  const dashboard = await response.json();
  const elapsedMs = Math.round(performance.now() - start);
  assert.equal(dashboard.metrics.agent_count, 5);
  assert(dashboard.metrics.total_lines > 500_000);
  if (allRead) assert.equal(dashboard.metrics.read_lines, dashboard.metrics.total_lines);
  console.log(JSON.stringify({ agents: 5, lines: dashboard.metrics.total_lines, all_read: allRead, concurrent_upload_ms: uploadMs, response_ms: elapsedMs, rss_mb: Math.round(process.memoryUsage().rss / 1048576), isolated: true }));
} finally {
  if (running) { await new Promise(resolve => running.server.close(resolve)); running.db.close(); }
  if (!temp.startsWith(`${tmpdir()}${path.sep}hivemind-scale-`)) throw new Error('Unexpected scale directory');
  await rm(temp, { recursive: true, force: true });
}

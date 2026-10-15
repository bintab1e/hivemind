import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { gunzipSync } from 'node:zlib';
import { buildCoverageScope, defaultCoveragePrefixes } from './coverage-scope.mjs';
import { readFrontMatter } from './contract.mjs';
import { assertFreshCheckout, coverageProgressStub, encodeJsonBody, makeBatch, pendingBatches, retryableTelemetryRejection, supportsGzipTelemetry, validateCoverageSummary } from './sync-agent.mjs';

test('coverage metadata excludes local analyst notes', () => {
  const commit = 'a'.repeat(40);
  const { data, body } = readFrontMatter(coverageProgressStub('7.3-rc4', commit));
  assert.deepEqual(data, { schema_version: 1, version_id: '7.3-rc4', repo_commit: commit });
  assert.equal(body, '');
});

test('coverage scope follows NFS includes and reports unavailable headers', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'hivemind-scope-'));
  try {
    for (const directory of ['fs/nfsd', 'net/sunrpc', 'include/linux/sunrpc', 'include/linux']) mkdirSync(path.join(root, directory), { recursive: true });
    writeFileSync(path.join(root, 'fs/nfsd/main.c'), '#include <linux/sunrpc/svc.h>\n');
    writeFileSync(path.join(root, 'include/linux/sunrpc/svc.h'), '#include "../types.h"\n#include <net/missing.h>\n');
    writeFileSync(path.join(root, 'include/linux/types.h'), '/* types */\n');
    writeFileSync(path.join(root, 'include/linux/unrelated.h'), '/* unrelated */\n');
    writeFileSync(path.join(root, 'net/sunrpc/svc.c'), '/* RPC source */\n');
    writeFileSync(path.join(root, 'fs/nfsd/Makefile'), 'obj-y += main.o\n');
    writeFileSync(path.join(root, 'net/sunrpc/Kconfig'), 'config SUNRPC\n');
    const scope = await buildCoverageScope(root, ['fs/nfsd/', 'net/sunrpc/']);
    assert.deepEqual([...scope.files].sort(), ['fs/nfsd/main.c', 'include/linux/sunrpc/svc.h', 'include/linux/types.h', 'net/sunrpc/svc.c']);
    assert.deepEqual([...scope.missingIncludes], ['net/missing.h']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('default scope includes NFS client, shared NFS, lockd, exportfs and SunRPC source trees', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'hivemind-knfsd-scope-'));
  try {
    for (const prefix of defaultCoveragePrefixes) {
      mkdirSync(path.join(root, prefix), { recursive: true });
      writeFileSync(path.join(root, prefix, 'source.c'), '/* scoped source */\n');
    }
    mkdirSync(path.join(root, 'fs', 'unrelated'), { recursive: true });
    writeFileSync(path.join(root, 'fs', 'unrelated', 'source.c'), '/* unrelated */\n');
    const { files } = await buildCoverageScope(root, defaultCoveragePrefixes);
    for (const prefix of defaultCoveragePrefixes) assert(files.has(`${prefix}source.c`));
    assert(!files.has('fs/unrelated/source.c'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('new commit needs a fresh agentcov checkout', () => {
  const commit = 'a'.repeat(40);
  const nextCommit = 'b'.repeat(40);
  assert.doesNotThrow(() => assertFreshCheckout({ repo_root: 'C:\\audit', repo_commit: commit }, 'C:\\audit', commit));
  assert.doesNotThrow(() => assertFreshCheckout({ repo_root: 'C:\\audit', repo_commit: commit }, 'C:\\audit-next', nextCommit));
  assert.throws(() => assertFreshCheckout({ repo_root: 'C:\\audit', repo_commit: commit }, 'C:\\audit', nextCommit), /fresh repo_root/);
});

test('sparse AgentCov upload preserves the dense eligible and read line counts', () => {
  const dense = 'TN:agentcov\nSF:fs/nfsd/main.c\nDA:1,0\nDA:2,1\nDA:3,0\nLF:3\nLH:1\nend_of_record\n'
    + 'TN:agentcov\nSF:net/sunrpc/empty.c\nDA:1,0\nDA:2,0\nLF:2\nLH:0\nend_of_record\n';
  const sparse = 'TN:hivemind-sparse-v1\nSF:fs/nfsd/main.c\nDA:2,1\nLH:1\nLF:3\nend_of_record\n'
    + 'TN:hivemind-sparse-v1\nSF:net/sunrpc/empty.c\nLH:0\nLF:2\nend_of_record\n';
  const expected = JSON.stringify({ files: 2, total_lines: 5, read_lines: 1 });
  assert.deepEqual(validateCoverageSummary(sparse, expected, '.'), validateCoverageSummary(dense, expected, '.'));
  const batch = lcov => makeBatch({ agentId: 'pc1', versionId: 'v1', repoRoot: '.', commit: 'a'.repeat(40), clean: true,
    generatedAt: '2026-10-12T00:00:00Z', lcov, coverageJson: '{}', progressMd: '', agentcovConfig: '' });
  assert.equal(batch(sparse).manifest.coverage_scope_hash, batch(dense).manifest.coverage_scope_hash);
});

test('telemetry uses repository-relative paths and keeps checkout path local', () => {
  const checkout = 'C:\\private\\analyst\\linux';
  const lcov = `TN:agentcov\nSF:${checkout}\\fs\\nfsd\\main.c\nDA:1,1\nLF:1\nLH:1\nend_of_record\n`;
  const batch = makeBatch({ agentId: 'pc1', versionId: 'v1', repoRoot: checkout, commit: 'a'.repeat(40), clean: true, generatedAt: '2026-10-12T00:00:00Z', lcov, coverageJson: '{}', progressMd: '', agentcovConfig: '' });
  assert.equal(batch.manifest.repo_root, '.');
  assert.match(batch.lcov, /SF:fs\/nfsd\/main\.c/);
  assert(!JSON.stringify(batch).includes('private'));
});

test('telemetry compression is capability-gated and preserves the JSON body', async () => {
  assert.equal(supportsGzipTelemetry({ telemetry: { content_encodings: ['identity', 'gzip'] } }), true);
  assert.equal(supportsGzipTelemetry({ ok: true }), false);
  const payload = { coverage_json: 'x'.repeat(100_000) };
  const encoded = await encodeJsonBody(payload, true);
  assert.equal(encoded.headers['Content-Encoding'], 'gzip');
  assert.deepEqual(JSON.parse(gunzipSync(encoded.body).toString('utf8')), payload);
  assert.equal(retryableTelemetryRejection('/v1/telemetry/batches: 400 Invalid batch content'), true);
  assert.equal(retryableTelemetryRejection('/v1/telemetry/batches: 413 Request too large'), true);
  assert.equal(retryableTelemetryRejection('/v1/telemetry/batches: 400 Hash mismatch: coverage.json'), false);
});

test('gzip-capable servers receive and acknowledge a previously rejected batch', async t => {
  const home = mkdtempSync(path.join(tmpdir(), 'hivemind-retry-'));
  const batchId = 'a'.repeat(64);
  const batchFolder = path.join(home, 'telemetry', 'batches', 'pc1', batchId);
  mkdirSync(batchFolder, { recursive: true });
  writeFileSync(path.join(batchFolder, 'manifest.json'), JSON.stringify({ batch_id: batchId, source_digest: 'source', generated_at: '2026-09-27T00:00:00Z' }));
  writeFileSync(path.join(batchFolder, 'agentcov.info'), 'lcov');
  writeFileSync(path.join(batchFolder, 'coverage.json'), '{"coverage":true}');
  writeFileSync(path.join(batchFolder, 'progress.md'), 'progress');
  writeFileSync(path.join(batchFolder, 'rejected.json'), JSON.stringify({ error: '/v1/telemetry/batches: 400 Invalid batch content' }));
  let received;
  const server = createServer((request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      assert.equal(request.headers['content-encoding'], 'gzip');
      received = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString('utf8'));
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ accepted: true, batch_id: batchId, warnings: [] }));
    });
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(home, { recursive: true, force: true }); });
  await pendingBatches({ home, agent_id: 'pc1', server: `http://127.0.0.1:${server.address().port}` }, 'token', { gzip: true });
  assert.equal(received.coverage_json, '{"coverage":true}');
  assert.equal(JSON.parse(readFileSync(path.join(batchFolder, 'ack.json'), 'utf8')).result.accepted, true);
});

test('only the newest telemetry batch is retained and sent', async t => {
  const home = mkdtempSync(path.join(tmpdir(), 'hivemind-latest-'));
  const root = path.join(home, 'telemetry', 'batches', 'pc1');
  const ids = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
  for (const [index, batchId] of ids.entries()) {
    const folder = path.join(root, batchId);
    mkdirSync(folder, { recursive: true });
    const manifest = { batch_id: batchId, source_digest: `source-${index}`, repo_root: '/repo', repo_commit: 'd'.repeat(40), generated_at: `2026-09-27T00:0${index}:00Z` };
    writeFileSync(path.join(folder, 'manifest.json'), JSON.stringify(manifest));
    writeFileSync(path.join(folder, 'agentcov.info'), `lcov-${index}`);
    writeFileSync(path.join(folder, 'coverage.json'), JSON.stringify({ coverage: index }));
    writeFileSync(path.join(folder, 'progress.md'), `progress-${index}`);
  }
  mkdirSync(path.join(root, '.creating-stale'), { recursive: true });
  let received;
  const server = createServer((request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      received = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ accepted: true, batch_id: received.manifest.batch_id, warnings: [] }));
    });
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(home, { recursive: true, force: true }); });
  await pendingBatches({ home, agent_id: 'pc1', repo_root: '/repo', server: `http://127.0.0.1:${server.address().port}` }, 'token');
  assert.equal(received.manifest.batch_id, ids[2]);
  assert.equal(received.coverage_json, '{"coverage":2}');
  assert.equal(existsSync(path.join(root, ids[0])), false);
  assert.equal(existsSync(path.join(root, ids[1])), false);
  assert.equal(existsSync(path.join(root, '.creating-stale')), false);
  assert.equal(existsSync(path.join(root, ids[2], 'ack.json')), true);
  const state = JSON.parse(readFileSync(path.join(home, 'sync-state-pc1.json'), 'utf8'));
  assert.deepEqual([state.batch_id, state.repo_root, state.repo_commit], [ids[2], '/repo', 'd'.repeat(40)]);
});

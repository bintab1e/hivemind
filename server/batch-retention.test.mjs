import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { issueAgentToken, startServer } from './server.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const commit = 'a'.repeat(40);
const anotherCommit = 'b'.repeat(40);

function batch(agent, generatedAt, { clean = true, revision = commit, read = [1] } = {}) {
  const version = revision === commit ? '7.3-rc7' : '7.3-rc8';
  const lcov = `TN:agentcov\nSF:fs/nfsd/main.c\nDA:1,${Number(read.includes(1))}\nDA:2,${Number(read.includes(2))}\nLH:${read.length}\nLF:2\nend_of_record\n`;
  const coverageJson = '{}';
  const progressMd = `---\nschema_version: 1\nversion_id: ${version}\nrepo_commit: ${revision}\n---\n`;
  const hashes = { 'agentcov.info': hash(lcov), 'coverage.json': hash(coverageJson), 'progress.md': hash(progressMd) };
  const scopeHash = hash('shared-scope');
  const id = hash([version, agent, revision, scopeHash, String(clean), generatedAt, ...Object.values(hashes)].join('\0'));
  return { manifest: { schema_version: 1, batch_id: id, agent_id: agent, version_id: version, repo_commit: revision, repo_root: '.', coverage_scope_hash: scopeHash, worktree_clean: clean, generated_at: generatedAt, hashes }, lcov, coverage_json: coverageJson, progress_md: progressMd };
}

test('telemetry retains the latest snapshot and latest clean fallback per agent and commit', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-retention-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'admin' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const tokens = Object.fromEntries(['pc1', 'pc2'].map(agent => [agent, issueAgentToken(db, agent).token]));
  const upload = async payload => {
    const response = await fetch(`${url}/v1/telemetry/batches`, { method: 'POST', headers: { Authorization: `Bearer ${tokens[payload.manifest.agent_id]}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const result = await response.json();
    assert.equal(response.status, 200, JSON.stringify(result));
    return result;
  };
  const rows = () => db.prepare('SELECT id FROM batches WHERE agent_id = ? AND version_id = ? AND repo_commit = ? ORDER BY generated_at').all('pc1', '7.3-rc7', commit).map(row => row.id);
  const at = minute => `2026-10-13T00:0${minute}:00Z`;
  const clean1 = batch('pc1', at(1), { read: [1, 2] });
  const clean2 = batch('pc1', at(2));
  const dirty3 = batch('pc1', at(3), { clean: false, read: [1, 2] });
  const dirty4 = batch('pc1', at(4), { clean: false, read: [1, 2] });
  const clean5 = batch('pc1', at(5), { read: [1, 2] });
  await upload(clean1);
  await upload(clean2);
  assert.deepEqual(rows(), [clean2.manifest.batch_id]);
  await upload(dirty3);
  await upload(dirty4);
  assert.deepEqual(rows(), [clean2.manifest.batch_id, dirty4.manifest.batch_id]);
  await upload(batch('pc2', at(1)));
  await upload(batch('pc1', at(1), { revision: anotherCommit }));
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM batches').get().count, 4);
  const coverage = await (await fetch(`${url}/api/dashboard?version_id=7.3-rc7&repo_commit=${commit}`)).json();
  const pc1 = coverage.coverage_agents.find(agent => agent.agent_id === 'pc1');
  assert.deepEqual([pc1.read_lines, pc1.using_clean_fallback], [1, true]);
  assert.equal((await upload(clean2)).replayed, true);
  const stale = await upload(clean1);
  assert.deepEqual([stale.accepted, stale.replayed, stale.retained], [true, false, false]);
  assert.deepEqual(rows(), [clean2.manifest.batch_id, dirty4.manifest.batch_id]);
  await upload(clean5);
  assert.deepEqual(rows(), [clean5.manifest.batch_id]);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM batches').get().count, 3);
  const archived = await fetch(`${url}/v1/admin/batches/${clean1.manifest.batch_id}`, { headers: { Authorization: 'Bearer admin' } });
  assert.equal(archived.status, 404);
});

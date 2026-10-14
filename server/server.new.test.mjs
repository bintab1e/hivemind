import assert from 'node:assert/strict';
import { createHash, scryptSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { issueAgentToken, startServer } from './server.mjs';
import { reviewFindingWithKimi } from './integrations.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const commit = 'a'.repeat(40);

test('direct knfsd finding, evidence, and dashboard auth', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-hub-'));
  const password = 'a-one-time-password';
  const salt = 'test-salt';
  const { server, db, url } = await startServer({ port: 0, dataDir, allowLegacyFindings: true, apiToken: 'admin', dashboardPasswordHash: scryptSync(password, salt, 32).toString('hex'), dashboardPasswordSalt: salt });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const dashboardAuth = { Authorization: `Basic ${Buffer.from(`viewer:${password}`).toString('base64')}` };
  assert.equal((await fetch(`${url}/api/dashboard`)).status, 401);
  const agentResponse = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer admin', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc01' }) });
  assert.equal(agentResponse.status, 201);
  const token = (await agentResponse.json()).token;
  const poc = 'int main(void) { return 0; }\n';
  const kasan = 'BUG: KASAN: slab-out-of-bounds in nfsd_test\nWrite of size 8 at addr deadbeef\n';
  const markdown = `---\nschema_version: 1\nkind: finding\nversion_id: 7.2.5\nrepo_commit: ${commit}\ntitle: "knfsd 경계 검증"\nfile_path: "fs/nfsd/nfs4proc.c"\nvm_environment: "서버 VM과 클라이언트 VM을 분리해 NFS 요청을 전송함"\nverified_impacts:\n  - "kasan_write"\naccess_requirements:\n  - "auth_unix"\nimpact: "경계값 요청에서 메모리 쓰기 오류를 확인함"\nreproduction_command: "cc -o poc poc.c && ./poc"\npoc_source: ${JSON.stringify(poc)}\npoc_sha256: "${sha(poc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\nscope:\n  - "fs/nfsd/"\ncode_refs:\n  - "fs/nfsd/nfs4proc.c#nfsd_test"\nangle: runtime-reproduction\ncreated_at: "2026-10-12T00:00:00Z"\n---\n\n## 분석 보고서\n입력 경계를 재현하고 영향을 확인함.\n`;
  const event = { agent_id: 'pc01', source_path: 'exchange/outbox/pc01/finding.md', markdown, sha256: sha(markdown) };
  const submit = await fetch(`${url}/v1/exchange/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(event) });
  const result = await submit.json();
  assert.equal(submit.status, 200, JSON.stringify(result));
  assert.equal(result.hypothesis_id, null);
  const dashboard = await (await fetch(`${url}/api/dashboard`, { headers: dashboardAuth })).json();
  assert.equal(dashboard.findings.length, 1);
  assert.equal(dashboard.findings[0].vm_environment.includes('서버 VM'), true);
  assert.equal(dashboard.findings[0].static_review.status, 'unconfigured');
  assert.deepEqual(dashboard.findings[0].verified_impacts, ['kasan_write']);
  assert.equal(await (await fetch(`${url}/api/events/${result.event_id}/poc`, { headers: dashboardAuth })).text(), poc);
  for (const [index, file] of ['fs/nfs/client.c', 'fs/nfs_common/nfsacl.c', 'fs/lockd/svc.c', 'net/sunrpc/svcsock.c', 'include/linux/sunrpc/svc.h', 'mm/slab_common.c'].entries()) {
    const related = markdown.replaceAll('fs/nfsd/nfs4proc.c', file);
    const response = await fetch(`${url}/v1/exchange/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc01', source_path: `exchange/outbox/pc01/related-${index}.md`, markdown: related, sha256: sha(related) }) });
    assert.equal(response.status, 200, `${file}: ${await response.text()}`);
  }
  assert.equal((await (await fetch(`${url}/api/dashboard`, { headers: dashboardAuth })).json()).findings.length, 7);
});

test('team coverage keeps per-file reads and overlaps for more than five agents', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-six-agents-'));
  const { server, db, url } = await startServer({ port: 0, dataDir });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const reads = [
    [1], [1, 3], [3], [2], [], [1, 4],
  ];
  const generatedAt = '2026-10-12T00:00:00Z';
  const coverageScopeHash = sha('shared-knfsd-scope');
  for (const [index, lines] of reads.entries()) {
    const agentId = `pc${index + 1}`;
    const { token } = issueAgentToken(db, agentId);
    const record = (file, numbers) => `TN:agentcov\nSF:${file}\n${numbers.map(line => `DA:${line},${lines.includes(line) ? 1 : 0}\n`).join('')}LF:${numbers.length}\nLH:${numbers.filter(line => lines.includes(line)).length}\nend_of_record\n`;
    const lcov = record('fs/nfsd/main.c', [1, 2]) + record('net/sunrpc/svc.c', [3, 4]);
    const coverageJson = '{}';
    const progressMd = `---\nschema_version: 1\nversion_id: 7.3-rc4\nrepo_commit: ${commit}\n---\n`;
    const hashes = { 'agentcov.info': sha(lcov), 'coverage.json': sha(coverageJson), 'progress.md': sha(progressMd) };
    const batchId = sha(['7.3-rc4', agentId, commit, coverageScopeHash, 'true', generatedAt, ...Object.values(hashes)].join('\0'));
    const manifest = { schema_version: 1, batch_id: batchId, agent_id: agentId, version_id: '7.3-rc4', repo_commit: commit, repo_root: '.', coverage_scope_hash: coverageScopeHash, worktree_clean: true, generated_at: generatedAt, hashes };
    const response = await fetch(`${url}/v1/telemetry/batches`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ manifest, lcov, coverage_json: coverageJson, progress_md: progressMd }) });
    assert.equal(response.status, 200, `${agentId}: ${await response.text()}`);
  }
  const dashboard = await (await fetch(`${url}/api/dashboard`)).json();
  assert.equal(dashboard.metrics.agent_count, 6);
  assert.equal(dashboard.metrics.overlap_lines, 2);
  assert.equal(dashboard.coverage_agents.length, 6);
  const byPath = new Map(dashboard.files.map(file => [file.path, file]));
  assert.deepEqual(byPath.get('fs/nfsd/main.c').agent_reads, { pc1: 1, pc2: 1, pc3: 0, pc4: 1, pc5: 0, pc6: 1 });
  assert.equal(byPath.get('fs/nfsd/main.c').overlap_lines, 1);
  assert.deepEqual(byPath.get('net/sunrpc/svc.c').agent_reads, { pc1: 0, pc2: 1, pc3: 1, pc4: 0, pc5: 0, pc6: 1 });
  assert.equal(byPath.get('net/sunrpc/svc.c').overlap_lines, 1);
});

test('Kimi static review sends only the supplied report and records uncertainty', async () => {
  let request;
  const result = await reviewFindingWithKimi({ title: 'knfsd case', filePath: 'fs/nfsd/nfs4proc.c', codeRefs: ['fs/nfsd/nfs4proc.c#foo'], impact: 'memory error', report: '분석 보고서' }, {
    apiKey: 'test-key',
    fetchImpl: async (_url, options) => {
      request = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'uncertain', summary: '추가 코드 확인 필요' }) } }] }) };
    },
  });
  assert.equal(result.verdict, 'uncertain');
  assert.equal(request.messages[1].content.includes('분석 보고서'), true);
  assert.equal(request.messages[1].content.includes('kasan_log'), false);
});

test('removed patch routes return 404 even for authenticated users', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-mvp-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, dashboardPassword: 'test-pass' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  assert.deepEqual(db.prepare("SELECT name FROM sqlite_master WHERE name IN ('patches', 'patch_reviews')").all(), []);
  const auth = { Authorization: `Basic ${Buffer.from('viewer:test-pass').toString('base64')}` };
  for (const pathname of ['/api/patch-reviews', `/api/patch-reviews/${'a'.repeat(64)}`, `/api/patches/${'a'.repeat(64)}/content`, `/api/findings/${'a'.repeat(64)}/patches`, `/patch-reviews/${'a'.repeat(64)}`, '/patch-review.js']) {
    assert.equal((await fetch(`${url}${pathname}`, { headers: auth })).status, 404, pathname);
  }
  assert.equal((await fetch(`${url}/api/patch-reviews`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: '{}' })).status, 404);
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { gzipSync } from 'node:zlib';
import test from 'node:test';
import { startServer } from './server/server.mjs';
import { userspacePocError } from './server/contract.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const commit = 'a'.repeat(40);
const rcCommit = 'b'.repeat(40);
const alternateCommit = 'c'.repeat(40);
const stamp = '2026-09-23T01:00:00Z';

test('events remain immutable; conflicting checks and overlapping coverage stay visible', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-test-'));
  const oldDb = new DatabaseSync(path.join(dataDir, 'hivemind.sqlite3'));
  oldDb.exec('CREATE TABLE batches (id TEXT PRIMARY KEY, agent_id TEXT, version_id TEXT, repo_commit TEXT, scope_hash TEXT, worktree_clean INTEGER, generated_at TEXT, received_at TEXT, files_json TEXT, coverage_json TEXT, progress_md TEXT)');
  oldDb.close();
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'test-token' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const agentTokens = {};
  for (const agent of ['pc1', 'pc2', 'pc3', 'pc4', 'pc5']) {
    const response = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test-token' }, body: JSON.stringify({ agent_id: agent }) });
    assert.equal(response.status, 201);
    agentTokens[agent] = (await response.json()).token;
  }
  const post = async (endpoint, body, token = agentTokens[body.agent_id || body.manifest?.agent_id]) => {
    const response = await fetch(`${url}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
    return [response.status, await response.json()];
  };
  const mcp = async (agent, method, args = {}) => {
    const response = await fetch(`${url}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25', Authorization: `Bearer ${agentTokens[agent]}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: method === 'tools/call' ? args : args }) });
    assert.equal(response.status, 200);
    return (await response.json()).result;
  };
  const tool = (agent, name, args) => mcp(agent, 'tools/call', { name, arguments: args }).then(result => result.structuredContent);
  const event = (agent_id, source_path, fields, body = '## 근거\n코드 위치와 조건을 확인함.\n', version = '7.2.5', revision = commit) => {
    const base = `schema_version: 1\nversion_id: ${version}\nrepo_commit: ${revision}\n`;
    const markdown = `---\n${base}${fields}${fields.includes('kind: hypothesis') ? 'verification_plan: "반례 입력으로 분기 확인"\n' : ''}scope:\n  - "src/app.py"\ncode_refs:\n  - "src/app.py#parse_request"\nangle: static-trace\ncreated_at: "${stamp}"\n---\n\n${body}`;
    return { agent_id, source_path, markdown, sha256: sha(markdown) };
  };
  const englishBody = event('pc1', 'exchange/outbox/pc1/english-body.md', 'kind: hypothesis\ntitle: "English title is allowed"\nclaim_key: "english-body"\npreflight: checked\n', '## Evidence\nObserved the code path.\n');
  assert.equal((await post('/v1/exchange/events', englishBody))[0], 400);
  const englishPlan = event('pc1', 'exchange/outbox/pc1/english-plan.md', 'kind: hypothesis\ntitle: "English title is allowed"\nclaim_key: "english-plan"\npreflight: checked\n');
  englishPlan.markdown = englishPlan.markdown.replace('반례 입력으로 분기 확인', 'Reproduce the branch with a boundary input');
  englishPlan.sha256 = sha(englishPlan.markdown);
  assert.equal((await post('/v1/exchange/events', englishPlan))[0], 400);
  const hypothesis = event('pc1', 'exchange/outbox/pc1/h1.md', 'kind: hypothesis\ntitle: "경계값 우회"\nclaim_key: "boundary-bypass"\npreflight: checked\n');
  assert.equal((await post('/v1/exchange/events', hypothesis, 'wrong'))[0], 401);
  assert.equal((await post('/v1/exchange/events', hypothesis, agentTokens.pc2))[0], 403);
  const [status, first] = await post('/v1/exchange/events', hypothesis);
  assert.equal(status, 200);
  assert.match(first.hypothesis_id, /^H-/);
  const verificationFields = method => `kind: verification\ntitle: "English title is allowed"\nverification_of: "${first.hypothesis_id}"\nmethod: "${method}"\nverdict: inconclusive\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
  assert.equal((await post('/v1/exchange/events', event('pc2', 'exchange/outbox/pc2/english-verification-body.md', verificationFields('정적 코드 경로 추적'), '## Evidence\nObserved the code path.\n')))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc2', 'exchange/outbox/pc2/english-verification-method.md', verificationFields('Static code-path trace'))))[0], 400);
  assert.equal((await post('/v1/exchange/events', hypothesis))[1].replayed, true);
  const edited = { ...hypothesis, markdown: `${hypothesis.markdown}\nchanged` };
  edited.sha256 = sha(edited.markdown);
  assert.equal((await post('/v1/exchange/events', edited))[0], 409);
  const analysis = event('pc1', 'exchange/outbox/pc1/a1.md', `kind: analysis\ntitle: "조건 추적"\nhypothesis_id: "${first.hypothesis_id}"\n`);
  const [analysisStatus, analysisResult] = await post('/v1/exchange/events', analysis);
  assert.equal(analysisStatus, 200);
  assert.deepEqual([analysisResult.accepted, analysisResult.discarded, analysisResult.reason], [false, true, 'intermediate_analysis_disabled']);
  assert.equal(db.prepare('SELECT 1 FROM events WHERE id = ?').get(analysisResult.event_id), undefined);
  const secondHypothesis = event('pc4', 'exchange/outbox/pc4/h1.md', 'kind: hypothesis\ntitle: "경계값 우회"\nclaim_key: "boundary-bypass"\npreflight: checked\n');
  const [secondStatus, second] = await post('/v1/exchange/events', secondHypothesis);
  assert.equal(secondStatus, 200);
  assert.notEqual(second.hypothesis_id, first.hypothesis_id);
  assert.equal(second.possible_matches[0].hypothesis_id, first.hypothesis_id);

  const verificationIds = {};
  for (const [agent, verdict] of [['pc2', 'supports'], ['pc3', 'refutes']]) {
    const fields = `kind: verification\ntitle: "독립 검증 ${agent}"\nverification_of: "${first.hypothesis_id}"\nmethod: "경계값 실행"\nverdict: ${verdict}\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
    const [code, result] = await post('/v1/exchange/events', event(agent, `exchange/outbox/${agent}/v.md`, fields));
    assert.equal(code, 200);
    verificationIds[verdict] = result.event_id;
  }
  assert.equal((await (await fetch(`${url}/api/dashboard?version_id=7.2.5&repo_commit=${commit}`)).json()).findings.length, 0);
  const poc = 'int main(void) { return trigger_boundary(); }\n';
  const kasan = 'BUG: KASAN: slab-out-of-bounds in parse_request\nWrite of size 8 at addr deadbeef\nCall Trace:\n parse_request\n';
  const findingFields = (ids = []) => `kind: finding\ntitle: "경계값 우회 취약점 보고"\nfinding_of: "${first.hypothesis_id}"\nfile_path: "src/app.py"\nverified_impacts:\n  - "controlled_write"\naccess_requirements:\n  - "auth_null"\nimpact: "AUTH_NULL 또는 AUTH_UNIX 경계값 입력이 검사를 우회함"\nreproduction_command: "cc -o poc poc.c && ./poc"\npoc_source: ${JSON.stringify(poc)}\npoc_sha256: "${sha(poc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\n${ids.length ? `evidence_event_ids:\n${ids.map(id => `  - "${id}"`).join('\n')}\n` : ''}`;
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/english-impact.md', findingFields().replace('impact: "AUTH_NULL 또는 AUTH_UNIX 경계값 입력이 검사를 우회함"', 'impact: "Memory corruption"'))))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/no-poc.md', findingFields().replace(/^poc_source:.*\n/m, ''))))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/no-kasan.md', findingFields().replace(/^kasan_log:.*\n/m, ''))))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/bad-impact-type.md', findingFields().replace('  - "controlled_write"', '  - "possible_rce"'))))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/bad-access-type.md', findingFields().replace('  - "auth_null"', '  - "remote_magic"'))))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/unmatched-kasan-type.md', findingFields().replace('  - "controlled_write"', '  - "kasan_read"'))))[0], 400);
  const patchPoc = 'diff --git a/src/app.c b/src/app.c\n--- a/src/app.c\n+++ b/src/app.c\n@@ -1 +1 @@\n';
  const patchFields = findingFields()
    .replace('reproduction_command: "cc -o poc poc.c && ./poc"', 'reproduction_command: "git apply poc.patch && make"')
    .replace(`poc_source: ${JSON.stringify(poc)}`, `poc_source: ${JSON.stringify(patchPoc)}`)
    .replace(`poc_sha256: "${sha(poc)}"`, `poc_sha256: "${sha(patchPoc)}"`);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/kernel-patch-poc.md', patchFields)))[0], 400);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/bad-finding.md', findingFields(['f'.repeat(64)]))))[0], 422);
  const [findingStatus, finding] = await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/finding.md', findingFields()));
  assert.equal(findingStatus, 200);
  assert.equal(finding.hypothesis_id, first.hypothesis_id);
  assert.equal(await (await fetch(`${url}/api/events/${finding.event_id}/poc`)).text(), poc);
  assert.equal(await (await fetch(`${url}/api/events/${finding.event_id}/kasan`)).text(), kasan);
  assert(!(await (await fetch(`${url}/api/events/${finding.event_id}`)).json()).markdown.includes('poc_source'));
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/finding.md', findingFields())))[1].hypothesis_id, first.hypothesis_id);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/wrong-commit.md', findingFields([verificationIds.supports]), undefined, '7.2.5', alternateCommit)))[0], 422);
  const listed = await tool('pc5', 'list_findings', { version_id: '7.2.5', repo_commit: commit });
  assert.deepEqual(listed.findings.map(item => [item.event_id, item.hypothesis_id, item.file_path, item.agent_id, item.evidence_agents]), [[finding.event_id, first.hypothesis_id, 'src/app.py', 'pc4', []]]);
  assert.match(listed.findings[0].kasan_summary, /BUG: KASAN:/);
  const byLocation = await tool('pc5', 'search_hypotheses', { version_id: '7.2.5', repo_commit: commit, code_ref: 'src/app.py#parse_request' });
  assert(byLocation.matches.some(item => item.id === first.hypothesis_id && item.status === 'active' && item.verification_count === 2 && item.refutation_count === 1 && item.code_refs.includes('src/app.py#parse_request')));
  assert(byLocation.matches.some(item => item.id === first.hypothesis_id && item.verification_plan.includes('반례 입력')));
  const retiredHypothesis = event('pc1', 'exchange/outbox/pc1/retired.md', 'kind: hypothesis\ntitle: "잘못된 캐시 가설"\nclaim_key: "cache-failure"\npreflight: checked\n');
  const [, retired] = await post('/v1/exchange/events', retiredHypothesis);
  for (const agent of ['pc2', 'pc3']) {
    const fields = `kind: verification\ntitle: "반례 ${agent}"\nverification_of: "${retired.hypothesis_id}"\nmethod: "${agent}의 독립 추적"\nverdict: refutes\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
    assert.equal((await post('/v1/exchange/events', event(agent, `exchange/outbox/${agent}/retired-v.md`, fields)))[0], 200);
    if (agent === 'pc2') {
      assert.equal((await post('/v1/exchange/events', event(agent, `exchange/outbox/${agent}/retired-again.md`, fields)))[0], 200);
      const oneRefuter = await tool('pc5', 'get_hypothesis', { hypothesis_id: retired.hypothesis_id, repo_commit: commit, mode: 'claim_only' });
      assert.deepEqual([oneRefuter.status, oneRefuter.refutation_count], ['active', 1]);
      const oneDashboard = await (await fetch(`${url}/api/dashboard?version_id=7.2.5&repo_commit=${commit}`)).json();
      const state = oneDashboard.hypotheses.find(item => item.id === retired.hypothesis_id);
      assert.deepEqual([state.status, state.refutation_count], ['refuted', 1]);
    }
  }
  assert.equal((await tool('pc5', 'search_hypotheses', { version_id: '7.2.5', repo_commit: commit, query: 'cache-failure' })).matches[0].status, 'retired');
  assert.equal((await tool('pc5', 'search_hypotheses', { version_id: '7.2.5', repo_commit: commit, query: 'cache-failure' })).matches[0].refutation_count, 2);
  assert.equal((await tool('pc5', 'get_hypothesis', { hypothesis_id: retired.hypothesis_id, repo_commit: commit, mode: 'claim_only' })).status, 'retired');
  assert.equal((await tool('pc5', 'get_hypothesis', { hypothesis_id: retired.hypothesis_id, repo_commit: alternateCommit, mode: 'claim_only' })).status, 'stale');
  assert.equal((await (await fetch(`${url}/api/dashboard?version_id=7.2.5&repo_commit=${commit}`)).json()).metrics.retired_count, 1);

  const batch = (agent_id, read, version = '7.2.5', revision = commit, generatedAt = stamp) => {
    const source = agent_id === 'pc1' ? 'C:\\audit\\src\\app.py' : 'src/app.py';
    const lcov = `TN:\nSF:${source}\nDA:10,${read.includes(10) ? 1 : 0}\nDA:20,${read.includes(20) ? 1 : 0}\nDA:30,${read.includes(30) ? 1 : 0}\nDA:40,${read.includes(40) ? 1 : 0}\nLF:4\nLH:${read.length}\nend_of_record\n`;
    const coverage_json = JSON.stringify({ hivemind_scope: { missing_includes: ['include/linux/example.h', 'include/net/example.h'] } });
    const progress_md = `---\nschema_version: 1\nversion_id: ${version}\nrepo_commit: ${revision}\nupdated_at: "${stamp}"\n---\n\n| task_id | status |\n| --- | --- |\n| T-001 | in_progress |\n`;
    const hashes = { 'agentcov.info': sha(lcov), 'coverage.json': sha(coverage_json), 'progress.md': sha(progress_md) };
    const coverage_scope_hash = sha('test-scope');
    const batch_id = sha([version, agent_id, revision, coverage_scope_hash, 'true', generatedAt, ...Object.values(hashes)].join('\0'));
    return { manifest: { schema_version: 1, batch_id, agent_id, version_id: version, repo_commit: revision, repo_root: 'C:\\audit', coverage_scope_hash, worktree_clean: true, generated_at: generatedAt, hashes }, lcov, coverage_json, progress_md };
  };
  const firstBatch = batch('pc1', [10, 20]);
  assert.equal((await post('/v1/telemetry/batches', firstBatch))[0], 200);
  assert.equal((await post('/v1/telemetry/batches', firstBatch))[1].replayed, true);
  const rawBatch = await fetch(`${url}/v1/admin/batches/${firstBatch.manifest.batch_id}`, { headers: { Authorization: 'Bearer test-token' } });
  assert.equal((await rawBatch.json()).lcov, firstBatch.lcov);
  assert.equal((await post('/v1/telemetry/batches', batch('pc2', [20, 30])))[0], 200);
  assert.equal((await post('/v1/telemetry/batches', batch('pc1', [40], '7.2.5', commit, new Date(Date.parse(stamp) - 1000).toISOString())))[0], 200);
  const broken = batch('pc3', [40]); broken.manifest.hashes['agentcov.info'] = 'wrong';
  assert.equal((await post('/v1/telemetry/batches', broken))[0], 400);
  const mismatched = batch('pc3', [40]); mismatched.progress_md = mismatched.progress_md.replace('7.2.5', '7.2.5-rc1');
  mismatched.manifest.hashes['progress.md'] = sha(mismatched.progress_md);
  assert.equal((await post('/v1/telemetry/batches', mismatched))[0], 400);
  const response = await fetch(`${url}/api/dashboard`);
  assert.equal(response.status, 200);
  const dashboard = await response.json();
  assert.deepEqual([dashboard.metrics.read_lines, dashboard.metrics.total_lines, dashboard.metrics.overlap_lines], [3, 4, 1]);
  assert.equal(dashboard.metrics.read_percent, 75);
  assert.equal(dashboard.metrics.missing_includes, 2);
  assert.deepEqual(dashboard.coverage_agents.map(agent => [agent.agent_id, agent.read_lines, agent.total_lines, agent.read_percent, agent.included_in_team]), [['pc1', 2, 4, 50, true], ['pc2', 2, 4, 50, true]]);
  assert.equal(dashboard.hypotheses.find(item => item.id === first.hypothesis_id).status, 'contested');
  assert.equal(dashboard.findings[0].hypothesis_status, 'contested');
  assert.deepEqual(dashboard.findings[0].verified_impacts, ['kasan_write', 'controlled_write']);
  assert.deepEqual(dashboard.findings[0].access_requirements, ['auth_null', 'auth_unix']);
  assert.deepEqual(dashboard.verifications.filter(item => item.hypothesis_id === first.hypothesis_id).map(item => [item.agent_id, item.verdict, item.hypothesis_id]).sort(), [['pc2', 'supports', first.hypothesis_id], ['pc3', 'refutes', first.hypothesis_id]]);
  assert.equal(dashboard.agents.find(agent => agent.agent_id === 'pc1').unique_lines, 1);
  assert.equal(dashboard.progress.in_progress, 1);
  const coverageUrl = `${url}/api/coverage?version_id=7.2.5&repo_commit=${commit}`;
  const teamCoverage = await (await fetch(coverageUrl)).json();
  const pc1Coverage = await (await fetch(`${coverageUrl}&agent_id=pc1`)).json();
  const pc2Coverage = await (await fetch(`${coverageUrl}&agent_id=pc2`)).json();
  assert.deepEqual([teamCoverage.metrics.read_lines, pc1Coverage.metrics.read_lines, pc2Coverage.metrics.read_lines], [3, 2, 2]);
  assert.deepEqual([teamCoverage.metrics.missing_includes, pc1Coverage.metrics.missing_includes, pc2Coverage.metrics.missing_includes], [2, 2, 2]);
  assert.deepEqual([teamCoverage.files[0].read, pc1Coverage.files[0].read, pc2Coverage.files[0].read], [3, 2, 2]);
  assert.equal((await fetch(`${coverageUrl}&agent_id=pc5`)).status, 404);
  assert.equal((await mcp('pc1', 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } })).protocolVersion, '2025-11-25');
  const listedTools = (await mcp('pc1', 'tools/list')).tools;
  assert(listedTools.some(tool => tool.name === 'get_coverage_gaps'));
  assert(!listedTools.some(tool => tool.name === 'get_recent_analyses'));
  const gaps = await tool('pc1', 'get_coverage_gaps', { version_id: '7.2.5', repo_commit: commit });
  assert.deepEqual(gaps.files[0].ranges, [{ start: 40, end: 40 }]);
  const reviews = await tool('pc1', 'get_review_gaps', { version_id: '7.2.5', repo_commit: commit });
  assert(reviews.hypotheses.some(item => item.id === first.hypothesis_id && item.status === 'contested'));
  assert.equal((await tool('pc1', 'get_team_status', { version_id: '7.2.5', repo_commit: commit })).metrics.read_lines, 3);
  const claim = await tool('pc5', 'get_hypothesis', { hypothesis_id: first.hypothesis_id, mode: 'claim_only' });
  assert(!Object.hasOwn(claim, 'checks'));
  assert((await tool('pc2', 'get_hypothesis', { hypothesis_id: first.hypothesis_id, mode: 'full' })).checks.length >= 2);
  const exposedFields = `kind: verification\ntitle: "노출 이후 재검증"\nverification_of: "${first.hypothesis_id}"\nmethod: "독립 추적 주장"\nverdict: supports\nprior_exposure: none\nbased_on_event_ids: []\n`;
  const [, exposedResult] = await post('/v1/exchange/events', event('pc2', 'exchange/outbox/pc2/exposed.md', exposedFields));
  assert.deepEqual(exposedResult.warnings, ['prior_exposure_differs_from_server_log']);
  const [, summaryHypothesis] = await post('/v1/exchange/events', event('pc1', 'exchange/outbox/pc1/summary.md', 'kind: hypothesis\ntitle: "요약 노출 가설"\nclaim_key: "summary-exposure"\npreflight: checked\n'));
  await tool('pc2', 'get_team_status', { version_id: '7.2.5', repo_commit: commit });
  for (const [agent, method] of [['pc2', '정적 추적'], ['pc3', '실행 재현']]) {
    const fields = `kind: verification\ntitle: "요약 노출 검증 ${agent}"\nverification_of: "${summaryHypothesis.hypothesis_id}"\nmethod: "${method}"\nverdict: refutes\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
    const [, outcome] = await post('/v1/exchange/events', event(agent, `exchange/outbox/${agent}/summary-v.md`, fields));
    if (agent === 'pc2') assert.deepEqual(outcome.warnings, ['prior_exposure_differs_from_server_log']);
  }
  assert.equal((await tool('pc5', 'get_hypothesis', { hypothesis_id: summaryHypothesis.hypothesis_id, repo_commit: commit, mode: 'full' })).status, 'retired');
  assert((await (await fetch(`${url}/api/team-status.md?version_id=7.2.5&repo_commit=${commit}`)).text()).includes('버전: 7.2.5'));
  const badOrigin = await fetch(`${url}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', Authorization: `Bearer ${agentTokens.pc1}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  assert.equal(badOrigin.status, 403);
  const rcHypothesis = event('pc1', 'exchange/outbox/pc1/h1.md', 'kind: hypothesis\ntitle: "RC 경계값 우회"\nclaim_key: "boundary-bypass"\npreflight: checked\n', undefined, '7.2.5-rc1', rcCommit);
  const [rcStatus, rcEvent] = await post('/v1/exchange/events', rcHypothesis);
  assert.equal(rcStatus, 200);
  assert.notEqual(rcEvent.hypothesis_id, first.hypothesis_id);
  assert.deepEqual(rcEvent.possible_matches, []);
  assert.equal((await post('/v1/telemetry/batches', batch('pc1', [40], '7.2.5-rc1', rcCommit)))[0], 200);
  const rcDashboard = await (await fetch(`${url}/api/dashboard?version_id=7.2.5-rc1&repo_commit=${rcCommit}`)).json();
  assert.deepEqual([rcDashboard.selected.version_id, rcDashboard.metrics.read_lines, rcDashboard.metrics.total_lines], ['7.2.5-rc1', 1, 4]);
  assert.equal(rcDashboard.hypotheses.length, 1);
  assert.equal(rcDashboard.verifications.length, 0);
  assert.equal(rcDashboard.findings.length, 0);
  assert.equal(rcDashboard.versions.length, 2);
  assert.equal((await post('/v1/telemetry/batches', batch('pc5', [10], '7.2.5', alternateCommit)))[0], 200);
  const alternate = await (await fetch(`${url}/api/dashboard?version_id=7.2.5&repo_commit=${alternateCommit}`)).json();
  assert.equal(alternate.metrics.read_lines, 1);
  assert.equal(alternate.versions.length, 3);
  const nextSupportFields = `kind: verification\ntitle: "새 커밋 재검증"\nverification_of: "${first.hypothesis_id}"\nmethod: "새 커밋 런타임 재현"\nverdict: supports\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
  const [nextSupportStatus, nextSupport] = await post('/v1/exchange/events', event('pc2', 'exchange/outbox/pc2/next-support.md', nextSupportFields, undefined, '7.2.5', alternateCommit));
  assert.equal(nextSupportStatus, 200);
  const [nextFindingStatus] = await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/next-finding.md', findingFields([nextSupport.event_id]), undefined, '7.2.5', alternateCommit));
  assert.equal(nextFindingStatus, 200);
  assert.equal((await (await fetch(`${url}/api/dashboard?version_id=7.2.5&repo_commit=${alternateCommit}`)).json()).findings.length, 1);
  const rotated = await fetch(`${url}/v1/admin/agents/pc5`, { method: 'PUT', headers: { Authorization: 'Bearer test-token' } });
  assert.equal(rotated.status, 200);
  assert.equal((await fetch(`${url}/v1/sync/health`, { headers: { Authorization: `Bearer ${agentTokens.pc5}` } })).status, 401);
  const dashboardPage = await fetch(`${url}/`);
  assert.equal(dashboardPage.status, 200);
  const dashboardHtml = await dashboardPage.text();
  assert.match(dashboardHtml, /id="recent" class="recent-list" role="region" aria-label="최근 기록 목록" tabindex="0"/);
  assert.match(dashboardHtml, /id="hypothesis-pagination" class="pagination" aria-label="가설 페이지" hidden/);
  assert.match(dashboardHtml, /id="finding-pagination" class="pagination" aria-label="취약점 보고 페이지" hidden/);
  const dashboardScript = await fetch(`${url}/app.js`);
  assert.equal(dashboardScript.status, 200);
  const dashboardJs = await dashboardScript.text();
  assert.match(dashboardJs, /const pageSize = 10/);
  assert.match(dashboardJs, /for \(const hypothesis of page\.items\)/);
  assert.match(dashboardJs, /for \(const finding of page\.items\)/);
  assert.match(dashboardJs, /impact-table/);
  const dashboardStyle = await fetch(`${url}/style.css`);
  assert.equal(dashboardStyle.status, 200);
  const dashboardCss = await dashboardStyle.text();
  assert.match(dashboardCss, /\.recent-list\{max-height:360px;overflow-y:auto;scrollbar-gutter:stable/);
  assert.match(dashboardCss, /\.impact-result-cell\.verified/);
  assert.match(dashboardCss, /\.access-value/);
  assert.match(dashboardCss, /\.pagination button\[aria-current="page"\]/);
  assert.doesNotMatch(dashboardCss, /#reviews-view \.bottom-grid>\.panel\{height:/);
  assert.doesNotMatch(dashboardCss, /#reviews-view #hypotheses,#reviews-view #verifications\{[^}]*overflow-y:/);

  const activate = (track, version_id, repo_commit) => fetch(`${url}/v1/admin/tracks/${track}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test-token' }, body: JSON.stringify({ version_id, repo_commit }) });
  assert.equal((await activate('mainline', '7.2.5', commit)).status, 200);
  assert.equal((await activate('rc', '7.2.5-rc1', rcCommit)).status, 200);
  const nextRc = 'd'.repeat(40);
  assert.equal((await activate('rc', '7.2.5-rc2', nextRc)).status, 200);
  const moved = await (await fetch(`${url}/api/dashboard?track_id=rc`)).json();
  assert.equal(moved.tracks.length, 2);
  assert.deepEqual([moved.selected.track_id, moved.selected.version_id, moved.metrics.total_lines], ['rc', '7.2.5-rc2', 0]);
  assert(moved.hypotheses.some(item => item.id === rcEvent.hypothesis_id && item.status === 'stale'));
  assert(!(await tool('pc1', 'get_review_gaps', { track_id: 'rc' })).hypotheses.some(item => item.id === rcEvent.hypothesis_id));
  assert(!moved.hypotheses.some(item => item.id === first.hypothesis_id));
  assert.equal((await tool('pc1', 'get_team_status', { track_id: 'rc' })).selected.version_id, '7.2.5-rc2');
  assert.deepEqual((await tool('pc1', 'get_coverage_gaps', { track_id: 'rc' })).files, []);
  const staleEvent = event('pc1', 'exchange/outbox/pc1/stale-after-rollover.md', 'kind: hypothesis\ntitle: "이전 RC에서 늦게 도착한 가설"\nclaim_key: "late-rc"\npreflight: checked\n', undefined, '7.2.5-rc1', rcCommit);
  const [staleStatus, staleResult] = await post('/v1/exchange/events', staleEvent);
  assert.equal(staleStatus, 200);
  assert.deepEqual(staleResult.warnings, ['inactive_track_target']);
  assert.deepEqual((await post('/v1/exchange/events', staleEvent))[1].warnings, ['inactive_track_target']);
  const [staleBatchStatus, staleBatchResult] = await post('/v1/telemetry/batches', batch('pc3', [10], '7.2.5-rc1', rcCommit));
  assert.equal(staleBatchStatus, 200);
  assert.deepEqual(staleBatchResult.warnings, ['inactive_track_target']);
  const carried = await tool('pc1', 'search_hypotheses', { track_id: 'rc', repo_commit: nextRc, query: 'boundary-bypass' });
  assert(carried.matches.some(item => item.id === rcEvent.hypothesis_id && item.status === 'stale'));
  assert(!carried.matches.some(item => item.id === first.hypothesis_id));
  const rcCheckFields = `kind: verification\ntitle: "다음 RC 재검증"\nverification_of: "${rcEvent.hypothesis_id}"\nmethod: "새 RC 실행 재현"\nverdict: supports\nprior_exposure: claim_only\nbased_on_event_ids: []\n`;
  const [rcCheckStatus, rcCheck] = await post('/v1/exchange/events', event('pc2', 'exchange/outbox/pc2/rc2-check.md', rcCheckFields, undefined, '7.2.5-rc2', nextRc));
  assert.equal(rcCheckStatus, 200);
  assert.equal((await post('/v1/exchange/events', event('pc4', 'exchange/outbox/pc4/rc2-finding.md', findingFields().replace(first.hypothesis_id, rcEvent.hypothesis_id), undefined, '7.2.5-rc2', nextRc)))[0], 200);
  const currentRc = await (await fetch(`${url}/api/dashboard?track_id=rc`)).json();
  assert.equal(currentRc.hypotheses.find(item => item.id === rcEvent.hypothesis_id).status, 'reported');
  assert.equal(currentRc.findings.length, 1);
  assert.equal((await (await fetch(`${url}/api/dashboard?track_id=mainline`)).json()).selected.version_id, '7.2.5');
});

test('coverage exclusions report the exact failed merge condition', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-exclusions-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'test-token' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const tokens = {};
  for (const agent of ['pc1', 'pc2', 'pc3', 'pc4', 'pc5']) {
    const response = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: agent }) });
    assert.equal(response.status, 201);
    tokens[agent] = (await response.json()).token;
  }
  const batch = (agent, { clean = true, scope = 'shared-scope', eligible = [10, 20], generatedAt = stamp, taskStatus = 'done' } = {}) => {
    const lcov = `TN:\nSF:/repo/src/app.py\n${eligible.map(line => `DA:${line},${line === 10 ? 1 : 0}`).join('\n')}\nLF:${eligible.length}\nLH:1\nend_of_record\n`;
    const coverage_json = '{}';
    const progress_md = `---\nschema_version: 1\nversion_id: 7.2.5\nrepo_commit: ${commit}\nupdated_at: "${stamp}"\n---\n\n| task_id | status |\n| --- | --- |\n| T-${agent} | ${taskStatus} |\n`;
    const hashes = { 'agentcov.info': sha(lcov), 'coverage.json': sha(coverage_json), 'progress.md': sha(progress_md) };
    const coverage_scope_hash = sha(scope);
    const batch_id = sha(['7.2.5', agent, commit, coverage_scope_hash, String(clean), generatedAt, ...Object.values(hashes)].join('\0'));
    return { manifest: { schema_version: 1, batch_id, agent_id: agent, version_id: '7.2.5', repo_commit: commit, repo_root: '/repo', coverage_scope_hash, worktree_clean: clean, generated_at: generatedAt, hashes }, lcov, coverage_json, progress_md };
  };
  const upload = async payload => {
    const response = await fetch(`${url}/v1/telemetry/batches`, { method: 'POST', headers: { Authorization: `Bearer ${tokens[payload.manifest.agent_id]}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    assert.equal(response.status, 200);
  };
  await upload(batch('pc1'));
  await upload(batch('pc2', { clean: false }));
  await upload(batch('pc3', { scope: 'different-scope' }));
  await upload(batch('pc4', { eligible: [10, 20, 30] }));
  await upload(batch('pc5'));
  await upload(batch('pc5', { clean: false, scope: 'temporary-dirty-scope', generatedAt: '2026-09-23T01:00:01Z', taskStatus: 'in_progress' }));
  const dashboard = await (await fetch(`${url}/api/dashboard`)).json();
  assert.deepEqual(dashboard.coverage_agents.map(agent => [agent.agent_id, agent.included_in_team, agent.exclusion_reason]), [
    ['pc1', true, null],
    ['pc2', false, 'worktree_dirty'],
    ['pc3', false, 'scope_mismatch'],
    ['pc4', false, 'file_shape_mismatch'],
    ['pc5', true, null],
  ]);
  assert.deepEqual(dashboard.coverage_agents.find(agent => agent.agent_id === 'pc5'), {
    agent_id: 'pc5', read_lines: 1, total_lines: 2, read_percent: 50,
    included_in_team: true, exclusion_reason: null, using_clean_fallback: true,
    latest_batch_exclusion_reason: 'worktree_dirty',
  });
  assert.deepEqual(dashboard.metrics.excluded_agents, ['pc2', 'pc3', 'pc4']);
  assert.deepEqual(dashboard.progress, { todo: 0, in_progress: 1, blocked: 0, done: 4 });
  const detail = await (await fetch(`${url}/api/coverage?version_id=7.2.5&repo_commit=${commit}&agent_id=pc2`)).json();
  assert.deepEqual([detail.included_in_team, detail.exclusion_reason], [false, 'worktree_dirty']);
  const fallbackDetail = await (await fetch(`${url}/api/coverage?version_id=7.2.5&repo_commit=${commit}&agent_id=pc5`)).json();
  assert.deepEqual([fallbackDetail.included_in_team, fallbackDetail.using_clean_fallback, fallbackDetail.latest_batch_exclusion_reason], [true, true, 'worktree_dirty']);
});

test('gzip telemetry accepts detailed coverage above the legacy 10 MB limit', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-gzip-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'test-token' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const created = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'gzip-agent' }) });
  const token = (await created.json()).token;
  const health = await (await fetch(`${url}/v1/sync/health`, { headers: { Authorization: `Bearer ${token}` } })).json();
  assert(health.telemetry.content_encodings.includes('gzip'));
  assert.equal(health.exchange.finding_revisions, true);

  const lcov = 'TN:\nSF:src/app.py\nDA:1,1\nLF:1\nLH:1\nend_of_record\n';
  const coverage_json = JSON.stringify({ files: {}, padding: 'x'.repeat(10_000_000) });
  const progress_md = `---\nschema_version: 1\nversion_id: 7.2.5\nrepo_commit: ${commit}\nupdated_at: "${stamp}"\n---\n`;
  const hashes = { 'agentcov.info': sha(lcov), 'coverage.json': sha(coverage_json), 'progress.md': sha(progress_md) };
  const coverage_scope_hash = sha('gzip-scope');
  const batch_id = sha(['7.2.5', 'gzip-agent', commit, coverage_scope_hash, 'true', stamp, ...Object.values(hashes)].join('\0'));
  const payload = { manifest: { schema_version: 1, batch_id, agent_id: 'gzip-agent', version_id: '7.2.5', repo_commit: commit, repo_root: '/repo', coverage_scope_hash, worktree_clean: true, generated_at: stamp, hashes }, lcov, coverage_json, progress_md };
  const response = await fetch(`${url}/v1/telemetry/batches`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    body: gzipSync(JSON.stringify(payload)),
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).accepted, true);
  assert.equal(db.prepare('SELECT length(coverage_json) AS length FROM batches WHERE id = ?').get(batch_id).length, coverage_json.length);

  const malformed = await fetch(`${url}/v1/telemetry/batches`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    body: Buffer.from('not gzip'),
  });
  assert.equal(malformed.status, 413);
});

test('PoC and KASAN can be reported directly from an unverified hypothesis', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'hivemind-direct-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, apiToken: 'test-token' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const response = await fetch(`${url}/v1/admin/agents`, { method: 'POST', headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc1' }) });
  const { token } = await response.json();
  const sendEvent = async (name, fields) => {
    const markdown = `---\nschema_version: 1\nversion_id: 7.2.5\nrepo_commit: ${commit}\n${fields}scope:\n  - "fs/nfsd/"\ncode_refs:\n  - "fs/nfsd/nfs4proc.c#nfsd4_open"\nangle: runtime-reproduction\ncreated_at: "${stamp}"\n---\n\n## 근거\n코드와 재현 결과를 확인함.\n`;
    const result = await fetch(`${url}/v1/exchange/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc1', source_path: `exchange/outbox/pc1/${name}.md`, markdown, sha256: sha(markdown) }) });
    assert.equal(result.status, 200);
    return result.json();
  };
  const hypothesis = await sendEvent('hypothesis', 'kind: hypothesis\ntitle: "직접 검증 가설"\nclaim_key: "direct-test"\nverification_plan: "입력을 실행한다"\npreflight: checked\n');
  const poc = 'int main(void) { return 0; }\n';
  const kasan = 'BUG: KASAN: use-after-free in nfsd4_open\n';
  const finding = await sendEvent('finding', `kind: finding\ntitle: "직접 재현"\nfinding_of: "${hypothesis.hypothesis_id}"\nfile_path: "fs/nfsd/nfs4proc.c"\nimpact: "메모리 오류"\nreproduction_command: "cc -o poc poc.c && ./poc"\npoc_source: ${JSON.stringify(poc)}\npoc_sha256: "${sha(poc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\n`);
  const dashboard = await (await fetch(`${url}/api/dashboard`)).json();
  assert.equal(dashboard.hypotheses[0].status, 'reported');
  assert.equal(dashboard.hypotheses[0].refutation_count, 0);
  assert.deepEqual(dashboard.findings[0].evidence_event_ids, []);
  assert.equal(await (await fetch(`${url}/api/events/${finding.event_id}/kasan`)).text(), kasan);

  const revisedPoc = 'int main(void) { return 2; }\n';
  const revised = await sendEvent('finding-revision', `kind: finding\ntitle: "수정된 직접 재현"\nfinding_of: "${hypothesis.hypothesis_id}"\ncorrects_event_id: "${finding.event_id}"\nfile_path: "fs/nfsd/nfs4proc.c"\nimpact: "수정된 PoC에서 메모리 오류를 재확인함"\nreproduction_command: "/usr/bin/gcc -o poc poc.c && ./poc"\npoc_source: ${JSON.stringify(revisedPoc)}\npoc_sha256: "${sha(revisedPoc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\n`);
  const revisedDashboard = await (await fetch(`${url}/api/dashboard`)).json();
  assert.deepEqual(revisedDashboard.findings.map(item => [item.event_id, item.title]), [[revised.event_id, '수정된 직접 재현']]);
  assert.equal(revisedDashboard.hypotheses[0].finding_count, 1);
  assert.equal(await (await fetch(`${url}/api/events/${finding.event_id}/poc`)).text(), poc);
  assert.equal(await (await fetch(`${url}/api/events/${revised.event_id}/poc`)).text(), revisedPoc);
  assert.match((await (await fetch(`${url}/api/events/${revised.event_id}`)).json()).markdown, /코드와 재현 결과를 확인함/);
});

test('standalone PoC validation accepts common compiler and build-tool forms', () => {
  const source = 'int main(void) { return 0; }\n';
  for (const command of [
    '/usr/bin/gcc -o poc poc.c && ./poc',
    'x86_64-linux-gnu-gcc -o poc poc.c && ./poc',
    'CC=clang make poc && ./poc',
    'cmake --build build && ./build/poc',
    'ninja -C build poc && ./build/poc',
  ]) assert.equal(userspacePocError(source, command), null, command);
  assert.match(userspacePocError(source, './poc'), /컴파일/);
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { issueAgentToken, openDatabase, startServer } from './server.mjs';
import { completeFindingReview, registerFinding, retryFindingReview } from './registry.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const commit = 'a'.repeat(40);
const poc = 'int main(void) { return 0; }\n';
const kasan = 'BUG: KASAN: slab-out-of-bounds in nfsd_test\nWrite of size 8 at addr deadbeef\n';

test('registered findings use the authenticated analyst identity and backfill only untouched blank owners', t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-agent-owners-'));
  const file = path.join(dataDir, 'data.sqlite3');
  let db = openDatabase(file);
  t.after(() => { db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const names = [
    ['jinpyo', '이진표'], ['hyunsol', '문현솔'], ['yeonsu', '정연수'],
    ['minsu', '김민수'], ['jiwoong', '위지웅'],
  ];
  const ids = [];
  const insert = db.prepare(`INSERT INTO events
    (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES (?, ?, ?, 'hash', 'finding', '7.3-rc7', ?, 'Candidate', '[]', ?, ?, '---\nschema_version: 1\nkind: finding\n---\n')`);
  for (const [index, [agentId, owner]] of names.entries()) {
    const id = String(index + 1).repeat(64);
    ids.push(id);
    insert.run(id, agentId, `exchange/outbox/${agentId}/finding.md`, commit,
      '2026-10-14T00:00:00Z', '2026-10-14T00:00:00Z');
    registerFinding(db, id, { registry_owner: '제출자가 적은 다른 이름' }, '2026-10-14T00:00:00Z');
    assert.equal(db.prepare('SELECT owner FROM finding_registry WHERE finding_id = ?').get(id).owner, owner);
  }
  db.prepare("UPDATE finding_registry SET owner = NULL, management_id = 'A-043', number = 43 WHERE finding_id = ?").run(ids[0]);
  db.prepare("UPDATE finding_registry SET owner = NULL, management_id = 'A-044', number = 44, admin_overrides_json = '[\"owner\"]' WHERE finding_id = ?").run(ids[1]);
  db.close();
  db = openDatabase(file);
  assert.equal(db.prepare('SELECT owner FROM finding_registry WHERE finding_id = ?').get(ids[0]).owner, '이진표');
  assert.equal(db.prepare('SELECT owner FROM finding_registry WHERE finding_id = ?').get(ids[1]).owner, null);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM registry_edits WHERE row_id = ?').get(ids[0]).count, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM registry_edits WHERE row_id = ?').get(ids[1]).count, 0);
});

test('legacy static review remains advisory while admin edits stay intact', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-registry-'));
  const { server, db, url } = await startServer({ port: 0, dataDir, allowLegacyFindings: true, apiToken: 'admin', dashboardPassword: 'test-password' });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); rmSync(dataDir, { recursive: true, force: true }); });
  const { token } = issueAgentToken(db, 'pc1');
  const basic = { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` };
  const admin = { Authorization: 'Bearer admin', 'Content-Type': 'application/json' };
  const submit = async (name, prior = '') => {
    const markdown = `---\nschema_version: 1\nkind: finding\nversion_id: 7.2.5\nrepo_commit: ${commit}\ntitle: "Finding ${name}"\nfile_path: "fs/nfsd/nfs4proc.c"\nregistry_option: "NFSv4.2"\nregistry_nfs_version: "4.2"\nregistry_vulnerability_type: "OOB Write"\nvm_environment: "서버 VM과 클라이언트 VM을 분리함"\nverified_impacts:\n  - "kasan_write"\naccess_requirements:\n  - "auth_unix"\nimpact: "메모리 쓰기 오류를 확인함"\nreproduction_command: "cc -o poc poc.c && ./poc"\npoc_source: ${JSON.stringify(poc)}\npoc_sha256: "${sha(poc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\n${prior ? `corrects_event_id: "${prior}"\n` : ''}scope:\n  - "fs/nfsd/"\ncode_refs:\n  - "fs/nfsd/nfs4proc.c#nfsd_test"\nangle: runtime-reproduction\ncreated_at: "2026-10-12T00:00:00Z"\n---\n\n## 분석 보고서\n입력 경계를 재현하고 영향을 확인함.\n`;
    const response = await fetch(`${url}/v1/exchange/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_id: 'pc1', source_path: `exchange/outbox/pc1/${name}.md`, markdown, sha256: sha(markdown) }) });
    const result = await response.json();
    assert.equal(response.status, 200, JSON.stringify(result));
    return result.event_id;
  };
  const registry = async () => (await (await fetch(`${url}/api/registry`, { headers: basic })).json());
  assert.equal((await fetch(`${url}/api/registry`)).status, 401);
  const first = await submit('first');
  let result = await registry();
  assert.equal(result.findings[0].management_id, null);
  assert.equal(result.findings[0].review_status, 'unconfigured');
  assert.equal(result.findings[0].report_status, '미제보');
  assert.equal(result.findings[0].target, 'knfsd');
  assert.equal(result.findings[0].nfs_version, '4.2');
  assert.deepEqual(result.sequences.map(item => item.next_id), ['A-043', 'B-022', 'C-002']);
  db.prepare("UPDATE finding_reviews SET status = 'error', summary = 'temporary API failure' WHERE finding_id = ?").run(first);
  const retryUrl = `${url}/v1/admin/registry/${first}/retry-review`;
  assert.equal((await fetch(retryUrl, { method: 'POST', headers: basic })).status, 401);
  let retryResponse = await fetch(retryUrl, { method: 'POST', headers: admin });
  assert.equal(retryResponse.status, 200);
  assert.equal((await retryResponse.json()).status, 'unconfigured');
  assert.equal((await fetch(retryUrl, { method: 'POST', headers: admin })).status, 409);
  db.prepare("UPDATE finding_reviews SET status = 'error' WHERE finding_id = ?").run(first);
  assert.equal(retryFindingReview(db, first, true).status, 'pending');
  assert.equal(db.prepare('SELECT status FROM finding_reviews WHERE finding_id = ?').get(first).status, 'pending');
  const mutationUrl = `${url}/v1/admin/registry/${first}`;
  assert.equal((await fetch(mutationUrl, { method: 'PATCH', headers: { ...basic, 'Content-Type': 'application/json' }, body: JSON.stringify({ revision: 0, report_status: '제보 완료' }) })).status, 401);
  let response = await fetch(mutationUrl, { method: 'PATCH', headers: admin, body: JSON.stringify({ revision: 0, title: 'Curated finding title', owner: '담당자', report_status: '제보 완료', cve: 'CVE-2026-12345', report_project: 'Kernel security', methodology: 'Manual', found_date: '2026-09-07' }) });
  const edited = await response.json();
  assert.equal(response.status, 200, JSON.stringify(edited));
  assert.equal(edited.report_status, '제보 완료');
  assert.equal(edited.title, 'Curated finding title');
  assert.equal((await fetch(mutationUrl, { method: 'PATCH', headers: admin, body: JSON.stringify({ revision: edited.revision, target: 'NFS-Ganesha' }) })).status, 400);
  assert.equal((await fetch(mutationUrl, { method: 'PATCH', headers: admin, body: JSON.stringify({ revision: 0, owner: '다른 담당자' }) })).status, 409);
  db.prepare("UPDATE finding_reviews SET status = 'processing' WHERE finding_id = ?").run(first);
  assert.equal(completeFindingReview(db, first, { verdict: 'uncertain', summary: '코드 경로 추가 확인 필요' }), null);
  assert.equal((await registry()).findings[0].management_id, null);
  db.prepare("UPDATE finding_reviews SET status = 'processing' WHERE finding_id = ?").run(first);
  assert.equal(completeFindingReview(db, first, { verdict: 'likely', summary: '제출된 코드 경로상 결함 가능성 높음' }), null);
  result = await registry();
  assert.equal(result.findings[0].management_id, null);
  assert.equal(result.findings[0].number, null);
  assert.equal(result.findings[0].report_status, '제보 완료');
  assert.equal(result.findings[0].title, 'Curated finding title');
  assert.equal(result.findings[0].owner, '담당자');
  assert.equal(result.findings[0].report_project, 'Kernel security');
  assert.equal(result.findings[0].methodology, 'Manual');
  assert.equal(result.findings[0].found_date, '2026-09-07');
  assert.equal(result.findings[0].registration_status, 'pending');
  assert.equal(result.sequences[0].next_id, 'A-043');
});

test('restart does not promote a completed Kimi-only review', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'knfsd-registry-restart-'));
  const file = path.join(dataDir, 'hivemind.sqlite3');
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  let db = openDatabase(file);
  // An older static-only review must remain unnumbered after deployment or restart.
  const fake = 'f'.repeat(64);
  const markdown = `---\nschema_version: 1\nkind: finding\nvm_environment: "두 VM"\npoc_source: ${JSON.stringify(poc)}\npoc_sha256: "${sha(poc)}"\nkasan_log: ${JSON.stringify(kasan)}\nkasan_sha256: "${sha(kasan)}"\nreproduction_command: "cc -o poc poc.c && ./poc"\n---\n보고서`;
  db.prepare(`INSERT INTO events (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES (?, 'pc1', 'exchange/outbox/pc1/test.md', ?, 'finding', '7.2.5', ?, 'Finding', '[]', '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z', ?)`).run(fake, sha(markdown), commit, markdown);
  db.prepare("INSERT INTO finding_reviews(finding_id, provider, status, verdict, summary, requested_at, completed_at) VALUES (?, 'kimi', 'complete', 'likely', '정적 검토', '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z')").run(fake);
  const withdrawn = 'e'.repeat(64);
  const correction = 'd'.repeat(64);
  db.prepare(`INSERT INTO events (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, created_at, received_at, markdown)
    VALUES (?, 'pc1', 'exchange/outbox/pc1/withdrawn.md', ?, 'finding', '7.2.5', ?, 'Withdrawn', '[]', '2026-10-12T00:00:00Z', '2026-10-12T00:00:01Z', ?)`).run(withdrawn, sha(markdown), commit, markdown);
  db.prepare("INSERT INTO finding_reviews(finding_id, provider, status, verdict, summary, requested_at, completed_at) VALUES (?, 'kimi', 'complete', 'likely', '정적 검토', '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z')").run(withdrawn);
  db.prepare(`INSERT INTO events (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title, scope_json, corrects_event_id, created_at, received_at, markdown)
    VALUES (?, 'pc1', 'exchange/outbox/pc1/correction.md', ?, 'correction', '7.2.5', ?, 'Correction', '[]', ?, '2026-10-12T00:00:02Z', '2026-10-12T00:00:02Z', 'withdrawal')`).run(correction, sha('withdrawal'), commit, withdrawn);
  db.close();
  db = openDatabase(file);
  assert.equal(db.prepare('SELECT management_id FROM finding_registry WHERE finding_id = ?').get(fake).management_id, null);
  assert.deepEqual({ ...db.prepare('SELECT management_id, report_status FROM finding_registry WHERE finding_id = ?').get(withdrawn) }, { management_id: null, report_status: '철회' });
  db.close();
  db = openDatabase(file);
  assert.equal(db.prepare('SELECT last_number FROM registry_sequences WHERE target = ?').get('knfsd').last_number, 42);
  db.close();
});

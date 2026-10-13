import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('finding filters use registry fields, split comma values, and preserve selections', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const start = source.indexOf('const findingFilters = [');
  const end = source.indexOf('const isRegistered =', start);
  assert.ok(start >= 0 && end > start);
  const selects = new Map();
  const context = {
    document: {
      getElementById: id => selects.get(id),
      createElement: tagName => ({ tagName, value: '', textContent: '' }),
    },
  };
  vm.runInNewContext(
    source.slice(0, source.indexOf('const number =')) +
    source.slice(start, end) +
    '\nglobalThis.filters = { findingFilters, populateFindingFilters, matchesFindingFilters };',
    context,
  );
  const { findingFilters, populateFindingFilters, matchesFindingFilters } = context.filters;
  for (const [id] of findingFilters) {
    assert.match(html, new RegExp(`id="${id}"`));
    selects.set(id, {
      value: '',
      options: [],
      replaceChildren() { this.options = []; this.value = ''; },
      append(option) { this.options.push(option); },
    });
  }
  const rows = [
    { target: 'knfsd', report_status: '제보 완료', privilege: 'AUTH_SYS', owner: '이진표', nfs_version: '4.1, 4.2', vulnerability_type: 'Race, UAF' },
    { target: 'NFS-Ganesha', report_status: null, privilege: null, owner: null, nfs_version: '3 / NFSACL', vulnerability_type: 'Resource Leak' },
    { target: 'libnfs', report_status: '미제보', privilege: 'Raw ZDR caller', owner: '이진표', nfs_version: null, vulnerability_type: 'OOB Write' },
  ];
  populateFindingFilters(rows);
  assert.ok(selects.get('finding-nfs-version').options.some(option => option.textContent === '4.2'));
  assert.ok(selects.get('finding-nfs-version').options.some(option => option.textContent === '3'));
  assert.ok(!selects.get('finding-nfs-version').options.some(option => option.textContent === '3 / NFSACL'));
  assert.ok(selects.get('finding-vulnerability-type').options.some(option => option.textContent === 'UAF'));
  assert.ok(selects.get('finding-report-status').options.some(option => option.textContent === '미입력'));
  assert.equal(matchesFindingFilters(rows[0], [['nfs_version', 'value:4.2'], ['vulnerability_type', 'value:UAF'], ['report_status', 'value:제보 완료']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['report_status', 'missing'], ['owner', 'missing']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['nfs_version', 'value:3']]), true);
  assert.equal(matchesFindingFilters({ nfs_version: 'NFS/RDMA' }, [['nfs_version', 'value:NFS/RDMA']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['nfs_version', 'value:4.2']]), false);
  selects.get('finding-target').value = 'value:knfsd';
  populateFindingFilters(rows);
  assert.equal(selects.get('finding-target').value, 'value:knfsd');
  populateFindingFilters(rows.slice(1));
  assert.equal(selects.get('finding-target').value, '');
});

test('new findings include only numbered verified rows and show the right verification basis', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const start = source.indexOf('const isRegistered =');
  const end = source.indexOf('function renderFindingStats', start);
  assert.ok(start >= 0 && end > start);
  const rows = [
    { event_id: 'pending', origin: 'agent', management_id: null, registration_status: 'pending' },
    { event_id: 'unverified', origin: 'agent', management_id: 'A-043', registration_status: 'pending' },
    { event_id: 'old-agent', origin: 'agent', management_id: 'A-042', registration_status: 'verified' },
    { event_id: 'old-ganesha', origin: 'agent', management_id: 'B-021', registration_status: 'verified' },
    { event_id: 'old-libnfs', origin: 'agent', management_id: 'C-001', registration_status: 'verified' },
    { event_id: 'old-history', origin: 'history', management_id: 'B-022', registration_status: 'history' },
    { event_id: 'knfsd', origin: 'agent', management_id: 'A-043', registration_status: 'verified', review_provider: 'codex_qemu' },
    { event_id: 'ganesha', origin: 'agent', management_id: 'B-022', registration_status: 'verified' },
    { event_id: 'libnfs', origin: 'agent', management_id: 'C-002', registration_status: 'verified' },
  ];
  const context = { testState: { registry: { findings: rows } }, testView: 'findings' };
  vm.runInNewContext(
    'const state = globalThis.testState; const activeView = () => globalThis.testView;\n' +
    source.slice(start, end) +
    '\nglobalThis.findingView = { isNewFinding, visibleFindings, reviewLabel, impactEvidence };',
    context,
  );
  const { isNewFinding, visibleFindings, reviewLabel, impactEvidence } = context.findingView;
  assert.deepEqual(Array.from(visibleFindings(), row => row.event_id), ['knfsd', 'ganesha', 'libnfs']);
  assert.equal(isNewFinding(rows[0]), false);
  assert.equal(isNewFinding(rows[1]), false);
  assert.equal(isNewFinding(rows[2]), false);
  assert.equal(isNewFinding(rows[3]), false);
  assert.equal(isNewFinding(rows[4]), false);
  assert.equal(isNewFinding(rows[5]), false);
  assert.equal(reviewLabel(rows[6]), '2VM 검증 완료');
  assert.equal(impactEvidence(rows[6], true), '서버 2VM 재현으로 확인');
  assert.equal(reviewLabel(rows[7]), '정적 검증 통과');
  assert.match(impactEvidence(rows[7], true), /서버 독립 재현 아님/);
  assert.equal(impactEvidence(rows[0], true), '제출 주장, 정적 검증 대기');
  assert.equal(impactEvidence(rows[6], false), '기록 없음');
  context.location = { search: '?demo=1' };
  context.URLSearchParams = URLSearchParams;
  assert.deepEqual(Array.from(visibleFindings(), row => row.event_id), ['demo-preview', 'knfsd', 'ganesha', 'libnfs']);
  assert.equal(isNewFinding(visibleFindings()[0]), false);
  assert.equal(reviewLabel(visibleFindings()[0]), '화면 예시 · 실제 검증 아님');
  context.testView = 'queue';
  assert.deepEqual(Array.from(visibleFindings(), row => row.event_id), ['knfsd', 'ganesha', 'libnfs']);
  context.testView = 'registry';
  assert.equal(visibleFindings().length, rows.length);
});

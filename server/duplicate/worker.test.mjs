import test from 'node:test';
import assert from 'node:assert/strict';
import { runDailyDuplicateOnce, runDuplicateOnce, runInternalDuplicateOnce } from './worker.mjs';

const row = { row_id: 'history:A-024', revision: 0, target: 'knfsd', management_id: 'A-024',
  title: 'PRIVATE lifetime bug', report_status: null,
  report_excerpt: 'fs/nfsd/nfs4state.c:40 reference lifetime',
  file_path: 'fs/nfsd/nfs4state.c', code_refs: [] };
const item = { kind: 'branch', title: 'nfsd: fix reference lifetime',
  url: `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${'a'.repeat(40)}`,
  text: 'fs/nfsd/nfs4state.c: hold reference through validation' };
const mail = { kind: 'mail', title: 'nfsd reference lifetime discussion',
  url: 'https://patchwork.kernel.org/project/linux-nfs/patch/abc/',
  text: 'The same fs/nfsd/nfs4state.c reference lifetime is affected.' };
const config = { socketPath: '/private/verifier.sock', cliPath: '/usr/bin/codex', workRoot: '/private/work' };

test('daily worker reads official sources and records a reviewed duplicate without counting review-only as changed', async () => {
  const calls = [];
  const transport = async (_socket, route, body) => {
    calls.push([route, body]);
    if (route === '/duplicate/candidates') return { candidates: [row] };
    return { row_id: row.row_id, verdict: body.verdict, status_changed: false };
  };
  const counts = await runDuplicateOnce({ config, transport,
    sourceLoader: async () => ({ mail: { ok: true, items: [mail] }, branch: { ok: true, items: [item] } }),
    mailSearch: async () => [], branchSearch: async () => [], hydrator: async value => value,
    reviewer: async () => ({ verdict: 'duplicate', reason: '같은 코드 원인',
      evidence: [{ kind: 'branch', url: item.url, title: item.title }] }) });
  assert.deepEqual(counts, { checked: 1, duplicates: 0, uncertain: 0, errors: 0 });
  assert.equal(calls[1][0], '/duplicate/result');
  assert.equal(calls[1][1].verdict, 'duplicate');
  assert.deepEqual(calls[1][1].sources_checked, { mail: true, branch: true });
});

test('source failure produces an error result and cannot tag a duplicate', async () => {
  const calls = [];
  const counts = await runDuplicateOnce({ config, transport: async (_socket, route, body) => {
    calls.push([route, body]);
    return route === '/duplicate/candidates' ? { candidates: [row] } : { status_changed: false };
  }, sourceLoader: async () => ({ mail: { ok: false, items: [] }, branch: { ok: true, items: [item] } }),
  reviewer: async () => { throw new Error('must_not_review'); } });
  assert.equal(counts.errors, 1);
  assert.equal(calls[1][1].verdict, 'error');
  assert.deepEqual(calls[1][1].sources_checked, { mail: false, branch: true });
});

test('internal daily pass reviews the whole A/B/C catalog and records an ID-based match', async () => {
  const references = [
    { ...row, row_id: 'history:A-001', management_id: 'A-001', report_status: '제보 완료' },
    { ...row, row_id: 'history:B-001', management_id: 'B-001', target: 'NFS-Ganesha' },
    { ...row, row_id: 'history:C-001', management_id: 'C-001', target: 'libnfs' },
  ];
  const calls = [];
  const counts = await runInternalDuplicateOnce({ config,
    transport: async (_socket, route, body) => {
      calls.push([route, body]);
      if (route === '/duplicate/internal-candidates') return { candidates: [row], references };
      return { status_changed: true };
    },
    internalReviewer: async (candidate, all) => {
      assert.equal(candidate.management_id, 'A-024');
      assert.deepEqual(all.map(item => item.management_id), ['A-001', 'B-001', 'C-001']);
      return { verdict: 'duplicate', reason: '동일한 코드 원인',
        matched_management_id: 'A-001' };
    },
  });
  assert.deepEqual(counts, { checked: 1, duplicates: 1, uncertain: 0, errors: 0 });
  assert.equal(calls[1][0], '/duplicate/internal-result');
  assert.equal(calls[1][1].matched_management_id, 'A-001');
});

test('public source failure does not prevent the independent internal check', async () => {
  const calls = [];
  const counts = await runDailyDuplicateOnce({ config,
    transport: async (_socket, route, body) => {
      calls.push(route);
      if (route === '/duplicate/internal-candidates') return { candidates: [row], references: [] };
      if (route === '/duplicate/candidates') return { candidates: [row] };
      return { status_changed: false };
    },
    internalReviewer: async () => ({ verdict: 'no_match', reason: '선행 기록 없음',
      matched_management_id: null }),
    sourceLoader: async () => ({ mail: { ok: false, items: [] }, branch: { ok: true, items: [item] } }),
  });
  assert.equal(counts.internal.checked, 1);
  assert.equal(counts.public.errors, 1);
  assert.deepEqual(calls, ['/duplicate/internal-candidates', '/duplicate/internal-result',
    '/duplicate/candidates', '/duplicate/result']);
});

test('one failed internal result does not skip later findings', async () => {
  const second = { ...row, row_id: 'history:A-025', management_id: 'A-025' };
  let writes = 0;
  const counts = await runInternalDuplicateOnce({ config,
    transport: async (_socket, route) => {
      if (route === '/duplicate/internal-candidates') return { candidates: [row, second], references: [] };
      if (++writes === 1) throw new Error('transient_write_failure');
      return { status_changed: false };
    },
    internalReviewer: async () => ({ verdict: 'no_match', reason: '선행 기록 없음',
      matched_management_id: null }),
  });
  assert.equal(writes, 2);
  assert.deepEqual(counts, { checked: 2, duplicates: 0, uncertain: 0, errors: 1 });
});

test('a newly tagged duplicate cannot become the next finding’s canonical reference', async () => {
  const first = { ...row, row_id: 'history:A-010', management_id: 'A-010', report_status: '미제보' };
  const second = { ...row, row_id: 'history:A-020', management_id: 'A-020', report_status: '미제보' };
  const old = { ...row, row_id: 'history:A-001', management_id: 'A-001', report_status: '제보 완료' };
  let writes = 0;
  const counts = await runInternalDuplicateOnce({ config,
    transport: async (_socket, route) => route === '/duplicate/internal-candidates'
      ? { candidates: [first, second], references: [old, { ...first }, { ...second }] }
      : { status_changed: ++writes === 1 },
    internalReviewer: async (candidate, references) => {
      if (candidate.management_id === 'A-010') return {
        verdict: 'duplicate', reason: '기존 보고와 동일', matched_management_id: 'A-001',
      };
      assert.equal(references.find(item => item.management_id === 'A-010').report_status, '중복');
      return { verdict: 'no_match', reason: '추가 선행 기록 없음', matched_management_id: null };
    },
  });
  assert.equal(writes, 2);
  assert.deepEqual(counts, { checked: 2, duplicates: 1, uncertain: 0, errors: 0 });
});

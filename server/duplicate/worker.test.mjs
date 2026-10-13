import test from 'node:test';
import assert from 'node:assert/strict';
import { runDuplicateOnce } from './worker.mjs';

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

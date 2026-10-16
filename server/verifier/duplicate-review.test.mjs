import assert from 'node:assert/strict';
import test from 'node:test';
import { reviewSubmittedDuplicateWithCodex, validateDuplicateBatch } from './duplicate-review.mjs';

const candidateCause = 'nfsd4_process_open2 releases the client reference before callback completion.';
const earlierCause = 'nfsd4_process_open2 releases the client reference before callback completion.';
const candidate = { target: 'knfsd', title: 'New callback finding',
  file_path: 'fs/nfsd/nfs4state.c', code_refs: ['fs/nfsd/nfs4state.c:42'],
  report_excerpt: `## Summary\nSubmitted callback issue.\n\n## Root cause\n${candidateCause}\n\n## Impact analysis\nUAF.`,
  requested_management_id: null };
const reference = (id, target = 'knfsd', cause = earlierCause) => ({
  management_id: id, target, title: 'Older callback finding', report_status: '미제보',
  file_path: target === 'knfsd' ? 'fs/nfsd/nfs4state.c' : null,
  code_refs: target === 'knfsd' ? ['fs/nfsd/nfs4state.c:42'] : [],
  report_excerpt: `## Summary\nEarlier report.\n\n## Root cause\n${cause}\n\n## Impact analysis\nUAF.`,
});
const comparison = { reachable_path: 'NFS request reaches the same callback release path.',
  faulty_operation: 'The client reference is released before callback completion.',
  violated_invariant: 'The callback must retain the client reference until it finishes.',
  defenses: 'Both paths lack a reference that spans the callback completion.',
  candidate_quote: candidateCause, reference_quote: earlierCause };
const review = (id, verdict, evidence = verdict === 'uncertain' ? null : comparison) => ({
  management_id: id, verdict, reason: verdict === 'same' ? '같은 수명 관리 결함입니다.' : '다른 결함입니다.',
  comparison: evidence,
});

test('every A/B/C reference is compared and a grounded A match is selected', async () => {
  const references = [reference('A-001'), reference('B-001', 'NFS-Ganesha'), reference('C-001', 'libnfs')];
  const prompts = [];
  const result = await reviewSubmittedDuplicateWithCodex(candidate, references, {
    runner: async (prompt, schema) => {
      prompts.push(prompt);
      assert.match(schema, /duplicate-review\.schema\.json$/);
      return { parsed: { reviews: [review('A-001', 'same'), review('B-001', 'different'),
        review('C-001', 'different')] } };
    },
  });
  assert.equal(result.verdict, 'duplicate');
  assert.equal(result.matched_management_id, 'A-001');
  assert.equal(prompts.length, 1);
  for (const id of ['A-001', 'B-001', 'C-001']) assert.match(prompts[0], new RegExp(id));
  assert.match(prompts[0], /faulty operation, violated invariant/);
  assert.match(prompts[0], /path-specific operation that first fails to retain or release ownership/);
});

test('title alone or invented causal quote cannot confirm a duplicate', () => {
  const old = reference('A-001');
  const invented = validateDuplicateBatch({ reviews: [review('A-001', 'same', {
    ...comparison, reference_quote: 'A different operation releases an unrelated object before use.',
  })] }, candidate, [old]);
  assert.equal(invented[0].verdict, 'uncertain');
  const summaryOnly = validateDuplicateBatch({ reviews: [review('A-001', 'same', {
    ...comparison, candidate_quote: 'Submitted callback issue.',
  })] }, candidate, [old]);
  assert.equal(summaryOnly[0].verdict, 'uncertain');
  const multiline = validateDuplicateBatch({ reviews: [{ ...review('A-001', 'different'),
    reason: '서로 다른\n수명 관리 동작' }] }, candidate, [old]);
  assert.equal(multiline[0].reason, '서로 다른 수명 관리 동작');
  const ungroundedDifference = validateDuplicateBatch({ reviews: [review('A-001', 'different', null)] },
    candidate, [old]);
  assert.equal(ungroundedDifference[0].verdict, 'uncertain');
  assert.match(ungroundedDifference[0].reason, /원인 인용|비교 근거/);
  assert.doesNotMatch(ungroundedDifference[0].reason, /다른 결함/);
});

test('a legacy report without a Root cause heading can still ground the same flaw', async () => {
  const old = { ...reference('A-001'), report_excerpt: `# Historical analysis\n\n${earlierCause}` };
  const result = await reviewSubmittedDuplicateWithCodex(candidate, [old], {
    runner: async prompt => {
      assert.match(prompt, /Historical analysis/);
      return { reviews: [review('A-001', 'same')] };
    },
  });
  assert.equal(result.verdict, 'duplicate');
  assert.equal(result.matched_management_id, 'A-001');
});

test('a long matching title without root-cause or PoC evidence cannot justify merging', async () => {
  const title = 'NFS callback client reference release with a long matching description';
  const result = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, title, report_excerpt: title },
    [{ ...reference('A-001'), title, report_excerpt: title }], {
      runner: async () => ({ reviews: [review('A-001', 'same', { ...comparison,
        candidate_quote: title, reference_quote: title })] }),
    });
  assert.equal(result.verdict, 'new');
});

test('available A references are compared in bounded batches', async () => {
  const references = Array.from({ length: 9 }, (_, i) => reference(`A-${String(i + 1).padStart(3, '0')}`));
  let calls = 0;
  const result = await reviewSubmittedDuplicateWithCodex(candidate, references, {
    runner: async (prompt, schema, settings) => {
      calls++;
      assert.equal(settings.timeoutMs, 300_000);
      const ids = [...prompt.matchAll(/"management_id":"(A-\d{3})"/g)].map(match => match[1]);
      assert.ok(ids.length <= 4);
      return { reviews: ids.map(id => review(id, 'different')) };
    },
  });
  assert.equal(result.verdict, 'new');
  assert.equal(result.matched_management_id, null);
  assert.equal(calls, 3);
});

test('uncertain comparisons do not block registration, but multiple proven matches wait', async () => {
  const uncertain = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001')], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(uncertain.verdict, 'new');
  const multiple = await reviewSubmittedDuplicateWithCodex(candidate,
    [reference('A-001'), reference('A-002')], {
      runner: async () => ({ reviews: [review('A-001', 'same'), review('A-002', 'same')] }),
    });
  assert.equal(multiple.verdict, 'uncertain');
  assert.match(multiple.reason, /A-001/);
  assert.match(multiple.reason, /A-002/);
  assert.match(multiple.reason, /비교 후보\(중복 확정 아님\)/);
  const missing = await reviewSubmittedDuplicateWithCodex(candidate,
    [{ ...reference('A-001'), report_excerpt: '' }],
    { runner: async () => { throw new Error('not called'); } });
  assert.equal(missing.verdict, 'new');
});

test('unrelated missing reports and cross-project findings do not veto a new knfsd finding', async () => {
  const missingA = { ...reference('A-001'), file_path: null, code_refs: [], report_excerpt: '' };
  const missingB = { ...reference('B-001', 'NFS-Ganesha'), report_excerpt: '' };
  const result = await reviewSubmittedDuplicateWithCodex(candidate, [missingA, missingB], {
    runner: async () => { throw new Error('no comparable reports'); },
  });
  assert.equal(result.verdict, 'new');
  const unrelatedSameTitle = { ...reference('A-002', 'knfsd',
    'unrelated_issue reports a different object lifetime and caller path.'),
    file_path: null, code_refs: [] };
  const unrelated = await reviewSubmittedDuplicateWithCodex(candidate, [unrelatedSameTitle], {
    runner: async () => ({ reviews: [review('A-002', 'uncertain')] }),
  });
  assert.equal(unrelated.verdict, 'new');
  const cross = await reviewSubmittedDuplicateWithCodex(candidate,
    [reference('B-001', 'NFS-Ganesha')], {
      runner: async () => ({ reviews: [review('B-001', 'same')] }),
    });
  assert.equal(cross.verdict, 'new');
});

test('a grounded same-project match merges despite sparse or uncertain other records', async () => {
  const unrelated = { ...reference('A-002'), file_path: null, code_refs: [], report_excerpt: '' };
  const merge = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001'), unrelated], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(merge.verdict, 'duplicate');
  assert.equal(merge.matched_management_id, 'A-001');
  const material = { ...reference('A-002'), report_excerpt: '' };
  const withSparseReference = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001'), material], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(withSparseReference.verdict, 'duplicate');
  assert.equal(withSparseReference.matched_management_id, 'A-001');
});

test('shared root-cause identifier alone does not block registration', async () => {
  const old = { ...reference('A-001'), file_path: 'fs/nfsd/other.c',
    code_refs: ['fs/nfsd/other.c:12'], report_excerpt: reference('A-001').report_excerpt
      .replace('nfsd4_process_open2', 'nfsd4_process_open2()') };
  const withFunction = { ...candidate, report_excerpt: candidate.report_excerpt
    .replace('nfsd4_process_open2', 'nfsd4_process_open2()') };
  const result = await reviewSubmittedDuplicateWithCodex(withFunction, [old], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(result.verdict, 'new');
});

test('shared source file alone does not block registration', async () => {
  const old = { ...reference('A-001', 'knfsd',
    'different_function releases an unrelated request after its final use.'),
    file_path: null, code_refs: ['fs/nfsd/nfs4state.c:99'] };
  const result = await reviewSubmittedDuplicateWithCodex({ ...candidate, file_path: null }, [old], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(result.verdict, 'new');
});

test('historical reports with a shared path but uncertain cause do not block registration', async () => {
  const old = { ...reference('A-001', 'knfsd',
    'The flaw is in fs/nfsd/nfs4state.c, but the exact operation is unresolved.'),
    file_path: null, code_refs: [] };
  const result = await reviewSubmittedDuplicateWithCodex(candidate, [old], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(result.verdict, 'new');
});

test('invalid comparison quotes cannot justify a match or block registration', async () => {
  const result = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001')], {
    runner: async () => ({ reviews: [review('A-001', 'different', null)] }),
  });
  assert.equal(result.verdict, 'new');
});

test('grounded same cause in an inactive record is held with its ID', async () => {
  const old = { ...reference('A-001'), report_status: '중복' };
  const held = await reviewSubmittedDuplicateWithCodex(candidate, [old], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001.*중복·철회/);
});

test('requested enhancement hint cannot block registration when evidence is unavailable', async () => {
  const old = { ...reference('A-001'), file_path: null, code_refs: [], report_excerpt: '' };
  const held = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, requested_management_id: 'A-001' }, [old], {
      runner: async () => { throw new Error('no comparable reports'); },
    });
  assert.equal(held.verdict, 'new');
  const absent = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, requested_management_id: 'A-999' }, [old],
    { runner: async () => { throw new Error('not called'); } });
  assert.equal(absent.verdict, 'new');
});

test('a sparse report can still ground a same-root comparison in both PoCs', async () => {
  const poc = 'static int nfsd4_process_open2(void) { put_client_ref(client); return use_client(client); }';
  const newFinding = { ...candidate, report_excerpt: 'Short report.', poc_excerpt: poc };
  const old = { ...reference('A-001'), report_excerpt: 'Short report.', poc_excerpt: poc };
  const result = await reviewSubmittedDuplicateWithCodex(newFinding, [old], {
    runner: async prompt => {
      assert.match(prompt, /put_client_ref\(client\)/);
      return { reviews: [review('A-001', 'same', { ...comparison,
        candidate_quote: poc, reference_quote: poc })] };
    },
  });
  assert.equal(result.verdict, 'duplicate');
  assert.equal(result.matched_management_id, 'A-001');
});

test('identical PoC and overlapping causal source anchors trigger a focused duplicate review', async () => {
  const poc = 'int main(void) { /* Reproduce the Read-list page-budget omission. */ return run_read_chunks(); }';
  const cause = 'svc_rdma_recvfrom omits inline bytes from the Read-list page budget, so rc_page_count exceeds rc_pages in svc_rdma_clear_rqst_pages.';
  const newFinding = { ...candidate, title: 'Read-list page count issue',
    file_path: 'net/sunrpc/xprtrdma/svc_rdma_rw.c',
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1148'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: `${poc}\n` };
  const old = { ...reference('A-044'), title: 'Read-segment page budget issue',
    file_path: newFinding.file_path,
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1147-1149'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: poc };
  let calls = 0;
  const result = await reviewSubmittedDuplicateWithCodex(newFinding, [old], {
    runner: async prompt => {
      calls++;
      if (calls === 1) return { reviews: [review('A-044', 'uncertain')] };
      assert.match(prompt, /byte-identical/);
      return { reviews: [review('A-044', 'same', { ...comparison,
        candidate_quote: cause, reference_quote: cause })] };
    },
  });
  assert.equal(calls, 2);
  assert.equal(result.verdict, 'duplicate');
  assert.equal(result.matched_management_id, 'A-044');
});

test('a grounded same-root verdict survives a model paraphrase of its causal quotes', async () => {
  const poc = 'int main(void) { return run_read_chunks_and_check_rc_page_count(); }';
  const cause = 'svc_rdma_recvfrom omits inline bytes so rc_page_count exceeds rc_pages before svc_rdma_clear_rqst_pages clears pointers.';
  const newFinding = { ...candidate, file_path: 'net/sunrpc/xprtrdma/svc_rdma_rw.c',
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1148'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: `${poc}\n` };
  const old = { ...reference('A-044'), file_path: newFinding.file_path,
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1147-1149'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: poc };
  let calls = 0;
  const result = await reviewSubmittedDuplicateWithCodex(newFinding, [old], {
    runner: async () => {
      calls++;
      return { reviews: [review('A-044', 'same', {
        reachable_path: 'The same RPC-over-RDMA Read-list reaches svc_rdma_recvfrom.',
        faulty_operation: 'svc_rdma_clear_rqst_pages indexes rc_pages with excessive rc_page_count.',
        violated_invariant: 'rc_page_count must stay within the rc_pages allocation.',
        defenses: 'The Read length check does not include inline data in either report.',
        candidate_quote: 'The candidate says rc_page_count exceeds the available rc_pages entries.',
        reference_quote: 'The reference also says rc_page_count exceeds its rc_pages allocation.',
      })] };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.verdict, 'duplicate');
  assert.equal(result.matched_management_id, 'A-044');
});

test('unresolved high-risk same-root signal does not silently register a new finding', async () => {
  const poc = 'int main(void) { return run_read_chunks_and_check_rc_page_count(); }';
  const cause = 'The Read-list budget omits inline bytes, then rc_page_count exceeds rc_pages before svc_rdma_clear_rqst_pages writes the pointers.';
  const newFinding = { ...candidate, file_path: 'net/sunrpc/xprtrdma/svc_rdma_rw.c',
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1148'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: poc };
  const old = { ...reference('A-044'), file_path: newFinding.file_path,
    code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:797', 'net/sunrpc/xprtrdma/svc_rdma_rw.c:1147-1149'],
    report_excerpt: `## Root cause\n${cause}`, poc_excerpt: poc };
  let calls = 0;
  const held = await reviewSubmittedDuplicateWithCodex(newFinding, [old], {
    runner: async () => {
      calls++;
      return { reviews: [review('A-044', 'same', { ...comparison, defenses: 'none',
        candidate_quote: cause, reference_quote: cause })] };
    },
  });
  assert.equal(calls, 2);
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-044/);

  const reusedPoc = await reviewSubmittedDuplicateWithCodex(newFinding,
    [{ ...old, code_refs: ['net/sunrpc/xprtrdma/svc_rdma_rw.c:200',
      'net/sunrpc/xprtrdma/svc_rdma_rw.c:300'] }], {
      runner: async () => ({ reviews: [review('A-044', 'uncertain')] }),
    });
  assert.equal(reusedPoc.verdict, 'new');

  const truncated = 'x'.repeat(12_000);
  const clippedPoCs = await reviewSubmittedDuplicateWithCodex(
    { ...newFinding, poc_excerpt: truncated }, [{ ...old, poc_excerpt: truncated }], {
      runner: async () => ({ reviews: [review('A-044', 'uncertain')] }),
    });
  assert.equal(clippedPoCs.verdict, 'new');
});

test('submitter management-ID hint cannot force a merge', async () => {
  const result = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, requested_management_id: 'A-001' }, [reference('A-001')], {
      runner: async () => ({ reviews: [review('A-001', 'different')] }),
    });
  assert.equal(result.verdict, 'new');
  assert.equal(result.matched_management_id, null);
});

test('missing or repeated model decisions fail closed', () => {
  assert.throws(() => validateDuplicateBatch({ reviews: [] }, candidate, [reference('A-001')]),
    /invalid_duplicate_review/);
  assert.throws(() => validateDuplicateBatch({ reviews: [review('A-001', 'different'),
    review('A-001', 'different')] }, candidate, [reference('A-001'), reference('A-002')]),
  /invalid_duplicate_review/);
});

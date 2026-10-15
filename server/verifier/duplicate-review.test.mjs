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

test('available A references are compared in bounded batches', async () => {
  const references = Array.from({ length: 9 }, (_, i) => reference(`A-${String(i + 1).padStart(3, '0')}`));
  let calls = 0;
  const result = await reviewSubmittedDuplicateWithCodex(candidate, references, {
    runner: async prompt => {
      calls++;
      const ids = [...prompt.matchAll(/"management_id":"(A-\d{3})"/g)].map(match => match[1]);
      return { reviews: ids.map(id => review(id, 'different')) };
    },
  });
  assert.equal(result.verdict, 'new');
  assert.equal(result.matched_management_id, null);
  assert.equal(calls, 2);
});

test('material uncertainty and multiple same-project matches wait with management IDs', async () => {
  const uncertain = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001')], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(uncertain.verdict, 'uncertain');
  assert.match(uncertain.reason, /A-001/);
  const multiple = await reviewSubmittedDuplicateWithCodex(candidate,
    [reference('A-001'), reference('A-002')], {
      runner: async () => ({ reviews: [review('A-001', 'same'), review('A-002', 'same')] }),
    });
  assert.equal(multiple.verdict, 'uncertain');
  assert.match(multiple.reason, /A-001/);
  assert.match(multiple.reason, /A-002/);
  const missing = await reviewSubmittedDuplicateWithCodex(candidate,
    [{ ...reference('A-001'), report_excerpt: '' }],
    { runner: async () => { throw new Error('not called'); } });
  assert.equal(missing.verdict, 'uncertain');
  assert.match(missing.reason, /A-001: 기존 취약점의 분석 보고서가 없습니다/);
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

test('a grounded same-project match merges despite unrelated gaps, but a material gap holds', async () => {
  const unrelated = { ...reference('A-002'), file_path: null, code_refs: [], report_excerpt: '' };
  const merge = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001'), unrelated], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(merge.verdict, 'duplicate');
  assert.equal(merge.matched_management_id, 'A-001');
  const material = { ...reference('A-002'), report_excerpt: '' };
  const hold = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001'), material], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(hold.verdict, 'uncertain');
  assert.match(hold.reason, /A-001/);
  assert.match(hold.reason, /A-002: 기존 취약점의 분석 보고서가 없습니다/);
});

test('shared root-cause identifier makes a different-path uncertainty material', async () => {
  const old = { ...reference('A-001'), file_path: 'fs/nfsd/other.c',
    code_refs: ['fs/nfsd/other.c:12'], report_excerpt: reference('A-001').report_excerpt
      .replace('nfsd4_process_open2', 'nfsd4_process_open2()') };
  const withFunction = { ...candidate, report_excerpt: candidate.report_excerpt
    .replace('nfsd4_process_open2', 'nfsd4_process_open2()') };
  const held = await reviewSubmittedDuplicateWithCodex(withFunction, [old], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001/);
});

test('source-reference paths also identify material uncertainty', async () => {
  const old = { ...reference('A-001', 'knfsd',
    'different_function releases an unrelated request after its final use.'),
    file_path: null, code_refs: ['fs/nfsd/nfs4state.c:99'] };
  const held = await reviewSubmittedDuplicateWithCodex({ ...candidate, file_path: null }, [old], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001/);
});

test('invalid comparison quotes produce a specific hold rather than a contradictory difference', async () => {
  const held = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001')], {
    runner: async () => ({ reviews: [review('A-001', 'different', null)] }),
  });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001: 양쪽 보고서의 원인 인용/);
  assert.doesNotMatch(held.reason, /다른 결함/);
});

test('grounded same cause in an inactive record is held with its ID', async () => {
  const old = { ...reference('A-001'), report_status: '중복' };
  const held = await reviewSubmittedDuplicateWithCodex(candidate, [old], {
    runner: async () => ({ reviews: [review('A-001', 'same')] }),
  });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001.*중복·철회/);
});

test('requested enhancement is held when its old report is unavailable', async () => {
  const old = { ...reference('A-001'), file_path: null, code_refs: [], report_excerpt: '' };
  const held = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, requested_management_id: 'A-001' }, [old], {
      runner: async () => { throw new Error('no comparable reports'); },
    });
  assert.equal(held.verdict, 'uncertain');
  assert.match(held.reason, /A-001: 기존 취약점의 분석 보고서가 없습니다/);
  const absent = await reviewSubmittedDuplicateWithCodex(
    { ...candidate, requested_management_id: 'A-999' }, [old]);
  assert.equal(absent.verdict, 'uncertain');
  assert.match(absent.reason, /A-999/);
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

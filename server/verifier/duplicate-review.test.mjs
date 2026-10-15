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
});

test('a new finding requires an explicit different verdict for every existing record', async () => {
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

test('ambiguous, multiple, missing-report and cross-project matches wait for review', async () => {
  const uncertain = await reviewSubmittedDuplicateWithCodex(candidate, [reference('A-001')], {
    runner: async () => ({ reviews: [review('A-001', 'uncertain')] }),
  });
  assert.equal(uncertain.verdict, 'uncertain');
  const multiple = await reviewSubmittedDuplicateWithCodex(candidate,
    [reference('A-001'), reference('A-002')], {
      runner: async () => ({ reviews: [review('A-001', 'same'), review('A-002', 'same')] }),
    });
  assert.equal(multiple.verdict, 'uncertain');
  const missing = await reviewSubmittedDuplicateWithCodex(candidate,
    [{ ...reference('A-001'), report_excerpt: '' }],
    { runner: async () => { throw new Error('not called'); } });
  assert.equal(missing.verdict, 'uncertain');
  const cross = await reviewSubmittedDuplicateWithCodex(candidate,
    [reference('B-001', 'NFS-Ganesha')], {
      runner: async () => ({ reviews: [review('B-001', 'same')] }),
    });
  assert.equal(cross.verdict, 'uncertain');
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

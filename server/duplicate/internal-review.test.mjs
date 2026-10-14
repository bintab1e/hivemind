import test from 'node:test';
import assert from 'node:assert/strict';
import { referencePrecedes, reviewInternalDuplicatesWithCodex,
  validateInternalReview } from './internal-review.mjs';

const base = { row_id: 'history:A-020', management_id: 'A-020', target: 'knfsd',
  report_status: '미제보', title: 'Client reference lifetime',
  vulnerability_type: 'Race, UAF', file_path: 'fs/nfsd/nfs4state.c',
  code_refs: ['nfsd4_process_open2'],
  report_excerpt: '## Summary\nUAF on client release.\n## Root cause\nnfsd4_process_open2 releases the client reference before callback completion.' };
const earlier = { ...base, row_id: 'history:A-001', management_id: 'A-001',
  title: 'Earlier callback UAF',
  report_excerpt: '## Summary\nUAF on callback.\n## Root cause\nnfsd4_process_open2 releases the client reference before callback completion.' };
const causeQuote = 'nfsd4_process_open2 releases the client reference before callback completion.';
const duplicateReview = (overrides = {}) => ({ verdict: 'duplicate', reason: '동일한 콜백 참조 해제 원인입니다.',
  matched_management_id: 'A-001', shared_code_ref: 'nfsd4_process_open2',
  candidate_root_cause_quote: causeQuote, reference_root_cause_quote: causeQuote, ...overrides });
const noMatchReview = { verdict: 'no_match', reason: 'Different failure mechanism',
  matched_management_id: null, shared_code_ref: null,
  candidate_root_cause_quote: null, reference_root_cause_quote: null };

test('reported findings precede unreported ones and duplicate references cannot be canonical', () => {
  assert.equal(referencePrecedes(base, earlier), true);
  assert.equal(referencePrecedes(earlier, base), false);
  assert.equal(referencePrecedes(base, { ...earlier, management_id: 'B-021',
    target: 'NFS-Ganesha', report_status: '제보 완료' }), true);
  assert.equal(referencePrecedes(base, { ...earlier, report_status: '중복' }), false);
});

test('internal review compares all targets but confirms only identical implementation and cause', async () => {
  const cross = { ...earlier, management_id: 'B-001', target: 'NFS-Ganesha',
    report_status: '제보 완료',
    report_excerpt: 'A protocol callback defect in a different implementation.' };
  const prompts = [];
  const result = await reviewInternalDuplicatesWithCodex(base, [cross, earlier], {
    runner: async (prompt, schema) => {
      prompts.push(prompt);
      if (schema.includes('shortlist')) return { management_ids: ['A-001'] };
      return duplicateReview();
    },
  });
  assert.deepEqual(result, { verdict: 'duplicate', reason: '동일한 콜백 참조 해제 원인입니다.',
    matched_management_id: 'A-001' });
  assert.match(prompts[0], /B-001/);
  assert.match(prompts[0], /A-001/);
  assert.match(prompts[0], /reachability path, faulty operation and violated invariant/);
  assert.match(prompts[1], /path from reachable request to affected function/);
  assert.match(prompts[1], /prerequisites or defenses/);
  assert.equal(prompts.length, 2);
});

test('model cannot mark a similar title or different implementation as duplicate', () => {
  const badRef = validateInternalReview(duplicateReview({ reason: 'Similar name',
    shared_code_ref: 'unrelated_function' }), base, [earlier]);
  assert.equal(badRef.verdict, 'uncertain');
  const fileOnly = validateInternalReview(duplicateReview({ reason: 'Same file',
    shared_code_ref: 'fs/nfsd/nfs4state.c' }), base, [earlier]);
  assert.equal(fileOnly.verdict, 'uncertain');
  const prefix = validateInternalReview(duplicateReview({ reason: 'Function prefix only',
    shared_code_ref: 'nfsd4_process_open' }), base, [earlier]);
  assert.equal(prefix.verdict, 'uncertain');
  const cross = validateInternalReview(duplicateReview({ reason: 'Same protocol',
    matched_management_id: 'B-001' }),
  base, [{ ...earlier, management_id: 'B-001', target: 'NFS-Ganesha' }]);
  assert.equal(cross.verdict, 'uncertain');
  assert.equal(cross.matched_management_id, null);
});

test('a shared function only in titles or metadata is not root-cause evidence', () => {
  const incidental = { ...earlier,
    code_refs: ['nfsd4_process_open2'],
    report_excerpt: '## Summary\nnfsd4_process_open2 is mentioned in the introduction.\n' +
      '## Root cause\nAnother callback cleanup path drops a reference too early.' };
  const result = validateInternalReview(duplicateReview({ reason: 'Same title and function name',
    reference_root_cause_quote: 'Another callback cleanup path drops a reference too early.' }), base, [incidental]);
  assert.equal(result.verdict, 'uncertain');
  assert.equal(result.matched_management_id, null);
});

test('fabricated or summary-only root-cause quotes cannot confirm a duplicate', () => {
  const fabricated = validateInternalReview(duplicateReview({ reference_root_cause_quote:
    'nfsd4_process_open2 frees a different object before callback completion.' }), base, [earlier]);
  assert.equal(fabricated.verdict, 'uncertain');
  const summaryOnly = validateInternalReview(duplicateReview({ candidate_root_cause_quote:
    'UAF on client release.' }), base, [earlier]);
  assert.equal(summaryOnly.verdict, 'uncertain');
});

test('an omitted shortlist candidate cannot produce a definitive no-match', async () => {
  const empty = await reviewInternalDuplicatesWithCodex(base, [earlier], {
    runner: async () => ({ management_ids: [] }),
  });
  assert.equal(empty.verdict, 'uncertain');

  const second = { ...earlier, management_id: 'A-002', row_id: 'history:A-002' };
  const partial = await reviewInternalDuplicatesWithCodex(base, [earlier, second], {
    runner: async (_prompt, schema) => schema.includes('shortlist')
      ? { management_ids: ['A-001'] }
      : noMatchReview,
  });
  assert.equal(partial.verdict, 'uncertain');
});

test('a no-match remains possible after every eligible report is compared', async () => {
  const result = await reviewInternalDuplicatesWithCodex(base, [earlier], {
    runner: async (_prompt, schema) => schema.includes('shortlist')
      ? { management_ids: ['A-001'] }
      : noMatchReview,
  });
  assert.equal(result.verdict, 'no_match');
});

test('empty reports remain uncertain and cannot be auto-tagged', async () => {
  const result = await reviewInternalDuplicatesWithCodex({ ...base, report_excerpt: '' },
    [earlier], { runner: async () => { throw new Error('should not run'); } });
  assert.equal(result.verdict, 'uncertain');
});

test('invalid shortlist identifiers are rejected', async () => {
  await assert.rejects(reviewInternalDuplicatesWithCodex(base, [earlier], {
    runner: async () => ({ management_ids: ['C-999'] }),
  }), /invalid_internal_shortlist/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { reviewDuplicateWithCodex, validateDuplicateReview } from './codex-review.mjs';

const cause = 'nfsd4_process_open2 releases the client reference before callback completion';
const row = { target: 'knfsd', title: 'PRIVATE title', management_id: 'A-001',
  report_excerpt: `## Summary\nClient lifetime issue.\n## Root cause\n${cause} in fs/nfsd/nfs4state.c.\n## PoC\nReproduction.`,
  file_path: 'fs/nfsd/nfs4state.c', code_refs: [] };
const evidence = { kind: 'branch', title: 'nfsd: fix lifetime flaw',
  url: `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${'a'.repeat(40)}`,
  text: `fs/nfsd/nfs4state.c: ${cause}. Hold the reference until callback teardown.` };
const comparison = { candidate_cause_quote: `${cause} in fs/nfsd/nfs4state.c.`,
  public_cause_quote: `fs/nfsd/nfs4state.c: ${cause}.`,
  reachability_path: 'NFSv4 callback reaches nfsd4_process_open2',
  faulty_operation: 'The reference is released before callback completion',
  violated_invariant: 'The client must remain alive until callback completion',
  conditions_and_defenses: 'Both cases use the same callback path and lack a lifetime guard' };
const answer = { verdict: 'duplicate', reason: '동일한 참조 수명 오류입니다.',
  evidence_url: evidence.url, shared_code_ref: 'fs/nfsd/nfs4state.c', comparison };

test('a public duplicate requires grounded causal quotes and a shared Root cause code reference', () => {
  assert.equal(validateDuplicateReview(answer, row, [evidence]).verdict, 'duplicate');
  assert.equal(validateDuplicateReview({ ...answer, evidence_url: 'https://attacker.example/x' }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview({ ...answer, shared_code_ref: 'fs/nfsd/other.c' }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview(answer, row, [{ ...evidence, text: 'A different bug in another file.' }]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview({ ...answer, comparison: { ...comparison, public_cause_quote: 'Invented matching operation in the public patch' } }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview({ ...answer, comparison: { ...comparison, candidate_cause_quote: 'Invented matching operation in the private report' } }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview({ ...answer, comparison: null }, row, [evidence]).verdict, 'uncertain');
});

test('a title or metadata-only match cannot automatically mark a duplicate', () => {
  const titleOnly = { ...row, report_excerpt: '## Summary\nfs/nfsd/nfs4state.c has a lifetime flaw.\n## Root cause\nThe cause is not established.' };
  assert.equal(validateDuplicateReview(answer, titleOnly, [evidence]).verdict, 'uncertain');
  const sameTitle = { ...evidence, title: row.title, text: 'fs/nfsd/nfs4state.c has a completely different bounds check defect.' };
  assert.equal(validateDuplicateReview(answer, row, [sameTitle]).verdict, 'uncertain');
  const bodyIsTitle = { ...evidence, title: evidence.text, text: evidence.text };
  assert.equal(validateDuplicateReview(answer, row, [bodyIsTitle]).verdict, 'uncertain');
});

test('non-duplicate output does not carry contradictory evidence or bypass missing root cause', () => {
  const clean = { verdict: 'no_match', reason: '공개 자료는 다른 오류입니다.',
    evidence_url: null, shared_code_ref: null, comparison: null };
  assert.equal(validateDuplicateReview(clean, row, [evidence]).verdict, 'no_match');
  assert.equal(validateDuplicateReview({ ...clean, evidence_url: evidence.url }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview(clean, { ...row, report_excerpt: '## Summary\nTitle only.' }, [evidence]).verdict, 'uncertain');
});

test('Codex receives private report only as local prompt data and must compare causal evidence', async () => {
  const result = await reviewDuplicateWithCodex(row, [evidence], { cliPath: '/usr/bin/codex', workRoot: '/tmp',
    runner: async (prompt, schema, options) => {
      assert.match(prompt, /PRIVATE title/);
      assert.match(prompt, /reachable request/);
      assert.match(prompt, /violated invariant/);
      assert.match(prompt, /fs\/nfsd\/nfs4state.c/);
      assert.match(schema, /codex-output.schema.json$/);
      assert.equal(options.timeoutMs, 300_000);
      return { parsed: answer };
    } });
  assert.equal(result.verdict, 'duplicate');
});

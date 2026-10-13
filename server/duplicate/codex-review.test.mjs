import test from 'node:test';
import assert from 'node:assert/strict';
import { reviewDuplicateWithCodex, validateDuplicateReview } from './codex-review.mjs';

const row = { target: 'knfsd', title: 'PRIVATE title', management_id: 'A-001',
  report_excerpt: 'The same lifetime flaw is in fs/nfsd/nfs4state.c:40.',
  file_path: 'fs/nfsd/nfs4state.c', code_refs: [] };
const evidence = { kind: 'branch', title: 'nfsd: fix lifetime flaw',
  url: `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${'a'.repeat(40)}`,
  text: 'Fix lifetime flaw in fs/nfsd/nfs4state.c by holding the reference through validation.' };

test('a duplicate verdict must cite a supplied public item and an exact shared source reference', () => {
  const answer = { verdict: 'duplicate', reason: '동일한 참조 수명 오류입니다.',
    evidence_url: evidence.url, shared_code_ref: 'fs/nfsd/nfs4state.c' };
  assert.equal(validateDuplicateReview(answer, row, [evidence]).verdict, 'duplicate');
  assert.equal(validateDuplicateReview({ ...answer, evidence_url: 'https://attacker.example/x' }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview({ ...answer, shared_code_ref: 'fs/nfsd/other.c' }, row, [evidence]).verdict, 'uncertain');
  assert.equal(validateDuplicateReview(answer, row, [{ ...evidence, text: 'A different bug in another file.' }]).verdict, 'uncertain');
});

test('Codex receives private report only as local prompt data', async () => {
  const result = await reviewDuplicateWithCodex(row, [evidence], { cliPath: '/usr/bin/codex', workRoot: '/tmp',
    runner: async (prompt, schema, options) => {
      assert.match(prompt, /PRIVATE title/);
      assert.match(prompt, /fs\/nfsd\/nfs4state.c/);
      assert.match(schema, /codex-output.schema.json$/);
      assert.equal(options.timeoutMs, 300_000);
      return { parsed: { verdict: 'duplicate', reason: '같은 오류', evidence_url: evidence.url,
        shared_code_ref: 'fs/nfsd/nfs4state.c' } };
    } });
  assert.equal(result.verdict, 'duplicate');
});

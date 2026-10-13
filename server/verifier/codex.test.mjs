import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CodexReviewError, VerifierUnavailableError, loadTrustedKernelSource, reviewReproductionWithCodex, reviewSubmissionWithCodex } from './codex.mjs';

const trustedSource = { commit: 'a'.repeat(40), files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [
  { number: 1, text: 'int nfsd4_proc_compound(void) { return 0; }' },
] }] };
const options = cliPath => ({ cliPath, trustedSource });

test('both structured-output schemas are valid JSON', () => {
  for (const name of ['codex-output.schema.json', 'codex-relevance.schema.json']) {
    assert.doesNotThrow(() => JSON.parse(fs.readFileSync(new URL(name, import.meta.url), 'utf8')));
  }
});

const submission = {
  project: 'knfsd',
  title: 'Candidate boundary bug',
  report: 'Submitted reasoning, not verified.',
  files: [
    { name: 'old.py', content: 'print("candidate")\n' },
    { name: 'candidate.c', content: 'int main(void) { return 0; }\n' },
    { name: 'report.txt', content: 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n' },
  ],
};

const answer = {
  verdict: 'likely',
  reason: 'The code path is plausible but requires reproduction.',
  normalized: {
    title: 'NFS 경계 오류',
    report: '## 분석\n정적 검토상 가능성이 있으나 재현 전입니다.',
    file_path: 'fs/nfsd/nfs4proc.c',
    code_refs: ['fs/nfsd/nfs4proc.c:nfsd4_proc_compound'],
    source_evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1 }],
    options: null,
    permission: 'AUTH_SYS',
    nfs_version: '4.2',
    vulnerability_type: 'OOB Read',
    found_date: null,
    claimed_impacts: ['kasan_read'],
    poc_file_index: 1,
    poc_language: 'c',
    build_command: 'cc -o poc poc.c',
    run_command: './poc',
    log_file_indexes: [2],
  },
};

function fakeCli(t, result, event = { type: 'turn.completed' }, delayMs = 0, marker = '<submission>') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-verifier-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cli = path.join(dir, 'fake-codex.mjs');
  const code = `#!/usr/bin/env node
import fs from 'node:fs';
const args = process.argv.slice(2);
let prompt = '';
for await (const chunk of process.stdin) prompt += chunk;
if (!args.includes('--ephemeral') || !args.includes('--ignore-user-config') || !args.includes('--ignore-rules') || !args.includes('shell_tool') || !args.includes('--sandbox') || !args.includes('read-only') || !args.includes('--output-schema') || !prompt.includes(${JSON.stringify(marker)}) || !prompt.includes('<trusted-source>') || prompt.includes('HIGHLY_SENSITIVE')) process.exit(41);
await new Promise(resolve => setTimeout(resolve, ${delayMs}));
fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(result))});
process.stdout.write(${JSON.stringify(`${JSON.stringify(event)}\n`)});
`;
  fs.writeFileSync(cli, code, { mode: 0o700 });
  return cli;
}

test('uses a C PoC before Python, retains original evidence, and never claims reproduction', async t => {
  const result = await reviewSubmissionWithCodex({ ...submission, auth_token: 'HIGHLY_SENSITIVE', metadata: { secret: 'HIGHLY_SENSITIVE', nfs_version: '4.2' } }, options(fakeCli(t, answer)));
  assert.deepEqual([result.verdict, result.model], ['likely', 'codex-default']);
  assert.deepEqual(result.normalized.poc, {
    filename: 'poc.c', original_name: 'candidate.c', source_index: 1,
    source: submission.files[1].content, language: 'c',
    build_command: 'cc -o poc poc.c', run_command: './poc',
  });
  assert.deepEqual(result.normalized.logs, [{ filename: 'evidence-1.log', original_name: 'report.txt', source_index: 2, content: submission.files[2].content }]);
  assert.deepEqual(result.grounding, { source_commit: trustedSource.commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1, text: trustedSource.files[0].lines[0].text }] });
  assert.equal(Object.hasOwn(result, 'reproduced'), false);
  assert.equal(Object.hasOwn(result, 'approved'), false);
});

test('fills omitted PoC command hints from the isolated guest defaults', async t => {
  const cAnswer = structuredClone(answer);
  cAnswer.normalized.build_command = null;
  cAnswer.normalized.run_command = null;
  const cReview = await reviewSubmissionWithCodex({ ...submission, metadata: { reproduction_command: 'cc candidate.c && ./a.out' } }, options(fakeCli(t, cAnswer)));
  assert.equal(cReview.verdict, 'likely');
  assert.deepEqual([cReview.normalized.poc.source_index, cReview.normalized.poc.source, cReview.normalized.poc.build_command, cReview.normalized.poc.run_command],
    [1, submission.files[1].content, 'gcc -O0 -g -o /tmp/hivemind-poc /mnt/job/poc.c', '/tmp/hivemind-poc 10.77.0.1 /mnt/nfs']);

  const pythonOnly = { ...submission, files: [submission.files[0], submission.files[2]] };
  const pythonAnswer = structuredClone(answer);
  Object.assign(pythonAnswer.normalized, { poc_file_index: 0, poc_language: 'python', build_command: null, run_command: null, log_file_indexes: [1] });
  const pythonReview = await reviewSubmissionWithCodex(pythonOnly, options(fakeCli(t, pythonAnswer)));
  assert.deepEqual([pythonReview.normalized.poc.filename, pythonReview.normalized.poc.run_command],
    ['poc.py', 'python3 /mnt/job/poc.py 10.77.0.1 /mnt/nfs']);
});

test('fails closed when CLI is missing or submitted paths are unsafe', async () => {
  await assert.rejects(reviewSubmissionWithCodex(submission, options('')), error => error instanceof VerifierUnavailableError && error.code === 'not_configured');
  await assert.rejects(reviewSubmissionWithCodex(submission, { cliPath: '/missing/codex' }), error => error instanceof CodexReviewError && error.code === 'trusted_source_missing');
  await assert.rejects(reviewSubmissionWithCodex({ ...submission, files: [{ name: '../secret', content: 'x' }] }, options('/missing/codex')), error => error instanceof CodexReviewError && error.code === 'invalid_submission');
});

test('rejects unsupported Python selection when a C PoC exists and invalid model indexes', async t => {
  const wrongLanguage = structuredClone(answer);
  Object.assign(wrongLanguage.normalized, { poc_file_index: 0, poc_language: 'python', build_command: null, run_command: 'python3 poc.py' });
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, wrongLanguage))), error => error instanceof CodexReviewError && error.code === 'invalid_output');
  const wrongIndex = structuredClone(answer);
  wrongIndex.normalized.log_file_indexes = [99];
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, wrongIndex))), error => error instanceof CodexReviewError && error.code === 'invalid_output');
});

test('rejects incomplete or failed Codex turns even if a result file exists', async t => {
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, answer, { type: 'turn.failed' }))), error => error instanceof CodexReviewError && error.code === 'runtime_failure');
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, answer, { type: 'item.completed' }))), error => error instanceof CodexReviewError && error.code === 'runtime_failure');
});

test('rejects invalid JSON shape and times out without promoting a claim', async t => {
  const invalid = { ...answer, normalized: { ...answer.normalized, extra: 'unexpected' } };
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, invalid))), error => error instanceof CodexReviewError && error.code === 'invalid_output');
  await assert.rejects(reviewSubmissionWithCodex(submission, { ...options(fakeCli(t, answer, { type: 'turn.completed' }, 1000)), timeoutMs: 100 }), error => error instanceof CodexReviewError && error.code === 'timeout');
});

test('reads source from the clean pinned Git checkout and rejects drift', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-kernel-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'fs/nfsd'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'fs/nfsd/nfs4proc.c'), 'int nfsd4_proc_compound(void) { return 0; }\n');
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const fixture = { metadata: { file_path: 'fs/nfsd/nfs4proc.c:1' }, report: 'candidate' };
  const source = await loadTrustedKernelSource(dir, commit, fixture);
  assert.equal(source.commit, commit);
  assert.deepEqual(source.files[0].lines[0], { number: 1, text: 'int nfsd4_proc_compound(void) { return 0; }' });
  const attachmentOnly = await loadTrustedKernelSource(dir, commit, { files: [{ content: 'Investigate fs/nfsd/nfs4proc.c:1' }] });
  assert.equal(attachmentOnly.files[0].path, 'fs/nfsd/nfs4proc.c');
  await assert.rejects(loadTrustedKernelSource(dir, '0'.repeat(40), fixture), error => error.code === 'source_commit_or_cleanliness_mismatch');
  fs.appendFileSync(path.join(dir, 'fs/nfsd/nfs4proc.c'), '/* dirty */\n');
  await assert.rejects(loadTrustedKernelSource(dir, commit, fixture), error => error.code === 'source_commit_or_cleanliness_mismatch');
});

test('static likely verdict cannot cite a source line that is absent from the trusted checkout', async t => {
  const ungrounded = structuredClone(answer);
  ungrounded.normalized.source_evidence[0].line = 99;
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, ungrounded))), error => error.code === 'ungrounded_output');
});

test('post-QEMU relevance requires an exact server KASAN frame, pinned source line, and original PoC line', async t => {
  const review = await reviewSubmissionWithCodex(submission, options(fakeCli(t, answer)));
  const serverSerial = 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n nfsd4_proc_compound+0x4/0x20\n';
  const symbolizedFrames = [{ trace_line: 'nfsd4_proc_compound+0x4/0x20', locations: [{ path: 'fs/nfsd/nfs4proc.c', line: 17 }] }];
  const supporting = { verdict: 'supports', reason: 'Matching frame', trace_line: 'nfsd4_proc_compound+0x4/0x20',
    source_path: 'fs/nfsd/nfs4proc.c', source_line: 1, poc_line: 1 };
  const input = { review, serverSerial, pocSource: submission.files[1].content, trustedSource, symbolizedFrames };
  const result = await reviewReproductionWithCodex(input,
    { cliPath: fakeCli(t, supporting, { type: 'turn.completed' }, 0, '<server-serial>') });
  assert.equal(result.verdict, 'supports');
  assert.equal(result.poc_line, 1);
  assert.equal(result.symbolized_path, 'fs/nfsd/nfs4proc.c');
  assert.equal(result.symbolized_line, 17);
  await assert.rejects(reviewReproductionWithCodex(input,
    { cliPath: fakeCli(t, { ...supporting, trace_line: 'invented frame' }, { type: 'turn.completed' }, 0, '<server-serial>') }), error => error.code === 'ungrounded_relevance');
  await assert.rejects(reviewReproductionWithCodex(input,
    { cliPath: fakeCli(t, { ...supporting, source_line: 2 }, { type: 'turn.completed' }, 0, '<server-serial>') }), error => error.code === 'ungrounded_relevance');
  await assert.rejects(reviewReproductionWithCodex({ ...input, symbolizedFrames: [{ ...symbolizedFrames[0], locations: [] }] },
    { cliPath: fakeCli(t, supporting, { type: 'turn.completed' }, 0, '<server-serial>') }), error => error.code === 'ungrounded_relevance');
  await assert.rejects(reviewReproductionWithCodex({ ...input, symbolizedFrames: [{ ...symbolizedFrames[0], locations: [
    { path: 'fs/nfsd/nfs4proc.c', line: 17 }, { path: 'fs/nfsd/nfs4proc.c', line: 18 },
  ] }] }, { cliPath: fakeCli(t, supporting, { type: 'turn.completed' }, 0, '<server-serial>') }), error => error.code === 'ungrounded_relevance');
});

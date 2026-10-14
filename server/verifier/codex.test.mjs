import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CodexReviewError, VerifierUnavailableError, loadTrustedKernelSource, reviewPrimitiveWithCodex, reviewReproductionWithCodex, reviewSameRootCauseWithCodex, reviewSubmissionWithCodex } from './codex.mjs';

const trustedSource = { commit: 'a'.repeat(40), files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [
  { number: 1, text: 'int nfsd4_proc_compound(void) { return 0; }' },
] }] };
const options = cliPath => ({ cliPath, trustedSource });

test('both structured-output schemas are valid JSON', () => {
  for (const name of ['codex-output.schema.json', 'codex-relevance.schema.json', 'codex-primitive.schema.json', 'codex-same-root.schema.json']) {
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
    title: 'NFSv4 COMPOUND boundary out-of-bounds read',
    report: '## Summary\n경계 검사가 의심됩니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:1 코드에서 검사가 필요합니다.\n```c\nint nfsd4_proc_compound(void) { return 0; }\n```\n\n## Reproduction environment\n제출 환경만 확인했고 2VM 실행 전입니다.\n\n## PoC\nC 프로그램이 경계를 검사합니다.\n\n## Impact analysis\n제출 로그는 KASAN 읽기를 주장하지만 재현 전입니다.',
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

test('same-root review compares the prior report and new grounded source, not the title alone', async t => {
  const reviewed = await reviewSubmissionWithCodex(submission, options(fakeCli(t, answer)));
  const existing = { management_id: 'A-005', title: 'Similar title', file_path: 'fs/nfsd/nfs4proc.c',
    report: 'The earlier flaw was a separate lifetime error in another operation.' };
  const cliPath = fakeCli(t, { verdict: 'different', reason: 'Different violated invariant' },
    { type: 'turn.completed' }, 0, '<existing>');
  const result = await reviewSameRootCauseWithCodex(existing, reviewed, { cliPath, trustedSource });
  assert.equal(result.verdict, 'different');
  assert.match(result.reason, /Different/);
  await assert.rejects(reviewSameRootCauseWithCodex({ ...existing, report: '' }, reviewed,
    { cliPath, trustedSource }), error => error.code === 'invalid_same_root_input');
});

test('primitive review stays advisory and grounds each suggested direction in pinned source', async t => {
  const finding = {
    title: 'NFSv4 COMPOUND boundary read', file_path: 'fs/nfsd/nfs4proc.c',
    nfs_version: '4.2', privilege: 'AUTH_SYS', verified_impacts: ['kasan_read'],
    report: '## Summary\nA bounds read was observed.',
    poc_source: 'int main(void) { return 0; }\n',
    kasan_log: 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n',
  };
  const answer = {
    candidates: [{ primitive: 'controlled_read', source_path: 'fs/nfsd/nfs4proc.c', source_line: 1,
      basis: '길이 인자에 따라 읽는 위치가 달라질 가능성이 있습니다.', missing_evidence: '읽기 주소의 제어 범위를 별도로 확인해야 합니다.' }],
  };
  const cliPath = fakeCli(t, answer, { type: 'turn.completed' }, 0, '<primitive-evidence>');
  const result = await reviewPrimitiveWithCodex(finding, { cliPath, trustedSource });
  assert.match(result.summary, /Controlled Read 추가 가능성/);
  assert.doesNotMatch(result.summary, /미재현|불명확/);
  assert.match(result.summary, /fs\/nfsd\/nfs4proc\.c:1/);
  assert.equal(result.candidates.length, 1);
  assert.deepEqual(finding.verified_impacts, ['kasan_read']);
  const noCandidateCli = fakeCli(t, { candidates: [] }, { type: 'turn.completed' }, 0, '<primitive-evidence>');
  assert.equal((await reviewPrimitiveWithCodex(finding, { cliPath: noCandidateCli, trustedSource })).summary, null);
  const badCli = fakeCli(t, { ...answer, candidates: [{ ...answer.candidates[0], source_line: 99 }] }, { type: 'turn.completed' }, 0, '<primitive-evidence>');
  await assert.rejects(reviewPrimitiveWithCodex(finding, { cliPath: badCli, trustedSource }),
    error => error instanceof CodexReviewError && error.code === 'ungrounded_output');
});

test('uses a C PoC, includes impact allegations, retains original evidence, and never claims reproduction', async t => {
  const result = await reviewSubmissionWithCodex({ ...submission, auth_token: 'HIGHLY_SENSITIVE', metadata: { secret: 'HIGHLY_SENSITIVE', nfs_version: '4.2', claimed_impacts: ['kasan_read', 'lpe'] } },
    options(fakeCli(t, answer, { type: 'turn.completed' }, 0, '"claimed_impacts":["kasan_read","lpe"]')));
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

test('fills omitted C PoC command hints and requires a C PoC for a likely verdict', async t => {
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
  await assert.rejects(reviewSubmissionWithCodex(pythonOnly, options(fakeCli(t, pythonAnswer))), error => error.code === 'invalid_output');
  const missingPoc = structuredClone(answer);
  Object.assign(missingPoc.normalized, { poc_file_index: null, poc_language: null, build_command: null, run_command: null, log_file_indexes: [1] });
  await assert.rejects(reviewSubmissionWithCodex(pythonOnly, options(fakeCli(t, missingPoc))), error => error.code === 'ungrounded_output');
});

test('canonicalizes common permission and NFS version aliases, rejecting ambiguous versions and unstructured reports', async t => {
  const aliases = structuredClone(answer);
  aliases.normalized.title = '  NFSv4   COMPOUND  boundary out-of-bounds read  ';
  aliases.normalized.permission = 'AUTH_UNIX';
  aliases.normalized.nfs_version = 'NFSv4.2';
  aliases.normalized.vulnerability_type = 'Race; Use-after-free';
  const reviewed = await reviewSubmissionWithCodex(submission, options(fakeCli(t, aliases)));
  assert.deepEqual([reviewed.normalized.title, reviewed.normalized.permission, reviewed.normalized.nfs_version, reviewed.normalized.vulnerability_type],
    ['NFSv4 COMPOUND boundary out-of-bounds read', 'AUTH_SYS', '4.2', 'Race, UAF']);
  const ambiguous = structuredClone(answer);
  ambiguous.normalized.nfs_version = '4.1, 4.2';
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, ambiguous))), error => error.code === 'invalid_output');
  const unstructured = structuredClone(answer);
  unstructured.normalized.report = '## Summary\nOnly one section.';
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, unstructured))), error => error.code === 'invalid_output');
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
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, answer, { type: 'turn.failed' }))), error => error instanceof CodexReviewError && error.code === 'turn_failed');
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, answer, { type: 'item.completed' }))), error => error instanceof CodexReviewError && error.code === 'turn_incomplete');
});

test('classifies CLI execution failures without exposing diagnostics', async t => {
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, answer, { type: 'turn.completed' }, 0, 'missing-marker'))),
    error => error instanceof CodexReviewError && error.code === 'cli_nonzero_exit');
  const nonExecutable = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'codex-noexec-test-')), 'noexec');
  t.after(() => fs.rmSync(path.dirname(nonExecutable), { recursive: true, force: true }));
  fs.writeFileSync(nonExecutable, '#!/bin/sh\nexit 0\n', { mode: 0o600 });
  await assert.rejects(reviewSubmissionWithCodex(submission, options(nonExecutable)),
    error => error instanceof CodexReviewError && error.code === 'spawn_failed');
  const overflowing = fakeCli(t, answer);
  fs.appendFileSync(overflowing, "process.stdout.write('x'.repeat(4_100_000));\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(overflowing)),
    error => error instanceof CodexReviewError && error.code === 'cli_output_too_large');
});

test('classifies bounded nonzero-exit diagnostics into fixed safe codes', async t => {
  const cases = [
    ['auth_or_session', 'Authentication failed; secret=PRIVATE_EVIDENCE'],
    ['rate_limited', 'Rate limit exceeded; secret=PRIVATE_EVIDENCE'],
    ['context_too_large', 'Maximum context length exceeded; secret=PRIVATE_EVIDENCE'],
    ['output_token_limit', 'Maximum output tokens exceeded; secret=PRIVATE_EVIDENCE'],
    ['schema_error', 'Invalid output schema; secret=PRIVATE_EVIDENCE'],
    ['parse_error', 'Failed to parse JSON; secret=PRIVATE_EVIDENCE'],
    ['invalid_request', 'Invalid request; secret=PRIVATE_EVIDENCE'],
    ['retry_exhausted', 'Retries exhausted; secret=PRIVATE_EVIDENCE'],
    ['network_connection_reset', 'Upstream connection reset; secret=PRIVATE_EVIDENCE'],
    ['approval_workspace_routing', 'Failed to load workspace requirements; secret=PRIVATE_EVIDENCE'],
    ['policy_rejected', 'Request blocked by the safety policy; secret=PRIVATE_EVIDENCE'],
  ];
  for (const [expected, diagnostic] of cases) {
    const cli = fakeCli(t, answer);
    fs.appendFileSync(cli, `process.stderr.write(${JSON.stringify(diagnostic)}); process.exit(19);\n`);
    await assert.rejects(reviewSubmissionWithCodex(submission, options(cli)), error =>
      error instanceof CodexReviewError && error.code === expected && !JSON.stringify(error).includes('PRIVATE_EVIDENCE'));
  }
  const jsonError = fakeCli(t, answer, { type: 'turn.failed', error: { message: 'context_length_exceeded; https://secret.invalid/12345' } });
  fs.appendFileSync(jsonError, 'process.exit(19);\n');
  await assert.rejects(reviewSubmissionWithCodex(submission, options(jsonError)), error =>
    error.code === 'context_too_large' && !JSON.stringify(error).includes('secret.invalid'));
  const beyondLimit = fakeCli(t, answer);
  fs.appendFileSync(beyondLimit, "process.stderr.write('x'.repeat(70_000) + ' Rate limit exceeded'); process.exit(19);\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(beyondLimit)), error => error.code === 'cli_nonzero_exit');
});

test('nonzero-exit diagnostics summarize only fixed enums and structured error codes', async t => {
  const structured = fakeCli(t, answer, { type: 'turn.failed', error: {
    code: 'context_length_exceeded', message: 'opaque PRIVATE_EVIDENCE', secret_id: 'PRIVATE_EVIDENCE' } });
  fs.appendFileSync(structured, 'process.exit(1);\n');
  await assert.rejects(reviewSubmissionWithCodex(submission, options(structured)), error => {
    assert.equal(error.code, 'context_too_large');
    assert.deepEqual(error.diagnostic, { exit_code: 'one', signal: 'none', stderr_size: 'empty',
      json_error_events: 'turn_failed', json_error_keys: ['error', 'error.code', 'error.message'], hints: ['context_too_large'] });
    assert.doesNotMatch(JSON.stringify(error), /PRIVATE_EVIDENCE|secret_id/);
    return true;
  });
  const killed = fakeCli(t, answer);
  fs.appendFileSync(killed, "process.kill(process.pid, 'SIGTERM');\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(killed)), error =>
    error.code === 'cli_nonzero_exit' && error.diagnostic.exit_code === 'signal' && error.diagnostic.signal === 'term');
  const truncated = fakeCli(t, answer);
  fs.appendFileSync(truncated, "process.stderr.write('x'.repeat(70_000) + ' Rate limit exceeded'); process.exit(1);\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(truncated)), error =>
    error.code === 'cli_nonzero_exit' && error.diagnostic.stderr_size === 'truncated' && error.diagnostic.hints.length === 0);
});

test('classifies JSON upstream errors into fixed network subtypes', async t => {
  const cases = [
    ['network_stream_disconnected', 'stream disconnected before completion'],
    ['network_connection_reset', 'connection reset'],
    ['network_connection_refused', 'connection refused'],
    ['network_connection_timeout', 'connection timed out'],
    ['network_dns', 'DNS resolution failure'],
    ['network_tls', 'TLS handshake failure'],
    ['upstream_gateway_timeout', 'gateway timeout'],
    ['upstream_service_unavailable', 'service unavailable'],
    ['upstream_backend', 'backend error'],
    ['network_error', 'network error'],
    ['upstream_other', 'upstream error'],
  ];
  for (const [expected, message] of cases) {
    const cli = fakeCli(t, answer, { type: 'turn.failed', error: { message: `${message}; PRIVATE_EVIDENCE` } });
    fs.appendFileSync(cli, 'process.exit(1);\n');
    await assert.rejects(reviewSubmissionWithCodex(submission, options(cli)), error =>
      error.code === expected && error.diagnostic.hints.includes(expected) && !JSON.stringify(error).includes('PRIVATE_EVIDENCE'));
  }
});

test('retries bounded CLI failures and discards an earlier result file', async t => {
  const transient = fakeCli(t, answer);
  const transientCount = path.join(path.dirname(transient), 'attempts');
  fs.appendFileSync(transient, `
const countPath = ${JSON.stringify(transientCount)};
const count = Number(fs.existsSync(countPath) ? fs.readFileSync(countPath, 'utf8') : 0) + 1;
fs.writeFileSync(countPath, String(count));
if (count === 1) {
  process.stdout.write(${JSON.stringify(`${JSON.stringify({ type: 'turn.failed', error: { message: 'connection reset; PRIVATE_EVIDENCE' } })}\n`)});
  process.exit(1);
}
`);
  assert.equal((await reviewSubmissionWithCodex(submission, options(transient))).verdict, 'likely');
  assert.equal(fs.readFileSync(transientCount, 'utf8'), '2');

  const persistent = fakeCli(t, answer);
  const persistentCount = path.join(path.dirname(persistent), 'attempts');
  fs.appendFileSync(persistent, `
fs.appendFileSync(${JSON.stringify(persistentCount)}, 'x');
process.stderr.write('Upstream connection reset; PRIVATE_EVIDENCE');
process.exit(1);
`);
  await assert.rejects(reviewSubmissionWithCodex(submission, options(persistent)), error =>
    error.code === 'network_connection_reset' && !JSON.stringify(error).includes('PRIVATE_EVIDENCE'));
  assert.equal(fs.readFileSync(persistentCount, 'utf8'), 'xxx');

  const generic = fakeCli(t, answer);
  const genericCount = path.join(path.dirname(generic), 'attempts');
  fs.appendFileSync(generic, `
fs.appendFileSync(${JSON.stringify(genericCount)}, 'x');
process.exit(1);
`);
  await assert.rejects(reviewSubmissionWithCodex(submission, options(generic)), error => error.code === 'cli_nonzero_exit');
  assert.equal(fs.readFileSync(genericCount, 'utf8'), 'xx');
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

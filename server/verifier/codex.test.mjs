import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CodexReviewError, VerifierUnavailableError, loadTrustedKernelSource, reviewPrimitiveWithCodex, reviewStaticProofWithCodex, reviewSubmissionWithCodex } from './codex.mjs';

const trustedSource = { commit: 'a'.repeat(40), files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [
  { number: 1, text: 'int nfsd4_proc_compound(void) {' },
  { number: 2, text: '  return decode_compound_request();' },
] }] };
const options = cliPath => ({ cliPath, trustedSource });

test('structured-output schemas are valid JSON', () => {
  for (const name of ['codex-output.schema.json', 'codex-proof.schema.json', 'codex-primitive.schema.json']) {
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
  integrity: { verdict: 'clear', reason: 'Original C PoC, source and submitted log agree without test-only modifications.',
    admin_action_required: false, admin_trigger: null },
  proof: {
    entry: { path: 'fs/nfsd/nfs4proc.c', line: 1, explanation: 'Entry point for the request.' },
    flaw: { path: 'fs/nfsd/nfs4proc.c', line: 2, explanation: 'Claimed faulty decode operation.' },
    impact: { path: 'fs/nfsd/nfs4proc.c', line: 2, explanation: 'Claimed effect of that operation.' },
    defenses: { path: 'fs/nfsd/nfs4proc.c', line: 2, explanation: 'Relevant check is claimed inadequate.' },
    poc: { line: 1, explanation: 'Original C trigger line.' },
    log: { index: 2, line: 2, explanation: 'Submitted diagnostic read line.' },
  },
  normalized: {
    title: 'NFSv4 COMPOUND boundary out-of-bounds read',
    report: '## Summary\n경계 검사가 의심됩니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:1 코드에서 검사가 필요합니다.\n```c\nint nfsd4_proc_compound(void) { return 0; }\n```\n\n## Reproduction environment\n제출 환경만 확인했고 2VM 실행 전입니다.\n\n## PoC\nC 프로그램이 경계를 검사합니다.\n\n## Impact analysis\n제출 로그는 KASAN 읽기를 주장하지만 재현 전입니다.',
    file_path: 'fs/nfsd/nfs4proc.c',
    code_refs: ['fs/nfsd/nfs4proc.c:nfsd4_proc_compound'],
    source_evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 1 }, { path: 'fs/nfsd/nfs4proc.c', line: 2 }],
    options: null,
    permission: 'AUTH_SYS',
    nfs_version: '4.2',
    pre_auth: null,
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

test('a short submitted report and basic original C PoC do not fail static normalization', async t => {
  const sparse = { ...submission, report: '입력 경계가 의심됩니다.' };
  const reviewed = await reviewSubmissionWithCodex(sparse, options(fakeCli(t, answer,
    { type: 'turn.completed' }, 0, ['A short report, basic original C PoC',
      'natural Korean 음슴체', 'multiple short fenced C excerpts',
      'Set claimed_impacts to exactly the categories described as observed'])));
  assert.equal(reviewed.verdict, 'likely');
  assert.equal(reviewed.normalized.poc.source, submission.files[1].content);
  assert.match(reviewed.normalized.report, /^## Summary/m);
});

function fakeCli(t, result, event = { type: 'turn.completed' }, delayMs = 0, marker = '<submission>') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-verifier-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cli = path.join(dir, 'fake-codex.mjs');
  const requiredMarkers = Array.isArray(marker) ? marker : [marker];
  const code = `#!/usr/bin/env node
import fs from 'node:fs';
const args = process.argv.slice(2);
let prompt = '';
for await (const chunk of process.stdin) prompt += chunk;
if (!args.includes('--ephemeral') || !args.includes('--ignore-user-config') || !args.includes('--ignore-rules') || !args.includes('shell_tool') || !args.includes('--sandbox') || !args.includes('read-only') || !args.includes('--output-schema') || ${JSON.stringify(requiredMarkers)}.some(marker => !prompt.includes(marker)) || !prompt.includes('<trusted-source>') || prompt.includes('HIGHLY_SENSITIVE')) process.exit(41);
await new Promise(resolve => setTimeout(resolve, ${delayMs}));
fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(result))});
process.stdout.write(${JSON.stringify(`${JSON.stringify(event)}\n`)});
`;
  fs.writeFileSync(cli, code, { mode: 0o700 });
  return cli;
}

test('primitive review stays advisory and grounds each suggested direction in pinned source', async t => {
  const finding = {
    title: 'NFSv4 COMPOUND boundary read', file_path: 'fs/nfsd/nfs4proc.c',
    nfs_version: '4.2', privilege: 'AUTH_SYS', verified_impacts: ['kasan_read'], claimed_impacts: [],
    report: '## Summary\nA bounds read was observed.',
    poc_source: 'int main(void) { return 0; }\n',
    kasan_log: 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n',
  };
  const answer = {
    candidates: [{ primitive: 'controlled_read', source_path: 'fs/nfsd/nfs4proc.c', source_line: 1,
      basis: '길이 인자에 따라 읽는 위치가 달라질 가능성이 있습니다.', missing_evidence: '읽기 주소의 제어 범위를 별도로 확인해야 합니다.' }],
  };
  const cliPath = fakeCli(t, answer, { type: 'turn.completed' }, 0,
    ['<primitive-evidence>', 'Do not suggest a primitive already listed in claimed_impacts']);
  const result = await reviewPrimitiveWithCodex(finding, { cliPath, trustedSource });
  assert.match(result.summary, /Controlled Read 추가 가능성/);
  assert.doesNotMatch(result.summary, /미재현|불명확/);
  assert.match(result.summary, /fs\/nfsd\/nfs4proc\.c:1/);
  assert.equal(result.candidates.length, 1);
  assert.deepEqual(finding.verified_impacts, ['kasan_read']);
  const alreadyClaimed = await reviewPrimitiveWithCodex({ ...finding, claimed_impacts: ['controlled_read'] },
    { cliPath, trustedSource });
  assert.equal(alreadyClaimed.summary, null);
  assert.deepEqual(alreadyClaimed.candidates, []);
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
  assert.deepEqual(result.grounding, { source_commit: trustedSource.commit, evidence: trustedSource.files[0].lines.map(line => ({ path: 'fs/nfsd/nfs4proc.c', line: line.number, text: line.text })) });
  assert.deepEqual(result.proof, answer.proof);
  assert.equal(result.integrity.admin_action_required, false);
  assert.equal(Object.hasOwn(result, 'reproduced'), false);
  assert.equal(Object.hasOwn(result, 'approved'), false);
});

test('likely static proof requires distinct grounded entry and flaw, original PoC and primary log lines', async t => {
  for (const alter of [
    result => { result.proof = null; },
    result => { result.proof.flaw.line = 1; },
    result => { result.proof.defenses.line = 99; },
    result => { result.proof.poc.line = 99; },
    result => { result.proof.log.index = 0; },
    result => { result.proof.log.line = 99; },
  ]) {
    const invalid = structuredClone(answer);
    alter(invalid);
    await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, invalid))),
      error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof');
  }
  const uncertain = structuredClone(answer);
  uncertain.verdict = 'uncertain';
  uncertain.proof = null;
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, uncertain)))).proof, null);
  uncertain.proof = structuredClone(answer.proof);
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, uncertain))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof');
});

test('first static review requires an explicit administrator-action assessment', async t => {
  const ordinarySetup = await reviewSubmissionWithCodex(submission, options(fakeCli(t, answer,
    { type: 'turn.completed' }, 0, 'QEMU VM setup, network namespaces, Soft-RoCE/RDMA device setup')));
  assert.equal(ordinarySetup.integrity.admin_action_required, false);
  for (const value of [undefined, 'false', 0]) {
    const invalid = structuredClone(answer);
    if (value === undefined) delete invalid.integrity.admin_action_required;
    else invalid.integrity.admin_action_required = value;
    await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, invalid))),
      error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'shape');
  }
  const adminSubmission = { ...submission, files: submission.files.map((file, index) => index === 1
    ? { ...file, content: 'int main(void) { return mount("server:/export", "/mnt", "nfs", 0, 0); }\n' } : file) };
  const adminTrigger = structuredClone(answer);
  adminTrigger.verdict = 'unlikely';
  adminTrigger.integrity = { verdict: 'suspect', reason: 'Original C PoC invokes privileged mount() for its trigger.',
    admin_action_required: true, admin_trigger: { file_index: 1, line: 1, operation: 'mount' } };
  adminTrigger.proof = null;
  const rejected = await reviewSubmissionWithCodex(adminSubmission, options(fakeCli(t, adminTrigger)));
  assert.equal(rejected.integrity.admin_action_required, true);
  assert.deepEqual(rejected.integrity.admin_trigger, { file_index: 1, line: 1, operation: 'mount' });
  assert.equal(rejected.verdict, 'unlikely');

  const unknown = structuredClone(answer);
  unknown.verdict = 'uncertain';
  unknown.integrity = { verdict: 'uncertain', reason: 'PoC privilege prerequisite is not shown.',
    admin_action_required: null, admin_trigger: null };
  unknown.proof = null;
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, unknown)))).integrity.admin_action_required, null);

  const invalidApproval = structuredClone(answer);
  invalidApproval.integrity.admin_action_required = true;
  invalidApproval.integrity.admin_trigger = { file_index: 1, line: 1, operation: 'mount' };
  await assert.rejects(reviewSubmissionWithCodex(adminSubmission, options(fakeCli(t, invalidApproval))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'shape');
});

test('both static reviews distinguish a reserved client source port from target administrator action', async t => {
  const reservedPortSubmission = { ...submission,
    metadata: { access_requirements: ['local_privileged'], reproduction_command: 'sudo ./poc' },
    files: submission.files.map((file, index) => index === 1
      ? { ...file, content: 'int main(void) { return connect_reserved(); }\n' } : file)
      .concat({ name: 'run.sh', content: 'sudo ./poc\n' }) };
  const portPolicy = 'client TCP/UDP source port below 1024 is a transport prerequisite';
  const localPrivilegePolicy = 'access_requirements says local_privileged';
  const first = await reviewSubmissionWithCodex(reservedPortSubmission,
    options(fakeCli(t, answer, { type: 'turn.completed' }, 0,
      [portPolicy, localPrivilegePolicy, 'state that client-side port requirement',
        'do not waive any separate privileged mount'])));
  assert.equal(first.integrity.admin_action_required, false);
  const reservedUnknown = structuredClone(answer);
  reservedUnknown.verdict = 'uncertain';
  reservedUnknown.integrity = { verdict: 'clear', reason: 'The only stated root need is the client reserved-port bind.',
    admin_action_required: null, admin_trigger: null };
  reservedUnknown.proof = null;
  const reservedResult = await reviewSubmissionWithCodex(reservedPortSubmission,
    options(fakeCli(t, reservedUnknown)));
  assert.equal(reservedResult.integrity.admin_action_required, false);
  assert.equal(reservedResult.verdict, 'uncertain');
  const ordinaryUnknown = structuredClone(reservedUnknown);
  ordinaryUnknown.integrity.reason = 'The trigger privilege requirement is unresolved.';
  const ordinaryResult = await reviewSubmissionWithCodex(submission,
    options(fakeCli(t, ordinaryUnknown)));
  assert.equal(ordinaryResult.integrity.admin_action_required, null);
  for (const content of [
    'int main(void) { const char *text = "connect_reserved()"; return 0; }\n',
    'int main(void) { /* connect_reserved() */ return 0; }\n',
  ]) {
    const uncalledPort = { ...submission, files: submission.files.map((file, index) => index === 1
      ? { ...file, content } : file) };
    const result = await reviewSubmissionWithCodex(uncalledPort,
      options(fakeCli(t, ordinaryUnknown)));
    assert.equal(result.integrity.admin_action_required, null);
  }
  const checks = { reachability: 'supported', flaw: 'supported', poc: 'supported',
    log: 'supported', defenses: 'supported', admin_action: 'supported' };
  const second = await reviewStaticProofWithCodex(reservedPortSubmission, first,
    options(fakeCli(t, { verdict: 'supports', reason: 'Reserved client port only.', admin_action_required: false,
      admin_trigger: null, checks },
      { type: 'turn.completed' }, 0,
      [portPolicy, localPrivilegePolicy, 'normalized report discloses this client-side requirement',
        'still reject a separate indispensable privileged mount'])));
  assert.equal(second.checks.admin_action, 'supported');

  for (const adminTrigger of [
    { file_index: 1, line: 1, operation: 'connect_reserved' },
    { file_index: 3, line: 1, operation: 'sudo ./poc' },
  ]) {
    const mistakenFirst = structuredClone(answer);
    mistakenFirst.verdict = 'unlikely';
    mistakenFirst.integrity = { verdict: 'suspect',
      reason: 'The client needs sudo only to bind a reserved source port before the NFS request.',
      admin_action_required: true, admin_trigger: adminTrigger };
    mistakenFirst.proof = null;
    await assert.rejects(reviewSubmissionWithCodex(reservedPortSubmission,
      options(fakeCli(t, mistakenFirst))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'admin_trigger');

    const mistakenProof = { verdict: 'refutes',
      reason: 'The client needs sudo only to bind a reserved source port before the NFS request.',
      admin_action_required: true, admin_trigger: adminTrigger,
      checks: { ...checks, admin_action: 'contradicted' } };
    await assert.rejects(reviewStaticProofWithCodex(reservedPortSubmission, first,
      options(fakeCli(t, mistakenProof))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof_review');
  }

  const systemSubmission = { ...reservedPortSubmission,
    files: reservedPortSubmission.files.map((file, index) => index === 1
      ? { ...file, content: 'int main(void) { connect_reserved(); return system("sudo ./poc"); }\n' } : file) };
  const systemFirst = await reviewSubmissionWithCodex(systemSubmission,
    options(fakeCli(t, answer)));
  for (const operation of ['poc', 'system']) {
    const mistakenFirst = structuredClone(answer);
    mistakenFirst.verdict = 'unlikely';
    mistakenFirst.integrity = { verdict: 'suspect',
      reason: 'Only the client reserved source-port bind requires sudo.', admin_action_required: true,
      admin_trigger: { file_index: 1, line: 1, operation } };
    mistakenFirst.proof = null;
    await assert.rejects(reviewSubmissionWithCodex(systemSubmission,
      options(fakeCli(t, mistakenFirst))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'admin_trigger');

    const mistakenProof = { verdict: 'refutes',
      reason: 'Only the client reserved source-port bind requires sudo.', admin_action_required: true,
      admin_trigger: { file_index: 1, line: 1, operation },
      checks: { ...checks, admin_action: 'contradicted' } };
    await assert.rejects(reviewStaticProofWithCodex(systemSubmission, systemFirst,
      options(fakeCli(t, mistakenProof))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof_review');
  }

  for (const [name, submitted, adminTrigger] of [
    ['C string', { ...reservedPortSubmission,
      files: reservedPortSubmission.files.map((file, index) => index === 1
        ? { ...file, content: 'int main(void) { const char *text = "mount(\\"server\\", \\"/mnt\\")"; return connect_reserved(); }\n' } : file) },
    { file_index: 1, line: 1, operation: 'mount' }],
    ['C block comment', { ...reservedPortSubmission,
      files: reservedPortSubmission.files.map((file, index) => index === 1
        ? { ...file, content: 'int main(void) {\n/* mount("server:/export", "/mnt", "nfs", 0, 0); */\nreturn connect_reserved(); }\n' } : file) },
    { file_index: 1, line: 2, operation: 'mount' }],
    ['shell echo', { ...reservedPortSubmission,
      files: reservedPortSubmission.files.map((file, index) => index === 3
        ? { ...file, content: 'echo sudo mount server:/export /mnt\nsudo ./poc\n' } : file) },
    { file_index: 3, line: 1, operation: 'mount' }],
  ]) {
    const firstWithFalseAdmin = await reviewSubmissionWithCodex(submitted,
      options(fakeCli(t, answer)));
    const mistakenFirst = structuredClone(answer);
    mistakenFirst.verdict = 'unlikely';
    mistakenFirst.integrity = { verdict: 'suspect', reason: `${name} is not a privileged trigger.`,
      admin_action_required: true, admin_trigger: adminTrigger };
    mistakenFirst.proof = null;
    await assert.rejects(reviewSubmissionWithCodex(submitted,
      options(fakeCli(t, mistakenFirst))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'admin_trigger');
    const mistakenProof = { verdict: 'refutes', reason: `${name} is not a privileged trigger.`,
      admin_action_required: true, admin_trigger: adminTrigger,
      checks: { ...checks, admin_action: 'contradicted' } };
    await assert.rejects(reviewStaticProofWithCodex(submitted, firstWithFalseAdmin,
      options(fakeCli(t, mistakenProof))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof_review');
  }

  const exportSubmission = { ...reservedPortSubmission,
    files: reservedPortSubmission.files.map((file, index) => index === 3
      ? { ...file, content: 'sudo exportfs -ra\n./poc\n' } : file) };
  const exportFirst = structuredClone(answer);
  exportFirst.verdict = 'unlikely';
  exportFirst.integrity = { verdict: 'suspect', reason: 'The trigger changes the target NFS export with exportfs.',
    admin_action_required: true, admin_trigger: { file_index: 3, line: 1, operation: 'exportfs' } };
  exportFirst.proof = null;
  const confirmedAdmin = await reviewSubmissionWithCodex(exportSubmission,
    options(fakeCli(t, exportFirst)));
  assert.equal(confirmedAdmin.integrity.admin_action_required, true);
  assert.equal(confirmedAdmin.integrity.admin_trigger.operation, 'exportfs');

  const exportProof = { verdict: 'refutes', reason: 'The trigger changes the target NFS export with exportfs.',
    admin_action_required: true, admin_trigger: { file_index: 3, line: 1, operation: 'exportfs' },
    checks: { ...checks, admin_action: 'contradicted' } };
  const exportFirstLikely = await reviewSubmissionWithCodex(exportSubmission,
    options(fakeCli(t, answer)));
  const confirmedProof = await reviewStaticProofWithCodex(exportSubmission, exportFirstLikely,
    options(fakeCli(t, exportProof)));
  assert.equal(confirmedProof.admin_action_required, true);
  assert.equal(confirmedProof.admin_trigger.operation, 'exportfs');
});

test('first review retries twice for malformed administrator anchors before accepting the grounded finding', async t => {
  const labMount = { ...submission,
    report: 'The client is already mounted; victim-init.sh mounts it only to prepare the VM lab.',
    files: submission.files.map((file, index) => index === 1
      ? { ...file, content: 'int main(void) { return bind(3, 0, 0); }\n' } : file)
      .concat({ name: 'victim-init.sh', content: 'mount -t nfs server:/ /mnt\n' }) };
  const malformed = structuredClone(answer);
  malformed.verdict = 'unlikely';
  malformed.integrity = { verdict: 'suspect', reason: 'PRIVATE_EVIDENCE: client bind requires root.',
    admin_action_required: true, admin_trigger: { file_index: 1, line: 1, operation: 'bind' } };
  malformed.proof = null;
  const cli = fakeCli(t, answer);
  const dir = path.dirname(cli);
  fs.appendFileSync(cli, `
const countPath = ${JSON.stringify(path.join(dir, 'admin-attempts'))};
const count = Number(fs.existsSync(countPath) ? fs.readFileSync(countPath, 'utf8') : 0) + 1;
fs.writeFileSync(countPath, String(count));
fs.writeFileSync(${JSON.stringify(path.join(dir, 'admin-prompt-'))} + count, prompt);
if (count < 3) fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(malformed))});
`);
  const reviewed = await reviewSubmissionWithCodex(labMount, options(cli));
  assert.equal(reviewed.verdict, 'likely');
  assert.equal(reviewed.integrity.admin_action_required, false);
  assert.equal(fs.readFileSync(path.join(dir, 'admin-attempts'), 'utf8'), '3');
  const firstPrompt = fs.readFileSync(path.join(dir, 'admin-prompt-1'), 'utf8');
  const finalPrompt = fs.readFileSync(path.join(dir, 'admin-prompt-3'), 'utf8');
  assert.match(firstPrompt, /already-mounted/i);
  assert.match(firstPrompt, /fresh privileged victim mount/i);
  assert.match(finalPrompt, /previous draft failed local validation/i);
  assert.match(finalPrompt, /client.*(?:bind|source.port)/i);
  assert.doesNotMatch(finalPrompt, /PRIVATE_EVIDENCE/);
});

test('independent proof retries a malformed administrator anchor and preserves the lab-mount distinction', async t => {
  const labMount = { ...submission,
    report: 'The client is already mounted; victim-init.sh mounts it only to prepare the VM lab.',
    files: submission.files.map((file, index) => index === 1
      ? { ...file, content: 'int main(void) { return bind(3, 0, 0); }\n' } : file)
      .concat({ name: 'victim-init.sh', content: 'mount -t nfs server:/ /mnt\n' }) };
  const first = await reviewSubmissionWithCodex(labMount, options(fakeCli(t, answer)));
  const checks = { reachability: 'supported', flaw: 'supported', poc: 'supported',
    log: 'supported', defenses: 'supported', admin_action: 'supported' };
  const valid = { verdict: 'supports', reason: 'The only privileged mount prepares an already-mounted lab client.',
    admin_action_required: false, admin_trigger: null, checks };
  const malformed = { verdict: 'refutes', reason: 'PRIVATE_EVIDENCE: client bind requires root.',
    admin_action_required: true, admin_trigger: { file_index: 1, line: 1, operation: 'bind' },
    checks: { ...checks, admin_action: 'contradicted' } };
  const cli = fakeCli(t, valid, { type: 'turn.completed' }, 0, '<first-review>');
  const dir = path.dirname(cli);
  fs.appendFileSync(cli, `
const countPath = ${JSON.stringify(path.join(dir, 'proof-admin-attempts'))};
const count = Number(fs.existsSync(countPath) ? fs.readFileSync(countPath, 'utf8') : 0) + 1;
fs.writeFileSync(countPath, String(count));
fs.writeFileSync(${JSON.stringify(path.join(dir, 'proof-admin-prompt-'))} + count, prompt);
if (count === 1) fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(malformed))});
`);
  const result = await reviewStaticProofWithCodex(labMount, first, options(cli));
  assert.equal(result.verdict, 'supports');
  assert.equal(result.admin_action_required, false);
  assert.equal(fs.readFileSync(path.join(dir, 'proof-admin-attempts'), 'utf8'), '2');
  const firstPrompt = fs.readFileSync(path.join(dir, 'proof-admin-prompt-1'), 'utf8');
  const retryPrompt = fs.readFileSync(path.join(dir, 'proof-admin-prompt-2'), 'utf8');
  assert.match(firstPrompt, /already-mounted/i);
  assert.match(firstPrompt, /fresh privileged victim mount/i);
  assert.match(retryPrompt, /previous draft cited an invalid administrator trigger/i);
  assert.match(retryPrompt, /client.*(?:bind|source.port)/i);
  assert.doesNotMatch(retryPrompt, /PRIVATE_EVIDENCE/);
});

test('independent proof review supports a grounded flaw despite ancillary uncertainty', async t => {
  const first = await reviewSubmissionWithCodex(submission, options(fakeCli(t, answer)));
  const checks = { reachability: 'supported', flaw: 'supported', poc: 'supported',
    log: 'supported', defenses: 'supported', admin_action: 'supported' };
  const confirmed = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t,
    { verdict: 'supports', reason: 'All submitted claims match the shown source.', admin_action_required: false,
      admin_trigger: null, checks },
    { type: 'turn.completed' }, 0, ['<first-review>', 'confirmed artificial trigger is indispensable'])));
  assert.deepEqual(confirmed, { verdict: 'supports', reason: 'All submitted claims match the shown source.',
    admin_action_required: false, admin_trigger: null, checks });
  const ordinarySetup = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t,
    { verdict: 'supports', reason: 'Existing export is target setup, not a trigger privilege.',
      admin_action_required: false, admin_trigger: null, checks },
    { type: 'turn.completed' }, 0, 'QEMU VM preparation, network namespaces, Soft-RoCE/RDMA device setup')));
  assert.equal(ordinarySetup.admin_action_required, false);
  const ancillaryUncertainty = { verdict: 'supports', reason: 'Faulty operation is visible; other limits remain.',
    admin_action_required: false, admin_trigger: null,
    checks: { ...checks, reachability: 'uncertain', log: 'uncertain', defenses: 'uncertain' } };
  const limited = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t, ancillaryUncertainty,
    { type: 'turn.completed' }, 0, '<first-review>')));
  assert.equal(limited.verdict, 'supports');
  assert.equal(limited.checks.defenses, 'uncertain');
  const limitedFlaw = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t,
    { ...ancillaryUncertainty, checks: { ...ancillaryUncertainty.checks, flaw: 'uncertain' } },
    { type: 'turn.completed' }, 0, 'A short report')));
  assert.equal(limitedFlaw.checks.flaw, 'uncertain');
  const uncertain = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t,
    { verdict: 'uncertain', reason: 'Missing guard context.', admin_action_required: false,
      admin_trigger: null, checks: ancillaryUncertainty.checks },
    { type: 'turn.completed' }, 0, '<first-review>')));
  assert.equal(uncertain.verdict, 'uncertain');
  const mountSubmission = { ...submission, files: submission.files.map((file, index) => index === 1
    ? { ...file, content: 'int main(void) { return mount("server:/export", "/mnt", "nfs", 0, 0); }\n' } : file) };
  const mountFirst = await reviewSubmissionWithCodex(mountSubmission, options(fakeCli(t, answer)));
  const requiresAdmin = await reviewStaticProofWithCodex(mountSubmission, mountFirst, options(fakeCli(t,
    { verdict: 'refutes', reason: 'Original C PoC invokes privileged mount() for its trigger.',
      admin_action_required: true, admin_trigger: { file_index: 1, line: 1, operation: 'mount' },
      checks: { ...checks, admin_action: 'contradicted' } },
    { type: 'turn.completed' }, 0, '<first-review>')));
  assert.equal(requiresAdmin.admin_action_required, true);
  assert.equal(requiresAdmin.admin_trigger.operation, 'mount');
  assert.equal(requiresAdmin.checks.admin_action, 'contradicted');
  const unknownPrivilege = await reviewStaticProofWithCodex(submission, first, options(fakeCli(t,
    { verdict: 'uncertain', reason: 'Privilege prerequisite is missing.', admin_action_required: null,
      admin_trigger: null, checks: { ...checks, admin_action: 'uncertain' } },
    { type: 'turn.completed' }, 0, '<first-review>')));
  assert.equal(unknownPrivilege.admin_action_required, null);
  for (const invalid of [
    { verdict: 'supports', reason: 'Admin trigger.', admin_action_required: true,
      admin_trigger: { file_index: 1, line: 1, operation: 'mount' },
      checks: { ...checks, admin_action: 'contradicted' } },
    { verdict: 'supports', reason: 'Missing assessment.', admin_action_required: false,
      admin_trigger: null, checks: { ...checks, admin_action: 'uncertain' } },
    { verdict: 'supports', reason: 'Missing flag.', admin_trigger: null, checks },
    { verdict: 'supports', reason: 'A guard defeats the flaw.', admin_action_required: false,
      admin_trigger: null, checks: { ...checks, defenses: 'contradicted' } },
  ]) {
    await assert.rejects(reviewStaticProofWithCodex(submission, first, options(fakeCli(t, invalid,
      { type: 'turn.completed' }, 0, '<first-review>'))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'proof_review');
  }
  await assert.rejects(reviewStaticProofWithCodex(submission, { ...first, proof: null }, options(fakeCli(t, confirmed))),
    error => error.code === 'invalid_proof_input');
});

test('fills omitted C PoC command hints and requires a C PoC for a likely verdict', async t => {
  const cAnswer = structuredClone(answer);
  cAnswer.normalized.build_command = null;
  cAnswer.normalized.run_command = null;
  const cReview = await reviewSubmissionWithCodex({ ...submission, metadata: { reproduction_command: 'cc candidate.c && ./a.out' } }, options(fakeCli(t, cAnswer)));
  assert.equal(cReview.verdict, 'likely');
  assert.deepEqual([cReview.normalized.poc.source_index, cReview.normalized.poc.source, cReview.normalized.poc.build_command, cReview.normalized.poc.run_command],
    [1, submission.files[1].content, 'cc -o poc poc.c', null]);

  const pythonOnly = { ...submission, files: [submission.files[0], submission.files[2]] };
  const pythonAnswer = structuredClone(answer);
  Object.assign(pythonAnswer.normalized, { poc_file_index: 0, poc_language: 'python', build_command: null, run_command: null, log_file_indexes: [1] });
  await assert.rejects(reviewSubmissionWithCodex(pythonOnly, options(fakeCli(t, pythonAnswer))), error => error.code === 'invalid_output');
  const missingPoc = structuredClone(answer);
  Object.assign(missingPoc.normalized, { poc_file_index: null, poc_language: null, build_command: null, run_command: null, log_file_indexes: [1] });
  await assert.rejects(reviewSubmissionWithCodex(pythonOnly, options(fakeCli(t, missingPoc))), error => error.code === 'ungrounded_output');
});

test('canonicalizes common permission and NFS version aliases, leaving ambiguous versions unknown', async t => {
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
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, ambiguous)))).normalized.nfs_version,
    null);
  const unstructured = structuredClone(answer);
  unstructured.normalized.report = '## Summary\nOnly one section.';
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, unstructured))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'report_format');
});

test('normalizes a grounded access-control bypass without changing its authentication requirement', async t => {
  const bypass = structuredClone(answer);
  bypass.normalized.vulnerability_type = 'Access Control Bypass';
  const reviewed = await reviewSubmissionWithCodex(submission, options(fakeCli(t, bypass)));
  assert.equal(reviewed.normalized.vulnerability_type, 'Authorization Bypass');
  assert.equal(reviewed.normalized.permission, 'AUTH_SYS');
});

test('keeps build settings and concise NFS features out of option prose', async t => {
  const build = structuredClone(answer);
  build.normalized.options = 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y, CONFIG_SUNRPC_XPRT_RDMA=y; iWARP listener on TCP port 20049';
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, build)))).normalized.options,
    'CONFIG_NFSD=y, CONFIG_NFSD_V4=y, CONFIG_SUNRPC_XPRT_RDMA=y');
  for (const feature of ['pNFS SCSI', 'LOCALIO', 'RPCSEC_GSS/Kerberos', 'RPC/RDMA', 'NFSv4.2 xattr', 'pNFS DS']) {
    const named = structuredClone(answer);
    named.normalized.options = feature;
    assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, named)))).normalized.options, feature);
  }
  const prose = structuredClone(answer);
  prose.normalized.options = 'KNFSD iWARP listener on TCP port 20049; max_block_size=1048576';
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, prose)))).normalized.options, null);
  const fullBuild = structuredClone(answer);
  fullBuild.normalized.options = Array.from({ length: 25 }, (_, index) =>
    `CONFIG_NFSD_FEATURE_${index}=y`).join(', ');
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, fullBuild)))).normalized.options,
    fullBuild.normalized.options);
  const oversized = structuredClone(answer);
  oversized.normalized.options = 'CONFIG_NFSD_FEATURE=y, '.repeat(200);
  assert.equal((await reviewSubmissionWithCodex(submission, options(fakeCli(t, oversized)))).normalized.options,
    null);
});

test('identifies invalid output stage without retaining model text', async t => {
  const extra = structuredClone(answer);
  extra.normalized.extra = 'PRIVATE_EVIDENCE';
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, extra))), error => {
    assert.equal(error.code, 'invalid_output');
    assert.deepEqual(error.diagnostic, { validation_stage: 'shape' });
    assert.doesNotMatch(JSON.stringify(error), /PRIVATE_EVIDENCE/);
    return true;
  });
  const malformed = fakeCli(t, answer);
  fs.appendFileSync(malformed, "fs.writeFileSync(args[args.indexOf('-o') + 1], '{');\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(malformed)),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'json_parse');
});

test('retries a malformed or ungrounded static review once without promoting the first result', async t => {
  const malformed = structuredClone(answer);
  malformed.normalized.extra = 'PRIVATE_EVIDENCE';
  const ungrounded = structuredClone(answer);
  ungrounded.normalized.source_evidence[0].line = 99;
  for (const firstResult of [malformed, ungrounded, '{']) {
    const cli = fakeCli(t, answer);
    const countPath = path.join(path.dirname(cli), 'attempts');
    fs.appendFileSync(cli, `
const countPath = ${JSON.stringify(countPath)};
const count = Number(fs.existsSync(countPath) ? fs.readFileSync(countPath, 'utf8') : 0) + 1;
fs.writeFileSync(countPath, String(count));
if (count === 1) fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(typeof firstResult === 'string' ? firstResult : JSON.stringify(firstResult))});
`);
    const review = await reviewSubmissionWithCodex(submission, options(cli));
    assert.equal(review.verdict, 'likely');
    assert.equal(fs.readFileSync(countPath, 'utf8'), '2');
  }
});

test('persistent invalid output fails closed after two calls; CLI turn errors are not retried', async t => {
  const invalid = structuredClone(answer);
  invalid.normalized.extra = 'PRIVATE_EVIDENCE';
  for (const [event, expectedCount, expectedCode] of [
    [{ type: 'turn.completed' }, '2', 'invalid_output'],
    [{ type: 'turn.failed' }, '1', 'turn_failed'],
  ]) {
    const cli = fakeCli(t, invalid, event);
    const countPath = path.join(path.dirname(cli), 'attempts');
    fs.appendFileSync(cli, `fs.appendFileSync(${JSON.stringify(countPath)}, 'x');\n`);
    await assert.rejects(reviewSubmissionWithCodex(submission, options(cli)), error =>
      error.code === expectedCode && !JSON.stringify(error).includes('PRIVATE_EVIDENCE'));
    assert.equal(fs.readFileSync(countPath, 'utf8'), 'x'.repeat(Number(expectedCount)));
  }
});

test('pre-auth review requires grounded source and original C PoC lines without a fabricated NFS version', async t => {
  const direct = structuredClone(answer);
  direct.normalized.nfs_version = null;
  direct.normalized.permission = 'Pre-auth';
  direct.normalized.pre_auth = { source_path: 'fs/nfsd/nfs4proc.c', source_line: 1, poc_line: 1 };
  const reviewed = await reviewSubmissionWithCodex(submission, options(fakeCli(t, direct)));
  assert.equal(reviewed.normalized.nfs_version, null);
  assert.deepEqual(reviewed.normalized.pre_auth, direct.normalized.pre_auth);
  for (const change of [
    result => { result.normalized.pre_auth.source_line = 99; },
    result => { result.normalized.pre_auth.poc_line = 9; },
    result => { result.normalized.nfs_version = '4.2'; },
  ]) {
    const invalid = structuredClone(direct);
    change(invalid);
    await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, invalid))),
      error => error.code === 'ungrounded_output');
  }
});

test('pre-auth validation retry gives a bounded correction without echoing the rejected draft', async t => {
  const corrected = structuredClone(answer);
  corrected.normalized.nfs_version = null;
  corrected.normalized.permission = 'Pre-auth';
  corrected.normalized.pre_auth = { source_path: 'fs/nfsd/nfs4proc.c', source_line: 1, poc_line: 1 };
  const invalid = structuredClone(corrected);
  invalid.reason = 'PRIVATE_EVIDENCE';
  invalid.normalized.pre_auth.source_line = 99;
  invalid.normalized.nfs_version = '4.2';
  const cli = fakeCli(t, corrected);
  const dir = path.dirname(cli);
  fs.appendFileSync(cli, `
const countPath = ${JSON.stringify(path.join(dir, 'attempts'))};
const count = Number(fs.existsSync(countPath) ? fs.readFileSync(countPath, 'utf8') : 0) + 1;
fs.writeFileSync(countPath, String(count));
fs.writeFileSync(${JSON.stringify(path.join(dir, 'prompt-'))} + count, prompt);
if (count === 1) fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(invalid))});
`);
  const reviewed = await reviewSubmissionWithCodex(submission, options(cli));
  assert.equal(reviewed.verdict, 'likely');
  assert.deepEqual(reviewed.normalized.pre_auth, corrected.normalized.pre_auth);
  assert.equal(fs.readFileSync(path.join(dir, 'attempts'), 'utf8'), '2');
  const firstPrompt = fs.readFileSync(path.join(dir, 'prompt-1'), 'utf8');
  const retryPrompt = fs.readFileSync(path.join(dir, 'prompt-2'), 'utf8');
  assert.doesNotMatch(firstPrompt, /previous draft failed local validation/i);
  assert.match(retryPrompt, /pre_auth claim requires source_path and source_line exactly in trusted source_evidence, poc_line in the original C PoC, and nfs_version=null/);
  assert.match(retryPrompt, /set pre_auth=null and assess the narrower base flaw on its own/);
  assert.doesNotMatch(retryPrompt, /PRIVATE_EVIDENCE/);
});

test('likely reports must quote a grounded primary-path source line and retain code references', async t => {
  const unquoted = structuredClone(answer);
  unquoted.normalized.report = unquoted.normalized.report.replace('int nfsd4_proc_compound(void) {', 'int unrelated(void) {');
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, unquoted))),
    error => error.code === 'ungrounded_output' && error.diagnostic?.validation_stage === 'report_source');
  const noRefs = structuredClone(answer);
  noRefs.normalized.code_refs = [];
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, noRefs))),
    error => error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'source_refs');
});

test('fails closed when CLI is missing or submitted paths are unsafe', async () => {
  await assert.rejects(reviewSubmissionWithCodex(submission, options('')), error => error instanceof VerifierUnavailableError && error.code === 'not_configured');
  await assert.rejects(reviewSubmissionWithCodex(submission, { cliPath: '/missing/codex' }), error => error instanceof CodexReviewError && error.code === 'trusted_source_missing');
  await assert.rejects(reviewSubmissionWithCodex({ ...submission, files: [{ name: '../secret', content: 'x' }] }, options('/missing/codex')), error => error instanceof CodexReviewError && error.code === 'invalid_submission');
});

test('rejects unsupported Python selection when a C PoC exists and invalid model indexes', async t => {
  const wrongLanguage = structuredClone(answer);
  Object.assign(wrongLanguage.normalized, { poc_file_index: 0, poc_language: 'python', build_command: null, run_command: 'python3 poc.py' });
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, wrongLanguage))),
    error => error instanceof CodexReviewError && error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'poc');
  const wrongIndex = structuredClone(answer);
  wrongIndex.normalized.log_file_indexes = [99];
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, wrongIndex))),
    error => error instanceof CodexReviewError && error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'logs');
});

test('gives malformed log selections one more bounded correction attempt', async t => {
  const wrongIndex = structuredClone(answer);
  wrongIndex.normalized.log_file_indexes = [99];
  const cli = fakeCli(t, answer);
  const dir = path.dirname(cli);
  const attempts = path.join(dir, 'attempts');
  fs.appendFileSync(cli, `
const count = Number(fs.existsSync(${JSON.stringify(attempts)}) ? fs.readFileSync(${JSON.stringify(attempts)}, 'utf8') : 0) + 1;
fs.writeFileSync(${JSON.stringify(attempts)}, String(count));
if (count < 3) fs.writeFileSync(args[args.indexOf('-o') + 1], ${JSON.stringify(JSON.stringify(wrongIndex))});
`);
  assert.equal((await reviewSubmissionWithCodex(submission, options(cli))).verdict, 'likely');
  assert.equal(fs.readFileSync(attempts, 'utf8'), '3');

  const noKasanEvent = { ...submission, files: [
    ...submission.files.slice(0, 2), { name: 'serial.log', content: 'Linux KASAN kernel booted\nNo sanitizer event\n' },
  ] };
  await assert.rejects(reviewSubmissionWithCodex(noKasanEvent, options(fakeCli(t, answer))),
    error => error instanceof CodexReviewError && error.code === 'invalid_output' && error.diagnostic?.validation_stage === 'logs');
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
    error => process.platform === 'win32' ? error instanceof VerifierUnavailableError :
      error instanceof CodexReviewError && error.code === 'spawn_failed');
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
    error.code === 'cli_nonzero_exit' && (process.platform === 'win32' ||
      error.diagnostic.exit_code === 'signal' && error.diagnostic.signal === 'term'));
  const truncated = fakeCli(t, answer);
  fs.appendFileSync(truncated, "process.stderr.write('x'.repeat(70_000) + ' Rate limit exceeded'); process.exit(1);\n");
  await assert.rejects(reviewSubmissionWithCodex(submission, options(truncated)), error =>
    error.code === 'cli_nonzero_exit' && error.diagnostic.stderr_size === 'truncated' && error.diagnostic.hints.length === 0);
});

test('final failed turn determines the cause ahead of earlier error events', async t => {
  const earlierRateLimit = { type: 'error', message: 'Rate limit exceeded; PRIVATE_EVIDENCE' };
  const finalContextError = { type: 'turn.failed', error: { code: 'context_length_exceeded', message: 'Prompt too long after a rate limit retry' } };
  const cli = fakeCli(t, answer, earlierRateLimit);
  fs.appendFileSync(cli, `process.stdout.write(${JSON.stringify(`${JSON.stringify(finalContextError)}\n`)}); process.exitCode = 19;\n`);
  await assert.rejects(reviewSubmissionWithCodex(submission, options(cli)), error =>
    error.code === 'context_too_large' && error.diagnostic.hints.includes('rate_limited') &&
    !JSON.stringify(error).includes('PRIVATE_EVIDENCE'));

  const unknownFinal = fakeCli(t, answer, earlierRateLimit);
  fs.appendFileSync(unknownFinal, `process.stdout.write(${JSON.stringify(`${JSON.stringify({ type: 'turn.failed', error: { message: 'Turn failed' } })}\n`)}); process.exitCode = 19;\n`);
  await assert.rejects(reviewSubmissionWithCodex(submission, options(unknownFinal)), error =>
    error.code === 'cli_nonzero_exit' && error.diagnostic.hints.includes('rate_limited'));
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

test('keeps distant cited source lines within the 400-line excerpt budget', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-kernel-windows-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'fs/nfsd'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'fs/nfsd/nfs4proc.c'),
    Array.from({ length: 1100 }, (_, index) => `int line_${index + 1};`).join('\n'));
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const name = 'fs/nfsd/nfs4proc.c';
  const cited = [50, 250, 550, 900];
  const source = await loadTrustedKernelSource(dir, commit,
    { report: cited.map(line => `${name}:${line}`).join('\n') });
  const excerpt = source.files[0];
  const selected = new Set(excerpt.lines.map(line => line.number));
  assert.equal(excerpt.total_lines, 1100);
  assert.equal(excerpt.excerpted, true);
  assert.ok(excerpt.lines.length <= 400);
  for (const line of cited) {
    assert.ok(selected.has(line), `missing cited line ${line}`);
    assert.ok(selected.has(line - 1), `missing context for cited line ${line}`);
  }
});

test('keeps both ends of cited source ranges amid competing references', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-kernel-ranges-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const siw = 'drivers/infiniband/sw/siw/siw_cm.c';
  const recv = 'net/sunrpc/xprtrdma/svc_rdma_recvfrom.c';
  for (const name of [siw, recv]) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Array.from({ length: 1800 }, (_, index) => `int line_${index + 1};`).join('\n'));
  }
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const source = await loadTrustedKernelSource(dir, commit, { metadata: { code_refs: [
    `${siw}:383-408`, `${siw}:563-753`, `${siw}:653`,
    `${recv}:321`, `${recv}:944-1027`, `${recv}:1600`,
  ] } });
  for (const [name, required] of [[siw, [383, 408, 563, 658, 750, 753]],
    [recv, [321, 944, 985, 1026, 1027, 1600]]]) {
    const excerpt = source.files.find(file => file.path === name);
    assert.ok(excerpt, `missing ${name}`);
    assert.ok(excerpt.lines.length <= 400);
    const selected = new Set(excerpt.lines.map(line => line.number));
    for (const line of required) assert.ok(selected.has(line), `missing ${name}:${line}`);
  }
});

test('keeps comma-separated and same-file ranges from a report within the source budget', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-kernel-report-citations-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const transport = 'net/sunrpc/xprtrdma/svc_rdma_transport.c';
  const driver = 'drivers/infiniband/core/iwcm.c';
  for (const name of [transport, driver]) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Array.from({ length: 1100 }, (_, index) => `int line_${index + 1};`).join('\n'));
  }
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const report = `${transport}:316-326,257-271 and (같은 파일:223-230). ` +
    `${transport}:316-326,120-126 and (same file:900-905). ` +
    `${driver}:50 (같은 파일:700-705).`;
  const source = await loadTrustedKernelSource(dir, commit, { report });
  const transportLines = new Set(source.files.find(file => file.path === transport).lines.map(line => line.number));
  const driverLines = new Set(source.files.find(file => file.path === driver).lines.map(line => line.number));
  assert.ok(source.files.every(file => file.lines.length <= 400));
  for (const line of [120, 126, 223, 230, 257, 271, 316, 326, 900, 905]) {
    assert.ok(transportLines.has(line), `missing ${transport}:${line}`);
  }
  for (const line of [50, 700, 705]) assert.ok(driverLines.has(line), `missing ${driver}:${line}`);
  assert.equal(transportLines.has(700), false);
});

test('loads pinned NFS and RDMA driver files across a multi-file call path', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-rdma-source-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const paths = [
    'fs/nfsd/nfs4proc.c',
    'net/sunrpc/xprtrdma/svc_rdma_recvfrom.c',
    'net/sunrpc/xprtrdma/svc_rdma_rw.c',
    'drivers/infiniband/sw/siw/siw_cm.c',
    'drivers/infiniband/core/iwcm.c',
    'drivers/infiniband/core/cma.c',
    'include/rdma/ib_verbs.h',
  ];
  for (const name of paths) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, 'int entry(void) { return 0; }\nint flaw(void) { return 1; }\n');
  }
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const source = await loadTrustedKernelSource(dir, commit,
    { report: paths.map(name => `${name}:2`).join('\n') + '\ndrivers/net/other.c:2' });
  assert.deepEqual(source.files.map(file => file.path), paths);
  const driver = paths[3];
  const response = structuredClone(answer);
  response.normalized.file_path = driver;
  response.normalized.code_refs = [`${driver}:2`];
  response.normalized.source_evidence = [{ path: driver, line: 1 }, { path: driver, line: 2 }];
  for (const role of ['entry', 'flaw', 'impact', 'defenses']) response.proof[role].path = driver;
  response.normalized.report = response.normalized.report.replaceAll('fs/nfsd/nfs4proc.c', driver)
    .replace('int nfsd4_proc_compound(void) { return 0; }', 'int entry(void) { return 0; }');
  const reviewed = await reviewSubmissionWithCodex(submission,
    { cliPath: fakeCli(t, response), trustedSource: source });
  assert.equal(reviewed.normalized.file_path, driver);
  assert.equal(reviewed.grounding.evidence[1].text, 'int flaw(void) { return 1; }');
});

test('keeps a later root-cause source citation when more than eight files are referenced', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-root-cause-priority-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const entry = 'net/sunrpc/xprtrdma/svc_rdma_transport.c';
  const earlier = Array.from({ length: 8 }, (_, index) => `net/sunrpc/xprtrdma/helper_${index + 1}.c`);
  const flaw = 'net/sunrpc/xprtrdma/svc_rdma_rw.c';
  for (const name of [entry, ...earlier, flaw]) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, name === flaw
      ? Array.from({ length: 600 }, (_, index) => `int source_line_${index + 1};`).join('\n')
      : 'int entry(void) { return 0; }\n');
  }
  const run = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  run('init', '-q');
  run('config', 'user.name', 'Test');
  run('config', 'user.email', 'test@example.invalid');
  run('add', '.');
  run('commit', '-qm', 'fixture');
  const commit = run('rev-parse', 'HEAD');
  const source = await loadTrustedKernelSource(dir, commit, {
    metadata: { file_path: `${entry}:1`, code_refs: earlier.map(name => `${name}:1`) },
    report: `## Root cause\nThe faulty operation is at ${flaw}:512.`,
  });
  assert.ok(source.files.length <= 8);
  assert.ok(source.files.some(file => file.path === entry));
  const excerpt = source.files.find(file => file.path === flaw);
  assert.ok(excerpt, `missing root-cause file ${flaw}`);
  assert.deepEqual(excerpt.lines.find(line => line.number === 512),
    { number: 512, text: 'int source_line_512;' });
});

test('static likely verdict cannot cite a source line that is absent from the trusted checkout', async t => {
  const ungrounded = structuredClone(answer);
  ungrounded.normalized.source_evidence[0].line = 99;
  await assert.rejects(reviewSubmissionWithCodex(submission, options(fakeCli(t, ungrounded))),
    error => error.code === 'ungrounded_output' &&
      error.diagnostic?.validation_stage === 'source_evidence' &&
      Object.keys(error.diagnostic).length === 1);
});

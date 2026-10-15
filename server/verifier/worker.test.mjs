import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CodexReviewError } from './codex.mjs';
import { processSubmissionJob, runWorkerOnce, stableWorkerId } from './worker.mjs';

const commit = 'a'.repeat(40);
const stableCommit = 'b'.repeat(40);
const entryLine = 'int nfsd4_proc_compound(const char *buffer, unsigned int count) {';
const line = 'if (count > available) return -EINVAL;';
const poc = 'int main(void) { return 0; }\n';
const log = 'BUG: KASAN: submitted only\nRead of size 4\n';
const report = `## Summary\n길이 검사 후보입니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:42\n\`\`\`c\n${line}\n\`\`\`\n\n## Reproduction environment\n제출 환경입니다.\n\n## PoC\n원본 C 요청입니다.\n\n## Impact analysis\n제출 로그의 주장입니다.`;
const job = { submission_id: 'c'.repeat(64), lease_token: 'd'.repeat(64), project: 'knfsd',
  title: 'Candidate', metadata: { repo_commit: commit, version_id: 'rc' }, report,
  files: [
    { name: 'original.c', kind: 'poc', content_base64: Buffer.from(poc).toString('base64') },
    { name: 'original.log', kind: 'log', content_base64: Buffer.from(log).toString('base64') },
  ] };
const trustedSource = { commit, files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [{ number: 41, text: entryLine }, { number: 42, text: line }] }] };
const sourceProof = { path: 'fs/nfsd/nfs4proc.c', line: 42, explanation: 'This source line is part of the alleged request path.' };
const proof = { entry: { path: 'fs/nfsd/nfs4proc.c', line: 41,
  explanation: 'This source entry point receives the input from the caller.' },
  flaw: sourceProof, impact: sourceProof, defenses: sourceProof,
  poc: { line: 1, explanation: 'This original C line constructs the submitted request.' },
  log: { index: 1, line: 1, explanation: 'This submitted trace names the claimed failure.' } };
const proofReviewer = async () => ({ verdict: 'supports', admin_action_required: false,
  reason: 'All six static links withstand independent review',
  checks: { reachability: 'supported', flaw: 'supported', poc: 'supported', log: 'supported',
    defenses: 'supported', admin_action: 'supported' } });
const reviewer = async () => ({ verdict: 'likely', integrity: { verdict: 'clear', admin_action_required: false,
  reason: 'No artificial conditions' },
  reason: 'Plausible static candidate', model: 'test',
  proof,
  grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 42, text: line },
    { path: 'fs/nfsd/nfs4proc.c', line: 41, text: entryLine }] },
  normalized: { title: 'NFS request length error', report, file_path: 'fs/nfsd/nfs4proc.c',
    code_refs: ['fs/nfsd/nfs4proc.c:42'], nfs_version: '4.2', permission: 'AUTH_SYS',
    vulnerability_type: 'OOB Read',
    poc: { filename: 'poc.c', original_name: 'original.c', source_index: 0, source: poc, language: 'c' },
    logs: [{ filename: 'evidence-1.log', original_name: 'original.log', source_index: 1, content: log }] } });

function config(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-static-worker-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { socketPath: path.join(dir, 'worker.sock'), cliPath: '/usr/bin/codex', workRoot: dir,
    sourceTargets: { [commit]: '/trusted/rc', [stableCommit]: '/trusted/stable' } };
}

test('worker identity is stable per instance rather than pinned to an RC or stable commit', t => {
  const first = config(t);
  assert.equal(stableWorkerId(first, 'host'), stableWorkerId({ ...first }, 'host'));
  assert.notEqual(stableWorkerId(first, 'host'), stableWorkerId({ ...first, workRoot: '/other' }, 'host'));
});

test('ungrounded model output reports only a safe validation stage', async t => {
  const result = await processSubmissionJob(job, { config: config(t), sourceLoader: async () => trustedSource,
    reviewer: async () => { throw new CodexReviewError('ungrounded_output',
      { validation_stage: 'source_evidence', private_text: 'do not expose this PoC' }); } });
  assert.equal(result.review.reason, 'ungrounded_output {"validation_stage":"source_evidence"}');
  assert.doesNotMatch(result.review.reason, /private_text|PoC/);
});

test('static screening preserves original C/log and never invokes a VM', async t => {
  const phases = [];
  const result = await processSubmissionJob(job, { config: config(t), reviewer, proofReviewer,
    sourceLoader: async (directory, requested) => {
      assert.equal(directory, '/trusted/rc'); assert.equal(requested, commit); return trustedSource;
    }, onPhase: phase => phases.push(phase) });
  assert.equal(result.review.verdict, 'likely');
  assert.equal(result.review.proof_review.verdict, 'supports');
  assert.equal(result.reproduction.status, 'not_run');
  assert.deepEqual(phases, ['static_review']);
  assert.equal(result.artifacts.poc.source, poc);
  assert.equal(result.artifacts.log.content, log);
  assert.doesNotMatch(result.artifacts.report.content, /서버 VM에서.*관찰/);
});

test('grounded base flaw proceeds despite uncertain reachability or defenses when PoC and log are supported', async t => {
  const result = await processSubmissionJob(job, { config: config(t), reviewer,
    sourceLoader: async () => trustedSource,
    proofReviewer: async () => ({ ...await proofReviewer(),
      verdict: 'uncertain', reason: 'The core claim is supported; ancillary source paths remain unresolved.',
      checks: { reachability: 'uncertain', flaw: 'supported', poc: 'supported',
        log: 'supported', defenses: 'uncertain', admin_action: 'supported' } }) });
  assert.equal(result.review.verdict, 'likely');
  assert.equal(result.artifacts.log.content, log);
});

test('independent core uncertainty or concrete contradiction still holds approval', async t => {
  for (const [verdict, checks] of [
    ['uncertain', { reachability: 'supported', flaw: 'uncertain', poc: 'supported', log: 'supported',
      defenses: 'supported', admin_action: 'supported' }],
    ['uncertain', { reachability: 'supported', flaw: 'supported', poc: 'uncertain', log: 'supported',
      defenses: 'supported', admin_action: 'supported' }],
    ['uncertain', { reachability: 'supported', flaw: 'supported', poc: 'supported', log: 'uncertain',
      defenses: 'supported', admin_action: 'supported' }],
    ['refutes', { reachability: 'supported', flaw: 'supported', poc: 'supported', log: 'supported',
      defenses: 'supported', admin_action: 'supported' }],
    ['refutes', { reachability: 'contradicted', flaw: 'supported', poc: 'supported', log: 'supported',
      defenses: 'supported', admin_action: 'supported' }],
  ]) {
    const result = await processSubmissionJob(job, { config: config(t), reviewer,
      sourceLoader: async () => trustedSource,
      proofReviewer: async () => ({ ...await proofReviewer(), verdict, checks }) });
    assert.equal(result.review.verdict, 'uncertain');
    assert.equal(result.artifacts, undefined);
  }
});

test('suspicious shortcut is never promoted even if source path is plausible', async t => {
  const result = await processSubmissionJob(job, { config: config(t), sourceLoader: async () => trustedSource,
    proofReviewer, reviewer: async () => ({ ...await reviewer(), integrity: { verdict: 'suspect', reason: 'Injected kernel delay' } }) });
  assert.equal(result.review.integrity.verdict, 'suspect');
  assert.equal(result.artifacts, undefined);
});

test('administrator prerequisites stop before artifacts, including when found by the independent reviewer', async t => {
  const cfg = config(t);
  const sourceLoader = async () => trustedSource;
  const primary = await processSubmissionJob(job, { config: cfg, sourceLoader,
    reviewer: async () => ({ ...await reviewer(), integrity: { verdict: 'suspect',
      admin_action_required: true, reason: 'Original trigger requires sudo mount' } }),
    proofReviewer: async () => { throw new Error('independent review should not run'); } });
  assert.equal(primary.review.integrity.admin_action_required, true);
  assert.equal(primary.artifacts, undefined);
  const secondary = await processSubmissionJob(job, { config: cfg, sourceLoader, reviewer,
    proofReviewer: async () => ({ ...await proofReviewer(), verdict: 'refutes',
      admin_action_required: true, reason: 'Original trigger requires sudo mount',
      checks: { ...(await proofReviewer()).checks, admin_action: 'contradicted' } }) });
  assert.equal(secondary.review.integrity.verdict, 'suspect');
  assert.equal(secondary.review.integrity.admin_action_required, true);
  assert.equal(secondary.artifacts, undefined);
});

test('unresolved administrator prerequisite holds the submission', async t => {
  const cfg = config(t);
  const sourceLoader = async () => trustedSource;
  const primary = await processSubmissionJob(job, { config: cfg, sourceLoader,
    reviewer: async () => ({ ...await reviewer(), integrity: { verdict: 'uncertain',
      admin_action_required: null, reason: 'PoC privilege is not stated' } }), proofReviewer });
  assert.equal(primary.artifacts, undefined);
  const secondary = await processSubmissionJob(job, { config: cfg, sourceLoader, reviewer,
    proofReviewer: async () => ({ ...await proofReviewer(), verdict: 'uncertain',
      admin_action_required: null, reason: 'PoC privilege is not stated',
      checks: { ...(await proofReviewer()).checks, admin_action: 'uncertain' } }) });
  assert.equal(secondary.review.verdict, 'uncertain');
  assert.equal(secondary.artifacts, undefined);
});

test('missing proof or independent contradiction prevents canonical promotion', async t => {
  const cfg = config(t);
  const sourceLoader = async () => trustedSource;
  const missing = await processSubmissionJob(job, { config: cfg, reviewer: async () => ({ ...await reviewer(), proof: null }),
    proofReviewer, sourceLoader });
  assert.equal(missing.review.verdict, 'uncertain');
  assert.equal(missing.artifacts, undefined);
  const contradicted = await processSubmissionJob(job, { config: cfg, reviewer, sourceLoader,
    proofReviewer: async () => ({ ...await proofReviewer(), verdict: 'refutes', reason: 'A bounds check prevents the claimed access' }) });
  assert.equal(contradicted.review.verdict, 'uncertain');
  assert.equal(contradicted.artifacts, undefined);
});

test('independent challenge keeps the complete explanation for queue review', async t => {
  const explanation = '소스의 전제 조건과 반례를 다시 확인해야 합니다. '.repeat(65);
  const result = await processSubmissionJob(job, { config: config(t), reviewer,
    sourceLoader: async () => trustedSource,
    proofReviewer: async () => ({ ...await proofReviewer(), verdict: 'refutes', reason: explanation }) });
  assert.equal(result.review.reason,
    `Independent static challenge did not confirm the claim: ${explanation}`);
});

test('verifier leaves same-root comparison to the dedicated duplicate reviewer', async t => {
  let compared = false;
  const result = await processSubmissionJob(job, { config: config(t), sourceLoader: async () => trustedSource,
    reviewer, proofReviewer, candidateLookup: async () => { compared = true; throw new Error('unexpected lookup'); },
    sameRootReviewer: async () => { compared = true; throw new Error('unexpected comparison'); } });
  assert.equal(compared, false);
  assert.ok(result.artifacts?.report?.content);
  assert.equal(result.review.same_root_cause, undefined);
});

test('two pooled workers claim compatible commits and report active target only while busy', async t => {
  const cfg = config(t);
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/claim' ? { job } : endpoint === '/same-root-candidates'
      ? { candidates: [], truncated: false } : {};
  };
  assert.equal(await runWorkerOnce({ config: cfg, transport, reviewer, proofReviewer, sourceLoader: async () => trustedSource,
    workerId: 'e'.repeat(32) }), true);
  assert.deepEqual(calls[0].body.supported_commits, [commit, stableCommit]);
  assert.equal(calls.find(call => call.endpoint === '/heartbeat' && call.body.submission_id).body.target_commit, commit);
  assert.equal(calls.at(-1).body.target_commit, null);
  assert.equal(calls.find(call => call.endpoint === '/complete').body.result.reproduction.status, 'not_run');
  assert.equal(calls.find(call => call.endpoint === '/complete').body.result.review.normalized.logs[0].content, undefined);
  assert.equal(calls.some(call => call.endpoint === '/same-root-candidates'), false);
});

for (const [status, expectedAttempts] of [[400, 1], [500, 3]]) {
  test(`/complete HTTP ${status} records a bounded diagnostic without leaking the review`, async t => {
    const calls = [];
    const transport = async (_socket, endpoint, body) => {
      calls.push({ endpoint, body });
      if (endpoint === '/claim') return { job };
      if (endpoint === '/complete') {
        const error = new Error('private PoC and model text must not appear in the queue');
        error.code = 'server_error';
        error.status = status;
        throw error;
      }
      return {};
    };
    await assert.rejects(runWorkerOnce({ config: config(t), transport,
      reviewer: async () => ({ verdict: 'unlikely', reason: 'private review text',
        integrity: { verdict: 'clear', admin_action_required: false, reason: 'private integrity text' } }),
      sourceLoader: async () => trustedSource }), error => error.code === 'completion_delivery_failed');
    assert.equal(calls.filter(call => call.endpoint === '/complete').length, expectedAttempts);
    const failures = calls.filter(call => call.endpoint === '/fail');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].body.reason, `Verification result delivery failed: server_error_http_${status}`);
    assert.ok(Buffer.byteLength(failures[0].body.reason) < 1000);
    assert.doesNotMatch(failures[0].body.reason, /private|PoC|model text|integrity/i);
  });
}

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { processSubmissionJob, runWorkerOnce, stableWorkerId } from './worker.mjs';

const commit = 'a'.repeat(40);
const stableCommit = 'b'.repeat(40);
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
const trustedSource = { commit, files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [{ number: 42, text: line }] }] };
const reviewer = async () => ({ verdict: 'likely', integrity: { verdict: 'clear', reason: 'No artificial conditions' },
  reason: 'Plausible static candidate', model: 'test',
  grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 42, text: line }] },
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

test('static screening preserves original C/log and never invokes a VM', async t => {
  const phases = [];
  const result = await processSubmissionJob(job, { config: config(t), reviewer,
    sourceLoader: async (directory, requested) => {
      assert.equal(directory, '/trusted/rc'); assert.equal(requested, commit); return trustedSource;
    }, onPhase: phase => phases.push(phase) });
  assert.equal(result.review.verdict, 'likely');
  assert.equal(result.reproduction.status, 'not_run');
  assert.deepEqual(phases, ['static_review']);
  assert.equal(result.artifacts.poc.source, poc);
  assert.equal(result.artifacts.log.content, log);
  assert.doesNotMatch(result.artifacts.report.content, /서버 VM에서.*관찰/);
});

test('suspicious shortcut is never promoted even if source path is plausible', async t => {
  const result = await processSubmissionJob(job, { config: config(t), sourceLoader: async () => trustedSource,
    reviewer: async () => ({ ...await reviewer(), integrity: { verdict: 'suspect', reason: 'Injected kernel delay' } }) });
  assert.equal(result.review.integrity.verdict, 'suspect');
  assert.equal(result.artifacts, undefined);
});

test('uncertain same-root candidates stop automatic numbering', async t => {
  const result = await processSubmissionJob(job, { config: config(t), sourceLoader: async () => trustedSource,
    reviewer, candidateLookup: async () => ({ candidates: [{ management_id: 'A-005', title: 'old',
      file_path: 'fs/nfsd/nfs4proc.c', report }], truncated: false }),
    sameRootReviewer: async () => ({ verdict: 'uncertain', reason: 'Old report incomplete' }) });
  assert.equal(result.review.same_root_cause.verdict, 'uncertain');
  assert.equal(result.artifacts, undefined);
});

test('two pooled workers claim compatible commits and report active target only while busy', async t => {
  const cfg = config(t);
  const calls = [];
  const transport = async (_socket, endpoint, body) => {
    calls.push({ endpoint, body });
    return endpoint === '/claim' ? { job } : endpoint === '/same-root-candidates'
      ? { candidates: [], truncated: false } : {};
  };
  assert.equal(await runWorkerOnce({ config: cfg, transport, reviewer, sourceLoader: async () => trustedSource,
    workerId: 'e'.repeat(32) }), true);
  assert.deepEqual(calls[0].body.supported_commits, [commit, stableCommit]);
  assert.equal(calls.find(call => call.endpoint === '/heartbeat' && call.body.submission_id).body.target_commit, commit);
  assert.equal(calls.at(-1).body.target_commit, null);
  assert.equal(calls.find(call => call.endpoint === '/complete').body.result.reproduction.status, 'not_run');
  assert.equal(calls.find(call => call.endpoint === '/complete').body.result.review.normalized.logs[0].content, undefined);
});

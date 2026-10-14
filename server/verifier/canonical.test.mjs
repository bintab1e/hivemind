import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalArtifacts } from './canonical.mjs';

const commit = 'a'.repeat(40);
const line = 'if (count > available) return -EINVAL;';
const source = { commit, files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [{ number: 42, text: line }] }] };
const report = `## Summary\n요청 길이 검사 후보입니다.\n\n## Root cause\nfs/nfsd/nfs4proc.c:42\n\n\`\`\`c\n${line}\n\`\`\`\n\n## Reproduction environment\n제출 환경입니다.\n\n## PoC\n원본 C 요청을 설명합니다.\n\n## Impact analysis\n제출 로그는 미재현 주장입니다.`;
const poc = { filename: 'poc.c', original_name: 'client.c', source_index: 1, language: 'c', source: 'int main(void) { return 0; }\n' };
const review = { verdict: 'likely', integrity: { verdict: 'clear', reason: 'No shortcuts' },
  grounding: { source_commit: commit, evidence: [{ path: 'fs/nfsd/nfs4proc.c', line: 42, text: line }] },
  normalized: { title: 'NFS request length check', report, file_path: 'fs/nfsd/nfs4proc.c',
    code_refs: ['fs/nfsd/nfs4proc.c:42'], nfs_version: '4.2',
    logs: [{ original_name: 'original.log', source_index: 2, content: 'BUG: KASAN: claimed\nRead of size 4\n' }] } };

test('canonical artifacts preserve submitted C and log and explicitly label static-only screening', () => {
  const artifacts = canonicalArtifacts({ review, trustedSource: source, poc, kernelCommit: commit });
  assert.equal(artifacts.poc.source, poc.source);
  assert.equal(artifacts.log.filename, 'evidence.log');
  assert.equal(artifacts.log.content, review.normalized.logs[0].content);
  assert.match(artifacts.report.content, /서버에서 실행하거나 재현하지 않았습니다/);
  assert.doesNotMatch(artifacts.report.content, /서버 VM에서.*관찰/);
  assert.match(artifacts.reproduction.content, /No server VM or PoC execution occurred/);
});

test('missing trusted source, original log, or clear integrity cannot produce canonical artifacts', () => {
  assert.equal(canonicalArtifacts({ review: { ...review, integrity: { verdict: 'suspect' } }, trustedSource: source, poc, kernelCommit: commit }), null);
  assert.equal(canonicalArtifacts({ review, trustedSource: { ...source, files: [] }, poc, kernelCommit: commit }), null);
  assert.equal(canonicalArtifacts({ review: { ...review, normalized: { ...review.normalized, logs: [] } }, trustedSource: source, poc, kernelCommit: commit }), null);
});

test('uses a quoted grounded source line even when it is not the first primary-path anchor', () => {
  const entry = 'int nfsd_dispatch(struct svc_rqst *rqstp)';
  const withTwoLines = { commit, files: [{ path: 'fs/nfsd/nfs4proc.c', lines: [
    { number: 12, text: entry }, { number: 42, text: line },
  ] }] };
  const withTwoAnchors = { ...review, grounding: { source_commit: commit, evidence: [
    { path: 'fs/nfsd/nfs4proc.c', line: 12, text: entry },
    { path: 'fs/nfsd/nfs4proc.c', line: 42, text: line },
  ] } };
  assert.ok(canonicalArtifacts({ review: withTwoAnchors, trustedSource: withTwoLines, poc, kernelCommit: commit }));
  const withoutQuote = { ...withTwoAnchors, normalized: { ...review.normalized,
    report: report.replace(line, 'different ungrounded text') } };
  assert.equal(canonicalArtifacts({ review: withoutQuote, trustedSource: withTwoLines, poc, kernelCommit: commit }), null);
});

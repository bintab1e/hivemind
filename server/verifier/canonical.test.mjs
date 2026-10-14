import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalArtifacts } from './canonical.mjs';
import { runWorkerOnce } from './worker.mjs';

const commit = 'a'.repeat(40);
const filePath = 'fs/nfsd/nfs4proc.c';
const source = 'int main(void) { send_request(); return 0; }\n';
const trustedSource = { files: [{ path: filePath, lines: [
  { number: 41, text: 'if (count > max_count)' },
  { number: 42, text: '    return nfserr_inval;' },
  { number: 43, text: 'return nfsd_read(rqstp, count);' },
] }] };
const review = {
  verdict: 'likely', reason: 'A count check may be bypassed',
  grounding: { source_commit: commit, evidence: [{ path: filePath, line: 43, text: trustedSource.files[0].lines[2].text }] },
  relevance: { verdict: 'supports', source_path: filePath, source_line: 43, poc_line: 1, trace_line: 'nfsd_read+0x4/0x20' },
  normalized: { title: 'candidate', file_path: filePath, report: 'The checked count reaches nfsd_read.' },
};
const poc = { filename: 'poc.c', source_index: 1, source, language: 'c' };
const serial = 'BUG: KASAN: unrelated\nRead of size 1\nother+0x1/0x2\n' +
  'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n nfsd_read+0x4/0x20\n';

test('canonical artifacts use grounded source and only the related post-PoC KASAN block', () => {
  const result = canonicalArtifacts({ review, trustedSource, poc, serverSerial: serial, kernelCommit: commit, nfsVersion: '4.2' });
  assert.equal(result.title, 'nfs4proc.c slab-out-of-bounds read');
  assert.equal(result.report.filename, 'report.md');
  assert.deepEqual([...result.report.content.matchAll(/^## (.+)$/gm)].map(match => match[1]),
    ['Summary', 'Root cause', 'Reproduction environment', 'PoC', 'Impact analysis']);
  assert.match(result.report.content, /return nfsd_read\(rqstp, count\);/);
  assert.match(result.report.content, /fs\/nfsd\/nfs4proc\.c:43/);
  assert.match(result.report.content, /KASAN Read/);
  assert.doesNotMatch(result.report.content, /KASAN Write.*관찰되었습니다/);
  assert.equal(result.poc.filename, 'poc.c');
  assert.equal(result.poc.source, source);
  assert.equal(result.reproduction.filename, 'reproduction.md');
  assert.match(result.reproduction.content, /vers=4\.2,proto=tcp/);
  assert.equal(result.log.filename, 'kasan.log');
  assert.equal(result.log.content, 'BUG: KASAN: slab-out-of-bounds\nRead of size 4\n nfsd_read+0x4/0x20');
});

test('missing grounded source, PoC line, or matching trace cannot yield canonical artifacts', () => {
  const input = { review, trustedSource, poc, serverSerial: serial, kernelCommit: commit, nfsVersion: '4.2' };
  assert.equal(canonicalArtifacts({ ...input, trustedSource: { files: [] } }), null);
  assert.equal(canonicalArtifacts({ ...input, poc: { ...poc, language: 'python' } }), null);
  assert.equal(canonicalArtifacts({ ...input, serverSerial: serial.replace('nfsd_read+0x4/0x20', 'other+0x4/0x20') }), null);
  assert.equal(canonicalArtifacts({ ...input, nfsVersion: '4.1,4.2' }), null);
});

test('pre-auth artifacts describe direct 2VM transport without inventing an NFS mount or version', () => {
  const preAuthReview = structuredClone(review);
  preAuthReview.normalized.pre_auth = { source_path: filePath, source_line: 43, poc_line: 1 };
  const result = canonicalArtifacts({ review: preAuthReview, trustedSource, poc, serverSerial: serial,
    kernelCommit: commit, nfsVersion: null, preAuth: true });
  assert.ok(result);
  assert.match(result.report.content, /NFS 마운트 없이/);
  assert.match(result.reproduction.content, /NFS mount: none/);
  assert.match(result.reproduction.content, /hivemind-poc 10\.77\.0\.1`/);
  assert.doesNotMatch(result.reproduction.content, /vers=|4\.2|\/mnt\/nfs/);
  preAuthReview.normalized.pre_auth.source_line = 99;
  assert.equal(canonicalArtifacts({ review: preAuthReview, trustedSource, poc, serverSerial: serial,
    kernelCommit: commit, nfsVersion: null, preAuth: true }), null);
});

test('worker refuses conflicting NFS versions before starting two VMs', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-canonical-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const kernelInfoPath = path.join(directory, 'kernel-info.json');
  fs.writeFileSync(kernelInfoPath, JSON.stringify({ sourceCommit: commit, vmlinuxSha256: createHash('sha256').update('vmlinux').digest('hex') }));
  const config = { socketPath: path.join(directory, 'verifier.sock'), cliPath: '/usr/bin/codex', kernelInfoPath,
    kernelSource: '/trusted/linux', kernelImage: '/trusted/bzImage', vmlinuxImage: '/trusted/vmlinux',
    rootfsImage: '/trusted/rootfs.raw', workRoot: directory };
  const job = { submission_id: 'b'.repeat(64), lease_token: 'c'.repeat(64), project: 'knfsd', title: 'candidate', report: 'report',
    metadata: { repo_commit: commit, nfs_version: '4.1' },
    files: [{ name: 'source.c', kind: 'poc', content_base64: Buffer.from(source).toString('base64') }] };
  let completion;
  const transport = async (_socket, endpoint, body) => endpoint === '/claim' ? { job } : (completion = body, {});
  const reviewer = async () => ({ ...review, normalized: { ...review.normalized, nfs_version: '4.2',
    poc: { ...poc, original_name: 'source.c', source_index: 0 } } });
  await runWorkerOnce({ config, transport, reviewer, sourceLoader: async () => trustedSource,
    runner: () => { throw new Error('VM should not start'); } });
  assert.equal(completion.result.reproduction.status, 'inconclusive');
  assert.match(completion.result.reproduction.reason, /NFS version/);
  assert.equal(completion.result.artifacts, undefined);
});

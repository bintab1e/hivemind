import test from 'node:test';
import assert from 'node:assert/strict';
import { buildQemuArgs, clientPreparationFailure, summarizeEvidence, validateManifest } from './run.mjs';

const valid = {
  schemaVersion: 1,
  project: 'knfsd',
  targetCommit: 'a'.repeat(40),
  poc: 'poc.c',
  nfsVersion: '4.2',
  run: ['@BINARY@', '@SERVER@'],
};

test('only supported, bounded guest manifests enter the VM', () => {
  assert.equal(validateManifest(valid), valid);
  assert.equal(validateManifest({ ...valid, poc: 'poc.py', compile: [] }).poc, 'poc.py');
  assert.throws(() => validateManifest({ ...valid, poc: '../host.c' }), /invalid bundle path/);
  assert.throws(() => validateManifest({ ...valid, serverSetup: [['sh', '-c', 'echo BUG: KASAN:']] }), /serverSetup is forbidden/);
  assert.throws(() => validateManifest({ ...valid, clientSetup: [['sh', '-c', 'echo HV_POC_BEGIN']] }), /clientSetup is forbidden/);
  assert.throws(() => validateManifest({ ...valid, project: 'NFS-Ganesha' }), /knfsd/);
  assert.throws(() => validateManifest({ ...valid, targetCommit: 'a'.repeat(12) }), /full kernel commit/);
  assert.throws(() => validateManifest({ ...valid, nfsVersion: 4.2 }), /unsupported NFS version/);
  assert.equal(validateManifest({ ...valid, nfsVersion: undefined, mount: false }).mount, false);
  assert.throws(() => validateManifest({ ...valid, nfsVersion: undefined, mount: true }), /mount and version/);
  assert.throws(() => validateManifest({ ...valid, mount: false }), /mount and version/);
});

test('only post-start server KASAN can be observed', () => {
  const before = 'BUG: KASAN: stale boot issue\nWrite of size 8\nHV_SERVER_READY\nBUG: KASAN: before release\n';
  const after = 'BUG: KASAN: slab-out-of-bounds in nfsd4_proc_compound\nRead of size 4 at addr\n';
  const clientBeforeAck = 'HV_POC_READY\nHV_POC_BEGIN\n';
  const client = clientBeforeAck + 'HV_POC_EXEC\nHV_POC_EXIT:0\nHV_GUEST_DONE\n';
  const clientExecutionStart = Buffer.byteLength(clientBeforeAck);
  const outcome = summarizeEvidence({ manifest: valid, serverSerial: before + after, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, startSignalSent: true, baselineClean: true, clientSerial: client });
  assert.equal(outcome.status, 'observed');
  assert.equal(outcome.observation.serverEvidenceAfterPoc, true);
  assert.equal(outcome.observation.serverEvidenceStartOffset, Buffer.byteLength(before));
  assert.equal(outcome.observation.clientExecutionStartOffset, clientExecutionStart);
  assert.equal(outcome.observation.baselineClean, true);
  assert.equal(outcome.observation.kasanRead, true);
  assert.equal(outcome.observation.kasanWrite, false);
  assert.equal(outcome.observation.clientExitCode, 0);
  const stale = summarizeEvidence({ manifest: valid, serverSerial: before, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, startSignalSent: true, baselineClean: true, clientSerial: client });
  assert.equal(stale.status, 'not_observed');
  const forgedClient = summarizeEvidence({ manifest: valid, serverSerial: before, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, startSignalSent: true, baselineClean: true, clientSerial: client + after });
  assert.equal(forgedClient.status, 'not_observed');
  const noSignal = summarizeEvidence({ manifest: valid, serverSerial: before + after, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, clientSerial: client });
  assert.notEqual(noSignal.status, 'observed');
  const armedButNotReleased = summarizeEvidence({ manifest: valid, serverSerial: before + after, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, startSignalSent: true, baselineClean: true, clientSerial: clientBeforeAck });
  assert.equal(armedButNotReleased.observation.pocArmed, true);
  assert.equal(armedButNotReleased.observation.pocStarted, false);
  assert.notEqual(armedButNotReleased.status, 'observed');
  const unicodeBefore = '서버 준비\n' + before;
  const byteOffset = Buffer.byteLength(unicodeBefore);
  const unicode = summarizeEvidence({ manifest: valid, serverSerial: Buffer.from(unicodeBefore + after), serverEvidenceStart: byteOffset, clientExecutionStart, startSignalSent: true, baselineClean: true, clientSerial: Buffer.from(client) });
  assert.equal(unicode.status, 'observed');
  assert.equal(unicode.observation.serverEvidenceStartOffset, byteOffset);
  const dirtyBaseline = summarizeEvidence({ manifest: valid, serverSerial: before + after, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, startSignalSent: true, baselineClean: false, clientSerial: client });
  assert.notEqual(dirtyBaseline.status, 'observed');
  const preGoMarker = summarizeEvidence({ manifest: valid, serverSerial: before + after, serverEvidenceStart: Buffer.byteLength(before), clientSerial: 'HV_POC_BEGIN\nHV_POC_READY\n', clientEvidenceStart: Buffer.byteLength('HV_POC_BEGIN\n'), startSignalSent: true, baselineClean: true });
  assert.notEqual(preGoMarker.status, 'observed');
  const rootOnly = summarizeEvidence({ manifest: valid, serverSerial: before, serverEvidenceStart: Buffer.byteLength(before), clientExecutionStart, clientSerial: clientBeforeAck + 'HV_POC_EXEC\nHV_POC_EXIT:1\nHV_GUEST_DONE\n', startSignalSent: true, baselineClean: true });
  assert.equal(rootOnly.status, 'inconclusive');
});

test('both VMs use snapshots and only a private Unix-socket link', () => {
  const shared = { kernelImage: '/lab/bzImage', rootfsImage: '/lab/rootfs.raw', jobImage: '/job/job.raw', socketPath: '/job/pair.sock' };
  const server = buildQemuArgs({ ...shared, role: 'server' }).join(' ');
  const client = buildQemuArgs({ ...shared, role: 'client' }).join(' ');
  for (const args of [server, client]) {
    assert.match(args, /snapshot=on/);
    assert.match(args, /readonly=on/);
    assert.match(args, /addr\.type=unix,addr\.path=\/job\/pair\.sock/);
    assert.doesNotMatch(args, /-nic user|-netdev user|-netdev bridge|-netdev tap/);
    assert.match(args, /-sandbox on,obsolete=deny/);
  }
  assert.match(server, /hivemind\.role=server/);
  assert.match(server, /stream,id=private,server=on,/);
  assert.doesNotMatch(server, /wait=/);
  assert.match(client, /hivemind\.role=client/);
  assert.match(client, /stream,id=private,server=off,/);
  assert.throws(() => buildQemuArgs({ ...shared, role: 'server', socketPath: '/job/pair.sock,foo=bar' }), /option separators/);
});

test('client preparation errors use bounded diagnostics instead of a false timeout', () => {
  const deadline = 1000;
  const diagnose = (vm, now = 500) => clientPreparationFailure(vm, deadline, now);
  assert.equal(diagnose({ serial: 'HV_MOUNT_EXIT:2\r\nHV_GUEST_FAILED\r\n' }), 'guest NFS mount failed');
  assert.equal(diagnose({ serial: 'HV_BUILD_EXIT:1\nHV_GUEST_FAILED\n' }), 'guest PoC build failed');
  assert.equal(diagnose({ serial: 'HV_GUEST_TIMEOUT\nHV_GUEST_FAILED\n' }), 'guest preparation command timed out');
  assert.equal(diagnose({ serial: 'HV_GUEST_ERROR:ValueError\nHV_GUEST_FAILED\n' }), 'guest preparation raised an error');
  assert.equal(diagnose({ serial: 'HV_GUEST_FAILED\n' }), 'guest preparation failed');
  assert.equal(diagnose({ serial: '', closed: true, exitCode: 1, stderr: 'sensitive path' }), 'client QEMU exited before PoC ready (exit 1)');
  assert.equal(diagnose({ serial: '', error: new Error('sensitive path') }), 'client QEMU process error');
  assert.equal(diagnose({ serial: '', overflow: true }), 'client VM serial output exceeded limit');
  assert.equal(diagnose({ serial: '' }, 1000), 'verification deadline expired before PoC ready');
  assert.equal(diagnose({ serial: '' }), 'client VM stopped preparing PoC');
});

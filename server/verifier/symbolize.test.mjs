import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { symbolizeKasanFrames } from './symbolize.mjs';

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-symbol-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'scripts'));
  const vmlinuxPath = path.join(dir, 'vmlinux');
  fs.writeFileSync(vmlinuxPath, 'test symbol image');
  const kernelInfo = { vmlinuxSha256: createHash('sha256').update('test symbol image').digest('hex') };
  return { dir, vmlinuxPath, kernelInfo };
}

test('maps only raw post-KASAN function offsets through the pinned host decoder', async t => {
  const { dir, vmlinuxPath, kernelInfo } = fixture(t);
  fs.writeFileSync(path.join(dir, 'scripts/faddr2line'), `#!/usr/bin/env bash
printf 'nfsd4_proc_compound+0x4/0x20:\\nnfsd4_proc_compound at fs/nfsd/nfs4proc.c:17\\n'
`);
  const serverSerial = 'preboot_fn+0x1/0x20\nBUG: KASAN: slab-out-of-bounds\nRead of size 4\n nfsd4_proc_compound+0x4/0x20\n';
  const frames = await symbolizeKasanFrames({ serverSerial, vmlinuxPath, kernelInfo, sourceDir: dir });
  assert.deepEqual(frames, [{ trace_line: 'nfsd4_proc_compound+0x4/0x20', locations: [{ path: 'fs/nfsd/nfs4proc.c', line: 17 }] }]);
  await assert.rejects(symbolizeKasanFrames({ serverSerial, vmlinuxPath, kernelInfo: { vmlinuxSha256: '0'.repeat(64) }, sourceDir: dir }),
    /vmlinux_hash_mismatch/);
});

test('ignores decoded paths outside the trusted checkout or NFS scope', async t => {
  const { dir, vmlinuxPath, kernelInfo } = fixture(t);
  fs.writeFileSync(path.join(dir, 'scripts/faddr2line'), `#!/usr/bin/env bash
printf 'nfsd4_proc_compound+0x4/0x20:\\nnfsd4_proc_compound at /tmp/attacker/fs/nfsd/nfs4proc.c:17\\n(inlined by) helper at drivers/net/foo.c:4\\n'
`);
  const frames = await symbolizeKasanFrames({ serverSerial: 'BUG: KASAN: test\n nfsd4_proc_compound+0x4/0x20\n',
    vmlinuxPath, kernelInfo, sourceDir: dir });
  assert.deepEqual(frames, [{ trace_line: 'nfsd4_proc_compound+0x4/0x20', locations: [] }]);
});

test('real Linux faddr2line resolves a function+offset frame without a serial source path',
  { skip: !process.env.HIVEMIND_KERNEL_SOURCE }, async t => {
    const { dir, vmlinuxPath } = fixture(t);
    const sourceDir = process.env.HIVEMIND_KERNEL_SOURCE;
    fs.copyFileSync(path.join(sourceDir, 'scripts/faddr2line'), path.join(dir, 'scripts/faddr2line'));
    fs.mkdirSync(path.join(dir, 'fs/nfsd'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'init'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'fs/nfsd/nfs4proc.c'), '__attribute__((noinline)) int nfsd4_proc_compound(int x) { return x + 1; }\n__attribute__((noinline)) int after_nfsd(int x) { return x + 2; }\n');
    fs.writeFileSync(path.join(dir, 'init/main.c'), 'extern int nfsd4_proc_compound(int);\nint start_kernel(void) { return nfsd4_proc_compound(4); }\nint main(void) { return start_kernel(); }\n');
    execFileSync('gcc', ['-g', '-O0', '-fno-inline', '-no-pie', '-o', vmlinuxPath,
      path.join(dir, 'init/main.c'), path.join(dir, 'fs/nfsd/nfs4proc.c')]);
    const probe = execFileSync('bash', [path.join(dir, 'scripts/faddr2line'), vmlinuxPath, 'nfsd4_proc_compound+0x1'], { encoding: 'utf8' });
    const size = /nfsd4_proc_compound\+0x1\/(0x[0-9a-f]+):/i.exec(probe)?.[1];
    if (!size) t.diagnostic(execFileSync('readelf', ['--symbols', '--wide', vmlinuxPath], { encoding: 'utf8' }).split(/\r?\n/)
      .filter(line => /nfsd4_proc_compound|start_kernel| main$|\.text|_fini/.test(line)).join('\n'));
    assert.ok(size, probe);
    const kernelInfo = { vmlinuxSha256: createHash('sha256').update(fs.readFileSync(vmlinuxPath)).digest('hex') };
    const frames = await symbolizeKasanFrames({ serverSerial: `BUG: KASAN: test\n nfsd4_proc_compound+0x1/${size}\n`,
      vmlinuxPath, kernelInfo, sourceDir: dir });
    assert.equal(frames.length, 1);
    assert.equal(frames[0].locations[0]?.path, 'fs/nfsd/nfs4proc.c');
    assert.ok(frames[0].locations[0]?.line > 0);
  });

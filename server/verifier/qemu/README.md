# Disposable knfsd reproduction lab

`runTwoVmReproduction()` boots two QEMU guests from the same immutable root image: one runs Linux knfsd, and the other compiles and runs the submitted PoC. Both guests use a private Unix-socket Ethernet link with no host bridge, NAT, or guest internet access. QEMU snapshots the root disk; the submitted bundle is attached read-only. Serial and QEMU diagnostics are saved under a new, mode-0700 output directory. Nothing from the bundle runs on the host.

Provision **once** on a trusted Linux host with KVM, outside the application process:

1. On Ubuntu 24.04, ask an administrator to run `sudo apt-get update` and `sudo apt-get install -y qemu-system-x86 debootstrap e2fsprogs build-essential bc bison flex libssl-dev libelf-dev dwarves git python3`. The verifier should run as a separate, unprivileged OS account with `/dev/kvm` access and without dashboard DB/API credentials. Do not grant the web-server process KVM access.
2. Check out the exact, clean Linux kernel commit being tested. Run `build-kernel.sh /absolute/kernel/source /absolute/output/build 4`. It writes `arch/x86/boot/bzImage`, DWARF `vmlinux`, and `kernel-info.json` containing the source commit and both image hashes. The script requires `CONFIG_KASAN`, `CONFIG_NFSD`, NFS client support, virtio, ext4, and DWARF debug information to be built into the image.
3. Run `sudo build-rootfs.sh /absolute/output/rootfs.raw`. It creates a minimal Ubuntu Noble image with NFS userland, C compiler, and Python. This is a trusted provisioning action, never a per-submission step.

The verifier stages `manifest.json` and its referenced files in a server-owned directory that submitters cannot modify after upload. A minimal manifest is:

```json
{
  "schemaVersion": 1,
  "project": "knfsd",
  "targetCommit": "0123456789abcdef0123456789abcdef01234567",
  "poc": "poc.c",
  "files": [],
  "nfsVersion": "4.2",
  "mount": true,
  "compile": ["gcc", "-O0", "-g", "-o", "@BINARY@", "@POC@"],
  "run": ["@BINARY@", "@SERVER@", "@MOUNT@"],
  "clientSetup": [],
  "expected": {"stream": "server", "contains": "BUG: KASAN:"}
}
```

Use `poc.py` when no C PoC exists; omit `compile` and set `run` to `['python3', '@POC@', ...]`. Commands are argv arrays executed **inside the client guest** as the unprivileged `nobody` account. The guest launcher mounts NFS as root first. PoC/compiler stdout and stderr are discarded, and serial devices are root-only, so a normal submitted PoC cannot forge the guest runner's control markers. `@POC@`, `@BINARY@`, `@SERVER@`, and `@MOUNT@` expand to guest paths/IP. Both `serverSetup` and `clientSetup` are forbidden because they could forge evidence before the PoC. The fixed server guest exports `/srv/export`; for NFSv3, it also starts rpcbind/mountd. PoCs requiring guest root are inconclusive in this fixture. `expected` is a search aid, never independent proof.

Import `runTwoVmReproduction` from `run.mjs` and pass `{bundleDir, kernelImage, kernelInfoPath, rootfsImage, outputDir, timeoutMs}`. `outputDir` must not exist yet and its Unix-socket path must be at most 100 bytes. The return value has `status` (`observed`, `not_observed`, `inconclusive`), `reason`, `observation` (KASAN read/write signatures, guest exit, target commit match, `baselineClean`, and server/client serial start offsets as **UTF-8 byte offsets**), `evidence` (four log paths), and `kernelCommit`. After client preparation, the guest waits at `HV_POC_READY`; the host observes a two-second KASAN-free baseline, sends `HV_GO`, and waits for `HV_POC_BEGIN`. The guest remains blocked. The host checks the server baseline again, records the server serial byte offset, and sends `HV_POC_ACK` to release the PoC. The guest emits `HV_POC_EXEC` before executing it. Only server-kernel KASAN after this release can set `serverEvidenceAfterPoc` and produce `observed`; KASAN before release invalidates the baseline. The caller must still inspect the call trace and PoC relevance before approval. A missing guest, failed build/mount, timeout, or client-only logical output is `inconclusive`, not a verified vulnerability.

This first image covers **knfsd over TCP NFSv3/v4**. RPC/RDMA, pNFS-specific backends, malicious-server scenarios, NFS-Ganesha, and libnfs need separate guest fixtures and must not be auto-approved with this image. The lab has not been run on the shared server until QEMU, images, KVM permissions, and a trusted kernel checkout are provisioned there.

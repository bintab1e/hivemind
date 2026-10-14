import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream, constants } from 'node:fs';
import { access, chmod, copyFile, lstat, mkdir, open, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';

const MAX_FILES = 32;
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_SERIAL = 8 * 1024 * 1024;
const VALID_VERSIONS = new Set(['3', '4', '4.1', '4.2']);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function safePath(name) {
  if (typeof name !== 'string' || !name || name.includes('\\') || name.startsWith('/') ||
      name.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error(`invalid bundle path: ${name}`);
  }
  return name;
}

function checkCommands(commands, name, max = 1) {
  if (commands === undefined) return;
  if (name === 'compile' && Array.isArray(commands) && commands.length === 0) return;
  const list = max === 1 ? [commands] : commands;
  if (!Array.isArray(list) || list.length > max || list.some(argv =>
    !Array.isArray(argv) || !argv.length || argv.length > 32 ||
    argv.some(value => typeof value !== 'string' || !value || value.length > 512))) {
    throw new Error(`${name} must contain guest argv arrays`);
  }
}

export function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || manifest.schemaVersion !== 1 || manifest.project !== 'knfsd') {
    throw new Error('only schemaVersion 1 knfsd manifests are supported');
  }
  if (!/^[a-f0-9]{40}$/.test(manifest.targetCommit || '')) throw new Error('targetCommit must be a full kernel commit SHA');
  safePath(manifest.poc);
  if (!/\.(c|py)$/.test(manifest.poc)) throw new Error('PoC must be C or Python');
  if (manifest.files !== undefined && (!Array.isArray(manifest.files) || manifest.files.length > MAX_FILES || manifest.files.some(file => typeof file !== 'string'))) {
    throw new Error('files must be a bounded list of paths');
  }
  for (const file of manifest.files || []) safePath(file);
  if ((manifest.files || []).includes(manifest.poc)) throw new Error('files must not repeat the PoC');
  if (manifest.nfsVersion !== undefined && (typeof manifest.nfsVersion !== 'string' || !VALID_VERSIONS.has(manifest.nfsVersion))) throw new Error('unsupported NFS version');
  if (manifest.mount !== undefined && typeof manifest.mount !== 'boolean') throw new Error('mount must be boolean');
  if (manifest.mount === false ? manifest.nfsVersion !== undefined : !VALID_VERSIONS.has(manifest.nfsVersion)) {
    throw new Error('NFS mount and version must match');
  }
  if (manifest.serverSetup !== undefined && (!Array.isArray(manifest.serverSetup) || manifest.serverSetup.length)) {
    throw new Error('serverSetup is forbidden: server-console evidence must not be submitter-controlled');
  }
  checkCommands(manifest.compile, 'compile');
  checkCommands(manifest.run, 'run');
  if (manifest.clientSetup !== undefined && (!Array.isArray(manifest.clientSetup) || manifest.clientSetup.length)) {
    throw new Error('clientSetup is forbidden: guest control markers must not be submitter-controlled');
  }
  if (manifest.expected !== undefined &&
      (!manifest.expected || !['server', 'client'].includes(manifest.expected.stream) ||
       typeof manifest.expected.contains !== 'string' || !manifest.expected.contains || manifest.expected.contains.length > 200)) {
    throw new Error('expected must identify a guest serial stream and literal text');
  }
  return manifest;
}

async function sourceFile(bundleDir, name) {
  const root = await realpath(bundleDir);
  let current = root;
  for (const part of safePath(name).split('/')) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error(`symlink in bundle path: ${name}`);
  }
  if (!((await stat(current)).isFile())) throw new Error(`not a regular bundle file: ${name}`);
  const rel = relative(root, current);
  if (rel.startsWith(`..${sep}`) || rel === '..') throw new Error(`bundle path escapes root: ${name}`);
  return current;
}

async function sha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function runTool(binary, args, timeoutMs = 60000) {
  const child = spawn(binary, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let errorText = '';
  child.stderr.on('data', chunk => { errorText = (errorText + chunk).slice(-4096); });
  const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
  try {
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    if (code !== 0) throw new Error(`${binary} failed: ${errorText.trim() || code}`);
  } finally {
    clearTimeout(timer);
  }
}

export function buildQemuArgs({ role, kernelImage, rootfsImage, jobImage, socketPath }) {
  if (!['server', 'client'].includes(role)) throw new Error('invalid VM role');
  for (const value of [kernelImage, rootfsImage, jobImage, socketPath]) {
    if (typeof value !== 'string' || !value.startsWith('/') || /[,\r\n\0]/.test(value)) throw new Error('QEMU image and socket paths must be absolute and contain no option separators');
  }
  const backend = `stream,id=private,server=${role === 'server' ? 'on' : 'off'},addr.type=unix,addr.path=${socketPath}`;
  return [
    '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
    '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '2048',
    '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
    '-kernel', kernelImage,
    '-append', `root=/dev/vda rw console=ttyS0 loglevel=6 init=/usr/local/sbin/hivemind-guest-init hivemind.role=${role} kasan_multi_shot`,
    '-drive', `file=${rootfsImage},if=virtio,format=raw,snapshot=on`,
    '-drive', `file=${jobImage},if=virtio,format=raw,readonly=on`,
    '-netdev', backend,
    '-device', `virtio-net-pci,netdev=private,mac=52:54:00:77:00:0${role === 'server' ? '1' : '2'}`,
  ];
}

function startVm(binary, args, serialPath, stderrPath) {
  const child = spawn(binary, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const serialFile = createWriteStream(serialPath, { flags: 'wx', mode: 0o600 });
  const stderrFile = createWriteStream(stderrPath, { flags: 'wx', mode: 0o600 });
  const vm = { child, serial: '', serialChunks: [], serialBytes: 0, stderr: '', exitCode: null, closed: false, error: null, overflow: false };
  for (const file of [serialFile, stderrFile]) file.on('error', error => { vm.error = error; child.kill('SIGKILL'); });
  child.stdin.on('error', error => { vm.error = error; });
  child.stdout.on('data', chunk => {
    if (vm.serialBytes + chunk.length > MAX_SERIAL) {
      vm.overflow = true;
      child.kill('SIGKILL');
      return;
    }
    vm.serialBytes += chunk.length;
    vm.serialChunks.push(chunk);
    vm.serial += chunk.toString('utf8');
    serialFile.write(chunk);
  });
  child.stderr.on('data', chunk => {
    vm.stderr = (vm.stderr + chunk.toString('utf8')).slice(-8192);
    stderrFile.write(chunk);
  });
  vm.finished = new Promise(resolve => {
    child.once('error', error => { vm.error = error; });
    child.once('close', code => { vm.exitCode = code; vm.closed = true; resolve(); });
  });
  vm.closeLogs = async () => {
    await Promise.all([new Promise(resolve => serialFile.end(resolve)), new Promise(resolve => stderrFile.end(resolve))]);
  };
  return vm;
}

async function waitFor(vm, success, failure, deadline) {
  while (Date.now() < deadline) {
    if (vm.serial.includes(success)) return true;
    if (failure && vm.serial.includes(failure)) return false;
    if (vm.error || vm.closed || vm.overflow) return false;
    await delay(200);
  }
  return false;
}

export function clientPreparationFailure(vm, deadline, now = Date.now()) {
  const serial = vm.serial || '';
  if (/\bHV_MOUNT_EXIT:-?[1-9]\d*(?=\r?\n|$)/.test(serial)) return 'guest NFS mount failed';
  if (/\bHV_BUILD_EXIT:-?[1-9]\d*(?=\r?\n|$)/.test(serial)) return 'guest PoC build failed';
  if (serial.includes('HV_GUEST_TIMEOUT')) return 'guest preparation command timed out';
  if (serial.includes('HV_GUEST_ERROR:')) return 'guest preparation raised an error';
  if (serial.includes('HV_GUEST_FAILED')) return 'guest preparation failed';
  if (vm.overflow) return 'client VM serial output exceeded limit';
  if (vm.error) return 'client QEMU process error';
  if (vm.closed) return `client QEMU exited before PoC ready (exit ${Number.isInteger(vm.exitCode) ? vm.exitCode : 'unknown'})`;
  if (now >= deadline) return 'verification deadline expired before PoC ready';
  return 'client VM stopped preparing PoC';
}

async function stopVm(vm) {
  if (!vm) return;
  if (!vm.closed && !vm.error) vm.child.kill('SIGTERM');
  await Promise.race([vm.finished, delay(3000)]);
  if (!vm.closed) vm.child.kill('SIGKILL');
  await Promise.race([vm.finished, delay(3000).then(() => { throw new Error('QEMU did not stop after SIGKILL'); })]);
  await vm.closeLogs();
}

export function summarizeEvidence({ manifest, serverSerial = '', clientSerial = '', serverEvidenceStart = 0, clientEvidenceStart = 0, clientExecutionStart = 0, startSignalSent = false, baselineClean = false, reason = '', evidence = {}, kernelCommit }) {
  const serverAfterClient = (Buffer.isBuffer(serverSerial) ? serverSerial : Buffer.from(serverSerial)).subarray(serverEvidenceStart).toString('utf8');
  const clientAfterGo = (Buffer.isBuffer(clientSerial) ? clientSerial : Buffer.from(clientSerial)).subarray(clientEvidenceStart).toString('utf8');
  const clientAfterAck = (Buffer.isBuffer(clientSerial) ? clientSerial : Buffer.from(clientSerial)).subarray(clientExecutionStart).toString('utf8');
  const signatures = [...new Set(serverAfterClient.match(/BUG: KASAN:[^\r\n]*/g) || [])].slice(0, 16);
  const hasKasan = signatures.length > 0;
  const expectedStream = manifest.expected?.stream || 'server';
  const expectedText = manifest.expected?.contains || 'BUG: KASAN:';
  const expectedMatched = (expectedStream === 'server' ? serverAfterClient : clientAfterAck).includes(expectedText);
  const exitMatch = [...clientAfterAck.matchAll(/HV_POC_EXIT:(-?\d+)/g)].at(-1);
  const observation = {
    kasanRead: hasKasan && /\bRead of size \d+\b/i.test(serverAfterClient),
    kasanWrite: hasKasan && /\bWrite of size \d+\b/i.test(serverAfterClient),
    kasanSignatures: signatures,
    expectedMatched,
    expectedStream,
    clientExitCode: exitMatch ? Number(exitMatch[1]) : null,
    pocArmed: clientAfterGo.includes('HV_POC_BEGIN'),
    pocStarted: clientAfterAck.includes('HV_POC_EXEC'),
    guestCompleted: clientAfterAck.includes('HV_GUEST_DONE'),
    baselineClean,
    serverEvidenceStartOffset: serverEvidenceStart,
    clientEvidenceStartOffset: clientEvidenceStart,
    clientExecutionStartOffset: clientExecutionStart,
    serverEvidenceAfterPoc: hasKasan && baselineClean && startSignalSent && clientAfterGo.includes('HV_POC_BEGIN') && clientAfterAck.includes('HV_POC_EXEC'),
    targetCommitMatch: true,
  };
  const unsuccessfulPoc = observation.guestCompleted && observation.clientExitCode !== 0;
  const status = observation.serverEvidenceAfterPoc ? 'observed' :
    reason || unsuccessfulPoc || expectedStream === 'client' || expectedMatched ? 'inconclusive' : 'not_observed';
  if (status === 'observed') reason = 'server kernel emitted a KASAN report after the PoC started';
  if (!reason) reason = hasKasan ? 'server KASAN appeared before the PoC start marker and needs review' :
    unsuccessfulPoc ? 'PoC exited unsuccessfully as an unprivileged guest user' :
    expectedStream === 'client' || expectedMatched ? 'non-KASAN output needs independent review' :
    'PoC finished without the expected server KASAN evidence';
  return { status, reason, observation, evidence, kernelCommit };
}

export async function runTwoVmReproduction({ bundleDir, kernelImage, kernelInfoPath, rootfsImage, outputDir, timeoutMs = 300000, qemuBinary = 'qemu-system-x86_64' }) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 30000 || timeoutMs > 600000) throw new Error('timeoutMs must be 30-600 seconds');
  const manifest = validateManifest(JSON.parse(await readFile(join(bundleDir, 'manifest.json'), 'utf8')));
  const kernelInfo = JSON.parse(await readFile(kernelInfoPath, 'utf8'));
  if (kernelInfo.sourceCommit !== manifest.targetCommit || kernelInfo.kernelSha256 !== await sha256(kernelImage)) {
    throw new Error('kernel image/source commit does not match submitted targetCommit');
  }
  for (const file of [kernelImage, rootfsImage]) {
    if (!(await stat(file)).isFile()) throw new Error(`not a regular image: ${file}`);
  }
  await access('/dev/kvm', constants.R_OK | constants.W_OK);
  const files = [...new Set([manifest.poc, ...(manifest.files || [])])];
  let total = 0;
  for (const file of files) total += (await stat(await sourceFile(bundleDir, file))).size;
  if (files.length > MAX_FILES || total > MAX_BYTES) throw new Error('bundle exceeds verification size limit');
  const output = resolve(outputDir);
  await mkdir(output, { mode: 0o700 });
  const stage = join(output, 'job');
  await mkdir(stage, { mode: 0o755 });
  for (const file of files) {
    const destination = join(stage, file);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(await sourceFile(bundleDir, file), destination);
    await chmod(destination, 0o644);
  }
  await writeFile(join(stage, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });
  const jobImage = join(output, 'job.raw');
  const descriptor = await open(jobImage, 'wx', 0o600);
  await descriptor.truncate(64 * 1024 * 1024);
  await descriptor.close();
  await runTool('mkfs.ext4', ['-q', '-F', '-d', stage, jobImage]);

  const socketPath = join(output, 'pair.sock');
  if (Buffer.byteLength(socketPath) > 100) throw new Error('outputDir path is too long for the QEMU Unix socket');
  const evidence = {
    serverSerialPath: join(output, 'server.serial.log'),
    clientSerialPath: join(output, 'client.serial.log'),
    serverQemuStderrPath: join(output, 'server.qemu.log'),
    clientQemuStderrPath: join(output, 'client.qemu.log'),
  };
  const deadline = Date.now() + timeoutMs;
  let server;
  let client;
  let reason = '';
  let serverEvidenceStart = 0;
  let clientEvidenceStart = 0;
  let clientExecutionStart = 0;
  let serverReadyOffset = 0;
  let startSignalSent = false;
  let baselineClean = false;
  try {
    server = startVm(qemuBinary, buildQemuArgs({ role: 'server', kernelImage, rootfsImage, jobImage, socketPath }), evidence.serverSerialPath, evidence.serverQemuStderrPath);
    if (!(await waitFor(server, 'HV_SERVER_READY', 'Kernel panic', Math.min(deadline, Date.now() + 90000)))) {
      reason = `server VM failed to boot or start NFS: ${server.stderr || server.error?.message || 'timeout'}`;
    } else {
      serverReadyOffset = server.serialBytes;
      client = startVm(qemuBinary, buildQemuArgs({ role: 'client', kernelImage, rootfsImage, jobImage, socketPath }), evidence.clientSerialPath, evidence.clientQemuStderrPath);
      if (!(await waitFor(client, 'HV_POC_READY', 'HV_GUEST_FAILED', deadline))) {
        reason = `client VM did not prepare PoC: ${clientPreparationFailure(client, deadline)}`;
      } else {
        await delay(2000);
        const prePocServerLog = Buffer.concat(server.serialChunks).subarray(serverReadyOffset).toString('utf8');
        baselineClean = !/BUG: KASAN:/.test(prePocServerLog) && !server.closed && !server.error && !client.closed && !client.error;
        if (!baselineClean) {
          reason = 'server emitted KASAN or stopped before PoC start; baseline is invalid';
        } else {
          clientEvidenceStart = client.serialBytes;
          client.child.stdin.write('HV_GO\n');
          if (!(await waitFor(client, 'HV_POC_BEGIN', 'HV_GUEST_FAILED', deadline))) {
            reason = `client VM did not arm PoC: ${client.stderr || client.error?.message || 'timeout'}`;
          } else {
            await delay(500);
            const preReleaseLog = Buffer.concat(server.serialChunks).subarray(serverReadyOffset).toString('utf8');
            baselineClean = !/BUG: KASAN:/.test(preReleaseLog) && !server.closed && !server.error && !client.closed && !client.error;
            if (!baselineClean) {
              reason = 'server emitted KASAN or stopped before PoC release; baseline is invalid';
            } else {
              serverEvidenceStart = server.serialBytes;
              clientExecutionStart = client.serialBytes;
              client.child.stdin.write('HV_POC_ACK\n');
              startSignalSent = true;
              if (!(await waitFor(client, 'HV_GUEST_DONE', 'HV_GUEST_FAILED', deadline))) {
                reason = `client VM did not finish PoC: ${client.stderr || client.error?.message || 'timeout'}`;
              } else {
                await delay(2000);
              }
            }
          }
        }
      }
    }
  } finally {
    await Promise.all([stopVm(client), stopVm(server)]);
  }

  return summarizeEvidence({ manifest, serverSerial: server ? Buffer.concat(server.serialChunks) : '', clientSerial: client ? Buffer.concat(client.serialChunks) : '', serverEvidenceStart, clientEvidenceStart, clientExecutionStart, startSignalSent, baselineClean, reason, evidence, kernelCommit: kernelInfo.sourceCommit });
}

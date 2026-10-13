import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, statSync } from 'node:fs';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const framePattern = /\b([A-Za-z_][A-Za-z0-9_.$]*)\+(0x[0-9a-f]{1,16})\/(0x[0-9a-f]{1,16})(?=\s|$)/i;
const headerPattern = /^([A-Za-z_][A-Za-z0-9_.$]*)\+(0x[0-9a-f]{1,16})\/(0x[0-9a-f]{1,16}):$/i;
const sourcePathPattern = /^(?:fs\/(?:nfsd|nfs|nfs_common|lockd|exportfs)\/|net\/sunrpc\/|include\/(?:linux\/sunrpc|uapi\/linux\/nfsd)\/)[a-zA-Z0-9_./+-]+\.(?:c|h)$/;
const MAX_FRAMES = 24;

function frameKey(symbol, offset, size) {
  return `${symbol}|${BigInt(offset)}|${BigInt(size)}`;
}

function sourceLocation(filename, line, sourceRoot) {
  let relative = filename;
  if (path.isAbsolute(filename)) {
    if (!filename.startsWith(`${sourceRoot}${path.sep}`)) return null;
    relative = path.relative(sourceRoot, filename).split(path.sep).join('/');
  } else {
    relative = filename.replace(/^\.\//, '');
  }
  if (!sourcePathPattern.test(relative) || relative.split('/').some(part => !part || part === '.' || part === '..')) return null;
  const number = Number(line);
  return Number.isSafeInteger(number) && number > 0 ? { path: relative, line: number } : null;
}

async function fileSha256(filename) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(filename)) hash.update(bytes);
  return hash.digest('hex');
}

/** Decode only actual server-serial function+offset frames using the SHA-pinned, DWARF-enabled vmlinux. */
export async function symbolizeKasanFrames({ serverSerial, vmlinuxPath, kernelInfo, sourceDir }) {
  if (typeof serverSerial !== 'string' || Buffer.byteLength(serverSerial) > 600_000 ||
      !path.isAbsolute(vmlinuxPath || '') || !path.isAbsolute(sourceDir || '') ||
      !/^[a-f0-9]{64}$/.test(kernelInfo?.vmlinuxSha256 || '')) throw new Error('invalid_symbolization_input');
  const sourceRoot = fs.realpathSync(sourceDir);
  const vmlinux = fs.realpathSync(vmlinuxPath);
  const decoder = path.join(sourceRoot, 'scripts/faddr2line');
  if (!statSync(vmlinux).isFile() || !statSync(decoder).isFile() || await fileSha256(vmlinux) !== kernelInfo.vmlinuxSha256) {
    throw new Error('vmlinux_hash_mismatch');
  }
  const firstHeader = serverSerial.indexOf('BUG: KASAN:');
  if (firstHeader < 0) return [];
  const frames = [];
  const specs = new Map();
  for (const raw of serverSerial.slice(firstHeader).split(/\r?\n/)) {
    const traceLine = raw.trim();
    const match = framePattern.exec(traceLine);
    if (!match) continue;
    const key = frameKey(match[1], match[2], match[3]);
    frames.push({ trace_line: traceLine, key });
    if (!specs.has(key)) specs.set(key, `${match[1]}+${match[2]}/${match[3]}`);
    if (frames.length >= MAX_FRAMES) break;
  }
  if (!frames.length) return [];
  // Linux's faddr2line accounts for KASLR and duplicate symbols; no submitted path enters its argv.
  const { stdout } = await exec('bash', [decoder, vmlinux, ...specs.values()], {
    cwd: sourceRoot, timeout: 120_000, maxBuffer: 300_000,
    env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C', HOME: sourceRoot },
  });
  const locations = new Map();
  let current = null;
  for (const line of stdout.split(/\r?\n/)) {
    const header = headerPattern.exec(line.trim());
    if (header) {
      current = frameKey(header[1], header[2], header[3]);
      if (!locations.has(current)) locations.set(current, []);
      continue;
    }
    const location = /\bat\s+(\S+):([1-9][0-9]*)(?:\s|$)/.exec(line);
    if (!current || !location) continue;
    const parsed = sourceLocation(location[1], location[2], sourceRoot);
    if (parsed && !locations.get(current).some(item => item.path === parsed.path && item.line === parsed.line)) locations.get(current).push(parsed);
  }
  return frames.map(frame => ({ trace_line: frame.trace_line, locations: locations.get(frame.key) || [] }));
}

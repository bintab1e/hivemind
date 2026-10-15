import { inflateRawSync } from 'node:zlib';
import { TextDecoder } from 'node:util';
import { hash, invalid, isStandaloneUserspacePoc, required } from './contract.mjs';

const MAX_ZIP_BYTES = 8_000_000;
const MAX_UNPACKED_BYTES = 2_000_000;
const MAX_FILE_BYTES = 600_000;
const MAX_FILES = 20;
const decoder = new TextDecoder('utf-8', { fatal: true });
const sourcePath = /(?:fs\/(?:nfsd|nfs|nfs_common|lockd|exportfs)\/|net\/sunrpc\/|include\/(?:linux\/sunrpc|uapi\/linux\/nfsd)\/)[a-zA-Z0-9_./+-]+\.(?:c|h)/g;
const supported = new Set(['.md', '.txt', '.log', '.c', '.h', '.py', '.sh', '.json', '.yaml', '.yml', '.rst']);

function crc32(bytes) {
  let crc = -1;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ -1) >>> 0;
}

function checkedName(raw) {
  let name;
  try { name = decoder.decode(raw).normalize('NFC'); }
  catch { invalid('ZIP entry names must be UTF-8'); }
  if (!name || name.length > 500 || /[\x00-\x1f\x7f]/.test(name) || /^[/\\]|^[a-z]:/i.test(name)) invalid('Unsafe ZIP entry path');
  const parts = name.replaceAll('\\', '/').replace(/\/$/, '').split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || part.includes(':'))) invalid('Unsafe ZIP entry path');
  return name;
}

// Parse ZIP central-directory entries in memory; archive paths are never written to disk.
export function readZip(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 22 || bytes.length > MAX_ZIP_BYTES) invalid('ZIP must be between 22 and 8,000,000 bytes', 413);
  let end = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 65_557); at -= 1) {
    if (bytes.readUInt32LE(at) === 0x06054b50 && at + 22 + bytes.readUInt16LE(at + 20) === bytes.length) { end = at; break; }
  }
  if (end < 0 || bytes.readUInt16LE(end + 4) || bytes.readUInt16LE(end + 6) ||
      bytes.readUInt16LE(end + 8) !== bytes.readUInt16LE(end + 10)) invalid('Unsupported ZIP directory');
  const count = bytes.readUInt16LE(end + 10);
  const size = bytes.readUInt32LE(end + 12);
  const start = bytes.readUInt32LE(end + 16);
  if (!count || count > 64 || count === 0xffff || size === 0xffffffff || start === 0xffffffff || start + size !== end) invalid('Unsupported ZIP directory');
  const files = [];
  const seenPaths = new Set();
  let total = 0;
  let offset = start;
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > end || bytes.readUInt32LE(offset) !== 0x02014b50) invalid('Invalid ZIP entry');
    const flags = bytes.readUInt16LE(offset + 8);
    const method = bytes.readUInt16LE(offset + 10);
    const expectedCrc = bytes.readUInt32LE(offset + 16);
    const compressed = bytes.readUInt32LE(offset + 20);
    const unpacked = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const disk = bytes.readUInt16LE(offset + 34);
    const mode = bytes.readUInt32LE(offset + 38) >>> 16;
    const local = bytes.readUInt32LE(offset + 42);
    const next = offset + 46 + nameLength + extraLength + commentLength;
    if (unpacked > MAX_FILE_BYTES) invalid('ZIP member exceeds the 600,000-byte verifier limit', 413);
    if (next > end || !nameLength || disk || flags & ~0x0808 || ![0, 8].includes(method) ||
        compressed === 0xffffffff || unpacked === 0xffffffff ||
        local === 0xffffffff || local + 30 > start || bytes.readUInt32LE(local) !== 0x04034b50 ||
        mode && (mode & 0o170000) && ![0o100000, 0o040000].includes(mode & 0o170000)) invalid('Unsupported or unsafe ZIP entry');
    const rawName = bytes.subarray(offset + 46, offset + 46 + nameLength);
    const name = checkedName(rawName);
    const pathKey = name.replaceAll('\\', '/').toLocaleLowerCase('en-US');
    if (seenPaths.has(pathKey)) invalid('Duplicate ZIP entry path');
    seenPaths.add(pathKey);
    const directory = name.endsWith('/') || name.endsWith('\\');
    if (directory !== ((mode & 0o170000) === 0o040000) && (mode & 0o170000)) invalid('ZIP directory type mismatch');
    const localNameLength = bytes.readUInt16LE(local + 26);
    const localExtraLength = bytes.readUInt16LE(local + 28);
    const dataStart = local + 30 + localNameLength + localExtraLength;
    if (bytes.readUInt16LE(local + 6) !== flags || bytes.readUInt16LE(local + 8) !== method ||
        localNameLength !== nameLength || dataStart + compressed > start ||
        !bytes.subarray(local + 30, local + 30 + localNameLength).equals(rawName) ||
        !(flags & 0x0008) && (bytes.readUInt32LE(local + 14) !== expectedCrc ||
          bytes.readUInt32LE(local + 18) !== compressed || bytes.readUInt32LE(local + 22) !== unpacked)) invalid('ZIP local header mismatch');
    total += unpacked;
    if (total > MAX_UNPACKED_BYTES) invalid('ZIP expanded content is too large', 413);
    if (!directory) {
      const payload = bytes.subarray(dataStart, dataStart + compressed);
      let content;
      try { content = method === 0 ? payload : inflateRawSync(payload, { maxOutputLength: unpacked + 1 }); }
      catch { invalid('Invalid or oversized ZIP compression', 413); }
      if (content.length !== unpacked || crc32(content) !== expectedCrc) invalid('ZIP entry size or checksum mismatch');
      files.push({ path: name, content });
      if (files.length > MAX_FILES) invalid('ZIP contains too many files', 413);
    }
    offset = next;
  }
  if (offset !== end || !files.length) invalid('ZIP contains no supported files');
  return files;
}

function englishName(entry, index, ext) {
  const role = ext === '.c' || ext === '.py' || ext === '.h' ? 'source' : ext === '.log' ? 'evidence' : 'document';
  return `${role}-${String(index + 1).padStart(2, '0')}${ext}`;
}

export function uploadedSubmission(db, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || input.project !== 'knfsd') invalid('Only knfsd ZIP uploads are supported');
  if (input.existing_management_id != null &&
      (typeof input.existing_management_id !== 'string' || !/^A-\d{3,}$/.test(input.existing_management_id))) {
    invalid('Invalid existing_management_id');
  }
  if (input.existing_vulnerability_id != null &&
      (typeof input.existing_vulnerability_id !== 'string' ||
        !/^(?:V-\d{6,}|A-\d{3,})$/.test(input.existing_vulnerability_id))) {
    invalid('Invalid existing_vulnerability_id');
  }
  if (input.existing_management_id && input.existing_vulnerability_id) invalid('Supply one existing vulnerability ID');
  const reporter = required(input.reporter, 'reporter', 100);
  const title = required(input.title, 'title', 300);
  if (/[\x00-\x1f\x7f]/.test(reporter + title)) invalid('Reporter and title must be plain text');
  if (!['rc', 'mainline'].includes(input.track_id)) invalid('Choose an active kernel track');
  const target = db.prepare('SELECT version_id, repo_commit FROM track_targets WHERE track_id = ? AND active = 1').get(input.track_id);
  if (!target || !/^[a-f0-9]{40}$/.test(target.repo_commit)) invalid('The selected kernel track is not ready for the verifier', 409);
  const nfsVersion = input.nfs_version == null || input.nfs_version === '' ? null : input.nfs_version;
  if (nfsVersion && !['3', '4', '4.1', '4.2'].includes(nfsVersion)) invalid('Invalid NFS version');
  const encoded = input.zip_base64;
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(MAX_ZIP_BYTES / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) invalid('Invalid ZIP encoding', 413);
  const zip = Buffer.from(encoded, 'base64');
  if (zip.length > MAX_ZIP_BYTES || zip.toString('base64') !== encoded) invalid('Invalid ZIP size or encoding', 413);
  const entries = readZip(zip).filter(file => !file.path.split(/[\\/]/).some(part => part === '__MACOSX' || part === '.DS_Store'));
  const classified = entries.map((entry, index) => {
    const basename = entry.path.split(/[\\/]/).at(-1);
    const ext = basename.match(/\.[a-zA-Z0-9]+$/)?.[0].toLowerCase() ||
      (/^(?:readme|report|analysis|finding|분석|보고서)(?:[-_ ].*)?$/i.test(basename) ? '.txt' : null);
    if (!supported.has(ext)) invalid(`Unsupported ZIP member: ${entry.path}`);
    const name = englishName(entry, index, ext);
    let content;
    try { content = decoder.decode(entry.content); }
    catch { invalid(`ZIP member must be UTF-8 text: ${entry.path}`); }
    if (!content.trim() || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(content)) invalid(`Empty or binary ZIP member: ${entry.path}`);
    const type = ext === '.c' ? 'poc' : ext === '.log' ? 'log' : ['.md', '.txt', '.rst'].includes(ext) ? 'report' : 'other';
    return { original: entry.path, name, type, ext, content };
  });
  const reportRank = file => /(?:report|analysis|finding|분석|보고서)/i.test(file.original) ? 2
    : /readme/i.test(file.original) ? 1 : /(?:repro|steps|run|재현)/i.test(file.original) ? -1 : 0;
  const reports = classified.filter(file => file.type === 'report').sort((left, right) => reportRank(right) - reportRank(left));
  if (!reports.length) invalid('ZIP needs a UTF-8 .md, .txt, or .rst analysis report');
  const report = reports[0];
  const cPocs = classified.filter(file => file.name.endsWith('.c') && isStandaloneUserspacePoc(file.content, 'cc -o poc poc.c'));
  if (classified.some(file => file.name.endsWith('.c') && /\b(?:int|signed|void)\s+main\s*\(/.test(file.content) && !cPocs.includes(file))) invalid('C PoC with main must be a standalone userspace program, not a patch or kernel module');
  if (cPocs.some(file => /^\s*#\s*include\s*"/m.test(file.content))) invalid('C PoC must compile as one file using system headers; local include files are not mounted in the verifier VM');
  if (!cPocs.length) invalid('ZIP needs a standalone userspace C PoC');
  const reproduction = classified.find(file => file !== report && (file.ext === '.md' || file.ext === '.sh'));
  if (!reproduction) invalid('ZIP needs a separate reproduction .md or .sh file');
  reproduction.type = 'other';
  if (!classified.some(file => file.type === 'log' && /\b(?:KASAN|KCSAN)\b/i.test(file.content))) invalid('ZIP needs a KASAN or KCSAN .log file');
  const allText = classified.map(file => file.content).join('\n');
  if (![...allText.matchAll(sourcePath)].some(([name]) => name.split('/').every(part => part && part !== '.' && part !== '..')))
    invalid('Report or evidence must reference a knfsd kernel source path (for example fs/nfsd/nfs4proc.c)');
  const files = classified.filter(file => file !== report).map(file => ({ name: file.name, kind: file.type,
    content_base64: Buffer.from(file.content).toString('base64') }));
  if (Buffer.byteLength(report.content) > 150_000) invalid('Analysis report exceeds the 150,000-byte verifier preview limit', 413);
  if (files.some(file => Buffer.byteLength(file.content_base64, 'base64') > 600_000) ||
      cPocs.some(file => Buffer.byteLength(file.content) > 250_000)) invalid('ZIP text exceeds verifier limits', 413);
  const metadata = { version_id: target.version_id, repo_commit: target.repo_commit, track_id: input.track_id, reporter,
    ...(nfsVersion ? { nfs_version: nfsVersion } : {}),
    ...(input.existing_management_id ? { existing_management_id: input.existing_management_id } : {}),
    ...(input.existing_vulnerability_id ? { existing_vulnerability_id: input.existing_vulnerability_id } : {}) };
  const reviewBytes = Buffer.byteLength(JSON.stringify({ project: 'knfsd', title, report: report.content, metadata,
    files: classified.filter(file => file !== report).map(file => ({ name: file.name, kind: file.type, content: file.content })) }));
  if (reviewBytes > 1_800_000) invalid('ZIP text exceeds verifier review limit', 413);
  return { project: 'knfsd', title, report: report.content, metadata, files,
    agentId: `web:${hash(reporter).slice(0, 20)}` };
}

export function uploadedTargets(db) {
  return db.prepare("SELECT track_id, version_id, repo_commit FROM track_targets WHERE active = 1 AND track_id IN ('rc', 'mainline') AND length(repo_commit) = 40 ORDER BY CASE track_id WHEN 'rc' THEN 0 ELSE 1 END").all()
    .map(row => ({ ...row, label: row.track_id === 'rc' ? '최신 RC' : '최신 stable' }));
}

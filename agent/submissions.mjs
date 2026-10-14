import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

const maxFiles = 20;
const maxFileBytes = 2_000_000;
const maxTotalBytes = 8_000_000;
const maxReportBytes = 512 * 1024;
const kinds = new Set(['report', 'poc', 'log', 'other']);
const submissionIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const inside = (root, target) => {
  const relative = path.relative(root, target);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

function attachmentName(name) {
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || Buffer.byteLength(name) > 160 ||
    name.includes('/') || name.includes('\\') || /[\x00-\x1f\x7f]/.test(name)) throw new Error('Invalid attachment name');
  return name;
}

function inferKind(name) {
  const extension = path.extname(name).toLowerCase();
  if (name.toLowerCase() === 'reproduction.md') return 'other';
  if (extension === '.c' || extension === '.py') return 'poc';
  if (extension === '.log') return 'log';
  if (extension === '.md' || extension === '.txt') return 'report';
  return 'other';
}

async function readAttachment(config, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.path !== 'string' || !input.path.trim()) throw new Error('Invalid attachment path');
  const target = path.resolve(path.isAbsolute(input.path) ? input.path : path.join(config.repo_root, input.path));
  const roots = [path.resolve(config.home, 'evidence'), path.resolve(config.repo_root)];
  const root = roots.find(candidate => inside(candidate, target));
  if (!root) throw new Error('Attachment must be inside repo_root or home/evidence');
  if ((await fs.lstat(root)).isSymbolicLink()) throw new Error('Attachment symlinks are not allowed');
  const resolvedRoot = await fs.realpath(root);
  const resolvedTarget = await fs.realpath(target);
  if (!inside(resolvedRoot, resolvedTarget)) throw new Error('Attachment path escapes allowed root');
  let current = root;
  const parts = path.relative(root, target).split(path.sep);
  for (const [index, part] of parts.entries()) {
    if (part.startsWith('.')) throw new Error('Hidden attachment paths are not allowed');
    current = path.join(current, part);
    const info = await fs.lstat(current);
    if (info.isSymbolicLink()) throw new Error('Attachment symlinks are not allowed');
    if (index < parts.length - 1 && !info.isDirectory()) throw new Error('Invalid attachment path');
    if (index === parts.length - 1 && (!info.isFile() || info.size > maxFileBytes)) throw new Error('Invalid attachment file or size');
  }
  const name = attachmentName(input.name ?? path.basename(target));
  const kind = input.kind ?? inferKind(name);
  if (!kinds.has(kind)) throw new Error('Invalid attachment kind');
  const handle = await fs.open(target, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maxFileBytes) throw new Error('Invalid attachment file or size');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!bytes.length || bytes.length > maxFileBytes || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error('Attachment changed while reading');
    return { name, kind, bytes };
  } finally { await handle.close(); }
}

export async function buildSubmission(config, args, repoCommit) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid submission');
  if (args.project != null && args.project !== 'knfsd') throw new Error('Only knfsd submissions are supported');
  if (args.title != null && (typeof args.title !== 'string' || !args.title.trim() || Buffer.byteLength(args.title) > 300)) throw new Error('Invalid title');
  if (args.report != null && (typeof args.report !== 'string' || Buffer.byteLength(args.report) > maxReportBytes)) throw new Error('Invalid report');
  const files = args.files ?? [];
  if (!Array.isArray(files) || files.length > maxFiles) throw new Error('Invalid files');
  if (!args.report?.trim() && !files.length) throw new Error('Add a report or at least one file');
  if (args.client_submission_id != null && (typeof args.client_submission_id !== 'string' || !submissionIdPattern.test(args.client_submission_id))) throw new Error('Invalid client_submission_id');
  if (args.metadata != null && (!args.metadata || typeof args.metadata !== 'object' || Array.isArray(args.metadata))) throw new Error('Invalid metadata');
  if (args.metadata?.existing_management_id != null) throw new Error('Supply existing_management_id at the top level');
  if (args.existing_management_id != null && (typeof args.existing_management_id !== 'string' || !/^A-\d{3,}$/.test(args.existing_management_id))) throw new Error('Invalid existing_management_id');
  const metadata = { ...(args.metadata || {}), ...(args.existing_management_id ? { existing_management_id: args.existing_management_id } : {}), version_id: config.version_id, track_id: config.track_id || null, repo_commit: repoCommit };
  if (Buffer.byteLength(JSON.stringify(metadata)) > 20_000) throw new Error('Metadata is too large');
  const attachments = await Promise.all(files.map(file => readAttachment(config, file)));
  if (new Set(attachments.map(file => file.name.toLowerCase())).size !== attachments.length) throw new Error('Duplicate attachment name');
  if (Buffer.byteLength(args.report || '') + attachments.reduce((sum, file) => sum + file.bytes.length, 0) > maxTotalBytes) throw new Error('Submission exceeds 8 MB');
  return {
    project: 'knfsd',
    client_submission_id: args.client_submission_id || randomUUID(),
    ...(args.title ? { title: args.title.trim() } : {}),
    ...(args.report ? { report: args.report } : {}),
    metadata,
    files: attachments.map(({ name, kind, bytes }) => ({ name, kind, content_base64: bytes.toString('base64') })),
  };
}

const outbox = config => path.join(config.home, 'submissions', 'outbox', config.agent_id);
const ackFolder = config => path.join(config.home, 'submissions', 'ack', config.agent_id);
const queuedPath = (config, id) => path.join(outbox(config), `${id}.json`);
const ackPath = (config, id) => path.join(ackFolder(config), `${id}.json`);

export async function queueSubmission(config, body) {
  const id = body.client_submission_id;
  if (!submissionIdPattern.test(id)) throw new Error('Invalid client_submission_id');
  await fs.mkdir(outbox(config), { recursive: true, mode: 0o700 });
  await fs.chmod(outbox(config), 0o700);
  const encoded = JSON.stringify(body);
  const hash = digest(encoded);
  const oldAck = JSON.parse(await fs.readFile(ackPath(config, id), 'utf8').catch(error => {
    if (error.code === 'ENOENT') return 'null';
    throw error;
  }));
  if (oldAck) {
    if (oldAck.body_sha256 !== hash) throw new Error('client_submission_id already used for different content');
    return { file: null, hash, result: oldAck.result, replayed: true };
  }
  const file = queuedPath(config, id);
  const temporary = path.join(outbox(config), `${id}.${randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, encoded, { flag: 'wx', mode: 0o600 });
    try { await fs.link(temporary, file); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      if (await fs.readFile(file, 'utf8') !== encoded) throw new Error('client_submission_id already used for different content');
    }
  } finally {
    await fs.rm(temporary, { force: true });
  }
  return { file, hash, replayed: false };
}

export async function sendSubmission(config, token, body) {
  const response = await fetch(`${config.server}/v1/submissions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(`Central server returned ${response.status}: ${result.error || 'request failed'}`);
    error.status = response.status;
    throw error;
  }
  if (typeof result.submission_id !== 'string' || typeof result.status !== 'string') throw new Error('Invalid server submission response');
  return result;
}

export async function deliverSubmission(config, token, body, queued) {
  if (queued.result) return queued.result;
  const result = await sendSubmission(config, token, body);
  await fs.mkdir(ackFolder(config), { recursive: true, mode: 0o700 });
  await fs.writeFile(ackPath(config, body.client_submission_id), JSON.stringify({ body_sha256: queued.hash, result, at: new Date().toISOString() }), { mode: 0o600 });
  await fs.rm(queued.file, { force: true });
  return result;
}

export async function rejectSubmission(config, id, error) {
  await fs.mkdir(ackFolder(config), { recursive: true, mode: 0o700 });
  await fs.writeFile(ackPath(config, `${id}.rejected`), JSON.stringify({ error: error.message, at: new Date().toISOString() }), { mode: 0o600 });
}

export async function syncSubmissions(config, token) {
  await fs.mkdir(outbox(config), { recursive: true, mode: 0o700 });
  for (const entry of (await fs.readdir(outbox(config), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isFile() || !submissionIdPattern.test(entry.name.slice(0, -5)) || !entry.name.endsWith('.json')) continue;
    const file = path.join(outbox(config), entry.name);
    const id = entry.name.slice(0, -5);
    if (await fs.stat(ackPath(config, `${id}.malformed`)).catch(() => null)) continue;
    const before = await fs.stat(file);
    if (Date.now() - before.mtimeMs < 1000) continue;
    const encoded = await fs.readFile(file, 'utf8');
    const after = await fs.stat(file);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) continue;
    let body;
    try {
      body = JSON.parse(encoded);
      if (!body || typeof body !== 'object' || Array.isArray(body) || body.client_submission_id !== id || body.project !== 'knfsd' || !Array.isArray(body.files)) throw new Error('Invalid queued submission');
    } catch {
      await fs.mkdir(ackFolder(config), { recursive: true, mode: 0o700 });
      await fs.writeFile(ackPath(config, `${id}.malformed`), JSON.stringify({ error: 'Malformed queued submission', at: new Date().toISOString() }), { mode: 0o600 });
      console.error(`Submission ${id}: malformed queue file retained for inspection`);
      continue;
    }
    if (await fs.stat(ackPath(config, `${body.client_submission_id}.rejected`)).catch(() => null)) continue;
    if (await fs.stat(ackPath(config, body.client_submission_id)).catch(() => null)) {
      await fs.rm(file, { force: true });
      continue;
    }
    try {
      const result = await deliverSubmission(config, token, body, { file, hash: digest(encoded) });
      console.log(`Submission delivered: ${body.client_submission_id} → ${result.submission_id} (${result.status})`);
    } catch (error) {
      if (!error.status || error.status >= 500 || error.status === 429) throw error;
      await rejectSubmission(config, body.client_submission_id, error);
      console.error(`Submission ${body.client_submission_id}: ${error.message}`);
    }
  }
}

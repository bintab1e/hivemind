import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { invalid } from './contract.mjs';

const kinds = new Set(['report', 'poc', 'kasan']);
const previewExtensions = new Set([
  '.md', '.markdown', '.txt', '.log', '.c', '.h', '.cc', '.cpp', '.py',
  '.sh', '.patch', '.diff', '.json', '.yaml', '.yml', '.rst', '.html', '.htm',
  '.config', '.conf', '.frag', '.stderr', '.stdout', '.serial', '.in', '.gdb',
]);
const maxFiles = 2048;
const maxFileBytes = 128 * 1024 * 1024;
const maxTotalBytes = 2 * 1024 * 1024 * 1024;
const maxPreviewBytes = 6 * 1024 * 1024;
const idPattern = /^[ABC]-\d{3}$/;
const artifactPattern = /^[a-f0-9]{64}$/;
const curatedKinds = new Set(['report', 'poc', 'verification']);

export function initializeHistoryArtifacts(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS history_artifacts (
      id TEXT PRIMARY KEY,
      management_id TEXT NOT NULL REFERENCES registry_history(management_id),
      kind TEXT NOT NULL CHECK(kind IN ('report', 'poc', 'kasan')),
      name TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      size INTEGER NOT NULL,
      imported_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS history_artifacts_management
      ON history_artifacts(management_id, kind, name);
    CREATE TABLE IF NOT EXISTS history_artifact_curations (
      artifact_id TEXT PRIMARY KEY REFERENCES history_artifacts(id),
      kind TEXT NOT NULL CHECK(kind IN ('report', 'poc', 'verification')),
      label TEXT NOT NULL,
      download_name TEXT NOT NULL,
      display_order INTEGER NOT NULL
    );
  `);
}

function validateManifest(db, manifest) {
  if (!Array.isArray(manifest) || !manifest.length || manifest.length > maxFiles) invalid('Invalid historical artifact manifest');
  const seen = new Set();
  const exists = db.prepare('SELECT 1 FROM registry_history WHERE management_id = ?');
  return manifest.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.keys(entry).some(key => !['management_id', 'kind', 'source_path', 'display_name'].includes(key))) {
      invalid('Invalid historical artifact entry');
    }
    const { management_id: managementId, kind, source_path: sourcePath, display_name: name } = entry;
    if (typeof managementId !== 'string' || !idPattern.test(managementId) || !exists.get(managementId)) invalid('Unknown historical management ID');
    if (!kinds.has(kind)) invalid('Invalid historical artifact kind');
    if (typeof sourcePath !== 'string' || !sourcePath || sourcePath.length > 1024 ||
        /[\\:\x00-\x1f\x7f]/.test(sourcePath) || sourcePath.startsWith('/') ||
        sourcePath.split('/').some(part => !part || part === '.' || part === '..')) invalid('Invalid historical artifact source path');
    if (typeof name !== 'string' || !name.trim() || name.length > 255 ||
        /[\\/\x00-\x1f\x7f]/.test(name) || name === '.' || name === '..') invalid('Invalid historical artifact display name');
    try { encodeURIComponent(sourcePath); encodeURIComponent(name); }
    catch { invalid('Invalid historical artifact Unicode'); }
    const key = `${managementId}\0${kind}\0${sourcePath}`;
    if (seen.has(key)) invalid('Duplicate historical artifact entry');
    seen.add(key);
    return { managementId, kind, sourcePath, name: name.trim() };
  });
}

function sourceFile(root, relativePath) {
  let current = root;
  for (const segment of relativePath.split('/')) {
    current = path.join(current, segment);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) invalid('Historical artifact source symlink is not allowed');
  }
  const stat = fs.lstatSync(current);
  if (!stat.isFile()) invalid('Historical artifact source must be a regular file');
  return { file: current, size: stat.size };
}

function copyAndHash(source, destination) {
  const input = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let output;
  const sha = createHash('sha256');
  let size = 0;
  try {
    const stat = fs.fstatSync(input);
    if (!stat.isFile() || stat.size > maxFileBytes) invalid('Historical artifact exceeds file limit');
    output = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const read = fs.readSync(input, buffer, 0, buffer.length, null);
      if (!read) break;
      size += read;
      if (size > maxFileBytes) invalid('Historical artifact exceeds file limit');
      sha.update(buffer.subarray(0, read));
      let written = 0;
      while (written < read) written += fs.writeSync(output, buffer, written, read - written);
    }
    if (size !== stat.size) invalid('Historical artifact changed during import');
    fs.fsyncSync(output);
    return { size, sha256: sha.digest('hex') };
  } finally {
    if (output !== undefined) fs.closeSync(output);
    fs.closeSync(input);
  }
}

export function artifactDirectory(dataDir) {
  return path.join(dataDir, 'history-artifacts');
}

function isPreviewable(row) {
  return row.size <= maxPreviewBytes && (
    previewExtensions.has(path.extname(row.original_name || row.name).toLowerCase()) ||
    (row.original_name || row.name).endsWith(' · init')
  );
}

function hasCuration(db) {
  return Boolean(db.prepare('SELECT 1 FROM history_artifact_curations LIMIT 1').get());
}

export function curateHistoryArtifacts(db, plan) {
  if (!Array.isArray(plan) || !plan.length || plan.length > maxFiles) invalid('Invalid historical artifact curation');
  const lookup = db.prepare('SELECT management_id FROM history_artifacts WHERE id = ?');
  const seen = new Set();
  const labels = new Set();
  const reports = new Set();
  const selectedIds = new Set();
  const entries = plan.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.keys(entry).sort().join(',') !== 'artifact_id,download_name,kind,label,management_id') invalid('Invalid historical artifact curation entry');
    const { management_id: managementId, artifact_id: artifactId, kind, label, download_name: downloadName } = entry;
    if (typeof managementId !== 'string' || !idPattern.test(managementId) ||
        typeof artifactId !== 'string' || !artifactPattern.test(artifactId) ||
        lookup.get(artifactId)?.management_id !== managementId) invalid('Unknown historical artifact');
    if (!curatedKinds.has(kind)) invalid('Invalid historical artifact curation kind');
    if (typeof label !== 'string' || !label.trim() || label.length > 255 ||
        /[\\/\x00-\x1f\x7f]/.test(label)) invalid('Invalid historical artifact label');
    if (typeof downloadName !== 'string' || !downloadName.trim() || downloadName.length > 255 ||
        /[\\/\x00-\x1f\x7f]/.test(downloadName) || downloadName === '.' || downloadName === '..') invalid('Invalid historical artifact download name');
    if (seen.has(artifactId)) invalid('Duplicate historical artifact curation');
    const labelKey = `${managementId}\0${kind}\0${label.trim().toLowerCase()}`;
    if (labels.has(labelKey)) invalid('Duplicate historical artifact label');
    seen.add(artifactId);
    labels.add(labelKey);
    selectedIds.add(managementId);
    if (kind === 'report') reports.add(managementId);
    return { artifactId, kind, label: label.trim(), downloadName: downloadName.trim(), order: index };
  });
  const allIds = db.prepare('SELECT DISTINCT management_id FROM history_artifacts').all().map(row => row.management_id);
  if (allIds.length !== selectedIds.size || allIds.some(id => !selectedIds.has(id) || !reports.has(id))) {
    invalid('Historical artifact curation must retain a report for every finding');
  }
  const prior = db.prepare('SELECT artifact_id, kind, label, download_name, display_order FROM history_artifact_curations ORDER BY display_order').all();
  const same = prior.length === entries.length && prior.every((row, index) =>
    row.artifact_id === entries[index].artifactId && row.kind === entries[index].kind &&
    row.label === entries[index].label && row.download_name === entries[index].downloadName && row.display_order === entries[index].order);
  if (same) return { total: entries.length, changed: 0, hidden: db.prepare('SELECT count(*) AS n FROM history_artifacts').get().n - entries.length };
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec('DELETE FROM history_artifact_curations');
    const insert = db.prepare('INSERT INTO history_artifact_curations (artifact_id, kind, label, download_name, display_order) VALUES (?, ?, ?, ?, ?)');
    for (const entry of entries) insert.run(entry.artifactId, entry.kind, entry.label, entry.downloadName, entry.order);
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return { total: entries.length, changed: 1, hidden: db.prepare('SELECT count(*) AS n FROM history_artifacts').get().n - entries.length };
}

function artifactRow(db, managementId, artifactId = null) {
  const curated = hasCuration(db);
  const from = curated
    ? 'FROM history_artifacts a JOIN history_artifact_curations c ON c.artifact_id = a.id'
    : 'FROM history_artifacts a';
  const select = curated
    ? 'SELECT a.id, c.kind, c.label AS name, c.download_name, a.name AS original_name, a.size, a.sha256 '
    : "SELECT a.id, CASE a.kind WHEN 'kasan' THEN 'verification' ELSE a.kind END AS kind, a.name, a.name AS download_name, a.name AS original_name, a.size, a.sha256 ";
  if (artifactId) return db.prepare(`${select}${from} WHERE a.id = ? AND a.management_id = ?`).get(artifactId, managementId);
  const order = curated ? 'c.display_order' : "CASE a.kind WHEN 'report' THEN 0 WHEN 'poc' THEN 1 ELSE 2 END, a.name, a.id";
  return db.prepare(`${select}${from} WHERE a.management_id = ? ORDER BY ${order}`).all(managementId);
}

export function importHistoryArtifacts(db, dataDir, sourceDir, manifest) {
  const entries = validateManifest(db, manifest);
  const sourceRoot = fs.realpathSync(sourceDir);
  if (!fs.statSync(sourceRoot).isDirectory()) invalid('Historical artifact source is not a directory');
  const destination = artifactDirectory(dataDir);
  fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(destination).isDirectory() || fs.lstatSync(destination).isSymbolicLink()) invalid('Historical artifact directory is unsafe');
  fs.chmodSync(destination, 0o700);
  const staged = [];
  const created = [];
  let totalBytes = 0;
  let inTransaction = false;
  try {
    for (const entry of entries) {
      const source = sourceFile(sourceRoot, entry.sourcePath);
      if (source.size > maxFileBytes) invalid('Historical artifact exceeds file limit');
      const temporary = path.join(destination, `.import-${randomBytes(16).toString('hex')}`);
      staged.push({ temporary });
      const copied = copyAndHash(source.file, temporary);
      totalBytes += copied.size;
      if (totalBytes > maxTotalBytes) invalid('Historical artifacts exceed import size limit');
      staged[staged.length - 1] = { ...entry, ...copied, temporary,
        id: createHash('sha256').update(`${entry.managementId}\0${entry.kind}\0${entry.sourcePath}`).digest('hex') };
    }
    const existing = db.prepare('SELECT * FROM history_artifacts WHERE id = ?');
    const insert = db.prepare('INSERT INTO history_artifacts (id, management_id, kind, name, sha256, size, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
    db.exec('BEGIN IMMEDIATE');
    inTransaction = true;
    let added = 0;
    for (const entry of staged) {
      const finalPath = path.join(destination, entry.id);
      const previous = existing.get(entry.id);
      if (previous) {
        if (previous.management_id !== entry.managementId || previous.kind !== entry.kind ||
            previous.name !== entry.name || previous.sha256 !== entry.sha256 || previous.size !== entry.size ||
            !fs.existsSync(finalPath) || !fs.lstatSync(finalPath).isFile() || fs.statSync(finalPath).size !== entry.size) {
          invalid('Historical artifact differs from existing record', 409);
        }
        continue;
      }
      if (fs.existsSync(finalPath)) invalid('Historical artifact storage conflict', 409);
      fs.renameSync(entry.temporary, finalPath);
      fs.chmodSync(finalPath, 0o600);
      created.push(finalPath);
      insert.run(entry.id, entry.managementId, entry.kind, entry.name, entry.sha256, entry.size, new Date().toISOString());
      added++;
    }
    db.exec('COMMIT');
    inTransaction = false;
    return { total: entries.length, added, bytes: totalBytes };
  } catch (error) {
    if (inTransaction) db.exec('ROLLBACK');
    for (const file of created) fs.rmSync(file, { force: true });
    throw error;
  } finally {
    for (const entry of staged) fs.rmSync(entry.temporary, { force: true });
  }
}

export function listHistoryArtifacts(db, managementId) {
  if (!idPattern.test(managementId) || !db.prepare('SELECT 1 FROM registry_history WHERE management_id = ?').get(managementId)) invalid('Historical finding not found', 404);
  const rows = artifactRow(db, managementId);
  return rows.map(row => ({ ...row, previewable: isPreviewable(row) }));
}

export function openHistoryArtifact(db, dataDir, managementId, artifactId) {
  if (!idPattern.test(managementId) || !artifactPattern.test(artifactId)) invalid('Historical artifact not found', 404);
  const row = artifactRow(db, managementId, artifactId);
  if (!row) invalid('Historical artifact not found', 404);
  const file = path.join(artifactDirectory(dataDir), artifactId);
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)); }
  catch { invalid('Historical artifact unavailable', 404); }
  const stat = fs.fstatSync(fd);
  if (!stat.isFile() || stat.size !== row.size) { fs.closeSync(fd); invalid('Historical artifact unavailable', 404); }
  return { ...row, previewable: isPreviewable(row), fd };
}

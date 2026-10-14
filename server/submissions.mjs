import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { hash, invalid, isStandaloneUserspacePoc, readFrontMatter } from './contract.mjs';
import { registerFinding, validateRegistryMetadata } from './registry.mjs';
import { listHistoryArtifacts, openHistoryArtifact } from './history-artifacts.mjs';

const MAX_FILES = 20;
const MAX_FILE_BYTES = 2_000_000;
const MAX_TOTAL_BYTES = 8_000_000;
const MAX_REPORT_BYTES = 1_000_000;
const MAX_SERIAL_BYTES = 600_000;
const MAX_PENDING_PER_AGENT = 30;
const MAX_PENDING_TOTAL = 300;
const MAX_STORED_BYTES = 4_000_000_000;
const LEASE_MS = 60 * 60_000;
const WORKER_ONLINE_MS = 60_000;
const PRIMITIVE_LEASE_MS = 10 * 60_000;
const MAX_PRIMITIVE_SUMMARY_BYTES = 6000;
const verificationPhases = new Set(['preparing', 'static_review', 'qemu_reproduction', 'trace_review', 'finalizing']);
const now = () => new Date().toISOString();
const commitPattern = /^[a-f0-9]{40,64}$/i;
const nfsPath = /^(?:fs\/(?:nfsd|nfs|nfs_common|lockd|exportfs)\/|net\/sunrpc\/|include\/(?:linux\/sunrpc|uapi\/linux\/nfsd)\/)[a-zA-Z0-9_./+-]+$/;
const existingIdPattern = /^A-\d{3,}$/;

function value(input, name, max, required = false) {
  if (input == null || input === '') {
    if (required) invalid(`Missing ${name}`);
    return null;
  }
  if (typeof input !== 'string' || !input.trim() || Buffer.byteLength(input) > max || input.includes('\0')) invalid(`Invalid ${name}`);
  return input.trim();
}

function object(input, name) {
  if (input == null) return {};
  if (typeof input !== 'object' || Array.isArray(input)) invalid(`Invalid ${name}`);
  return input;
}

function base64Bytes(encoded) {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 + 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) invalid('Invalid attachment encoding');
  const bytes = Buffer.from(encoded, 'base64');
  if (!bytes.length || bytes.length > MAX_FILE_BYTES || bytes.toString('base64') !== encoded) invalid('Invalid attachment size or encoding', 413);
  return bytes;
}

function findExistingManagementId(db, managementId) {
  const live = db.prepare(`SELECT r.finding_id, e.repo_commit, e.title, e.markdown,
      r.approved_at, r.superseded_by FROM finding_registry r
      JOIN events e ON e.id = r.finding_id
      WHERE r.management_id = ? AND r.target = 'knfsd'`).get(managementId);
  if (live?.approved_at && !live.superseded_by) return { kind: 'live', ...live };
  const historical = db.prepare("SELECT title FROM registry_history WHERE management_id = ? AND target = 'knfsd'").get(managementId);
  return historical ? { kind: 'history', ...historical } : null;
}

function existingFindingContext(db, managementId, dataDir) {
  const found = findExistingManagementId(db, managementId);
  if (!found) return null;
  if (found.kind === 'live') {
    const prior = db.prepare(`SELECT a.content FROM submission_artifacts a
      JOIN submissions s ON s.id = a.submission_id
      WHERE s.finding_id = ? AND s.status = 'approved' AND a.ordinal = 1000
      ORDER BY s.submitted_at DESC, s.id DESC LIMIT 1`).get(found.finding_id);
    const parsed = readFrontMatter(found.markdown);
    return { management_id: managementId, title: found.title, file_path: parsed.data.file_path ?? null,
      report: Buffer.from(prior?.content ?? parsed.body).toString('utf8').slice(0, 30_000) };
  }
  let report = null;
  if (dataDir) {
    const artifact = listHistoryArtifacts(db, managementId).find(item => item.kind === 'report');
    if (artifact) {
      let opened;
      try {
        opened = openHistoryArtifact(db, dataDir, managementId, artifact.id);
        const bytes = Buffer.alloc(Math.min(opened.size, 30_000));
        const length = opened.content
          ? opened.content.copy(bytes, 0, 0, bytes.length)
          : fs.readSync(opened.fd, bytes, 0, bytes.length, 0);
        report = new TextDecoder().decode(bytes.subarray(0, length));
      } catch { report = null; }
      finally { if (opened?.fd !== undefined) fs.closeSync(opened.fd); }
    }
  }
  return { management_id: managementId, title: found.title, file_path: null, report };
}

export function initializeSubmissions(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, client_submission_id TEXT,
      project TEXT NOT NULL, title TEXT, report TEXT, metadata_json TEXT NOT NULL,
      raw_sha256 TEXT NOT NULL, status TEXT NOT NULL, reason TEXT,
      submitted_at TEXT NOT NULL, claimed_at TEXT, completed_at TEXT,
      attempts INTEGER NOT NULL DEFAULT 0, finding_id TEXT, management_id TEXT,
      verification_json TEXT, lease_token TEXT, fingerprint TEXT,
      origin TEXT NOT NULL DEFAULT 'agent',
      UNIQUE(agent_id, client_submission_id)
    );
    CREATE TABLE IF NOT EXISTS submission_artifacts (
      submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
      ordinal INTEGER NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
      sha256 TEXT NOT NULL, size INTEGER NOT NULL, content BLOB NOT NULL,
      PRIMARY KEY(submission_id, ordinal)
    );
    CREATE INDEX IF NOT EXISTS submissions_status ON submissions(status, submitted_at);
    CREATE TABLE IF NOT EXISTS verifier_workers (
      worker_id TEXT PRIMARY KEY, target_commit TEXT NOT NULL,
      current_submission_id TEXT, started_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS primitive_reviews (
      finding_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'complete', 'error')),
      summary TEXT, requested_at TEXT NOT NULL, claimed_at TEXT, completed_at TEXT,
      last_activity_at TEXT, lease_token TEXT, retry_after TEXT, attempts INTEGER NOT NULL DEFAULT 0,
      worker_id TEXT
    );
    CREATE INDEX IF NOT EXISTS primitive_reviews_queue ON primitive_reviews(status, requested_at, finding_id);
    CREATE TABLE IF NOT EXISTS primitive_workers (
      worker_id TEXT PRIMARY KEY, current_finding_id TEXT,
      started_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS finding_revision_audit (
      submission_id TEXT PRIMARY KEY REFERENCES submissions(id),
      management_id TEXT NOT NULL, previous_event_json TEXT,
      previous_registry_json TEXT NOT NULL, recorded_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS finding_revision_audit_no_update
      BEFORE UPDATE ON finding_revision_audit BEGIN SELECT RAISE(ABORT, 'Finding revisions are append-only'); END;
    CREATE TRIGGER IF NOT EXISTS finding_revision_audit_no_delete
      BEFORE DELETE ON finding_revision_audit BEGIN SELECT RAISE(ABORT, 'Finding revisions are append-only'); END;
  `);
  const columns = new Set(db.prepare('PRAGMA table_info(submissions)').all().map(column => column.name));
  if (!columns.has('lease_token')) db.exec('ALTER TABLE submissions ADD COLUMN lease_token TEXT');
  if (!columns.has('fingerprint')) db.exec('ALTER TABLE submissions ADD COLUMN fingerprint TEXT');
  if (!columns.has('phase')) db.exec('ALTER TABLE submissions ADD COLUMN phase TEXT');
  if (!columns.has('phase_updated_at')) db.exec('ALTER TABLE submissions ADD COLUMN phase_updated_at TEXT');
  if (!columns.has('last_activity_at')) db.exec('ALTER TABLE submissions ADD COLUMN last_activity_at TEXT');
  if (!columns.has('origin')) db.exec("ALTER TABLE submissions ADD COLUMN origin TEXT NOT NULL DEFAULT 'agent'");
  if (!columns.has('accepted_json')) db.exec('ALTER TABLE submissions ADD COLUMN accepted_json TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS submissions_fingerprint ON submissions(fingerprint, status)');
  const primitiveColumns = new Set(db.prepare('PRAGMA table_info(primitive_reviews)').all().map(column => column.name));
  if (!primitiveColumns.has('retry_after')) db.exec('ALTER TABLE primitive_reviews ADD COLUMN retry_after TEXT');
  db.prepare(`INSERT OR IGNORE INTO primitive_reviews (finding_id, status, requested_at)
    SELECT finding_id, 'pending', completed_at FROM submissions
    WHERE status = 'approved' AND finding_id IS NOT NULL AND completed_at IS NOT NULL`).run();
}

export function listVerificationQueue(db) {
  const fields = `id AS submission_id, agent_id, origin,
    CASE WHEN origin = 'manual_upload' THEN json_extract(metadata_json, '$.reporter') END AS reporter,
    project, title, status, reason, submitted_at,
    claimed_at, completed_at, attempts, management_id,
    json_extract(metadata_json, '$.existing_management_id') AS existing_management_id,
    phase, phase_updated_at, last_activity_at,
    json_extract(metadata_json, '$.repo_commit') AS target_commit`;
  const rows = db.prepare(`SELECT ${fields} FROM submissions WHERE status IN ('pending', 'processing') ORDER BY submitted_at, id`).all();
  const activityCutoff = Date.now() - WORKER_ONLINE_MS;
  const active = [], pending = [];
  for (const row of rows) {
    const lastActivity = Date.parse(row.last_activity_at || row.claimed_at || '');
    const stale = row.status === 'processing' && (!Number.isFinite(lastActivity) || lastActivity < activityCutoff);
    const item = { ...row, phase: row.status === 'pending' ? 'queued' : row.phase,
      stale, position: null };
    if (row.status === 'processing') active.push(item);
    else if (row.status === 'pending') { item.position = pending.length + 1; pending.push(item); }
  }
  const blocked = db.prepare(`SELECT ${fields} FROM submissions WHERE status IN ('needs_evidence', 'needs_review', 'error', 'rejected')
    ORDER BY completed_at DESC, id DESC LIMIT 50`).all().map(row => ({ ...row, stale: false, position: null }));
  const blockedCount = db.prepare("SELECT COUNT(*) AS count FROM submissions WHERE status IN ('needs_evidence', 'needs_review', 'error', 'rejected')").get().count;
  const onlineCutoff = Date.now() - WORKER_ONLINE_MS;
  const processingIds = new Set(active.map(row => row.submission_id));
  const recent = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
  const workerRows = db.prepare('SELECT worker_id, target_commit, current_submission_id, started_at, last_seen_at FROM verifier_workers WHERE last_seen_at >= ? ORDER BY last_seen_at DESC, worker_id LIMIT 30').all(recent);
  const onlineTargets = new Set(workerRows.filter(row => Date.parse(row.last_seen_at) >= onlineCutoff).map(row => row.target_commit));
  const offlineTargets = new Set();
  const workers = workerRows
    .filter(row => {
      if (Date.parse(row.last_seen_at) >= onlineCutoff) return true;
      if (onlineTargets.has(row.target_commit) || offlineTargets.has(row.target_commit)) return false;
      offlineTargets.add(row.target_commit);
      return true;
    })
    .map(row => {
      const online = Date.parse(row.last_seen_at) >= onlineCutoff;
      const current = online && processingIds.has(row.current_submission_id) ? row.current_submission_id : null;
      return { ...row, role: 'verifier', current_submission_id: current, status: online ? current ? 'busy' : 'idle' : 'offline' };
    });
  const primitivePending = db.prepare(`SELECT p.finding_id, r.management_id, e.title, p.requested_at, p.retry_after
    FROM primitive_reviews p JOIN finding_registry r ON r.finding_id = p.finding_id
    JOIN events e ON e.id = p.finding_id WHERE p.status = 'pending'
    ORDER BY p.requested_at, p.finding_id LIMIT 50`).all();
  const primitiveActive = db.prepare(`SELECT p.finding_id, r.management_id, e.title, p.claimed_at, p.last_activity_at
    FROM primitive_reviews p JOIN finding_registry r ON r.finding_id = p.finding_id
    JOIN events e ON e.id = p.finding_id WHERE p.status = 'processing'
    ORDER BY p.claimed_at, p.finding_id`).all();
  const primitiveErrors = db.prepare(`SELECT p.finding_id, r.management_id, e.title, p.summary, p.completed_at
    FROM primitive_reviews p JOIN finding_registry r ON r.finding_id = p.finding_id
    JOIN events e ON e.id = p.finding_id WHERE p.status = 'error'
    ORDER BY p.completed_at DESC, p.finding_id DESC LIMIT 50`).all();
  const primitiveCounts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) AS count FROM primitive_reviews GROUP BY status').all()
    .map(row => [row.status, row.count]));
  const primitiveRows = db.prepare(`SELECT w.worker_id, w.current_finding_id, w.started_at, w.last_seen_at,
      r.management_id AS current_management_id, e.title AS current_title, p.status AS review_status
    FROM primitive_workers w LEFT JOIN primitive_reviews p ON p.finding_id = w.current_finding_id
    LEFT JOIN finding_registry r ON r.finding_id = w.current_finding_id
    LEFT JOIN events e ON e.id = w.current_finding_id
    WHERE w.last_seen_at >= ? ORDER BY w.last_seen_at DESC, w.worker_id LIMIT 10`).all(recent);
  const anyPrimitiveOnline = primitiveRows.some(row => Date.parse(row.last_seen_at) >= onlineCutoff);
  const visiblePrimitiveWorkers = anyPrimitiveOnline
    ? primitiveRows.filter(row => Date.parse(row.last_seen_at) >= onlineCutoff)
    : primitiveRows.slice(0, 1);
  for (const row of visiblePrimitiveWorkers) {
    const online = Date.parse(row.last_seen_at) >= onlineCutoff;
    const current = online && row.review_status === 'processing' ? row.current_finding_id : null;
    workers.push({ worker_id: row.worker_id, role: 'primitive', target_commit: null,
      current_submission_id: null, current_finding_id: current,
      current_management_id: current ? row.current_management_id : null,
      current_title: current ? row.current_title : null,
      pending_count: primitiveCounts.pending || 0,
      started_at: row.started_at, last_seen_at: row.last_seen_at,
      status: online ? current ? 'busy' : 'idle' : 'offline' });
  }
  return { counts: { processing: active.length, pending: pending.length, blocked: blockedCount },
    active, pending, blocked, blocked_has_more: blockedCount > blocked.length, workers,
    primitive: { pending: primitivePending, active: primitiveActive, errors: primitiveErrors,
      counts: { pending: primitiveCounts.pending || 0, processing: primitiveCounts.processing || 0,
        complete: primitiveCounts.complete || 0, error: primitiveCounts.error || 0 } } };
}

export function submitSubmission(db, input, agentId, origin = 'agent') {
  if (!['agent', 'manual_upload'].includes(origin)) invalid('Invalid submission origin');
  if (!input || typeof input !== 'object' || Array.isArray(input) || input.project !== 'knfsd') invalid('Only knfsd submissions are supported');
  const clientId = value(input.client_submission_id, 'client_submission_id', 128);
  if (clientId && !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(clientId)) invalid('Invalid client_submission_id');
  const title = value(input.title, 'title', 300);
  const report = value(input.report, 'report', MAX_REPORT_BYTES);
  const metadata = object(input.metadata, 'metadata');
  const existingManagementId = metadata.existing_management_id;
  if (existingManagementId != null &&
      (typeof existingManagementId !== 'string' || !existingIdPattern.test(existingManagementId))) {
    invalid('Invalid existing_management_id');
  }
  const metadataJson = JSON.stringify(metadata);
  if (Buffer.byteLength(metadataJson) > 20_000) invalid('Metadata too large', 413);
  if (!Array.isArray(input.files) || input.files.length > MAX_FILES) invalid('Invalid files');
  let total = Buffer.byteLength(report || '');
  const seen = new Set();
  const files = input.files.map((file, ordinal) => {
    if (!file || typeof file !== 'object' || Array.isArray(file)) invalid('Invalid attachment');
    const name = value(file.name, 'attachment name', 160, true);
    if (name === '.' || name === '..' || /[/\\\x00-\x1f\x7f]/.test(name) || seen.has(name.toLowerCase())) invalid('Unsafe or duplicate attachment name');
    seen.add(name.toLowerCase());
    const kind = file.kind ?? 'other';
    if (!['report', 'poc', 'log', 'other'].includes(kind)) invalid('Invalid attachment kind');
    const bytes = base64Bytes(file.content_base64);
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) invalid('Submission too large', 413);
    return { ordinal, name, kind, bytes, sha256: hash(bytes) };
  });
  if (!report && !files.length) invalid('A report or attachment is required');
  const digest = hash(JSON.stringify({ project: input.project, title, report, metadata, files: files.map(file => [file.name, file.kind, file.sha256]) }));
  const id = hash(`${agentId}\0${clientId || digest}`);
  db.exec('BEGIN IMMEDIATE');
  try {
    const existing = db.prepare('SELECT raw_sha256, status, origin FROM submissions WHERE id = ?').get(id);
    if (existing) {
      if (existing.raw_sha256 !== digest || existing.origin !== origin) invalid('client_submission_id was reused with different content', 409);
      db.exec('COMMIT');
      return { submission_id: id, status: existing.status, replayed: true };
    }
    if (existingManagementId && !findExistingManagementId(db, existingManagementId)) {
      invalid('Existing verified knfsd finding not found', 404);
    }
    const backlog = db.prepare("SELECT COUNT(*) AS total, SUM(agent_id = ?) AS own FROM submissions WHERE status IN ('pending', 'processing')").get(agentId);
    if (backlog.total >= MAX_PENDING_TOTAL || backlog.own >= MAX_PENDING_PER_AGENT) invalid('Verification queue is full', 429);
    const stored = db.prepare('SELECT COALESCE(SUM(size), 0) AS bytes FROM submission_artifacts').get().bytes +
      db.prepare('SELECT COALESCE(SUM(length(CAST(report AS BLOB))), 0) AS bytes FROM submissions').get().bytes;
    if (stored + total > MAX_STORED_BYTES) invalid('Submission storage is full', 507);
    db.prepare(`INSERT INTO submissions
      (id, agent_id, client_submission_id, project, title, report, metadata_json, raw_sha256, status, submitted_at, origin)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`).run(id, agentId, clientId, input.project, title, report, metadataJson, digest, now(), origin);
    const insert = db.prepare('INSERT INTO submission_artifacts VALUES (?, ?, ?, ?, ?, ?, ?)');
    for (const file of files) insert.run(id, file.ordinal, file.name, file.kind, file.sha256, file.bytes.length, file.bytes);
    db.exec('COMMIT');
    return { submission_id: id, status: 'pending', replayed: false };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function listSubmissions(db, agentId = null) {
  const sql = `SELECT id AS submission_id, agent_id, project, title, status, reason,
    submitted_at, completed_at, management_id FROM submissions`;
  return agentId
    ? db.prepare(`${sql} WHERE agent_id = ? ORDER BY submitted_at DESC LIMIT 200`).all(agentId)
    : db.prepare(`${sql} ORDER BY submitted_at DESC LIMIT 200`).all();
}

export function getSubmission(db, id, agentId = null) {
  const row = db.prepare('SELECT id AS submission_id, agent_id, project, title, status, reason, submitted_at, completed_at, management_id, finding_id FROM submissions WHERE id = ?').get(id);
  if (!row || agentId && row.agent_id !== agentId) invalid('Submission not found', 404);
  return row;
}

export function listVerifiedArtifacts(db, findingId) {
  return db.prepare(`SELECT a.name, a.kind, a.sha256, a.size
    FROM submission_artifacts a WHERE a.submission_id = (
      SELECT id FROM submissions WHERE finding_id = ? AND status = 'approved'
      ORDER BY submitted_at DESC, id DESC LIMIT 1)
      AND a.ordinal BETWEEN 1000 AND 1003 ORDER BY a.ordinal`).all(findingId);
}

export function getVerifiedArtifact(db, findingId, filename) {
  if (!Object.values(artifactFiles).includes(filename)) invalid('Unknown artifact', 404);
  const row = db.prepare(`SELECT a.content FROM submission_artifacts a WHERE a.submission_id = (
      SELECT id FROM submissions WHERE finding_id = ? AND status = 'approved'
      ORDER BY submitted_at DESC, id DESC LIMIT 1)
      AND a.name = ? AND a.ordinal BETWEEN 1000 AND 1003`).get(findingId, filename);
  if (!row) invalid('Artifact not found', 404);
  return Buffer.from(row.content);
}

export function retrySubmission(db, id) {
  const row = db.prepare('SELECT status FROM submissions WHERE id = ?').get(id);
  if (!row) invalid('Submission not found', 404);
  if (!['error', 'needs_evidence', 'needs_review'].includes(row.status)) invalid('Submission cannot be retried', 409);
  db.prepare("UPDATE submissions SET status = 'pending', reason = NULL, claimed_at = NULL, completed_at = NULL, lease_token = NULL, phase = NULL, phase_updated_at = NULL, last_activity_at = NULL WHERE id = ?").run(id);
  return getSubmission(db, id);
}

export function claimSubmission(db, targetCommit = null, dataDir = null) {
  if (targetCommit !== null && (typeof targetCommit !== 'string' || !/^[a-f0-9]{40}$/.test(targetCommit))) invalid('Invalid target_commit');
  db.exec('BEGIN IMMEDIATE');
  try {
    const stale = new Date(Date.now() - LEASE_MS).toISOString();
    db.prepare("UPDATE submissions SET status = 'pending', reason = 'worker lease expired', claimed_at = NULL, lease_token = NULL, phase = NULL, phase_updated_at = NULL, last_activity_at = NULL WHERE status = 'processing' AND COALESCE(last_activity_at, claimed_at) < ? AND attempts < 3").run(stale);
    db.prepare("UPDATE submissions SET status = 'error', reason = 'worker lease expired after retries', completed_at = ?, lease_token = NULL, phase = NULL WHERE status = 'processing' AND COALESCE(last_activity_at, claimed_at) < ? AND attempts >= 3").run(now(), stale);
    const row = targetCommit === null
      ? db.prepare("SELECT * FROM submissions WHERE status = 'pending' ORDER BY submitted_at, id LIMIT 1").get()
      : db.prepare("SELECT * FROM submissions WHERE status = 'pending' AND json_extract(metadata_json, '$.repo_commit') = ? ORDER BY submitted_at, id LIMIT 1").get(targetCommit);
    if (!row) { db.exec('COMMIT'); return null; }
    const leaseToken = randomBytes(32).toString('hex');
    const claimedAt = now();
    db.prepare("UPDATE submissions SET status = 'processing', claimed_at = ?, lease_token = ?, attempts = attempts + 1, phase = 'preparing', phase_updated_at = ?, last_activity_at = ? WHERE id = ?").run(claimedAt, leaseToken, claimedAt, claimedAt, row.id);
    const files = db.prepare('SELECT name, kind, content FROM submission_artifacts WHERE submission_id = ? ORDER BY ordinal').all(row.id)
      .map(file => ({ name: file.name, kind: file.kind, content_base64: Buffer.from(file.content).toString('base64') }));
    const metadata = JSON.parse(row.metadata_json);
    const existingFinding = metadata.existing_management_id
      ? existingFindingContext(db, metadata.existing_management_id, dataDir) : null;
    db.exec('COMMIT');
    return { submission_id: row.id, lease_token: leaseToken, agent_id: row.agent_id,
      project: row.project, title: row.title, report: row.report, metadata, files,
      ...(metadata.existing_management_id ? { existing_finding: existingFinding } : {}) };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

function utf8(bytes) {
  const decoded = Buffer.from(bytes).toString('utf8');
  return Buffer.from(decoded, 'utf8').equals(bytes) ? decoded : null;
}

function checkedPoc(db, submissionId, normalized) {
  const poc = normalized?.poc;
  if (!poc || typeof poc !== 'object') return null;
  const source = poc.source;
  if (typeof source !== 'string' || !source.trim() || Buffer.byteLength(source) > 250_000 || source.includes('\0')) invalid('Invalid normalized PoC');
  if (poc.language !== 'c') invalid('A standalone C PoC is required', 422);
  const files = db.prepare('SELECT ordinal, name, kind, content FROM submission_artifacts WHERE submission_id = ? ORDER BY ordinal').all(submissionId);
  const cSource = file => /\.c$/i.test(file.name) && /\b(?:int|signed|void)\s+main\s*\(/.test(utf8(file.content) || '');
  const selected = files.find(file => file.ordinal === poc.source_index && file.name === poc.original_name &&
    utf8(file.content) === source && cSource(file));
  if (!selected) invalid('Normalized PoC must match a submitted source file', 422);
  if (!isStandaloneUserspacePoc(source, 'cc -o poc poc.c')) invalid('PoC is not a standalone userspace C program', 422);
  return { source, language: 'c', filename: 'poc.c' };
}

function kasanEvidence(serial, filePath, codeRefs, relevance) {
  if (typeof serial !== 'string' || Buffer.byteLength(serial) > MAX_SERIAL_BYTES) invalid('Invalid server VM evidence', 413);
  const headers = [...serial.matchAll(/^[^\r\n]*BUG:\s*KASAN:\s*[^\r\n]+/gim)];
  const symbols = (Array.isArray(codeRefs) ? codeRefs : []).flatMap(ref => {
    if (typeof ref !== 'string' || !ref.startsWith(filePath)) return [];
    const symbol = /[#:]([A-Za-z_][A-Za-z0-9_]{5,})\b/.exec(ref)?.[1];
    return symbol ? [symbol] : [];
  });
  for (let index = 0; index < headers.length; index += 1) {
    const log = serial.slice(headers[index].index, headers[index + 1]?.index ?? serial.length).slice(0, 500_000).trim();
    const impacts = [];
    if (/\bRead of size\s+\d+\b/i.test(log)) impacts.push('kasan_read');
    if (/\bWrite of size\s+\d+\b/i.test(log)) impacts.push('kasan_write');
    if (!impacts.length) continue;
    const matchesPath = log.includes(filePath);
    const matchesSymbol = symbols.some(symbol => new RegExp(`\\b${symbol}\\b`).test(log));
    const traceLine = relevance?.trace_line;
    const matchesSymbolizedFrame = typeof traceLine === 'string' && traceLine.trim() &&
      !/BUG:\s*KASAN:/.test(traceLine) && log.split(/\r?\n/).some(line => line.trim() === traceLine.trim());
    if (matchesSymbolizedFrame && (matchesPath || matchesSymbol || relevance?.symbolized_path === filePath)) return { log, impacts };
  }
  return null;
}

function groundedRelevance(review, commit, filePath, evidence, poc) {
  const grounding = review.grounding;
  const relevance = review.relevance;
  if (!grounding || grounding.source_commit !== commit || !Array.isArray(grounding.evidence) ||
      relevance?.verdict !== 'supports' || relevance.source_path !== filePath ||
      relevance.symbolized_path !== filePath || !Number.isInteger(relevance.symbolized_line) || relevance.symbolized_line < 1 ||
      !Number.isInteger(relevance.source_line) || relevance.source_line < 1 ||
      !Number.isInteger(relevance.poc_line) || relevance.poc_line < 1) return false;
  const sourceLine = grounding.evidence.find(item => item?.path === filePath && item.line === relevance.source_line &&
    typeof item.text === 'string' && item.text.trim());
  if (!sourceLine || typeof relevance.trace_line !== 'string' || !relevance.trace_line.trim() ||
      !evidence.log.split(/\r?\n/).some(line => line.trim() === relevance.trace_line.trim())) return false;
  return Boolean(poc.source.split(/\r?\n/)[relevance.poc_line - 1]?.trim());
}

function frontMatter(data, report) {
  const lines = ['---'];
  for (const [key, item] of Object.entries(data)) {
    if (Array.isArray(item)) {
      if (!item.length) lines.push(`${key}: []`);
      else lines.push(`${key}:`, ...item.map(value => `  - ${JSON.stringify(value)}`));
    } else lines.push(`${key}: ${JSON.stringify(item)}`);
  }
  return [...lines, '---', '', report.trim(), ''].join('\n');
}

function mark(db, id, status, reason, summary) {
  db.prepare('UPDATE submissions SET status = ?, reason = ?, verification_json = ?, completed_at = ?, lease_token = NULL WHERE id = ?')
    .run(status, String(reason).slice(0, 1000), JSON.stringify(summary), now(), id);
  return getSubmission(db, id);
}

function checkLease(row, token) {
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) ||
      !row?.lease_token || !timingSafeEqual(Buffer.from(row.lease_token, 'hex'), Buffer.from(token, 'hex'))) invalid('Invalid or expired verifier lease', 409);
}

const reportSections = ['Summary', 'Root cause', 'Reproduction environment', 'PoC', 'Impact analysis'];
const artifactFiles = { report: 'report.md', poc: 'poc.c', reproduction: 'reproduction.md', log: 'kasan.log' };

function canonicalTitle(input) {
  if (typeof input !== 'string') return null;
  const title = input.replace(/^\s*#+\s*/, '').replace(/\s+/g, ' ').trim();
  return title.length >= 8 && Buffer.byteLength(title) <= 300 && !/[\x00-\x1f\x7f]/.test(title) ? title : null;
}

function canonicalNfsVersion(input) {
  const match = /^(?:NFS\s*v?)?\s*(3|4(?:\.0|\.1|\.2)?)$/i.exec(String(input ?? '').trim());
  return match ? (match[1] === '4.0' ? '4' : match[1]) : null;
}

function canonicalPermission(input) {
  const value = String(input ?? '').trim().replace(/\s+/g, ' ').toUpperCase();
  if (['AUTH_SYS', 'AUTH_UNIX', 'SEC=SYS'].includes(value)) return 'AUTH_SYS';
  if (['AUTH_NONE', 'AUTH_NULL'].includes(value)) return 'AUTH_NONE';
  if (['RPCSEC_GSS', 'KERBEROS', 'SEC=KRB5'].includes(value)) return 'RPCSEC_GSS';
  if (value === 'AUTH DOMAIN') return 'Auth domain';
  return null;
}

function canonicalVulnerabilityType(input) {
  const aliases = new Map([
    ['race', 'Race'], ['uaf', 'UAF'], ['use after free', 'UAF'], ['oob read', 'OOB Read'],
    ['out of bounds read', 'OOB Read'], ['oob write', 'OOB Write'], ['out of bounds write', 'OOB Write'],
    ['uninitialized read', 'Uninitialized Read'], ['integer overflow', 'Integer Overflow'],
    ['resource leak', 'Resource Leak'], ['memory leak', 'Resource Leak'], ['logical', 'Logical'],
    ['double free', 'Double Free'], ['null dereference', 'NULL Dereference'], ['type confusion', 'Type Confusion'],
  ]);
  if (typeof input !== 'string') return null;
  const parts = input.split(',').map(part => aliases.get(part.trim().toLowerCase()));
  const order = ['Race', 'UAF', 'OOB Read', 'OOB Write', 'Uninitialized Read', 'Integer Overflow',
    'Resource Leak', 'Logical', 'Double Free', 'NULL Dereference', 'Type Confusion'];
  return parts.length && parts.length <= 4 && parts.every(Boolean)
    ? [...new Set(parts)].sort((left, right) => order.indexOf(left) - order.indexOf(right)).join(', ') : null;
}

function checkedArtifacts(result, review, poc, evidence) {
  const bundle = result.artifacts;
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return null;
  const limits = { report: MAX_REPORT_BYTES, poc: 250_000, reproduction: 100_000, log: 500_000 };
  for (const [role, filename] of Object.entries(artifactFiles)) {
    const item = bundle[role];
    const content = role === 'poc' ? item?.source : item?.content;
    if (!item || typeof item !== 'object' || Array.isArray(item) || item.filename !== filename ||
        typeof content !== 'string' || !content.trim() || Buffer.byteLength(content) > limits[role] || content.includes('\0')) return null;
  }
  if (bundle.poc.source !== poc.source ||
      bundle.poc.source_index !== review.normalized?.poc?.source_index || bundle.log.content.trim() !== evidence.log) return null;
  const headings = [...bundle.report.content.matchAll(/^##\s+(.+?)\s*$/gm)].map(match => match[1]);
  if (headings.length !== reportSections.length || headings.some((heading, index) => heading !== reportSections[index])) return null;
  const sections = bundle.report.content.split(/^##\s+.+?\s*$/gm).slice(1);
  if (sections.length !== reportSections.length || sections.some(section => !section.trim())) return null;
  if (!review.grounding?.evidence?.some(line => line.path === review.normalized.file_path &&
      typeof line.text === 'string' && line.text.trim() && sections[1].includes(line.text.trim()))) return null;
  return bundle;
}

export function progressSubmission(db, id, phase, leaseToken) {
  if (typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id) || !verificationPhases.has(phase)) invalid('Invalid verifier progress');
  const row = db.prepare('SELECT status, lease_token FROM submissions WHERE id = ?').get(id);
  if (row?.status !== 'processing') invalid('Submission is not processing', 409);
  checkLease(row, leaseToken);
  const at = now();
  db.prepare('UPDATE submissions SET phase = ?, phase_updated_at = CASE WHEN phase = ? THEN phase_updated_at ELSE ? END, last_activity_at = ? WHERE id = ?')
    .run(phase, phase, at, at, id);
  return { submission_id: id, phase, phase_updated_at: db.prepare('SELECT phase_updated_at FROM submissions WHERE id = ?').get(id).phase_updated_at };
}

export function heartbeatWorker(db, input) {
  const workerId = input?.worker_id;
  const targetCommit = input?.target_commit;
  const submissionId = input?.submission_id ?? null;
  if (typeof workerId !== 'string' || !/^[a-f0-9]{32}$/.test(workerId) ||
      typeof targetCommit !== 'string' || !/^[a-f0-9]{40}$/.test(targetCommit) ||
      submissionId !== null && (typeof submissionId !== 'string' || !/^[a-f0-9]{64}$/.test(submissionId))) invalid('Invalid worker heartbeat');
  if (submissionId !== null) {
    const row = db.prepare("SELECT status, lease_token, json_extract(metadata_json, '$.repo_commit') AS target_commit FROM submissions WHERE id = ?").get(submissionId);
    if (row?.status !== 'processing' || row.target_commit !== targetCommit) invalid('Submission is not processing on this kernel', 409);
    checkLease(row, input.lease_token);
  } else if (input.lease_token != null) invalid('Idle heartbeat cannot include a lease token');
  const at = now();
  db.exec('BEGIN IMMEDIATE');
  try {
    if (submissionId !== null) db.prepare('UPDATE submissions SET last_activity_at = ? WHERE id = ?').run(at, submissionId);
    db.prepare(`INSERT INTO verifier_workers (worker_id, target_commit, current_submission_id, started_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(worker_id) DO UPDATE SET target_commit = excluded.target_commit,
      current_submission_id = excluded.current_submission_id, last_seen_at = excluded.last_seen_at`)
      .run(workerId, targetCommit, submissionId, at, at);
    db.prepare('DELETE FROM verifier_workers WHERE last_seen_at < ?').run(new Date(Date.now() - 24 * 60 * 60_000).toISOString());
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return { worker_id: workerId, last_seen_at: at };
}

function primitiveWorkerId(input) {
  if (typeof input !== 'string' || !/^[a-f0-9]{32}$/.test(input)) invalid('Invalid primitive worker_id');
  return input;
}

function primitiveFindingId(input) {
  if (typeof input !== 'string' || !/^[a-f0-9]{64}$/.test(input)) invalid('Invalid primitive finding_id');
  return input;
}

function supportedPrimitiveCommits(input) {
  if (!Array.isArray(input) || input.length > 16 ||
      input.some(commit => typeof commit !== 'string' || !/^[a-f0-9]{40}$/.test(commit)) ||
      new Set(input).size !== input.length) invalid('Invalid supported_commits');
  return input;
}

function primitiveLease(row, token) {
  if (row?.status !== 'processing') invalid('Primitive review is not processing', 409);
  checkLease(row, token);
}

export function claimPrimitiveReview(db, workerId, supportedCommits) {
  primitiveWorkerId(workerId);
  const commits = supportedPrimitiveCommits(supportedCommits);
  db.exec('BEGIN IMMEDIATE');
  try {
    const stale = new Date(Date.now() - PRIMITIVE_LEASE_MS).toISOString();
    db.prepare(`UPDATE primitive_reviews SET status = 'pending', claimed_at = NULL, last_activity_at = NULL,
      lease_token = NULL, worker_id = NULL, retry_after = ?
      WHERE status = 'processing' AND last_activity_at < ? AND attempts < 3`)
      .run(new Date(Date.now() + 30_000).toISOString(), stale);
    db.prepare(`UPDATE primitive_reviews SET status = 'error', summary = 'Primitive review lease expired after retries',
      completed_at = ?, lease_token = NULL, worker_id = NULL, retry_after = NULL
      WHERE status = 'processing' AND last_activity_at < ? AND attempts >= 3`).run(now(), stale);
    if (!commits.length) { db.exec('COMMIT'); return null; }
    const placeholders = commits.map(() => '?').join(', ');
    const row = db.prepare(`SELECT p.finding_id, r.management_id, r.privilege, r.nfs_version,
        e.title, e.repo_commit, e.markdown, s.id AS submission_id
      FROM primitive_reviews p JOIN finding_registry r ON r.finding_id = p.finding_id
      JOIN events e ON e.id = p.finding_id
      JOIN submissions s ON s.id = (SELECT id FROM submissions
        WHERE finding_id = p.finding_id AND status = 'approved'
        ORDER BY submitted_at DESC, id DESC LIMIT 1)
      WHERE p.status = 'pending' AND e.repo_commit IN (${placeholders})
        AND (p.retry_after IS NULL OR p.retry_after <= ?)
      ORDER BY p.requested_at, p.finding_id LIMIT 1`).get(...commits, now());
    if (!row) { db.exec('COMMIT'); return null; }
    const artifacts = db.prepare(`SELECT ordinal, content FROM submission_artifacts
      WHERE submission_id = ? AND ordinal IN (1000, 1001, 1003) ORDER BY ordinal`).all(row.submission_id);
    if (artifacts.length !== 3 || artifacts.some((item, index) => item.ordinal !== [1000, 1001, 1003][index])) {
      db.prepare(`UPDATE primitive_reviews SET status = 'error', summary = 'Canonical verification artifacts are missing',
        completed_at = ? WHERE finding_id = ?`).run(now(), row.finding_id);
      db.exec('COMMIT');
      return null;
    }
    const { data } = readFrontMatter(row.markdown);
    const at = now();
    const leaseToken = randomBytes(32).toString('hex');
    db.prepare(`UPDATE primitive_reviews SET status = 'processing', claimed_at = ?, last_activity_at = ?,
      lease_token = ?, retry_after = NULL, attempts = attempts + 1, worker_id = ? WHERE finding_id = ?`)
      .run(at, at, leaseToken, workerId, row.finding_id);
    db.exec('COMMIT');
    return { finding_id: row.finding_id, management_id: row.management_id, title: row.title,
      repo_commit: row.repo_commit, file_path: data.file_path ?? null,
      code_refs: Array.isArray(data.code_refs) ? data.code_refs : [],
      nfs_version: row.nfs_version, privilege: row.privilege,
      verified_impacts: Array.isArray(data.verified_impacts) ? data.verified_impacts : [],
      report: Buffer.from(artifacts[0].content).toString('utf8'),
      poc_source: Buffer.from(artifacts[1].content).toString('utf8'),
      kasan_log: Buffer.from(artifacts[2].content).toString('utf8'), lease_token: leaseToken };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function heartbeatPrimitiveWorker(db, input) {
  const workerId = primitiveWorkerId(input?.worker_id);
  const findingId = input?.finding_id == null ? null : primitiveFindingId(input.finding_id);
  if (findingId === null && input?.lease_token != null) invalid('Idle primitive heartbeat cannot include a lease token');
  const at = now();
  db.exec('BEGIN IMMEDIATE');
  try {
    if (findingId !== null) {
      const row = db.prepare('SELECT status, lease_token, worker_id FROM primitive_reviews WHERE finding_id = ?').get(findingId);
      primitiveLease(row, input.lease_token);
      if (row.worker_id !== workerId) invalid('Primitive worker does not own this review', 409);
      db.prepare('UPDATE primitive_reviews SET last_activity_at = ? WHERE finding_id = ?').run(at, findingId);
    }
    db.prepare(`INSERT INTO primitive_workers(worker_id, current_finding_id, started_at, last_seen_at)
      VALUES (?, ?, ?, ?) ON CONFLICT(worker_id) DO UPDATE SET
      current_finding_id = excluded.current_finding_id, last_seen_at = excluded.last_seen_at`)
      .run(workerId, findingId, at, at);
    db.prepare('DELETE FROM primitive_workers WHERE last_seen_at < ?')
      .run(new Date(Date.now() - 24 * 60 * 60_000).toISOString());
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return { worker_id: workerId, last_seen_at: at };
}

export function completePrimitiveReview(db, findingId, summary, leaseToken) {
  primitiveFindingId(findingId);
  const normalized = summary === null || typeof summary === 'string' && !summary.trim()
    ? null : value(summary, 'primitive review summary', MAX_PRIMITIVE_SUMMARY_BYTES, true);
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db.prepare('SELECT status, lease_token, summary FROM primitive_reviews WHERE finding_id = ?').get(findingId);
    if (!row) invalid('Primitive review not found', 404);
    if (row.status === 'complete') {
      if (row.summary !== normalized) invalid('Primitive review already completed with different content', 409);
      db.exec('COMMIT');
      return { finding_id: findingId, status: 'complete', replayed: true };
    }
    primitiveLease(row, leaseToken);
    db.prepare(`UPDATE primitive_reviews SET status = 'complete', summary = ?, completed_at = ?,
      last_activity_at = ?, lease_token = NULL WHERE finding_id = ?`).run(normalized, now(), now(), findingId);
    db.exec('COMMIT');
    return { finding_id: findingId, status: 'complete', replayed: false };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function failPrimitiveReview(db, findingId, reason, leaseToken) {
  primitiveFindingId(findingId);
  const message = value(reason, 'primitive failure reason', 1000, true);
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db.prepare('SELECT status, lease_token, attempts FROM primitive_reviews WHERE finding_id = ?').get(findingId);
    if (!row) invalid('Primitive review not found', 404);
    primitiveLease(row, leaseToken);
    if (row.attempts < 3) {
      const retryAfter = new Date(Date.now() + 30_000 * 2 ** (row.attempts - 1)).toISOString();
      db.prepare(`UPDATE primitive_reviews SET status = 'pending', summary = NULL, claimed_at = NULL,
        last_activity_at = NULL, lease_token = NULL, worker_id = NULL, retry_after = ? WHERE finding_id = ?`)
        .run(retryAfter, findingId);
      db.exec('COMMIT');
      return { finding_id: findingId, status: 'pending', retry_after: retryAfter };
    }
    db.prepare(`UPDATE primitive_reviews SET status = 'error', summary = ?, completed_at = ?,
      lease_token = NULL, retry_after = NULL WHERE finding_id = ?`).run(message, now(), findingId);
    db.exec('COMMIT');
    return { finding_id: findingId, status: 'error', retry_after: null };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function failSubmission(db, id, reason, leaseToken) {
  const row = db.prepare('SELECT status, lease_token FROM submissions WHERE id = ?').get(id);
  if (!row) invalid('Submission not found', 404);
  if (row.status !== 'processing') invalid('Submission is not processing', 409);
  checkLease(row, leaseToken);
  return mark(db, id, 'error', value(reason, 'failure reason', 1000, true), { error: true });
}

export function completeSubmission(db, id, result, leaseToken) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) invalid('Invalid verification result');
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db.prepare('SELECT * FROM submissions WHERE id = ?').get(id);
    if (!row) invalid('Submission not found', 404);
    if (row.status === 'approved') { db.exec('COMMIT'); return getSubmission(db, id); }
    if (row.status !== 'processing') invalid('Submission is not processing', 409);
    checkLease(row, leaseToken);
    const review = object(result.review, 'review');
    const run = object(result.reproduction, 'reproduction');
    const metadata = JSON.parse(row.metadata_json);
    const existingManagementId = metadata.existing_management_id ?? null;
    if (!['likely', 'unlikely', 'uncertain'].includes(review.verdict)) invalid('Invalid static verdict');
    if (!['observed', 'not_observed', 'inconclusive'].includes(run.status)) invalid('Invalid reproduction status');
    const summary = { static_verdict: review.verdict, dynamic_status: run.status,
      kernel_commit: run.kernelCommit ?? null, observation: run.observation ?? null,
      ...(existingManagementId ? { same_root_cause: {
        verdict: ['same', 'different', 'uncertain'].includes(review.same_root_cause?.verdict)
          ? review.same_root_cause.verdict : 'uncertain',
        reason: typeof review.same_root_cause?.reason === 'string'
          ? review.same_root_cause.reason.slice(0, 1000) : null,
      } } : {}) };
    const reason = value(review.reason, 'review reason', 1000) || value(run.reason, 'reproduction reason', 1000) || 'Verification completed';
    if (review.verdict === 'unlikely') { const out = mark(db, id, 'needs_review', reason, summary); db.exec('COMMIT'); return out; }
    if (review.verdict !== 'likely') { const out = mark(db, id, 'needs_review', reason, summary); db.exec('COMMIT'); return out; }
    if (existingManagementId && review.same_root_cause?.verdict !== 'same') {
      const out = mark(db, id, 'needs_review', 'Same root cause as the existing finding was not established', summary);
      db.exec('COMMIT'); return out;
    }
    if (run.status === 'not_observed' && run.observation?.guestCompleted && run.observation?.targetCommitMatch) {
      const out = mark(db, id, 'rejected', value(run.reason, 'reproduction reason', 1000) || 'PoC did not reproduce in two VMs', summary);
      db.exec('COMMIT'); return out;
    }
    if (run.status !== 'observed' || !run.observation?.guestCompleted || !run.observation?.targetCommitMatch ||
        !run.observation?.baselineClean || !run.observation?.pocStarted || !run.observation?.serverEvidenceAfterPoc) {
      const out = mark(db, id, 'needs_evidence', value(run.reason, 'reproduction reason', 1000) || 'Two-VM reproduction was inconclusive', summary);
      db.exec('COMMIT'); return out;
    }
    const commit = value(metadata.repo_commit, 'repo_commit', 64);
    const version = value(metadata.version_id, 'version_id', 64);
    if (!commitPattern.test(commit || '') || !version || !/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(version) || run.kernelCommit !== commit) {
      const out = mark(db, id, 'needs_evidence', 'VM kernel commit does not match the submitted source commit', summary);
      db.exec('COMMIT'); return out;
    }
    const target = db.prepare('SELECT active FROM track_targets WHERE version_id = ? AND repo_commit = ?').get(version, commit);
    if (!target?.active) {
      const out = mark(db, id, 'needs_evidence', 'VM kernel is not the active registered track target', summary);
      db.exec('COMMIT'); return out;
    }
    const normalized = object(review.normalized, 'normalized finding');
    const title = canonicalTitle(normalized.title);
    const filePath = value(normalized.file_path, 'file_path', 300);
    const nfsVersion = canonicalNfsVersion(normalized.nfs_version);
    const testedVersion = canonicalNfsVersion(run.nfsVersion);
    const submittedVersion = metadata.nfs_version == null ? null : canonicalNfsVersion(metadata.nfs_version);
    const privilege = canonicalPermission(normalized.permission);
    const vulnerabilityType = canonicalVulnerabilityType(normalized.vulnerability_type);
    if (!title || !filePath || !nfsPath.test(filePath) || filePath.split('/').includes('..') ||
        !nfsVersion || !testedVersion || nfsVersion !== testedVersion ||
        metadata.nfs_version != null && submittedVersion !== nfsVersion || !privilege || !vulnerabilityType) {
      const out = mark(db, id, 'needs_review', 'Verified finding lacks consistent title, source path, tested NFS version, permission or vulnerability type', summary);
      db.exec('COMMIT'); return out;
    }
    const evidence = kasanEvidence(result.server_serial, filePath, normalized.code_refs, review.relevance);
    if (!evidence) {
      const out = mark(db, id, 'needs_evidence', 'Server KASAN trace does not identify the reviewed NFS source location', summary);
      db.exec('COMMIT'); return out;
    }
    let poc;
    try { poc = checkedPoc(db, id, normalized); }
    catch (error) {
      if (error.status !== 422) throw error;
      const out = mark(db, id, 'needs_review', error.message, summary); db.exec('COMMIT'); return out;
    }
    if (!poc) { const out = mark(db, id, 'needs_review', 'No selected PoC source', summary); db.exec('COMMIT'); return out; }
    if (!groundedRelevance(review, commit, filePath, evidence, poc)) {
      const out = mark(db, id, 'needs_review', 'Codex could not link the trusted source, original PoC and post-run KASAN trace', summary);
      db.exec('COMMIT'); return out;
    }
    const artifacts = checkedArtifacts(result, review, poc, evidence);
    if (!artifacts) {
      const out = mark(db, id, 'needs_review', 'Verifier did not produce a grounded report.md, poc.c, reproduction.md and KASAN log', summary);
      db.exec('COMMIT'); return out;
    }
    const kasanHeader = evidence.log.split(/\r?\n/, 1)[0].replace(/\+0x[0-9a-f]+\/[0-9a-f]+/gi, '').trim();
    const fingerprint = hash(`${commit}\0${filePath}\0${kasanHeader}`);
    const existing = existingManagementId ? findExistingManagementId(db, existingManagementId) : null;
    if (existingManagementId && !existing) {
      const out = mark(db, id, 'needs_review', 'Existing managed finding is no longer available', summary);
      db.exec('COMMIT'); return out;
    }
    const duplicate = db.prepare(`SELECT management_id FROM submissions
      WHERE fingerprint = ? AND status = 'approved' AND (? IS NULL OR management_id <> ?)
      LIMIT 1`).get(fingerprint, existingManagementId, existingManagementId);
    if (duplicate) {
      const out = mark(db, id, 'needs_review', `Possible duplicate of ${duplicate.management_id}; compare root cause before assigning another number`, summary);
      db.exec('COMMIT'); return out;
    }
    const at = now();
    const access = /AUTH_NONE|AUTH_NULL/i.test(privilege || '') ? ['auth_null'] : /AUTH_SYS|AUTH_UNIX/i.test(privilege || '') ? ['auth_unix'] : [];
    const foundDate = /^\d{4}-\d{2}-\d{2}$/.test(normalized.found_date || '') ? normalized.found_date : row.submitted_at.slice(0, 10);
    const data = {
      schema_version: 1, kind: 'finding', version_id: version, repo_commit: commit, title,
      file_path: filePath, scope: [filePath], code_refs: Array.isArray(normalized.code_refs) ? normalized.code_refs.filter(ref => typeof ref === 'string' && ref.length <= 300).slice(0, 30) : [],
      angle: 'qemu-two-vm-reproduction', created_at: at,
      vm_environment: `QEMU server/client, NFS ${nfsVersion}, kernel ${commit}`,
      verified_impacts: evidence.impacts, access_requirements: access,
      impact: vulnerabilityType,
      reproduction_command: 'gcc -O0 -g -o /tmp/hivemind-poc /mnt/job/poc.c && /tmp/hivemind-poc 10.77.0.1 /mnt/nfs',
      poc_source: poc.source, poc_sha256: hash(poc.source), kasan_log: evidence.log, kasan_sha256: hash(evidence.log),
      registry_target: 'knfsd', registry_option: value(normalized.options, 'options', 200),
      registry_privilege: privilege, registry_nfs_version: nfsVersion,
      registry_vulnerability_type: vulnerabilityType,
      registry_found_date: foundDate, registry_methodology: 'LLM', registry_report_project: 'Linux kernel',
      ...(row.origin === 'manual_upload' && typeof metadata.reporter === 'string' && metadata.reporter.length <= 100
        ? { registry_owner: metadata.reporter } : {}),
    };
    try { validateRegistryMetadata(data); }
    catch (error) {
      if (!error.status) throw error;
      const out = mark(db, id, 'needs_review', error.message, summary); db.exec('COMMIT'); return out;
    }
    const accepted = { title, file_path: filePath, code_refs: data.code_refs,
      verified_impacts: evidence.impacts, vm_environment: data.vm_environment,
      reproduction_command: data.reproduction_command, kasan_summary: evidence.log.split(/\r?\n/, 1)[0],
      option: data.registry_option, privilege, nfs_version: nfsVersion,
      vulnerability_type: vulnerabilityType };
    let findingId;
    let managementId;
    let visibleRevision = true;
    if (existing) {
      managementId = existingManagementId;
      findingId = existing.kind === 'live' ? existing.finding_id : null;
      const priorApproved = db.prepare(`SELECT id, submitted_at FROM submissions
        WHERE management_id = ? AND status = 'approved'
        ORDER BY submitted_at DESC, id DESC LIMIT 1`).get(managementId);
      visibleRevision = !priorApproved || priorApproved.submitted_at < row.submitted_at ||
        priorApproved.submitted_at === row.submitted_at && priorApproved.id < id;
      if (visibleRevision) {
        const previousRegistry = db.prepare(`SELECT * FROM ${existing.kind === 'live' ? 'finding_registry' : 'registry_history'}
          WHERE ${existing.kind === 'live' ? 'finding_id' : 'management_id'} = ?`).get(findingId ?? managementId);
        const previousEvent = findingId ? db.prepare('SELECT * FROM events WHERE id = ?').get(findingId) : null;
        db.prepare(`INSERT INTO finding_revision_audit
          (submission_id, management_id, previous_event_json, previous_registry_json, recorded_at)
          VALUES (?, ?, ?, ?, ?)`).run(id, managementId,
          previousEvent ? JSON.stringify(previousEvent) : null, JSON.stringify(previousRegistry), at);
        const priorImpacts = findingId ? readFrontMatter(previousEvent.markdown).data.verified_impacts :
          db.prepare(`SELECT observed_impacts_json FROM history_verification_runs
            WHERE management_id = ? AND result = 'verified' ORDER BY id DESC LIMIT 1`).get(managementId)?.observed_impacts_json;
        const earlier = db.prepare(`SELECT accepted_json FROM submissions
          WHERE management_id = ? AND status = 'approved' AND accepted_json IS NOT NULL`).all(managementId);
        const verified = new Set(evidence.impacts);
        for (const impact of Array.isArray(priorImpacts) ? priorImpacts :
          typeof priorImpacts === 'string' ? JSON.parse(priorImpacts) : []) verified.add(impact);
        for (const item of earlier) {
          for (const impact of JSON.parse(item.accepted_json).verified_impacts || []) verified.add(impact);
        }
        data.verified_impacts = [...verified];
        const fields = { title, option: data.registry_option, privilege,
          nfs_version: nfsVersion, vulnerability_type: vulnerabilityType };
        const overrides = new Set(JSON.parse(previousRegistry[existing.kind === 'live'
          ? 'admin_overrides_json' : 'manual_overrides_json']));
        if (existing.kind === 'live') {
          data.created_at = previousEvent.created_at;
          const markdown = frontMatter(data, artifacts.report.content);
          db.prepare(`UPDATE events SET version_id = ?, repo_commit = ?, title = ?, scope_json = ?,
            sha256 = ?, markdown = ? WHERE id = ?`).run(version, commit, title,
            JSON.stringify([filePath]), hash(markdown), markdown, findingId);
          db.prepare(`UPDATE finding_reviews SET provider = 'codex_qemu', status = 'complete',
            verdict = 'likely', summary = ?, requested_at = ?, completed_at = ? WHERE finding_id = ?`)
            .run(reason, row.submitted_at, at, findingId);
          const updates = Object.entries(fields).filter(([field]) => field !== 'title' && !overrides.has(field));
          const setters = [...updates.map(([field]) => `${field} = ?`), 'updated_at = ?', 'revision = revision + 1'];
          db.prepare(`UPDATE finding_registry SET ${setters.join(', ')} WHERE finding_id = ?`)
            .run(...updates.map(([, value]) => value), at, findingId);
          db.prepare(`UPDATE primitive_reviews SET status = 'pending', summary = NULL, requested_at = ?,
            claimed_at = NULL, completed_at = NULL, last_activity_at = NULL, lease_token = NULL,
            retry_after = NULL, attempts = 0, worker_id = NULL WHERE finding_id = ?`).run(at, findingId);
        } else {
          const updates = Object.entries(fields).filter(([field]) => !overrides.has(field));
          const setters = [...updates.map(([field]) => `${field} = ?`), 'updated_at = ?', 'revision = revision + 1'];
          db.prepare(`UPDATE registry_history SET ${setters.join(', ')} WHERE management_id = ?`)
            .run(...updates.map(([, value]) => value), at, managementId);
        }
      }
    } else {
      const markdown = frontMatter(data, artifacts.report.content);
      findingId = hash(`verified-submission\0${id}`);
      db.prepare(`INSERT INTO events
        (id, agent_id, source_path, sha256, kind, version_id, repo_commit, title,
         scope_json, created_at, received_at, markdown, based_on_json)
        VALUES (?, ?, ?, ?, 'finding', ?, ?, ?, ?, ?, ?, ?, '[]')`).run(
        findingId, row.agent_id, `verification/submissions/${id}.md`, hash(markdown), version, commit, title,
        JSON.stringify([filePath]), at, at, markdown);
      db.prepare(`INSERT INTO finding_reviews
        (finding_id, provider, status, verdict, summary, requested_at, completed_at)
        VALUES (?, 'codex_qemu', 'complete', 'likely', ?, ?, ?)`).run(findingId, reason, row.submitted_at, at);
      registerFinding(db, findingId, data, at);
      const sequence = db.prepare("UPDATE registry_sequences SET last_number = last_number + 1 WHERE target = 'knfsd' RETURNING last_number").get();
      managementId = `A-${String(sequence.last_number).padStart(3, '0')}`;
      db.prepare('UPDATE finding_registry SET management_id = ?, number = ?, approved_at = ?, updated_at = ? WHERE finding_id = ?')
        .run(managementId, sequence.last_number, at, at, findingId);
    }
    const insertArtifact = db.prepare('INSERT INTO submission_artifacts VALUES (?, ?, ?, ?, ?, ?, ?)');
    for (const [ordinal, role] of Object.keys(artifactFiles).entries()) {
      const content = role === 'poc' ? artifacts.poc.source : artifacts[role].content;
      const kind = role === 'reproduction' ? 'other' : role === 'log' ? 'log' : role === 'poc' ? 'poc' : 'report';
      insertArtifact.run(id, 1000 + ordinal, artifactFiles[role], kind, hash(content), Buffer.byteLength(content), Buffer.from(content));
    }
    db.prepare("UPDATE submissions SET status = 'approved', reason = ?, finding_id = ?, management_id = ?, fingerprint = ?, verification_json = ?, accepted_json = ?, completed_at = ?, lease_token = NULL WHERE id = ?")
      .run(reason, findingId, managementId, fingerprint, JSON.stringify(summary), JSON.stringify(accepted), at, id);
    if (existing?.kind === 'live' && !visibleRevision) {
      const currentEvent = db.prepare('SELECT * FROM events WHERE id = ?').get(findingId);
      const currentRegistry = db.prepare('SELECT * FROM finding_registry WHERE finding_id = ?').get(findingId);
      const parsed = readFrontMatter(currentEvent.markdown);
      const impacts = new Set([...(parsed.data.verified_impacts || []), ...evidence.impacts]);
      if (impacts.size > (parsed.data.verified_impacts || []).length) {
        db.prepare(`INSERT INTO finding_revision_audit
          (submission_id, management_id, previous_event_json, previous_registry_json, recorded_at)
          VALUES (?, ?, ?, ?, ?)`).run(id, managementId,
          JSON.stringify(currentEvent), JSON.stringify(currentRegistry), at);
        const markdown = frontMatter({ ...parsed.data, verified_impacts: [...impacts] }, parsed.body);
        db.prepare('UPDATE events SET markdown = ?, sha256 = ? WHERE id = ?')
          .run(markdown, hash(markdown), findingId);
        db.prepare('UPDATE finding_registry SET updated_at = ?, revision = revision + 1 WHERE finding_id = ?')
          .run(at, findingId);
        db.prepare(`UPDATE primitive_reviews SET status = 'pending', summary = NULL, requested_at = ?,
          claimed_at = NULL, completed_at = NULL, last_activity_at = NULL, lease_token = NULL,
          retry_after = NULL, attempts = 0, worker_id = NULL WHERE finding_id = ?`).run(at, findingId);
      }
    }
    if (!existing) db.prepare("INSERT INTO primitive_reviews(finding_id, status, requested_at) VALUES (?, 'pending', ?)")
      .run(findingId, at);
    db.exec('COMMIT');
    return getSubmission(db, id);
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

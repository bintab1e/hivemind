import { randomBytes } from 'node:crypto';
import { hash, invalid, required } from './contract.mjs';

const now = () => new Date().toISOString();
const leaseMs = 2 * 60 * 60_000;
const maxStoredBytes = 256_000_000;
const maxActiveReviews = 32;
const reviewIdPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;

export function initializePatchReviews(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS patch_reviews (
      id TEXT PRIMARY KEY,
      management_id TEXT NOT NULL,
      track_id TEXT NOT NULL,
      base_commit TEXT NOT NULL,
      filename TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      patch TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'reviewed', 'findings', 'error')),
      result_json TEXT,
      reason TEXT,
      submitted_at TEXT NOT NULL,
      claimed_at TEXT,
      completed_at TEXT,
      lease_token TEXT,
      worker_id TEXT,
      attempts INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS patch_reviews_queue ON patch_reviews(status, submitted_at);
    CREATE INDEX IF NOT EXISTS patch_reviews_finding ON patch_reviews(management_id, submitted_at);
  `);
}

export function validatePatchFile(input) {
  const filename = required(input?.filename, 'filename', 120);
  if (!/^[a-z0-9][a-z0-9._-]*\.(?:patch|diff)$/i.test(filename)) invalid('Patch filename must end in .patch or .diff');
  const encoded = required(input?.content_base64, 'content_base64', 1_400_000);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) invalid('Invalid base64 patch');
  const bytes = Buffer.from(encoded, 'base64');
  if (!bytes.length || bytes.length > 1_000_000 || bytes.includes(0)) invalid('Patch size or encoding is invalid', 413);
  const patch = bytes.toString('utf8');
  if (!Buffer.from(patch, 'utf8').equals(bytes)) invalid('Patch must be UTF-8');
  if (/^(?:GIT binary patch|Binary files |rename (?:from|to) |copy (?:from|to) |old mode |new mode |new file mode |deleted file mode )/m.test(patch) ||
      /^index [a-f0-9]+\.\.[a-f0-9]+ (?:120000|160000)\r?$/m.test(patch)) invalid('Binary, mode-changing, symlink, rename, copy, and file creation/deletion patches are not supported');
  const paths = [...patch.matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gm)];
  if (!paths.length) invalid('Patch needs a Git diff header');
  const headers = [...patch.matchAll(/^(?:---|\+\+\+) (\S+)$/gm)].map(match => match[1]);
  if (headers.length !== paths.length * 2) invalid('Patch file headers are incomplete');
  for (const match of paths) {
    const file = match[1];
    if (file !== match[2] || file.startsWith('/') || file.includes('\\') || file.includes(':') || /[\x00-\x1f]/.test(file) || file.split('/').some(part => !part || part === '.' || part === '..')) invalid('Patch must use safe repository-relative file paths');
  }
  for (let index = 0; index < paths.length; index += 1) {
    if (headers[index * 2] !== `a/${paths[index][1]}` || headers[index * 2 + 1] !== `b/${paths[index][1]}`) invalid('Patch file headers do not match the Git diff');
  }
  return { filename, patch, sha256: hash(bytes) };
}

function publicReview(row, detail = false) {
  if (!row) return null;
  const { patch, result_json, ...fields } = row;
  return detail ? { ...fields, result: result_json ? JSON.parse(result_json) : null } : fields;
}

export function listPatchReviews(db) {
  return db.prepare(`SELECT id, management_id, track_id, base_commit, filename, sha256, status,
    reason, submitted_at, claimed_at, completed_at, worker_id, attempts
    FROM patch_reviews ORDER BY submitted_at DESC, id DESC`).all();
}

export function getPatchReview(db, reviewId) {
  if (!reviewIdPattern.test(reviewId || '')) invalid('Invalid review ID');
  const row = db.prepare(`SELECT id, management_id, track_id, base_commit, filename, sha256,
    status, result_json, reason, submitted_at, claimed_at, completed_at, worker_id, attempts
    FROM patch_reviews WHERE id = ?`).get(reviewId);
  if (!row) invalid('Patch review not found', 404);
  return publicReview(row, true);
}

export function getPatchReviewFile(db, reviewId) {
  if (!reviewIdPattern.test(reviewId || '')) invalid('Invalid review ID');
  const row = db.prepare('SELECT filename, patch FROM patch_reviews WHERE id = ?').get(reviewId);
  if (!row) invalid('Patch review not found', 404);
  return row;
}

export function submitPatchReview(db, input, limits = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid('Invalid patch review');
  const managementId = required(input.management_id, 'management_id', 32);
  if (/^[BC]-\d{3,}$/.test(managementId)) invalid('Sashiko review currently supports knfsd (A-series) only', 422);
  if (!/^A-\d{3,}$/.test(managementId)) invalid('Invalid knfsd management ID');
  const exists = db.prepare(`SELECT 1 FROM registry_history WHERE management_id = ? AND target = 'knfsd'
    UNION ALL SELECT 1 FROM finding_registry WHERE management_id = ? AND target = 'knfsd' AND approved_at IS NOT NULL`).get(managementId, managementId);
  if (!exists) invalid('Verified knfsd finding not found', 404);
  const trackId = required(input.track_id, 'track_id', 16);
  if (!['rc', 'mainline'].includes(trackId)) invalid('Choose an active kernel track');
  const target = db.prepare('SELECT repo_commit FROM track_targets WHERE track_id = ? AND active = 1').get(trackId);
  if (!commitPattern.test(target?.repo_commit || '')) invalid('Selected kernel track is not ready', 409);
  const file = validatePatchFile(input);
  const id = hash([managementId, trackId, target.repo_commit, file.sha256].join('\0'));
  const select = db.prepare(`SELECT id, management_id, track_id, base_commit, filename, sha256, status,
    reason, submitted_at, claimed_at, completed_at, worker_id, attempts FROM patch_reviews WHERE id = ?`);
  db.exec('BEGIN IMMEDIATE');
  try {
    const existing = select.get(id);
    if (existing && existing.status !== 'error') {
      db.exec('COMMIT');
      return { ...existing, replayed: true };
    }
    const active = db.prepare("SELECT COUNT(*) AS count FROM patch_reviews WHERE status IN ('pending', 'processing')").get().count;
    if (active >= (limits.maxActiveReviews ?? maxActiveReviews)) invalid('Patch review queue is full', 429);
    const submittedAt = now();
    if (existing) {
      db.prepare(`UPDATE patch_reviews SET status = 'pending', result_json = NULL, reason = NULL,
        submitted_at = ?, claimed_at = NULL, completed_at = NULL, lease_token = NULL,
        worker_id = NULL WHERE id = ? AND status = 'error'`).run(submittedAt, id);
      const retried = select.get(id);
      db.exec('COMMIT');
      return { ...retried, replayed: false, retried: true };
    }
    const stored = db.prepare('SELECT COALESCE(SUM(length(CAST(patch AS BLOB))), 0) AS bytes FROM patch_reviews').get().bytes;
    if (stored + Buffer.byteLength(file.patch) > (limits.maxStoredBytes ?? maxStoredBytes)) invalid('Patch review storage is full', 413);
    db.prepare(`INSERT INTO patch_reviews (id, management_id, track_id, base_commit, filename,
      sha256, patch, status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`).run(
      id, managementId, trackId, target.repo_commit, file.filename, file.sha256, file.patch, submittedAt);
    db.exec('COMMIT');
    return { id, management_id: managementId, track_id: trackId, base_commit: target.repo_commit,
      filename: file.filename, sha256: file.sha256, status: 'pending', submitted_at: submittedAt,
      replayed: false };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function claimPatchReview(db, workerId, supportedCommits) {
  if (typeof workerId !== 'string' || !/^[a-z0-9][a-z0-9._:-]{0,99}$/i.test(workerId) ||
      !Array.isArray(supportedCommits) || supportedCommits.length < 1 || supportedCommits.length > 32 ||
      supportedCommits.some(commit => !commitPattern.test(commit))) invalid('Invalid patch claim request');
  const uniqueCommits = [...new Set(supportedCommits)];
  const placeholders = uniqueCommits.map(() => '?').join(',');
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare(`UPDATE patch_reviews SET status = 'pending', lease_token = NULL, worker_id = NULL
      WHERE status = 'processing' AND claimed_at < ?`).run(new Date(Date.now() - leaseMs).toISOString());
    const row = db.prepare(`SELECT id, management_id, track_id, base_commit, filename, sha256, patch
      FROM patch_reviews WHERE status = 'pending' AND base_commit IN (${placeholders})
      ORDER BY submitted_at, id LIMIT 1`).get(...uniqueCommits);
    if (!row) { db.exec('COMMIT'); return null; }
    const leaseToken = randomBytes(32).toString('hex');
    db.prepare(`UPDATE patch_reviews SET status = 'processing', claimed_at = ?, worker_id = ?,
      lease_token = ?, attempts = attempts + 1 WHERE id = ? AND status = 'pending'`).run(now(), workerId, leaseToken, row.id);
    db.exec('COMMIT');
    return { review_id: row.id, management_id: row.management_id, track_id: row.track_id,
      base_commit: row.base_commit, filename: row.filename, sha256: row.sha256,
      patch: row.patch, lease_token: leaseToken };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

function currentLease(db, reviewId, leaseToken) {
  if (!reviewIdPattern.test(reviewId || '') || !reviewIdPattern.test(leaseToken || '')) invalid('Invalid patch review lease');
  const row = db.prepare('SELECT status, lease_token FROM patch_reviews WHERE id = ?').get(reviewId);
  if (!row || row.status !== 'processing' || row.lease_token !== leaseToken) invalid('Patch review lease expired', 409);
}

export function completePatchReview(db, reviewId, leaseToken, status, result) {
  if (!['reviewed', 'findings', 'error'].includes(status)) invalid('Invalid patch review status');
  if (!result || typeof result !== 'object' || Array.isArray(result)) invalid('Invalid Sashiko result');
  const serialized = JSON.stringify(result);
  if (Buffer.byteLength(serialized) > 2_000_000) invalid('Sashiko result is too large', 413);
  currentLease(db, reviewId, leaseToken);
  const completedAt = now();
  const changed = db.prepare(`UPDATE patch_reviews SET status = ?, result_json = ?, reason = NULL,
    completed_at = ?, lease_token = NULL WHERE id = ? AND status = 'processing' AND lease_token = ?`)
    .run(status, serialized, completedAt, reviewId, leaseToken).changes;
  if (!changed) invalid('Patch review lease expired', 409);
  return { review_id: reviewId, status, completed_at: completedAt };
}

export function failPatchReview(db, reviewId, leaseToken, reason) {
  if (typeof reason !== 'string' || !reason.trim() || Buffer.byteLength(reason) > 2000) invalid('Invalid patch review failure reason');
  currentLease(db, reviewId, leaseToken);
  const completedAt = now();
  const changed = db.prepare(`UPDATE patch_reviews SET status = 'error', reason = ?, completed_at = ?,
    lease_token = NULL WHERE id = ? AND status = 'processing' AND lease_token = ?`)
    .run(reason.trim(), completedAt, reviewId, leaseToken).changes;
  if (!changed) invalid('Patch review lease expired', 409);
  return { review_id: reviewId, status: 'error', completed_at: completedAt };
}

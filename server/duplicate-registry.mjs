import fs from 'node:fs';
import { invalid, readFrontMatter } from './contract.mjs';
import { listHistoryArtifacts, openHistoryArtifact } from './history-artifacts.mjs';

const eligibleStatuses = new Set(['미제보', '제보 중']);
const verdicts = new Set(['duplicate', 'no_match', 'uncertain', 'error']);
const evidenceKinds = new Set(['mail', 'branch']);
const maxExcerptBytes = 24_000;
const maxPocBytes = 12_000;

export function initializeDuplicateRegistry(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS duplicate_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      row_id TEXT NOT NULL,
      revision_checked INTEGER NOT NULL,
      verdict TEXT NOT NULL CHECK(verdict IN ('duplicate', 'no_match', 'uncertain', 'error')),
      reason TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      sources_checked_json TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      received_at TEXT NOT NULL,
      status_before TEXT,
      status_after TEXT,
      outcome TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS duplicate_reviews_row ON duplicate_reviews(row_id, id DESC);
    CREATE TRIGGER IF NOT EXISTS duplicate_reviews_no_update
      BEFORE UPDATE ON duplicate_reviews BEGIN SELECT RAISE(ABORT, 'Duplicate reviews are append-only'); END;
    CREATE TRIGGER IF NOT EXISTS duplicate_reviews_no_delete
      BEFORE DELETE ON duplicate_reviews BEGIN SELECT RAISE(ABORT, 'Duplicate reviews are append-only'); END;
    CREATE TABLE IF NOT EXISTS internal_duplicate_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      row_id TEXT NOT NULL,
      revision_checked INTEGER NOT NULL,
      verdict TEXT NOT NULL CHECK(verdict IN ('duplicate', 'no_match', 'uncertain', 'error')),
      reason TEXT NOT NULL,
      matched_management_id TEXT,
      checked_at TEXT NOT NULL,
      received_at TEXT NOT NULL,
      status_before TEXT,
      status_after TEXT,
      outcome TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS internal_duplicate_reviews_row ON internal_duplicate_reviews(row_id, id DESC);
    CREATE TRIGGER IF NOT EXISTS internal_duplicate_reviews_no_update
      BEFORE UPDATE ON internal_duplicate_reviews BEGIN SELECT RAISE(ABORT, 'Internal duplicate reviews are append-only'); END;
    CREATE TRIGGER IF NOT EXISTS internal_duplicate_reviews_no_delete
      BEFORE DELETE ON internal_duplicate_reviews BEGIN SELECT RAISE(ABORT, 'Internal duplicate reviews are append-only'); END;
  `);
}

function excerpt(value, limit = maxExcerptBytes) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value) : Buffer.from(String(value ?? ''), 'utf8');
  return bytes.subarray(0, limit).toString('utf8').replace(/\uFFFD$/, '').trim();
}

function historicalText(db, dataDir, managementId, artifact, limit) {
  if (!dataDir || !artifact) return '';
  let opened;
  try {
    opened = openHistoryArtifact(db, dataDir, managementId, artifact.id);
    const buffer = Buffer.alloc(Math.min(opened.size, limit));
    const count = opened.content
      ? opened.content.copy(buffer, 0, 0, buffer.length)
      : fs.readSync(opened.fd, buffer, 0, buffer.length, 0);
    const text = excerpt(buffer.subarray(0, count), limit);
    return text.includes('\0') ? '' : text;
  } catch (error) {
    if (error.status === 404 || error.code === 'ENOENT') return '';
    throw error;
  } finally {
    if (opened?.fd !== undefined) fs.closeSync(opened.fd);
  }
}

function historicalReport(db, dataDir, managementId) {
  if (!dataDir) return '';
  return historicalText(db, dataDir, managementId,
    listHistoryArtifacts(db, managementId).find(item => item.kind === 'report'), maxExcerptBytes);
}

function historicalPoc(db, dataDir, managementId) {
  if (!dataDir) return '';
  let result = '';
  for (const item of listHistoryArtifacts(db, managementId)) {
    if (item.kind !== 'poc' || !/\.(?:c|h|sh|py|md|txt)$/i.test(item.original_name || item.name)) continue;
    const remaining = maxPocBytes - Buffer.byteLength(result);
    if (remaining < 200) break;
    const label = `--- ${String(item.original_name || item.name).slice(0, 100)} ---\n`;
    const body = historicalText(db, dataDir, managementId, item, remaining - Buffer.byteLength(label) - 2);
    if (body) result += `${label}${body}\n`;
  }
  return result.trim();
}

function liveReport(db, findingId, markdown) {
  const artifact = db.prepare(`SELECT substr(a.content, 1, ?) AS excerpt
    FROM submission_artifacts a JOIN submissions s ON s.id = a.submission_id
    WHERE s.finding_id = ? AND s.status = 'approved' AND a.ordinal = 1000
    ORDER BY s.submitted_at DESC, s.id DESC LIMIT 1`).get(maxExcerptBytes, findingId);
  if (artifact) return excerpt(artifact.excerpt);
  try { return excerpt(readFrontMatter(markdown).body); }
  catch { return ''; }
}

function livePoc(db, findingId) {
  const artifact = db.prepare(`SELECT substr(a.content, 1, ?) AS excerpt
    FROM submission_artifacts a JOIN submissions s ON s.id = a.submission_id
    WHERE s.finding_id = ? AND s.status = 'approved' AND a.ordinal = 1001 AND a.name = 'poc.c'
    ORDER BY s.submitted_at DESC, s.id DESC LIMIT 1`).get(maxPocBytes, findingId);
  return artifact ? excerpt(artifact.excerpt, maxPocBytes) : '';
}

function liveMetadata(markdown) {
  try {
    const { data } = readFrontMatter(markdown);
    return {
      file_path: typeof data.file_path === 'string' ? data.file_path.slice(0, 300) : null,
      code_refs: Array.isArray(data.code_refs) ? data.code_refs.filter(item => typeof item === 'string').slice(0, 40).map(item => item.slice(0, 300)) : [],
    };
  } catch { return { file_path: null, code_refs: [] }; }
}

function duplicateRows(db, dataDir, all) {
  const common = 'management_id, title, target, report_status, option, privilege, nfs_version, vulnerability_type, found_date, cve, revision';
  const history = db.prepare(`SELECT ${common} FROM registry_history
    ${all ? '' : "WHERE report_status IN ('미제보', '제보 중') OR report_status IS NULL"}
    ORDER BY management_id`).all().map(row => ({
    ...row, row_id: `history:${row.management_id}`, file_path: null, code_refs: [],
    report_excerpt: historicalReport(db, dataDir, row.management_id),
    poc_excerpt: historicalPoc(db, dataDir, row.management_id),
  }));
  const live = db.prepare(`SELECT r.management_id, COALESCE(r.title_override, e.title) AS title,
    r.target, r.report_status, r.option, r.privilege, r.nfs_version, r.vulnerability_type,
    r.found_date, r.cve, r.revision, r.finding_id, e.markdown
    FROM finding_registry r JOIN events e ON e.id = r.finding_id
    WHERE r.management_id IS NOT NULL AND r.superseded_by IS NULL
      ${all ? '' : "AND r.report_status IN ('미제보', '제보 중')"} ORDER BY r.management_id`).all().map(row => {
    const { finding_id: findingId, markdown, ...record } = row;
    return { ...record, row_id: findingId, ...liveMetadata(markdown),
      report_excerpt: liveReport(db, findingId, markdown), poc_excerpt: livePoc(db, findingId) };
  });
  return [...history, ...live];
}

export function listDuplicateCandidates(db, dataDir) {
  return duplicateRows(db, dataDir, false);
}

export function listInternalDuplicateReferences(db, dataDir) {
  return duplicateRows(db, dataDir, true);
}

function officialEvidenceUrl(value, kind, target) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !url.pathname || url.pathname === '/') return false;
  if (kind === 'mail') {
    if (target === 'knfsd') return url.hostname === 'lore.kernel.org' &&
      /^\/(?:linux-nfs|r)\/[^/]+/.test(url.pathname) || url.hostname === 'patchwork.kernel.org' &&
      /^\/project\/linux-nfs\/(?:patch|series)\/[^/]+/.test(url.pathname);
    if (target === 'NFS-Ganesha') return url.hostname === 'lists.nfs-ganesha.org' &&
      /^\/archives\/list\/devel@lists\.nfs-ganesha\.org\/(?:thread|message)\/[^/]+/.test(url.pathname);
    return target === 'libnfs' && url.hostname === 'groups.google.com' && /^\/g\/libnfs\/c\/[^/]+/.test(url.pathname);
  }
  if (url.hostname === 'git.kernel.org') return target === 'knfsd' &&
    /^\/pub\/scm\/linux\/kernel\/git\/cel\/linux\.git\/commit\/?$/.test(url.pathname) &&
    /^[a-f0-9]{40,64}$/i.test(url.searchParams.get('id') || '');
  if (url.hostname !== 'github.com') return false;
  const project = target === 'knfsd' ? 'torvalds/linux' :
    target === 'NFS-Ganesha' ? 'nfs-ganesha/nfs-ganesha' :
      target === 'libnfs' ? 'sahlberg/libnfs' : null;
  return Boolean(project && new RegExp(`^/${project}/commit/[a-f0-9]{40,64}/?$`, 'i').test(url.pathname));
}

function validInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).sort().join(',') !== 'checked_at,evidence,reason,revision,row_id,sources_checked,verdict') invalid('Invalid duplicate result fields');
  if (typeof input.row_id !== 'string' || !/^(?:history:[ABC]-\d{3}|[a-f0-9]{64})$/.test(input.row_id)) invalid('Invalid row_id');
  if (!Number.isInteger(input.revision) || input.revision < 0) invalid('Invalid revision');
  if (!verdicts.has(input.verdict)) invalid('Invalid duplicate verdict');
  if (typeof input.reason !== 'string' || !input.reason.trim() || Buffer.byteLength(input.reason) > 2000 || /[\x00-\x08\x0b-\x1f\x7f]/.test(input.reason)) invalid('Invalid duplicate reason');
  if (!input.sources_checked || typeof input.sources_checked !== 'object' || Array.isArray(input.sources_checked) ||
      Object.keys(input.sources_checked).sort().join(',') !== 'branch,mail' ||
      typeof input.sources_checked.mail !== 'boolean' || typeof input.sources_checked.branch !== 'boolean') invalid('Invalid sources_checked');
  if (typeof input.checked_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(input.checked_at) ||
      !Number.isFinite(Date.parse(input.checked_at))) invalid('Invalid checked_at');
  if (!Array.isArray(input.evidence) || input.evidence.length > 8 || input.evidence.some(item =>
    !item || typeof item !== 'object' || Array.isArray(item) ||
    Object.keys(item).sort().join(',') !== 'kind,title,url' || !evidenceKinds.has(item.kind) ||
    typeof item.title !== 'string' || !item.title.trim() || item.title.length > 300 || /[\x00-\x1f\x7f]/.test(item.title))) invalid('Invalid duplicate evidence');
  if (input.verdict === 'duplicate' && (!input.sources_checked.mail || !input.sources_checked.branch || !input.evidence.length)) {
    invalid('Duplicate verdict requires both source checks and public evidence');
  }
}

function validInternalInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).sort().join(',') !== 'checked_at,matched_management_id,reason,revision,row_id,verdict') invalid('Invalid internal duplicate result fields');
  if (typeof input.row_id !== 'string' || !/^(?:history:[ABC]-\d{3}|[a-f0-9]{64})$/.test(input.row_id)) invalid('Invalid row_id');
  if (!Number.isInteger(input.revision) || input.revision < 0) invalid('Invalid revision');
  if (!verdicts.has(input.verdict)) invalid('Invalid duplicate verdict');
  if (typeof input.reason !== 'string' || !input.reason.trim() || Buffer.byteLength(input.reason) > 2000 ||
      /[\x00-\x08\x0b-\x1f\x7f]/.test(input.reason)) invalid('Invalid duplicate reason');
  if (typeof input.checked_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(input.checked_at) ||
      !Number.isFinite(Date.parse(input.checked_at))) invalid('Invalid checked_at');
  if (input.verdict === 'duplicate' ? !/^[ABC]-\d{3,}$/.test(input.matched_management_id || '') : input.matched_management_id !== null) {
    invalid('Invalid matched_management_id');
  }
}

function currentRow(db, rowId) {
  if (rowId.startsWith('history:')) {
    return { history: true, row: db.prepare('SELECT management_id, revision, report_status, target FROM registry_history WHERE management_id = ?').get(rowId.slice(8)) };
  }
  return { history: false, row: db.prepare('SELECT management_id, revision, report_status, target FROM finding_registry WHERE finding_id = ? AND management_id IS NOT NULL AND superseded_by IS NULL').get(rowId) };
}

function referenceRow(db, managementId) {
  const matches = db.prepare(`SELECT management_id, report_status, 'history:' || management_id AS row_id
    FROM registry_history WHERE management_id = ?
    UNION ALL
    SELECT management_id, report_status, finding_id AS row_id
    FROM finding_registry WHERE management_id = ? AND superseded_by IS NULL`).all(managementId, managementId);
  if (matches.length !== 1) invalid('Matched finding not found or ambiguous', 404);
  return matches[0];
}

function reportForRow(db, dataDir, rowId) {
  if (rowId.startsWith('history:')) return historicalReport(db, dataDir, rowId.slice(8));
  const event = db.prepare('SELECT e.markdown FROM finding_registry r JOIN events e ON e.id = r.finding_id WHERE r.finding_id = ? AND r.superseded_by IS NULL').get(rowId);
  return event ? liveReport(db, rowId, event.markdown) : '';
}

function manuallyRevertedDuplicate(db, rowId) {
  const edits = db.prepare('SELECT actor, changes_json FROM registry_edits WHERE row_id = ? ORDER BY id').all(rowId);
  let automated = false;
  let manuallyReverted = false;
  for (const edit of edits) {
    let statusChange;
    try { statusChange = JSON.parse(edit.changes_json).report_status; } catch { continue; }
    if (!statusChange) continue;
    if (edit.actor === 'duplicate-agent' && statusChange.after === '중복') {
      automated = true;
      manuallyReverted = false;
    } else if (automated && edit.actor !== 'duplicate-agent' && statusChange.before === '중복') {
      manuallyReverted = true;
    }
  }
  return manuallyReverted;
}

export function recordDuplicateResult(db, input) {
  validInput(input);
  db.exec('BEGIN IMMEDIATE');
  try {
    const { history, row } = currentRow(db, input.row_id);
    if (!row) invalid('Finding not found', 404);
    if (input.evidence.some(item => !officialEvidenceUrl(item.url, item.kind, row.target))) invalid('Evidence URL is not an official public source');
    const receivedAt = new Date().toISOString();
    let outcome = 'checked';
    let statusAfter = row.report_status;
    let revisionAfter = row.revision;
    if (row.revision !== input.revision) outcome = 'stale';
    else if (input.verdict === 'duplicate') {
      if (row.report_status === null) outcome = 'review_only';
      else if (!eligibleStatuses.has(row.report_status)) outcome = 'ineligible';
      else if (manuallyRevertedDuplicate(db, input.row_id)) outcome = 'manual_override';
      else {
        const table = history ? 'registry_history' : 'finding_registry';
        const key = history ? 'management_id' : 'finding_id';
        const keyValue = history ? input.row_id.slice(8) : input.row_id;
        const overrideColumn = history ? 'manual_overrides_json' : 'admin_overrides_json';
        const overrides = JSON.stringify([...new Set([
          ...JSON.parse(db.prepare(`SELECT ${overrideColumn} AS value FROM ${table} WHERE ${key} = ?`).get(keyValue).value),
          'report_status',
        ])]);
        const changed = db.prepare(`UPDATE ${table} SET report_status = '중복', ${overrideColumn} = ?,
          updated_at = ?, revision = revision + 1
          WHERE ${key} = ? AND revision = ? AND report_status IN ('미제보', '제보 중')`)
          .run(overrides, receivedAt, keyValue, input.revision).changes;
        if (changed !== 1) invalid('Registry changed during duplicate review', 409);
        db.prepare('INSERT INTO registry_edits(row_id, actor, edited_at, changes_json) VALUES (?, ?, ?, ?)')
          .run(input.row_id, 'duplicate-agent', receivedAt, JSON.stringify({ report_status: { before: row.report_status, after: '중복' } }));
        statusAfter = '중복';
        revisionAfter++;
        outcome = 'changed';
      }
    } else if (!eligibleStatuses.has(row.report_status) && row.report_status !== null) outcome = 'ineligible';
    const audit = db.prepare(`INSERT INTO duplicate_reviews
      (row_id, revision_checked, verdict, reason, evidence_json, sources_checked_json,
       checked_at, received_at, status_before, status_after, outcome)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      input.row_id, input.revision, input.verdict, input.reason.trim(), JSON.stringify(input.evidence),
      JSON.stringify(input.sources_checked), input.checked_at, receivedAt, row.report_status, statusAfter, outcome);
    db.exec('COMMIT');
    return { row_id: input.row_id, verdict: input.verdict, outcome, status_changed: outcome === 'changed',
      report_status: statusAfter, revision: revisionAfter, audit_id: Number(audit.lastInsertRowid) };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function recordInternalDuplicateResult(db, input, dataDir) {
  validInternalInput(input);
  db.exec('BEGIN IMMEDIATE');
  try {
    const { history, row } = currentRow(db, input.row_id);
    if (!row) invalid('Finding not found', 404);
    const reference = input.verdict === 'duplicate' ? referenceRow(db, input.matched_management_id) : null;
    if (reference?.row_id === input.row_id || reference?.management_id === row.management_id) invalid('Finding cannot match itself');
    const receivedAt = new Date().toISOString();
    let outcome = 'checked';
    let statusAfter = row.report_status;
    let revisionAfter = row.revision;
    if (row.revision !== input.revision) outcome = 'stale';
    else if (input.verdict === 'duplicate') {
      if (row.report_status === null) outcome = 'review_only';
      else if (!eligibleStatuses.has(row.report_status)) outcome = 'ineligible';
      else if (['중복', '철회'].includes(reference.report_status) ||
          (reference.report_status !== '제보 완료' && reference.management_id >= row.management_id)) outcome = 'ineligible_reference';
      else if (!reportForRow(db, dataDir, input.row_id) || !reportForRow(db, dataDir, reference.row_id)) outcome = 'insufficient_reports';
      else if (manuallyRevertedDuplicate(db, input.row_id)) outcome = 'manual_override';
      else {
        const table = history ? 'registry_history' : 'finding_registry';
        const key = history ? 'management_id' : 'finding_id';
        const keyValue = history ? row.management_id : input.row_id;
        const overrideColumn = history ? 'manual_overrides_json' : 'admin_overrides_json';
        const overrides = JSON.stringify([...new Set([
          ...JSON.parse(db.prepare(`SELECT ${overrideColumn} AS value FROM ${table} WHERE ${key} = ?`).get(keyValue).value),
          'report_status',
        ])]);
        const changed = db.prepare(`UPDATE ${table} SET report_status = '중복', ${overrideColumn} = ?,
          updated_at = ?, revision = revision + 1
          WHERE ${key} = ? AND revision = ? AND report_status IN ('미제보', '제보 중')`)
          .run(overrides, receivedAt, keyValue, input.revision).changes;
        if (changed !== 1) invalid('Registry changed during internal duplicate review', 409);
        db.prepare('INSERT INTO registry_edits(row_id, actor, edited_at, changes_json) VALUES (?, ?, ?, ?)')
          .run(input.row_id, 'duplicate-agent', receivedAt, JSON.stringify({ report_status: { before: row.report_status, after: '중복' } }));
        statusAfter = '중복';
        revisionAfter++;
        outcome = 'changed';
      }
    } else if (!eligibleStatuses.has(row.report_status) && row.report_status !== null) outcome = 'ineligible';
    const audit = db.prepare(`INSERT INTO internal_duplicate_reviews
      (row_id, revision_checked, verdict, reason, matched_management_id,
       checked_at, received_at, status_before, status_after, outcome)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      input.row_id, input.revision, input.verdict, input.reason.trim(), input.matched_management_id,
      input.checked_at, receivedAt, row.report_status, statusAfter, outcome);
    db.exec('COMMIT');
    return { row_id: input.row_id, verdict: input.verdict, outcome, status_changed: outcome === 'changed',
      report_status: statusAfter, revision: revisionAfter, audit_id: Number(audit.lastInsertRowid) };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

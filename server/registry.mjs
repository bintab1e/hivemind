import { invalid, readFrontMatter } from './contract.mjs';
import { latestHistoryVerifications } from './history-verifications.mjs';

const prefixes = { knfsd: 'A', 'NFS-Ganesha': 'B', libnfs: 'C' };
const floors = { knfsd: 42, 'NFS-Ganesha': 21, libnfs: 1 };
const editable = {
  option: 200, privilege: 200, report_project: 200,
  report_status: 32, owner: 100, nfs_version: 100,
  vulnerability_type: 200, methodology: 100, found_date: 10,
  exploit: 100, cve: 32,
};
const metadataFields = Object.keys(editable).filter(key => key !== 'report_status');
const historicalFields = ['management_id', 'title', 'target', ...Object.keys(editable)];

function field(value, name, max) {
  if (value === null) return null;
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) invalid(`Invalid ${name}`);
  return value.trim();
}

export function validateRegistryMetadata(data) {
  if (data.registry_report_status !== undefined) invalid('registry_report_status is administrator-managed');
  if (data.registry_target !== undefined && data.registry_target !== 'knfsd') invalid('Agent findings must target knfsd');
  for (const key of metadataFields) {
    const value = data[`registry_${key}`];
    if (value !== undefined) field(value, `registry_${key}`, editable[key]);
  }
  if (data.registry_found_date != null && !/^\d{4}-\d{2}-\d{2}$/.test(data.registry_found_date)) invalid('Invalid registry_found_date');
  if (data.registry_cve != null && !/^CVE-\d{4}-\d{4,}$/i.test(data.registry_cve)) invalid('Invalid registry_cve');
}

export function initializeRegistry(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS registry_sequences (
      target TEXT PRIMARY KEY, last_number INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS finding_registry (
      finding_id TEXT PRIMARY KEY REFERENCES events(id),
      target TEXT NOT NULL, management_id TEXT UNIQUE, number INTEGER,
      title_override TEXT,
      option TEXT, privilege TEXT, report_project TEXT, report_status TEXT NOT NULL,
      owner TEXT, nfs_version TEXT, vulnerability_type TEXT, methodology TEXT,
      found_date TEXT, exploit TEXT, cve TEXT,
      approved_at TEXT, withdrawn_at TEXT, superseded_by TEXT,
      updated_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
      admin_overrides_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE UNIQUE INDEX IF NOT EXISTS registry_active_number
      ON finding_registry(target, number) WHERE management_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS registry_history (
      management_id TEXT PRIMARY KEY, number INTEGER NOT NULL, title TEXT NOT NULL,
      target TEXT NOT NULL, option TEXT, privilege TEXT, report_project TEXT,
      report_status TEXT, owner TEXT, nfs_version TEXT,
      vulnerability_type TEXT, methodology TEXT, found_date TEXT,
      exploit TEXT, cve TEXT, imported_at TEXT NOT NULL,
      updated_at TEXT, revision INTEGER NOT NULL DEFAULT 0,
      manual_overrides_json TEXT NOT NULL DEFAULT '[]',
      UNIQUE(target, number)
    );
    CREATE TABLE IF NOT EXISTS registry_edits (
      id INTEGER PRIMARY KEY,
      row_id TEXT NOT NULL,
      actor TEXT NOT NULL,
      edited_at TEXT NOT NULL,
      changes_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS registry_edits_row ON registry_edits(row_id, id);
  `);
  const columns = new Set(db.prepare('PRAGMA table_info(finding_registry)').all().map(column => column.name));
  if (!columns.has('admin_overrides_json')) db.exec("ALTER TABLE finding_registry ADD COLUMN admin_overrides_json TEXT NOT NULL DEFAULT '[]'");
  if (!columns.has('title_override')) db.exec('ALTER TABLE finding_registry ADD COLUMN title_override TEXT');
  const historyColumns = new Set(db.prepare('PRAGMA table_info(registry_history)').all().map(column => column.name));
  if (!historyColumns.has('updated_at')) db.exec('ALTER TABLE registry_history ADD COLUMN updated_at TEXT');
  if (!historyColumns.has('revision')) db.exec('ALTER TABLE registry_history ADD COLUMN revision INTEGER NOT NULL DEFAULT 0');
  if (!historyColumns.has('manual_overrides_json')) db.exec("ALTER TABLE registry_history ADD COLUMN manual_overrides_json TEXT NOT NULL DEFAULT '[]'");
  for (const [target, floor] of Object.entries(floors)) {
    db.prepare('INSERT OR IGNORE INTO registry_sequences(target, last_number) VALUES (?, ?)').run(target, floor);
    db.prepare('UPDATE registry_sequences SET last_number = ? WHERE target = ? AND last_number < ?').run(floor, target, floor);
  }
  for (const event of db.prepare("SELECT id, markdown, created_at FROM events WHERE kind = 'finding' AND id NOT IN (SELECT finding_id FROM finding_registry) ORDER BY received_at, id").all()) {
    registerFinding(db, event.id, readFrontMatter(event.markdown).data, event.created_at);
  }
  for (const correction of db.prepare("SELECT c.corrects_event_id, c.received_at FROM events c JOIN events f ON f.id = c.corrects_event_id WHERE c.kind = 'correction' AND f.kind = 'finding'").all()) {
    withdrawFinding(db, correction.corrects_event_id, correction.received_at);
  }
  // Submission screening may assign a number without claiming dynamic reproduction.
}

export function registerFinding(db, id, data, createdAt) {
  validateRegistryMetadata(data);
  const target = data.registry_target ?? 'knfsd';
  const values = {
    target,
    option: data.registry_option ?? null,
    privilege: data.registry_privilege ?? null,
    report_project: data.registry_report_project ?? (target === 'knfsd' ? 'Linux kernel' : null),
    report_status: '미제보',
    owner: data.registry_owner ?? null,
    nfs_version: data.registry_nfs_version ?? null,
    vulnerability_type: data.registry_vulnerability_type ?? null,
    methodology: data.registry_methodology ?? 'LLM',
    found_date: data.registry_found_date ?? createdAt.slice(0, 10),
    exploit: data.registry_exploit ?? null,
    cve: data.registry_cve ?? null,
  };
  db.prepare(`INSERT OR IGNORE INTO finding_registry
    (finding_id, target, option, privilege, report_project, report_status, owner,
     nfs_version, vulnerability_type, methodology, found_date, exploit, cve, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, ...Object.values(values), new Date().toISOString());
}

export function completeFindingReview(db, id, review) {
  if (!['likely', 'unlikely', 'uncertain'].includes(review.verdict) || typeof review.summary !== 'string' || !review.summary.trim()) invalid('Invalid static review');
  db.exec('BEGIN IMMEDIATE');
  try {
    const changed = db.prepare("UPDATE finding_reviews SET status = 'complete', verdict = ?, summary = ?, completed_at = ? WHERE finding_id = ? AND status = 'processing'").run(review.verdict, review.summary, new Date().toISOString(), id).changes;
    if (!changed) invalid('Finding review is not processing', 409);
    db.exec('COMMIT');
    return null;
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function retryFindingReview(db, id, configured) {
  const row = db.prepare('SELECT status FROM finding_reviews WHERE finding_id = ?').get(id);
  if (!row) invalid('Finding not found', 404);
  if (row.status !== 'error') invalid('Only failed static reviews can be retried', 409);
  const status = configured ? 'pending' : 'unconfigured';
  const updated = db.prepare("UPDATE finding_reviews SET status = ?, verdict = NULL, summary = NULL, requested_at = ?, completed_at = NULL WHERE finding_id = ? AND status = 'error'")
    .run(status, new Date().toISOString(), id);
  if (updated.changes !== 1) invalid('Review state changed; reload before retrying', 409);
  return { finding_id: id, status };
}

export function withdrawFinding(db, id, at = new Date().toISOString()) {
  const row = db.prepare('SELECT finding_id FROM finding_registry WHERE finding_id = ?').get(id);
  if (row) db.prepare("UPDATE finding_registry SET report_status = '철회', withdrawn_at = ?, updated_at = ?, revision = revision + 1 WHERE finding_id = ? AND withdrawn_at IS NULL").run(at, at, id);
}

export function listRegistry(db) {
  const historyVerifications = latestHistoryVerifications(db);
  const approvedVersions = new Map();
  for (const row of db.prepare(`SELECT management_id, agent_id, reason, submitted_at, completed_at,
      accepted_json, verification_json FROM submissions WHERE status = 'approved'
      AND management_id IS NOT NULL AND accepted_json IS NOT NULL
      ORDER BY submitted_at DESC, id DESC`).all()) {
    const accepted = JSON.parse(row.accepted_json);
    if (!approvedVersions.has(row.management_id)) approvedVersions.set(row.management_id,
      { latest: { ...row, accepted }, impacts: new Set() });
    for (const impact of accepted.verified_impacts || []) approvedVersions.get(row.management_id).impacts.add(impact);
  }
  const duplicateReviews = new Map(db.prepare(`SELECT row_id, verdict, reason, evidence_json,
    sources_checked_json, checked_at, outcome FROM duplicate_reviews
    WHERE id IN (SELECT MAX(id) FROM duplicate_reviews GROUP BY row_id)`).all().map(row => [row.row_id, {
    verdict: row.verdict, reason: row.reason, evidence: JSON.parse(row.evidence_json),
    sources_checked: JSON.parse(row.sources_checked_json), checked_at: row.checked_at, outcome: row.outcome,
  }]));
  const internalDuplicateReviews = new Map(db.prepare(`SELECT row_id, verdict, reason,
    matched_management_id, checked_at, outcome FROM internal_duplicate_reviews
    WHERE id IN (SELECT MAX(id) FROM internal_duplicate_reviews GROUP BY row_id)`).all().map(row => [row.row_id, {
    verdict: row.verdict, reason: row.reason, matched_management_id: row.matched_management_id,
    checked_at: row.checked_at, outcome: row.outcome,
  }]));
  const live = db.prepare(`SELECT r.*, e.title, e.agent_id, e.created_at, e.markdown,
    e.corrects_event_id AS replaces_event_id, v.status AS review_status,
    v.verdict AS review_verdict, v.summary AS review_summary, v.provider AS review_provider,
    pr.status AS primitive_review_status, pr.summary AS primitive_review_summary,
    pr.completed_at AS primitive_review_completed_at
    FROM finding_registry r JOIN events e ON e.id = r.finding_id
    LEFT JOIN finding_reviews v ON v.finding_id = r.finding_id
    LEFT JOIN primitive_reviews pr ON pr.finding_id = r.finding_id
    WHERE r.superseded_by IS NULL ORDER BY r.approved_at DESC, e.received_at DESC`).all().map(row => {
    const data = readFrontMatter(row.markdown).data;
    const { markdown, finding_id, approved_at, withdrawn_at, superseded_by, updated_at, admin_overrides_json, title_override, ...record } = row;
    return {
      event_id: finding_id, origin: 'agent', ...record, title: title_override ?? row.title,
      duplicate_review: duplicateReviews.get(finding_id) ?? null,
      internal_duplicate_review: internalDuplicateReviews.get(finding_id) ?? null,
      registration_status: row.management_id ? 'verified' : 'pending',
      verified_at: approved_at, updated_at,
      file_path: data.file_path || null, code_refs: data.code_refs || [],
      access_requirements: data.access_requirements || [], verified_impacts:
        [...new Set([...(data.verified_impacts || []), ...(approvedVersions.get(row.management_id)?.impacts || [])])],
      claimed_impacts: data.claimed_impacts || [], dynamic_status: data.dynamic_status ?? null,
      vm_environment: data.vm_environment || null, reproduction_command: data.reproduction_command || null,
      kasan_summary: data.kasan_log?.match(/^.*BUG:\s*KASAN:.*$/im)?.[0].trim() || null,
    };
  });
  const history = db.prepare('SELECT * FROM registry_history ORDER BY management_id').all().map(row => {
    const version = approvedVersions.get(row.management_id);
    const accepted = version?.latest.accepted;
    const verification = version ? JSON.parse(version.latest.verification_json) : null;
    const earlier = historyVerifications.get(row.management_id);
    const impacts = new Set([...(earlier?.result === 'verified' ? earlier.observed_impacts : []),
      ...(version?.impacts || [])]);
    const { manual_overrides_json, ...record } = row;
    return {
    ...record, event_id: `history:${row.management_id}`, origin: 'history',
    duplicate_review: duplicateReviews.get(`history:${row.management_id}`) ?? null,
    internal_duplicate_review: internalDuplicateReviews.get(`history:${row.management_id}`) ?? null,
    latest_verification: version ? {
      result: verification?.dynamic_status === 'not_run' ? 'static_screened' : 'verified',
      static_verdict: 'likely', reproduction_status: verification?.dynamic_status ?? 'observed',
      kernel_commit: verification?.kernel_commit,
      observed_impacts: verification?.dynamic_status === 'not_run' ? [] : [...impacts],
      reason: version.latest.reason, completed_at: version.latest.completed_at,
    } : earlier ?? null,
    agent_id: version?.latest.agent_id ?? null, created_at: null,
    review_status: version ? 'complete' : null, review_verdict: version ? 'likely' : null,
    review_provider: version ? verification?.dynamic_status === 'not_run' ? 'codex_static' : 'codex_qemu' : null,
    review_summary: version?.latest.reason ?? null,
    primitive_review_status: null, primitive_review_summary: null,
    primitive_review_completed_at: null,
    registration_status: version || earlier?.result === 'verified' ? 'verified' : 'history',
    verified_at: version?.latest.completed_at ?? null,
    updated_at: row.updated_at ?? row.imported_at, replaces_event_id: null,
    file_path: accepted?.file_path ?? null, code_refs: accepted?.code_refs ?? [],
    access_requirements: [], verified_impacts: [...impacts],
    claimed_impacts: accepted?.claimed_impacts ?? [], dynamic_status: accepted?.dynamic_status ?? null,
    vm_environment: accepted?.vm_environment ?? null,
    reproduction_command: accepted?.reproduction_command ?? null,
    kasan_summary: accepted?.kasan_summary ?? null,
  };
  });
  return [...history, ...live];
}

// Only the historical management columns enter this table; operational triage data stays out.
function normalizeHistoricalRows(rows) {
  if (!Array.isArray(rows)) invalid('Historical registry must be an array');
  const expected = Object.entries(floors).flatMap(([target, last]) =>
    Array.from({ length: last }, (_, index) => `${prefixes[target]}-${String(index + 1).padStart(3, '0')}`));
  if (rows.length !== expected.length) invalid(`Historical registry must contain ${expected.length} rows`);
  const seen = new Set();
  const normalized = rows.map(row => {
    if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).some(key => !historicalFields.includes(key))) invalid('Invalid historical registry fields');
    const match = /^([ABC])-(\d{3})$/.exec(row.management_id || '');
    if (!match || !expected.includes(row.management_id) || seen.has(row.management_id)) invalid('Missing, duplicate, or out-of-range historical management ID');
    seen.add(row.management_id);
    const target = Object.keys(prefixes).find(name => prefixes[name] === match[1]);
    if (row.target !== target) invalid('Historical target does not match management ID');
    const result = { management_id: row.management_id, number: Number(match[2]), title: field(row.title, 'title', 300), target };
    for (const [key, max] of Object.entries(editable)) result[key] = row[key] == null ? null : field(row[key], key, max);
    if (result.report_status !== null && !['미제보', '제보 중', '제보 완료', '중복', '철회'].includes(result.report_status)) invalid('Invalid historical report_status');
    if (result.found_date !== null && !/^(?:\d{4}-\d{2}-\d{2}|(?:0?[1-9]|1[0-2])\.(?:0?[1-9]|[12]\d|3[01]))$/.test(result.found_date)) invalid('Invalid historical found_date');
    if (result.cve !== null && !/^CVE-\d{4}-\d{4,}$/i.test(result.cve)) invalid('Invalid historical cve');
    return result;
  });
  if (seen.size !== expected.length || expected.some(id => !seen.has(id))) invalid('Historical registry has missing management IDs');
  return normalized;
}

export function importRegistryHistory(db, rows) {
  const normalized = normalizeHistoricalRows(rows);
  const columns = ['management_id', 'number', 'title', 'target', ...Object.keys(editable)];
  const insert = db.prepare(`INSERT INTO registry_history (${columns.join(', ')}, imported_at) VALUES (${columns.map(() => '?').join(', ')}, ?)`);
  const existing = db.prepare(`SELECT ${columns.join(', ')}, manual_overrides_json FROM registry_history WHERE management_id = ?`);
  const live = db.prepare('SELECT 1 FROM finding_registry WHERE management_id = ?');
  db.exec('BEGIN IMMEDIATE');
  try {
    const importedAt = new Date().toISOString();
    let added = 0;
    for (const row of normalized) {
      if (live.get(row.management_id)) invalid('Historical management ID conflicts with a live finding', 409);
      const values = columns.map(column => row[column]);
      const previous = existing.get(row.management_id);
      if (previous) {
        const overrides = new Set(JSON.parse(previous.manual_overrides_json));
        if (columns.some(column => !overrides.has(column) && previous[column] !== row[column])) invalid('Historical registry row differs from already imported data', 409);
      } else {
        insert.run(...values, importedAt);
        added++;
      }
    }
    db.exec('COMMIT');
    return { total: normalized.length, added };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

// Reconcile only the existing historical rows; live findings and number sequences are separate.
export function reconcileRegistryHistory(db, rows) {
  const normalized = normalizeHistoricalRows(rows);
  const columns = ['title', ...Object.keys(editable)];
  const existing = db.prepare(`SELECT management_id, manual_overrides_json, ${columns.join(', ')} FROM registry_history WHERE management_id = ?`);
  const update = db.prepare(`UPDATE registry_history SET ${columns.map(column => `${column} = ?`).join(', ')}, updated_at = ?, revision = revision + 1 WHERE management_id = ?`);
  const live = db.prepare('SELECT 1 FROM finding_registry WHERE management_id = ?');
  db.exec('BEGIN IMMEDIATE');
  try {
    const currentIds = db.prepare('SELECT management_id FROM registry_history').all().map(row => row.management_id);
    const requestedIds = new Set(normalized.map(row => row.management_id));
    if (currentIds.length !== normalized.length || currentIds.some(id => !requestedIds.has(id))) invalid('Historical registry does not match 64 expected IDs', 409);
    let updated = 0;
    for (const row of normalized) {
      if (live.get(row.management_id)) invalid('Historical management ID conflicts with a live finding', 409);
      const previous = existing.get(row.management_id);
      if (!previous) invalid('Historical registry has missing management IDs', 409);
      const overrides = new Set(JSON.parse(previous.manual_overrides_json));
      const next = Object.fromEntries(columns.map(column => [column, overrides.has(column) ? previous[column] : row[column]]));
      const changes = Object.fromEntries(columns.filter(column => previous[column] !== next[column])
        .map(column => [column, { before: previous[column], after: next[column] }]));
      if (Object.keys(changes).length) {
        const time = new Date().toISOString();
        update.run(...columns.map(column => next[column]), time, row.management_id);
        recordRegistryEdit(db, `history:${row.management_id}`, 'reconcile', time, changes);
        updated++;
      }
    }
    db.exec('COMMIT');
    return { total: normalized.length, updated };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function registrySequences(db) {
  return db.prepare("SELECT target, last_number FROM registry_sequences ORDER BY CASE target WHEN 'knfsd' THEN 0 WHEN 'NFS-Ganesha' THEN 1 ELSE 2 END").all()
    .map(row => ({ target: row.target, next_id: `${prefixes[row.target]}-${String(row.last_number + 1).padStart(3, '0')}` }));
}

const editableRowFields = { title: 300, ...editable };
const reportStatuses = new Set(['미제보', '제보 중', '제보 완료', '중복', '철회']);

function normalizeRegistryEdit(input, history) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || !Number.isInteger(input.revision) || input.revision < 0) invalid('Registry revision is required');
  const entries = Object.entries(input).filter(([key]) => key !== 'revision');
  if (!entries.length || entries.some(([key]) => !Object.hasOwn(editableRowFields, key))) invalid('Invalid registry fields');
  return entries.map(([key, value]) => {
    if (typeof value === 'string' && !value.trim() && key !== 'title') value = null;
    if (key === 'title' && value === null) invalid('Invalid title');
    if (key === 'report_status' && (value === null ? !history : !reportStatuses.has(value))) invalid('Invalid report_status');
    if (key === 'found_date' && value !== null && !(history
      ? /^(?:\d{4}-\d{2}-\d{2}|(?:0?[1-9]|1[0-2])\.(?:0?[1-9]|[12]\d|3[01]))$/
      : /^\d{4}-\d{2}-\d{2}$/).test(value)) invalid('Invalid found_date');
    if (key === 'cve' && value !== null && !/^CVE-\d{4}-\d{4,}$/i.test(value)) invalid('Invalid cve');
    return [key, field(value, key, editableRowFields[key])];
  });
}

function recordRegistryEdit(db, rowId, actor, time, changes) {
  db.prepare('INSERT INTO registry_edits(row_id, actor, edited_at, changes_json) VALUES (?, ?, ?, ?)')
    .run(rowId, actor, time, JSON.stringify(changes));
}

// Events and their original titles stay immutable; dashboard changes live in finding_registry.
export function updateRegistry(db, id, input, actor = 'admin') {
  const entries = normalizeRegistryEdit(input, false);
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db.prepare(`SELECT r.*, e.title AS submitted_title FROM finding_registry r
      JOIN events e ON e.id = r.finding_id WHERE r.finding_id = ? AND r.superseded_by IS NULL`).get(id);
    if (!row) invalid('Finding not found', 404);
    if (row.revision !== input.revision) invalid('Registry changed; reload before editing', 409);
    const changes = entries.filter(([key, value]) =>
      (key === 'title' ? row.title_override ?? row.submitted_title : row[key]) !== value);
    if (changes.length) {
      const time = new Date().toISOString();
      const overrides = [...new Set([...JSON.parse(row.admin_overrides_json), ...changes.map(([key]) => key)])];
      const update = Object.fromEntries(changes.map(([key, value]) => [key, {
        before: key === 'title' ? row.title_override ?? row.submitted_title : row[key], after: value,
      }]));
      const set = changes.map(([key]) => `${key === 'title' ? 'title_override' : key} = ?`);
      const status = changes.find(([key]) => key === 'report_status');
      if (status) set.push('withdrawn_at = ?');
      const params = changes.map(([, value]) => value);
      if (status) params.push(status[1] === '철회' ? time : null);
      const written = db.prepare(`UPDATE finding_registry SET ${set.join(', ')},
        admin_overrides_json = ?, updated_at = ?, revision = revision + 1
        WHERE finding_id = ? AND revision = ?`).run(...params, JSON.stringify(overrides), time, id, row.revision);
      if (written.changes !== 1) invalid('Registry changed; reload before editing', 409);
      recordRegistryEdit(db, id, actor, time, update);
    }
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return listRegistry(db).find(item => item.event_id === id);
}

function updateHistoricalRegistry(db, managementId, input, actor) {
  const entries = normalizeRegistryEdit(input, true);
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db.prepare('SELECT * FROM registry_history WHERE management_id = ?').get(managementId);
    if (!row) invalid('Finding not found', 404);
    if (row.revision !== input.revision) invalid('Registry changed; reload before editing', 409);
    const changes = entries.filter(([key, value]) => row[key] !== value);
    if (changes.length) {
      const time = new Date().toISOString();
      const overrides = [...new Set([...JSON.parse(row.manual_overrides_json), ...changes.map(([key]) => key)])];
      const written = db.prepare(`UPDATE registry_history SET ${changes.map(([key]) => `${key} = ?`).join(', ')},
        manual_overrides_json = ?, updated_at = ?, revision = revision + 1
        WHERE management_id = ? AND revision = ?`).run(
        ...changes.map(([, value]) => value), JSON.stringify(overrides), time, managementId, row.revision);
      if (written.changes !== 1) invalid('Registry changed; reload before editing', 409);
      recordRegistryEdit(db, `history:${managementId}`, actor, time, Object.fromEntries(changes.map(([key, value]) =>
        [key, { before: row[key], after: value }])));
    }
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return listRegistry(db).find(item => item.event_id === `history:${managementId}`);
}

export function updateRegistryRow(db, id, input, actor) {
  if (/^history:[ABC]-\d{3}$/.test(id)) return updateHistoricalRegistry(db, id.slice(8), input, actor);
  if (/^[a-f0-9]{64}$/.test(id)) return updateRegistry(db, id, input, actor);
  invalid('Finding not found', 404);
}

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { hash, evidenceLimits, HttpError, invalid, required, safeEqual, readFrontMatter, validateEvent, parseLcov, mcpTools } from './contract.mjs';
export { evidenceLimits, validateEvent, parseLcov, mcpTools } from './contract.mjs';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, 'public');
const now = () => new Date().toISOString();
function openDatabase(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, source_path TEXT NOT NULL,
      sha256 TEXT NOT NULL, kind TEXT NOT NULL, version_id TEXT NOT NULL,
      repo_commit TEXT NOT NULL, title TEXT NOT NULL,
      claim_key TEXT, hypothesis_id TEXT, verification_of TEXT, verdict TEXT,
      method TEXT, prior_exposure TEXT, based_on_json TEXT, scope_json TEXT NOT NULL,
      related_hypothesis_id TEXT, corrects_event_id TEXT, created_at TEXT NOT NULL,
      received_at TEXT NOT NULL, markdown TEXT NOT NULL,
      UNIQUE(version_id, agent_id, source_path)
    );
    CREATE INDEX IF NOT EXISTS events_version ON events(version_id, received_at);
    CREATE TABLE IF NOT EXISTS batches (
      id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, version_id TEXT NOT NULL,
      repo_commit TEXT NOT NULL, scope_hash TEXT NOT NULL,
      worktree_clean INTEGER NOT NULL, generated_at TEXT NOT NULL,
      received_at TEXT NOT NULL, files_json TEXT NOT NULL,
      manifest_json TEXT NOT NULL, lcov TEXT NOT NULL,
      coverage_json TEXT NOT NULL, progress_md TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS batches_version ON batches(version_id, repo_commit, generated_at);
    CREATE TABLE IF NOT EXISTS agents (
      agent_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL, last_seen_at TEXT
    );
    CREATE TABLE IF NOT EXISTS exposures (
      agent_id TEXT NOT NULL, hypothesis_id TEXT NOT NULL,
      mode TEXT NOT NULL, seen_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS exposures_lookup ON exposures(agent_id, hypothesis_id, seen_at);
    CREATE TABLE IF NOT EXISTS track_targets (
      track_id TEXT NOT NULL, version_id TEXT NOT NULL, repo_commit TEXT NOT NULL,
      active INTEGER NOT NULL, activated_at TEXT NOT NULL,
      PRIMARY KEY(track_id, version_id, repo_commit), UNIQUE(version_id, repo_commit)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS active_track ON track_targets(track_id) WHERE active = 1;
  `);
  const batchColumns = new Set(db.prepare('PRAGMA table_info(batches)').all().map(column => column.name));
  if (!batchColumns.has('manifest_json')) db.exec('ALTER TABLE batches ADD COLUMN manifest_json TEXT');
  if (!batchColumns.has('lcov')) db.exec('ALTER TABLE batches ADD COLUMN lcov TEXT');
  return db;
}

function issueAgentToken(db, agentId, rotate = false) {
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(agentId)) invalid('Invalid agent_id');
  const token = randomBytes(32).toString('hex');
  if (rotate) {
    if (!db.prepare('UPDATE agents SET token_hash = ? WHERE agent_id = ?').run(hash(token), agentId).changes) invalid('Unknown agent', 404);
  } else {
    if (db.prepare('SELECT 1 FROM agents WHERE agent_id = ?').get(agentId)) invalid('Agent already exists', 409);
    db.prepare('INSERT INTO agents VALUES (?, ?, ?, NULL)').run(agentId, hash(token), now());
  }
  return { agent_id: agentId, token };
}

function bearer(req) {
  return /^Bearer ([a-z0-9._~-]+)$/i.exec(req.headers.authorization || '')?.[1] || '';
}

function authenticatedAgent(db, req) {
  const token = bearer(req);
  const row = token && db.prepare('SELECT agent_id FROM agents WHERE token_hash = ?').get(hash(token));
  if (!row) invalid('Agent token required', 401);
  db.prepare('UPDATE agents SET last_seen_at = ? WHERE agent_id = ?').run(now(), row.agent_id);
  return row.agent_id;
}

function exposedModes(db, agentId, hypothesisId, before = now()) {
  return db.prepare('SELECT DISTINCT mode FROM exposures WHERE agent_id = ? AND hypothesis_id = ? AND seen_at <= ?').all(agentId, hypothesisId, before).map(row => row.mode);
}

function addEvent(db, input, agentId) {
  const event = validateEvent(input);
  if (event.agentId !== agentId) invalid('agent_id does not match token', 403);
  const { sourcePath, markdown, digest, data } = event;
  const id = hash(`${data.version_id}\0${agentId}\0${sourcePath}`);
  db.exec('BEGIN IMMEDIATE');
  try {
    const existing = db.prepare('SELECT id, sha256, hypothesis_id, verification_of, related_hypothesis_id FROM events WHERE version_id = ? AND agent_id = ? AND source_path = ?').get(data.version_id, agentId, sourcePath);
    if (existing) {
      if (existing.sha256 !== digest) invalid('immutable_event_changed', 409);
      db.exec('COMMIT');
      const warning = targetWarning(db, data.version_id, data.repo_commit);
      return { event_id: existing.id, hypothesis_id: existing.hypothesis_id || existing.verification_of || existing.related_hypothesis_id, replayed: true, possible_matches: [], warnings: warning ? [warning] : [] };
    }
    if (data.kind === 'verification' || data.kind === 'finding' || (data.kind === 'analysis' && data.hypothesis_id)) {
      const target = db.prepare("SELECT version_id, repo_commit FROM events h WHERE hypothesis_id = ? AND kind = 'hypothesis' AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = h.id)").get(data.verification_of || data.finding_of || data.hypothesis_id);
      if (!target || (target.version_id !== data.version_id && (!trackFor(db, data.version_id, data.repo_commit) || trackFor(db, data.version_id, data.repo_commit) !== trackFor(db, target.version_id, target.repo_commit)))) invalid('Unknown hypothesis', 422);
    }
    if (data.kind === 'finding') {
      const support = new Set(db.prepare("SELECT v.id FROM events v WHERE v.kind = 'verification' AND v.verification_of = ? AND v.repo_commit = ? AND v.verdict = 'supports' AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = v.id)").all(data.finding_of, data.repo_commit).map(row => row.id));
      if (data.evidence_event_ids.some(id => !support.has(id))) {
        if (data.evidence_event_ids.some(id => !db.prepare('SELECT 1 FROM events WHERE id = ?').get(id))) invalid('Unknown supporting verification', 422);
        invalid('Finding evidence must reference active supporting verifications', 422);
      }
    }
    if (data.kind === 'correction') {
      const target = db.prepare('SELECT version_id, agent_id FROM events WHERE id = ?').get(data.corrects_event_id);
      if (!target) invalid('Unknown corrected event', 422);
      if (target.version_id !== data.version_id || target.agent_id !== agentId) invalid('Corrected event must have the same version and author', 422);
    }
    const trackId = trackFor(db, data.version_id, data.repo_commit);
    const matches = data.kind !== 'hypothesis' ? [] : trackId
      ? db.prepare("SELECT h.* FROM events h JOIN track_targets t ON t.version_id = h.version_id AND t.repo_commit = h.repo_commit WHERE h.kind = 'hypothesis' AND t.track_id = ? AND (h.claim_key = ? OR lower(h.title) = lower(?)) AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = h.id) ORDER BY h.received_at DESC LIMIT 8").all(trackId, data.claim_key, data.title)
      : db.prepare("SELECT h.* FROM events h WHERE h.kind = 'hypothesis' AND h.version_id = ? AND (h.claim_key = ? OR lower(h.title) = lower(?)) AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = h.id) ORDER BY h.received_at DESC LIMIT 8").all(data.version_id, data.claim_key, data.title);
    const possibleMatches = matches.map(row => ({ hypothesis_id: row.hypothesis_id, title: row.title, agent_id: row.agent_id, code_refs: readFrontMatter(row.markdown).data.code_refs || [], status: claimStatus(hypothesisState(db, row, data.repo_commit, activeChecks(db, row.hypothesis_id)).status) }));
    const exposure = data.kind === 'verification' ? exposedModes(db, agentId, data.verification_of) : [];
    const exposureConflict = (exposure.some(mode => ['full', 'summary'].includes(mode)) && ['none', 'claim_only'].includes(data.prior_exposure)) || (exposure.includes('claim_only') && data.prior_exposure === 'none');
    const warnings = exposureConflict ? ['prior_exposure_differs_from_server_log'] : [];
    const warning = targetWarning(db, data.version_id, data.repo_commit);
    if (warning) warnings.push(warning);
    const hypothesisId = data.kind === 'hypothesis' ? `H-${id.slice(0, 12)}` : null;
    db.prepare(`INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      id, agentId, sourcePath, digest, data.kind, data.version_id,
      data.repo_commit, data.title, data.claim_key || null, hypothesisId,
      data.verification_of || null, data.verdict || null, data.method || null,
      data.prior_exposure || null, JSON.stringify(data.evidence_event_ids || data.based_on_event_ids || []),
      JSON.stringify(data.scope), data.finding_of || data.hypothesis_id || data.related_hypothesis_id || null,
      data.corrects_event_id || null, data.created_at, now(), markdown,
    );
    db.exec('COMMIT');
    return { event_id: id, hypothesis_id: hypothesisId || data.verification_of || data.finding_of || data.hypothesis_id || null, replayed: false, possible_matches: possibleMatches, warnings };
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function addBatch(db, input, agentId) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid('Invalid batch');
  const { manifest, lcov, coverage_json: coverageJson, progress_md: progressMd } = input;
  if (!manifest || typeof manifest !== 'object') invalid('Missing manifest');
  if (manifest.schema_version !== 1) invalid('Unsupported batch schema');
  for (const key of ['agent_id', 'version_id', 'repo_commit', 'coverage_scope_hash', 'generated_at', 'repo_root']) required(manifest[key], key, key === 'repo_root' ? 1000 : 200);
  if (manifest.agent_id !== agentId) invalid('agent_id does not match token', 403);
  if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(manifest.version_id)) invalid('Invalid version_id');
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(manifest.agent_id) || !/^[a-f0-9]{40,64}$/i.test(manifest.repo_commit)) invalid('Invalid agent or commit');
  if (manifest.worktree_clean !== true && manifest.worktree_clean !== false) invalid('worktree_clean must be boolean');
  if (!Number.isFinite(Date.parse(manifest.generated_at))) invalid('Invalid generated_at');
  if (typeof coverageJson !== 'string' || coverageJson.length > 10_000_000 || typeof progressMd !== 'string' || progressMd.length > 1_000_000) invalid('Invalid batch content');
  const files = parseLcov(lcov, manifest.repo_root);
  try { JSON.parse(coverageJson); } catch { invalid('Invalid coverage.json'); }
  const progressMeta = readFrontMatter(progressMd).data;
  if (progressMeta.schema_version !== 1 || progressMeta.version_id !== manifest.version_id || progressMeta.repo_commit !== manifest.repo_commit) invalid('Progress file version or commit mismatch');
  const hashes = { 'agentcov.info': hash(lcov), 'coverage.json': hash(coverageJson), 'progress.md': hash(progressMd) };
  for (const [name, digest] of Object.entries(hashes)) if (manifest.hashes?.[name] !== digest) invalid(`Hash mismatch: ${name}`);
  const id = hash([manifest.version_id, manifest.agent_id, manifest.repo_commit, manifest.coverage_scope_hash, String(manifest.worktree_clean), manifest.generated_at, ...Object.values(hashes)].join('\0'));
  if (manifest.batch_id && manifest.batch_id !== id) invalid('Batch ID mismatch');
  const warning = targetWarning(db, manifest.version_id, manifest.repo_commit);
  const warnings = warning ? [warning] : [];
  if (db.prepare('SELECT 1 FROM batches WHERE id = ?').get(id)) return { batch_id: id, accepted: true, replayed: true, warnings };
  db.prepare('INSERT INTO batches (id, agent_id, version_id, repo_commit, scope_hash, worktree_clean, generated_at, received_at, files_json, manifest_json, lcov, coverage_json, progress_md) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
    id, manifest.agent_id, manifest.version_id, manifest.repo_commit,
    manifest.coverage_scope_hash, Number(manifest.worktree_clean), manifest.generated_at,
    now(), JSON.stringify(files), JSON.stringify(manifest), lcov, coverageJson, progressMd,
  );
  return { batch_id: id, accepted: true, replayed: false, warnings };
}

function progressRows(markdown) {
  const tasks = [];
  for (const line of markdown.split(/\r?\n/)) {
    if (!line.startsWith('|')) continue;
    const cells = line.split('|').slice(1, -1).map(s => s.trim());
    if (cells.length >= 2 && /^[A-Za-z0-9_-]+$/.test(cells[0]) && ['todo', 'in_progress', 'blocked', 'done'].includes(cells[1])) tasks.push({ id: cells[0], status: cells[1] });
  }
  return tasks;
}

function versionRows(db) {
  return db.prepare(`SELECT version_id, repo_commit, MAX(received_at) AS updated_at FROM (
    SELECT version_id, repo_commit, received_at FROM events
    UNION ALL SELECT version_id, repo_commit, received_at FROM batches
  ) GROUP BY version_id, repo_commit ORDER BY updated_at DESC`).all();
}

function trackRows(db) {
  const active = new Map(db.prepare('SELECT track_id, version_id, repo_commit, activated_at FROM track_targets WHERE active = 1').all().map(row => [row.track_id, row]));
  return [['rc', '최신 RC'], ['mainline', '최신 stable']].map(([track_id, label]) => ({ track_id, label, version_id: active.get(track_id)?.version_id || null, repo_commit: active.get(track_id)?.repo_commit || null, activated_at: active.get(track_id)?.activated_at || null }));
}

function trackFor(db, versionId, commit) {
  return db.prepare('SELECT track_id FROM track_targets WHERE version_id = ? AND repo_commit = ?').get(versionId, commit)?.track_id || null;
}

function targetWarning(db, versionId, commit) {
  const target = db.prepare('SELECT active FROM track_targets WHERE version_id = ? AND repo_commit = ?').get(versionId, commit);
  if (target) return target.active ? null : 'inactive_track_target';
  return db.prepare('SELECT 1 FROM track_targets WHERE active = 1 LIMIT 1').get() ? 'unregistered_track_target' : null;
}

function setActiveTrack(db, trackId, input) {
  if (!['rc', 'mainline'].includes(trackId)) invalid('Unknown track', 404);
  const versionId = required(input?.version_id, 'version_id', 64);
  const commit = required(input?.repo_commit, 'repo_commit', 64);
  if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(versionId) || !/^[a-f0-9]{40,64}$/i.test(commit)) invalid('Invalid version or commit');
  db.exec('BEGIN IMMEDIATE');
  try {
    const other = trackFor(db, versionId, commit);
    if (other && other !== trackId) invalid('Target already belongs to another track', 409);
    db.prepare('UPDATE track_targets SET active = 0 WHERE track_id = ?').run(trackId);
    db.prepare('INSERT INTO track_targets (track_id, version_id, repo_commit, active, activated_at) VALUES (?, ?, ?, 1, ?) ON CONFLICT(track_id, version_id, repo_commit) DO UPDATE SET active = 1, activated_at = excluded.activated_at').run(trackId, versionId, commit, now());
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return trackRows(db).find(row => row.track_id === trackId);
}

function coverageState(db, versionId, commit) {
  const latest = db.prepare(`
    SELECT b.* FROM batches b JOIN (
      SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY generated_at DESC, received_at DESC) AS rn
        FROM batches WHERE version_id = ? AND repo_commit = ?
      ) WHERE rn = 1
    ) current ON current.id = b.id
    ORDER BY b.agent_id
  `).all(versionId, commit);
  const canonical = latest.find(row => row.worktree_clean)?.scope_hash;
  const accepted = [];
  const excluded = [];
  const coverageAgents = [];
  const fileShape = new Map();
  for (const row of latest) {
    const files = JSON.parse(row.files_json);
    const entries = Object.values(files);
    const totalLines = entries.reduce((sum, file) => sum + file.eligible.length, 0);
    const readLines = entries.reduce((sum, file) => sum + file.read.length, 0);
    const included = !!row.worktree_clean && row.scope_hash === canonical && (!fileShape.size || (Object.keys(files).length === fileShape.size && Object.entries(files).every(([name, file]) => fileShape.get(name) === JSON.stringify(file.eligible))));
    coverageAgents.push({ agent_id: row.agent_id, read_lines: readLines, total_lines: totalLines, read_percent: totalLines ? Math.round(readLines / totalLines * 1000) / 10 : null, included_in_team: included });
    if (!included) {
      excluded.push(row.agent_id);
      continue;
    }
    if (!fileShape.size) for (const [name, file] of Object.entries(files)) fileShape.set(name, JSON.stringify(file.eligible));
    accepted.push({ row, files });
  }
  // ponytail: merge the latest five snapshots on read; materialize only if dashboard refresh becomes slow.
  const combined = new Map();
  const frequency = new Map();
  for (const [name, eligible] of fileShape) combined.set(name, { path: name, eligible: JSON.parse(eligible), read: new Set(), agents: 0 });
  const agents = [];
  for (const { row, files } of accepted) {
    let read = 0;
    for (const [name, file] of Object.entries(files)) {
      const target = combined.get(name);
      if (file.read.length) target.agents++;
      for (const line of file.read) {
        target.read.add(line);
        const key = `${name}\0${line}`;
        frequency.set(key, (frequency.get(key) || 0) + 1);
        read++;
      }
    }
    agents.push({ agent_id: row.agent_id, read_lines: read, generated_at: row.generated_at, unique_lines: 0 });
  }
  for (const agent of agents) {
    const files = accepted.find(entry => entry.row.agent_id === agent.agent_id).files;
    for (const [name, file] of Object.entries(files)) for (const line of file.read) if (frequency.get(`${name}\0${line}`) === 1) agent.unique_lines++;
  }
  const files = [...combined.values()].map(file => ({ path: file.path, total: file.eligible.length, read: file.read.size, agents: file.agents, percent: file.eligible.length ? Math.round(file.read.size / file.eligible.length * 1000) / 10 : 0 })).sort((a, b) => (b.total - b.read) - (a.total - a.read));
  const scope = JSON.parse(accepted[0]?.row.coverage_json || '{}').hivemind_scope;
  return { latest, accepted, excluded, coverageAgents, combined, frequency, agents, files, missingIncludes: scope?.missing_includes?.length || 0 };
}

function hypothesisState(db, event, commit, checks) {
  const current = checks.filter(item => item.repo_commit === commit);
  const support = current.filter(item => item.verdict === 'supports');
  const refute = current.filter(item => item.verdict === 'refutes');
  const independentAttempts = rows => rows.filter(item =>
    ['none', 'claim_only'].includes(item.prior_exposure)
    && JSON.parse(item.based_on_json).length === 0
    && !exposedModes(db, item.agent_id, event.hypothesis_id, item.received_at).some(mode => ['full', 'summary'].includes(mode))
  );
  const independent = rows => new Set(independentAttempts(rows).map(item => item.agent_id)).size;
  let status = 'unverified';
  if (support.length && refute.length) status = 'contested';
  else if (refute.length && independent(refute) >= 2 && new Set(independentAttempts(refute).map(item => item.method.trim().toLowerCase())).size >= 2) status = 'retired';
  else if (refute.length) status = 'refuted';
  else if (support.length && independent(support) >= 2) status = 'independently_supported';
  else if (support.length) status = 'single_source';
  else if (current.length) status = 'inconclusive';
  else if (event.repo_commit !== commit) status = 'stale';
  return { status, current };
}

function activeChecks(db, hypothesisId) {
  return db.prepare("SELECT v.* FROM events v WHERE v.kind = 'verification' AND v.verification_of = ? AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = v.id) ORDER BY v.received_at DESC").all(hypothesisId);
}

const claimStatus = status => ['retired', 'stale'].includes(status) ? status : 'active';

function dashboard(db, requested = {}) {
  const versions = versionRows(db);
  const tracks = trackRows(db);
  const active = tracks.find(row => row.track_id === requested.track_id) || tracks.find(row => row.version_id);
  const direct = versions.find(row => row.version_id === requested.version_id && row.repo_commit === requested.repo_commit);
  const selected = requested.track_id
    ? active?.version_id && active.track_id === requested.track_id ? active : null
    : direct ? { ...direct, track_id: trackFor(db, direct.version_id, direct.repo_commit) } : active?.version_id ? active : versions[0];
  if (!selected) return { tracks, versions, selected: null, metrics: null, agents: [], coverage_agents: [], files: [], hypotheses: [], verifications: [], findings: [], recent: [], progress: {} };
  const { version_id: versionId, repo_commit: commit } = selected;
  const trackId = selected.track_id || null;
  const { latest, excluded, coverageAgents, frequency, agents, files, missingIncludes } = coverageState(db, versionId, commit);
  const lastSeen = new Map(db.prepare('SELECT agent_id, last_seen_at FROM agents').all().map(row => [row.agent_id, row.last_seen_at]));
  const totalLines = files.reduce((sum, file) => sum + file.total, 0);
  const readLines = files.reduce((sum, file) => sum + file.read, 0);
  const allEvents = trackId
    ? db.prepare('SELECT e.* FROM events e JOIN track_targets t ON t.version_id = e.version_id AND t.repo_commit = e.repo_commit WHERE t.track_id = ? ORDER BY e.received_at DESC').all(trackId)
    : db.prepare('SELECT * FROM events WHERE version_id = ? ORDER BY received_at DESC').all(versionId);
  const corrected = new Set(allEvents.filter(e => e.kind === 'correction').map(e => e.corrects_event_id));
  const attempts = allEvents.filter(e => e.kind === 'verification' && !corrected.has(e.id));
  const hypotheses = allEvents.filter(e => e.kind === 'hypothesis' && !corrected.has(e.id)).map(event => {
    const checks = attempts.filter(item => item.verification_of === event.hypothesis_id);
    const { status, current } = hypothesisState(db, event, commit, checks);
    return { id: event.hypothesis_id, event_id: event.id, title: event.title, agent_id: event.agent_id, status, scope: JSON.parse(event.scope_json), code_refs: readFrontMatter(event.markdown).data.code_refs || [], claim_key: event.claim_key, created_at: event.created_at, checks: current.map(item => ({ event_id: item.id, agent_id: item.agent_id, verdict: item.verdict, method: item.method, prior_exposure: item.prior_exposure, exposure_conflict: exposedModes(db, item.agent_id, event.hypothesis_id, item.received_at).some(mode => ['full', 'summary'].includes(mode)) && ['none', 'claim_only'].includes(item.prior_exposure) })) };
  });
  const titles = new Map(hypotheses.map(item => [item.id, item.title]));
  const verifications = attempts.filter(item => item.repo_commit === commit).map(item => ({ event_id: item.id, title: item.title, agent_id: item.agent_id, hypothesis_id: item.verification_of, hypothesis_title: titles.get(item.verification_of) || item.verification_of, verdict: item.verdict, method: item.method, code_refs: readFrontMatter(item.markdown).data.code_refs || [], created_at: item.created_at }));
  const byHypothesis = new Map(hypotheses.map(item => [item.id, item]));
  const activeSupport = new Map(verifications.filter(item => item.verdict === 'supports').map(item => [item.event_id, item]));
  const findings = allEvents.filter(item => item.kind === 'finding' && item.repo_commit === commit && !corrected.has(item.id) && readFrontMatter(item.markdown).data.poc_sha256 && readFrontMatter(item.markdown).data.kasan_sha256).map(item => {
    const data = readFrontMatter(item.markdown).data;
    const hypothesis = byHypothesis.get(item.related_hypothesis_id);
    const evidenceIds = JSON.parse(item.based_on_json);
    return { event_id: item.id, title: item.title, agent_id: item.agent_id, hypothesis_id: item.related_hypothesis_id, hypothesis_title: hypothesis?.title || item.related_hypothesis_id, hypothesis_agent_id: hypothesis?.agent_id || null, hypothesis_status: hypothesis?.status || 'stale', file_path: data.file_path, code_refs: data.code_refs || [], impact: data.impact, reproduction_command: data.reproduction_command, kasan_summary: data.kasan_log.match(/^.*BUG:\s*KASAN:.*$/im)?.[0].trim() || 'KASAN 기록', evidence_event_ids: evidenceIds, evidence_agents: [...new Set(evidenceIds.map(id => activeSupport.get(id)?.agent_id).filter(Boolean))], evidence_active: evidenceIds.every(id => activeSupport.has(id)), created_at: item.created_at };
  });
  const taskMap = new Map();
  for (const row of [...latest].sort((a, b) => a.generated_at.localeCompare(b.generated_at))) for (const task of progressRows(row.progress_md)) taskMap.set(task.id, task.status);
  const progress = Object.fromEntries(['todo', 'in_progress', 'blocked', 'done'].map(status => [status, [...taskMap.values()].filter(value => value === status).length]));
  const recent = allEvents.filter(event => event.repo_commit === commit).slice(0, 12).map(e => ({ id: e.id, kind: e.kind, title: e.title, agent_id: e.agent_id, received_at: e.received_at }));
  return {
    tracks, versions, selected: { track_id: trackId, version_id: versionId, repo_commit: commit },
    metrics: { read_lines: readLines, total_lines: totalLines, read_percent: totalLines ? Math.round(readLines / totalLines * 1000) / 10 : null, unread_lines: totalLines - readLines, overlap_lines: [...frequency.values()].filter(n => n > 1).length, agent_count: agents.length, excluded_agents: excluded, missing_includes: missingIncludes, hypothesis_count: hypotheses.length, contested_count: hypotheses.filter(h => h.status === 'contested').length, retired_count: hypotheses.filter(h => h.status === 'retired').length, updated_at: latest.reduce((value, row) => row.received_at > value ? row.received_at : value, '') || selected.activated_at || selected.updated_at },
    agents: agents.map(agent => ({ ...agent, last_seen_at: lastSeen.get(agent.agent_id) || null })), coverage_agents: coverageAgents, files, hypotheses, verifications, findings, recent, progress,
  };
}

function selectedVersion(db, args) {
  if (args.track_id && !args.version_id && !args.repo_commit) {
    const active = trackRows(db).find(row => row.track_id === args.track_id);
    if (!active?.version_id) invalid('Track has no current target', 404);
    return { versionId: active.version_id, commit: active.repo_commit };
  }
  const versionId = required(args.version_id, 'version_id', 64);
  const commit = required(args.repo_commit, 'repo_commit', 64);
  if (!versionRows(db).some(row => row.version_id === versionId && row.repo_commit === commit) && !trackFor(db, versionId, commit)) invalid('Unknown version or commit', 404);
  return { versionId, commit };
}

function coverageDetails(db, args) {
  const { versionId, commit } = selectedVersion(db, args);
  const state = coverageState(db, versionId, commit);
  const agentId = args.agent_id || null;
  let files = state.files;
  let missingIncludes = state.missingIncludes;
  let includedInTeam = true;
  if (agentId) {
    const snapshot = state.latest.find(row => row.agent_id === agentId);
    if (!snapshot) invalid('Unknown agent for this version and commit', 404);
    files = Object.entries(JSON.parse(snapshot.files_json)).map(([name, file]) => ({ path: name, total: file.eligible.length, read: file.read.length, percent: file.eligible.length ? Math.round(file.read.length / file.eligible.length * 1000) / 10 : 0 })).sort((a, b) => (b.total - b.read) - (a.total - a.read));
    missingIncludes = JSON.parse(snapshot.coverage_json).hivemind_scope?.missing_includes?.length || 0;
    includedInTeam = !state.excluded.includes(agentId);
  }
  const totalLines = files.reduce((sum, file) => sum + file.total, 0);
  const readLines = files.reduce((sum, file) => sum + file.read, 0);
  return { version_id: versionId, repo_commit: commit, agent_id: agentId, included_in_team: includedInTeam, files, metrics: { read_lines: readLines, total_lines: totalLines, read_percent: totalLines ? Math.round(readLines / totalLines * 1000) / 10 : null, read_files: files.filter(file => file.read > 0).length, missing_includes: missingIncludes } };
}

function lineRanges(lines) {
  const ranges = [];
  for (const line of lines) {
    const last = ranges.at(-1);
    if (last && line === last.end + 1) last.end = line;
    else ranges.push({ start: line, end: line });
  }
  return ranges;
}

function coverageGaps(db, args) {
  const { versionId, commit } = selectedVersion(db, args);
  const prefix = typeof args.path_prefix === 'string' ? args.path_prefix : '';
  const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 50);
  const state = coverageState(db, versionId, commit);
  const gaps = [...state.combined.values()]
    .filter(file => file.path.startsWith(prefix))
    .map(file => {
      const unread = file.eligible.filter(line => !file.read.has(line));
      const ranges = lineRanges(unread);
      return { path: file.path, unread_lines: unread.length, total_lines: file.eligible.length, ranges: ranges.slice(0, 30), more_ranges: Math.max(0, ranges.length - 30) };
    })
    .filter(file => file.unread_lines)
    .sort((a, b) => b.unread_lines - a.unread_lines || a.path.localeCompare(b.path));
  return { version_id: versionId, repo_commit: commit, files: gaps.slice(0, limit), total_gap_files: gaps.length, excluded_agents: state.excluded, note: 'agentcov가 관측하지 못한 열람 범위이며, 실제 미검토의 증거는 아닙니다.' };
}

function reviewGaps(db, args) {
  const { versionId, commit } = selectedVersion(db, args);
  const report = dashboard(db, { version_id: versionId, repo_commit: commit });
  const eventScopes = db.prepare("SELECT scope_json FROM events WHERE version_id = ? AND repo_commit = ? AND kind IN ('hypothesis','analysis','verification')").all(versionId, commit).flatMap(row => JSON.parse(row.scope_json));
  const withoutRecord = report.files.filter(file => file.read && !eventScopes.some(scope => file.path === scope || file.path.startsWith(scope.endsWith('/') ? scope : `${scope}/`))).slice(0, 20).map(file => ({ path: file.path, read_lines: file.read }));
  return {
    version_id: versionId, repo_commit: commit,
    hypotheses: report.hypotheses.filter(item => ['unverified', 'single_source', 'refuted', 'contested', 'stale', 'inconclusive'].includes(item.status)).slice(0, 20).map(({ id, title, status, scope, code_refs }) => ({ id, title, status, scope, code_refs })),
    observed_files_without_exchange_record: withoutRecord,
    note: '기록의 공백만 보여줍니다. 열람 여부로 검토 완료나 가설의 진실을 판단하지 않습니다.',
  };
}

function teamStatusMarkdown(report) {
  if (!report.selected) return '# knfsd 팀 현황\n\n아직 수집된 자료가 없습니다.\n';
  const safe = value => String(value).replaceAll('|', '\\|').replace(/\r?\n/g, ' ');
  const { metrics, selected, agents, hypotheses, findings, progress } = report;
  return [
    '# knfsd 팀 현황', '', `- 버전: ${selected.version_id}`, `- 코드 기준점: ${selected.repo_commit}`,
    `- 관측 열람: ${metrics.read_lines}/${metrics.total_lines}줄 (${metrics.read_percent == null ? '계산 불가' : `${metrics.read_percent}%`})`,
    `- 중복 열람: ${metrics.overlap_lines}줄`, `- 병합 제외 에이전트: ${metrics.excluded_agents.join(', ') || '없음'}`,
    `- 작업: 완료 ${progress.done}, 진행 ${progress.in_progress}, 차단 ${progress.blocked}, 대기 ${progress.todo}`,
    '', '## 에이전트', '', '| 에이전트 | 열람 줄 | 고유 기여 줄 |', '| --- | ---: | ---: |',
    ...agents.map(item => `| ${safe(item.agent_id)} | ${item.read_lines} | ${item.unique_lines} |`),
    '', '## 가설', '', '| ID | 주장 | 잠정 상태 | 검증 시도 |', '| --- | --- | --- | ---: |',
    ...hypotheses.map(item => `| ${safe(item.id)} | ${safe(item.title)} | ${safe(item.status)} | ${item.checks.length} |`),
    '', '## 취약점 보고', '', '| 보고 | 연결 가설 | 보고 에이전트 | 코드 위치 |', '| --- | --- | --- | --- |',
    ...findings.map(item => `| ${safe(item.title)} | ${safe(item.hypothesis_id)} | ${safe(item.agent_id)} | ${safe(item.file_path)} |`),
    '', 'agentcov 열람률은 관측된 코드 노출 범위이며 코드 이해도·검토 완료율·가설의 참거짓이 아닙니다.', '',
  ].join('\n');
}

function logExposure(db, agentId, hypothesisId, mode) {
  if (hypothesisId) db.prepare('INSERT INTO exposures VALUES (?, ?, ?, ?)').run(agentId, hypothesisId, mode, now());
}

function claimSection(markdown) {
  const lines = readFrontMatter(markdown).body.split(/\r?\n/);
  const start = lines.findIndex(line => /^##\s+주장\s*$/.test(line));
  if (start < 0) return '';
  const end = lines.findIndex((line, index) => index > start && /^##\s+/.test(line));
  return lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
}

function searchHypotheses(db, agentId, args) {
  const versionId = args.version_id == null ? null : required(args.version_id, 'version_id', 64);
  if (args.query != null && typeof args.query !== 'string') invalid('Invalid query');
  if (args.code_ref != null && typeof args.code_ref !== 'string') invalid('Invalid code_ref');
  const query = typeof args.query === 'string' ? args.query.trim().toLowerCase() : '';
  const sourceRef = typeof args.code_ref === 'string' ? args.code_ref.trim().toLowerCase() : '';
  if ((!query && !sourceRef) || query.length > 200 || sourceRef.length > 300) invalid('query or code_ref required');
  const commit = args.repo_commit == null ? null : required(args.repo_commit, 'repo_commit', 64);
  if (commit && !/^[a-f0-9]{40,64}$/i.test(commit)) invalid('Invalid repo_commit');
  const trackId = args.track_id || (versionId && commit ? trackFor(db, versionId, commit) : null);
  if (trackId && !['rc', 'mainline'].includes(trackId) || !trackId && !versionId) invalid('track_id or version_id required');
  const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 20);
  const words = query.split(/[\s._/+-]+/).filter(Boolean);
  const rows = trackId
    ? db.prepare("SELECT h.* FROM events h JOIN track_targets t ON t.version_id = h.version_id AND t.repo_commit = h.repo_commit WHERE h.kind = 'hypothesis' AND t.track_id = ? AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = h.id) ORDER BY h.received_at DESC LIMIT 1000").all(trackId)
    : db.prepare("SELECT h.* FROM events h WHERE h.kind = 'hypothesis' AND h.version_id = ? AND NOT EXISTS (SELECT 1 FROM events c WHERE c.kind = 'correction' AND c.corrects_event_id = h.id) ORDER BY h.received_at DESC LIMIT 1000").all(versionId);
  const found = rows.map(row => {
    const scope = JSON.parse(row.scope_json);
    const codeRefs = readFrontMatter(row.markdown).data.code_refs || [];
    const haystack = `${row.title} ${row.claim_key} ${scope.join(' ')} ${codeRefs.join(' ')}`.toLowerCase();
    const locationScore = sourceRef && codeRefs.some(ref => ref.toLowerCase() === sourceRef) ? 8 : sourceRef && haystack.includes(sourceRef) ? 3 : 0;
    const score = (query && row.claim_key?.toLowerCase() === query ? 8 : 0) + (query && row.title.toLowerCase() === query ? 5 : 0) + words.filter(word => haystack.includes(word)).length + locationScore;
    return { id: row.hypothesis_id, title: row.title, claim_key: row.claim_key, scope, code_refs: codeRefs, verification_plan: readFrontMatter(row.markdown).data.verification_plan || '', repo_commit: row.repo_commit, score, row };
  }).filter(item => item.score).sort((a, b) => b.score - a.score).slice(0, limit).map(({ row, ...item }) => {
    const checks = activeChecks(db, row.hypothesis_id);
    return { ...item, status: claimStatus(hypothesisState(db, row, commit || row.repo_commit, checks).status), verification_count: checks.filter(check => check.repo_commit === (commit || row.repo_commit)).length };
  });
  for (const item of found) logExposure(db, agentId, item.id, 'claim_only');
  return { matches: found, note: '문자열 기반 후보입니다. 일치 여부와 참거짓은 직접 검증해야 합니다.' };
}

function getHypothesis(db, agentId, args) {
  const hypothesisId = required(args.hypothesis_id, 'hypothesis_id', 64);
  const mode = args.mode ?? 'claim_only';
  if (!['claim_only', 'full'].includes(mode)) invalid('Invalid mode');
  const row = db.prepare("SELECT * FROM events WHERE kind = 'hypothesis' AND hypothesis_id = ?").get(hypothesisId);
  if (!row) invalid('Unknown hypothesis', 404);
  logExposure(db, agentId, hypothesisId, mode);
  const commit = args.repo_commit == null ? row.repo_commit : required(args.repo_commit, 'repo_commit', 64);
  if (!/^[a-f0-9]{40,64}$/i.test(commit)) invalid('Invalid repo_commit');
  const status = hypothesisState(db, row, commit, activeChecks(db, hypothesisId)).status;
  const basic = { id: row.hypothesis_id, version_id: row.version_id, repo_commit: row.repo_commit, title: row.title, claim: claimSection(row.markdown) || row.title, scope: JSON.parse(row.scope_json), code_refs: readFrontMatter(row.markdown).data.code_refs || [], verification_plan: readFrontMatter(row.markdown).data.verification_plan || '', status: claimStatus(status), verification_count: activeChecks(db, hypothesisId).filter(check => check.repo_commit === commit).length };
  if (mode === 'claim_only') return basic;
  const checks = activeChecks(db, hypothesisId).map(item => ({ event_id: item.id, agent_id: item.agent_id, repo_commit: item.repo_commit, verdict: item.verdict, method: item.method, prior_exposure: item.prior_exposure, code_refs: readFrontMatter(item.markdown).data.code_refs || [] }));
  return { ...basic, status, markdown: row.markdown, checks, note: '폐기는 현재 커밋에서 서로 다른 두 에이전트가 다른 방법으로 독립 반박했고 지지가 없을 때의 자동 상태입니다. 새 증거가 있으면 검증 이벤트로 반박할 수 있습니다.' };
}

function getEvent(db, agentId, args) {
  const id = required(args.event_id, 'event_id', 64);
  const row = db.prepare('SELECT id, kind, agent_id, version_id, repo_commit, title, markdown, hypothesis_id, verification_of, related_hypothesis_id FROM events WHERE id = ?').get(id);
  if (!row) invalid('Unknown event', 404);
  logExposure(db, agentId, row.hypothesis_id || row.verification_of || row.related_hypothesis_id, 'full');
  return { id: row.id, kind: row.kind, agent_id: row.agent_id, version_id: row.version_id, repo_commit: row.repo_commit, title: row.title, markdown: row.markdown };
}

function recentAnalyses(db, args) {
  const versionId = args.version_id == null ? null : required(args.version_id, 'version_id', 64);
  const trackId = args.track_id || null;
  if (trackId && !['rc', 'mainline'].includes(trackId) || !trackId && !versionId) invalid('track_id or version_id required');
  const since = args.since ?? '';
  if (typeof since !== 'string' || since.length > 40) invalid('Invalid since');
  const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 20);
  const rows = trackId
    ? db.prepare("SELECT e.id, e.kind, e.agent_id, e.version_id, e.repo_commit, e.title, e.related_hypothesis_id, e.verification_of, e.received_at FROM events e JOIN track_targets t ON t.version_id = e.version_id AND t.repo_commit = e.repo_commit WHERE t.track_id = ? AND e.kind IN ('analysis','verification','finding') AND e.received_at > ? ORDER BY e.received_at DESC LIMIT ?").all(trackId, since, limit)
    : db.prepare("SELECT id, kind, agent_id, version_id, repo_commit, title, related_hypothesis_id, verification_of, received_at FROM events WHERE version_id = ? AND kind IN ('analysis','verification','finding') AND received_at > ? ORDER BY received_at DESC LIMIT ?").all(versionId, since, limit);
  return { events: rows };
}

function callTool(db, agentId, name, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) invalid('Tool arguments must be an object');
  switch (name) {
    case 'list_versions': return { tracks: trackRows(db), versions: versionRows(db).map(({ version_id, repo_commit }) => ({ version_id, repo_commit })) };
    case 'search_hypotheses': return searchHypotheses(db, agentId, args);
    case 'get_hypothesis': return getHypothesis(db, agentId, args);
    case 'get_event': return getEvent(db, agentId, args);
    case 'get_team_status': {
      const { versionId, commit } = selectedVersion(db, args);
      const report = dashboard(db, { version_id: versionId, repo_commit: commit });
      for (const item of report.hypotheses) logExposure(db, agentId, item.id, 'summary');
      return { selected: report.selected, metrics: report.metrics, agents: report.agents, progress: report.progress, hypothesis_statuses: report.hypotheses.map(({ id, status }) => ({ id, status })) };
    }
    case 'get_coverage_gaps': return coverageGaps(db, args);
    case 'get_review_gaps': {
      const result = reviewGaps(db, args);
      for (const item of result.hypotheses) logExposure(db, agentId, item.id, 'summary');
      return result;
    }
    case 'get_recent_analyses': {
      const result = recentAnalyses(db, args);
      for (const item of result.events) logExposure(db, agentId, item.verification_of || item.related_hypothesis_id, 'summary');
      return result;
    }
    case 'list_findings': {
      const { versionId, commit } = selectedVersion(db, args);
      const findings = dashboard(db, { version_id: versionId, repo_commit: commit }).findings;
      for (const item of findings) logExposure(db, agentId, item.hypothesis_id, 'summary');
      return { findings, note: '근거가 있는 명시적 보고입니다. 가설의 참·거짓이나 취약점 확정 판정은 아닙니다.' };
    }
    default: invalid('Unknown tool', 404);
  }
}

function mcpResponse(db, agentId, message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return { jsonrpc: '2.0', id: message?.id ?? null, error: { code: -32600, message: 'Invalid Request' } };
  if (!Object.hasOwn(message, 'id')) return null;
  const answer = result => ({ jsonrpc: '2.0', id: message.id, result });
  if (message.method === 'initialize') return answer({ protocolVersion: ['2025-03-26', '2025-11-25'].includes(message.params?.protocolVersion) ? message.params.protocolVersion : '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'knfsd-hivemind', version: '1.0.0' } });
  if (message.method === 'ping') return answer({});
  if (message.method === 'tools/list') return answer({ tools: mcpTools });
  if (message.method !== 'tools/call') return { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } };
  if (!mcpTools.some(tool => tool.name === message.params?.name)) return { jsonrpc: '2.0', id: message.id, error: { code: -32602, message: 'Unknown tool' } };
  try {
    const data = callTool(db, agentId, message.params.name, message.params.arguments || {});
    return answer({ content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data, isError: false });
  } catch (error) {
    if (!(error instanceof HttpError)) throw error;
    return answer({ content: [{ type: 'text', text: error.message }], isError: true });
  }
}

function send(res, status, value, contentType = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(typeof value === 'string' ? value : JSON.stringify(value));
}

async function readJson(req) {
  if (!req.headers['content-type']?.startsWith('application/json')) invalid('Content-Type must be application/json', 415);
  let length = 0;
  const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 24_000_000) invalid('Request too large', 413);
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { invalid('Invalid JSON'); }
}

export async function startServer(options = {}) {
  const host = options.host ?? process.env.HIVEMIND_HOST ?? '127.0.0.1';
  const port = options.port ?? Number(process.env.HIVEMIND_PORT ?? 8765);
  const dataDir = options.dataDir ?? process.env.HIVEMIND_DATA_DIR ?? path.join(root, 'runtime', 'server');
  const dashboardPassword = options.dashboardPassword ?? process.env.HIVEMIND_DASHBOARD_PASSWORD ?? '';
  const dashboardUser = options.dashboardUser ?? process.env.HIVEMIND_DASHBOARD_USER ?? 'viewer';
  if (!['127.0.0.1', '::1', 'localhost'].includes(host) && !dashboardPassword) throw new Error('Set HIVEMIND_DASHBOARD_PASSWORD before binding beyond localhost');
  fs.mkdirSync(dataDir, { recursive: true });
  const tokenPath = path.join(dataDir, 'api-token.txt');
  const adminToken = options.apiToken ?? process.env.HIVEMIND_API_TOKEN ?? (fs.existsSync(tokenPath) ? fs.readFileSync(tokenPath, 'utf8').trim() : randomBytes(24).toString('hex'));
  if (!adminToken) throw new Error('Admin API token is empty');
  if (!fs.existsSync(tokenPath) && !options.apiToken && !process.env.HIVEMIND_API_TOKEN) fs.writeFileSync(tokenPath, `${adminToken}\n`, { mode: 0o600 });
  const db = openDatabase(path.join(dataDir, 'hivemind.sqlite3'));
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true });
      const admin = url.pathname.startsWith('/v1/admin/');
      const agentRoute = ['/v1/exchange/events', '/v1/telemetry/batches', '/v1/sync/health', '/mcp'].includes(url.pathname);
      if (url.pathname === '/mcp' && req.headers.origin) {
        const port = server.address().port;
        const allowed = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`, `http://[::1]:${port}`, ...(process.env.HIVEMIND_ALLOWED_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean)]);
        if (!allowed.has(req.headers.origin)) return send(res, 403, { error: 'Origin not allowed' });
      }
      let agentId;
      if (admin) {
        if (!safeEqual(bearer(req), adminToken)) return send(res, 401, { error: 'Admin token required' });
      } else if (agentRoute) {
        agentId = authenticatedAgent(db, req);
      } else if (dashboardPassword) {
        let user = '', password = '';
        try {
          const credentials = Buffer.from((req.headers.authorization || '').replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
          const separator = credentials.indexOf(':');
          if (separator >= 0) { user = credentials.slice(0, separator); password = credentials.slice(separator + 1); }
        } catch { /* invalid auth */ }
        if (!safeEqual(user, dashboardUser) || !safeEqual(password, dashboardPassword)) {
          res.setHeader('WWW-Authenticate', 'Basic realm="Hivemind"');
          return send(res, 401, { error: 'Dashboard login required' });
        }
      }
      if (url.pathname === '/v1/admin/agents' && req.method === 'GET') return send(res, 200, { agents: db.prepare('SELECT agent_id, created_at, last_seen_at FROM agents ORDER BY agent_id').all() });
      if (url.pathname === '/v1/admin/tracks' && req.method === 'GET') return send(res, 200, { tracks: trackRows(db) });
      const trackMatch = /^\/v1\/admin\/tracks\/(rc|mainline)$/.exec(url.pathname);
      if (trackMatch && req.method === 'PUT') return send(res, 200, setActiveTrack(db, trackMatch[1], await readJson(req)));
      if (url.pathname === '/v1/admin/agents' && req.method === 'POST') {
        const input = await readJson(req);
        return send(res, 201, issueAgentToken(db, required(input?.agent_id, 'agent_id', 64)));
      }
      const agentMatch = /^\/v1\/admin\/agents\/([a-z0-9][a-z0-9_-]*)$/i.exec(url.pathname);
      if (agentMatch && req.method === 'PUT') return send(res, 200, issueAgentToken(db, agentMatch[1], true));
      if (agentMatch && req.method === 'DELETE') {
        if (!db.prepare('DELETE FROM agents WHERE agent_id = ?').run(agentMatch[1]).changes) invalid('Unknown agent', 404);
        return send(res, 200, { agent_id: agentMatch[1], revoked: true });
      }
      if (url.pathname === '/v1/admin/batches' && req.method === 'GET') return send(res, 200, { batches: db.prepare('SELECT id, agent_id, version_id, repo_commit, generated_at, received_at FROM batches ORDER BY received_at DESC LIMIT 100').all() });
      const batchMatch = /^\/v1\/admin\/batches\/([a-f0-9]{64})$/i.exec(url.pathname);
      if (batchMatch && req.method === 'GET') {
        const row = db.prepare('SELECT agent_id, version_id, repo_commit, manifest_json, lcov, coverage_json, progress_md FROM batches WHERE id = ?').get(batchMatch[1]);
        return row ? send(res, 200, { agent_id: row.agent_id, version_id: row.version_id, repo_commit: row.repo_commit, manifest: JSON.parse(row.manifest_json), lcov: row.lcov, coverage_json: row.coverage_json, progress_md: row.progress_md }) : send(res, 404, { error: 'Batch not found' });
      }
      if (req.method === 'POST' && url.pathname === '/v1/exchange/events') return send(res, 200, addEvent(db, await readJson(req), agentId));
      if (req.method === 'POST' && url.pathname === '/v1/telemetry/batches') return send(res, 200, addBatch(db, await readJson(req), agentId));
      if (req.method === 'GET' && url.pathname === '/v1/sync/health') return send(res, 200, { ok: true, agent_id: agentId, server_time: now() });
      if (url.pathname === '/mcp' && req.method === 'GET') return send(res, 405, { error: 'SSE stream not supported' });
      if (url.pathname === '/mcp' && req.method === 'POST') {
        if (req.headers['mcp-protocol-version'] && !['2025-03-26', '2025-11-25'].includes(req.headers['mcp-protocol-version'])) invalid('Unsupported MCP protocol version');
        const response = mcpResponse(db, agentId, await readJson(req));
        if (!response) { res.writeHead(202, { 'Cache-Control': 'no-store' }); return res.end(); }
        return send(res, 200, response);
      }
      if (req.method === 'GET' && url.pathname === '/api/dashboard') return send(res, 200, dashboard(db, Object.fromEntries(url.searchParams)));
      if (req.method === 'GET' && url.pathname === '/api/coverage') return send(res, 200, coverageDetails(db, Object.fromEntries(url.searchParams)));
      if (req.method === 'GET' && url.pathname === '/api/team-status.md') return send(res, 200, teamStatusMarkdown(dashboard(db, Object.fromEntries(url.searchParams))), 'text/markdown; charset=utf-8');
      const evidenceMatch = /^\/api\/events\/([a-f0-9]{64})\/(poc|kasan)$/.exec(url.pathname);
      if (req.method === 'GET' && evidenceMatch) {
        const row = db.prepare("SELECT markdown FROM events WHERE id = ? AND kind = 'finding'").get(evidenceMatch[1]);
        if (!row) return send(res, 404, { error: 'Finding not found' });
        const data = readFrontMatter(row.markdown).data;
        const content = evidenceMatch[2] === 'poc' ? data.poc_source : data.kasan_log;
        return content ? send(res, 200, content, 'text/plain; charset=utf-8') : send(res, 404, { error: 'Evidence not found' });
      }
      if (req.method === 'GET' && url.pathname.startsWith('/api/events/')) {
        const row = db.prepare('SELECT id, kind, agent_id, title, markdown FROM events WHERE id = ?').get(url.pathname.slice('/api/events/'.length));
        return row ? send(res, 200, { ...row, markdown: row.kind === 'finding' ? readFrontMatter(row.markdown).body : row.markdown }) : send(res, 404, { error: 'Event not found' });
      }
      const staticFiles = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
      if (req.method === 'GET' && staticFiles[url.pathname]) {
        const [file, type] = staticFiles[url.pathname];
        return send(res, 200, fs.readFileSync(path.join(publicDir, file), 'utf8'), type);
      }
      return send(res, 404, { error: 'Not found' });
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) console.error(error);
      return send(res, status, { error: status === 500 ? 'Internal server error' : error.message });
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return { server, db, url: `http://${host}:${server.address().port}`, tokenPath };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startServer().then(({ url, tokenPath }) => {
    console.log(`Hivemind dashboard: ${url}`);
    console.log(`Admin token file: ${tokenPath}`);
  }).catch(error => { console.error(error); process.exitCode = 1; });
}

import { invalid, verifiedImpactTypes } from './contract.mjs';

const staticVerdicts = new Set(['likely', 'unlikely', 'uncertain']);
const reproductionStatuses = new Set(['observed', 'not_observed', 'inconclusive']);
const artifactIdPattern = /^[a-f0-9]{64}$/;
const managementIdPattern = /^A-0(?:0[1-9]|[1-3][0-9]|4[0-2])$/;

export function initializeHistoryVerifications(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS history_verification_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      management_id TEXT NOT NULL REFERENCES registry_history(management_id),
      result TEXT NOT NULL CHECK(result IN ('verified', 'not_reproduced', 'inconclusive')),
      static_verdict TEXT NOT NULL CHECK(static_verdict IN ('likely', 'unlikely', 'uncertain')),
      reproduction_status TEXT NOT NULL CHECK(reproduction_status IN ('observed', 'not_observed', 'inconclusive')),
      kernel_commit TEXT NOT NULL,
      report_artifact_id TEXT REFERENCES history_artifacts(id),
      poc_artifact_id TEXT REFERENCES history_artifacts(id),
      observed_impacts_json TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      reason TEXT NOT NULL,
      completed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS history_verification_runs_record
      ON history_verification_runs(management_id, id DESC);
    CREATE TRIGGER IF NOT EXISTS history_verification_runs_no_update
      BEFORE UPDATE ON history_verification_runs BEGIN SELECT RAISE(ABORT, 'Historical verification runs are append-only'); END;
    CREATE TRIGGER IF NOT EXISTS history_verification_runs_no_delete
      BEFORE DELETE ON history_verification_runs BEGIN SELECT RAISE(ABORT, 'Historical verification runs are append-only'); END;
  `);
}

function artifact(db, managementId, id, kind) {
  if (id == null) return null;
  if (typeof id !== 'string' || !artifactIdPattern.test(id)) invalid(`Invalid ${kind} artifact ID`);
  const row = db.prepare('SELECT 1 FROM history_artifacts WHERE id = ? AND management_id = ? AND kind = ?').get(id, managementId, kind);
  if (!row) invalid(`${kind} artifact does not belong to historical finding`);
  return id;
}

function decode(row) {
  if (!row) return null;
  const { observed_impacts_json, evidence_json, ...record } = row;
  return { ...record, observed_impacts: JSON.parse(observed_impacts_json), evidence: JSON.parse(evidence_json) };
}

export function latestHistoryVerifications(db) {
  const latest = new Map();
  for (const row of db.prepare('SELECT * FROM history_verification_runs ORDER BY id DESC').all()) {
    if (!latest.has(row.management_id)) latest.set(row.management_id, decode(row));
  }
  return latest;
}

export function appendHistoryVerification(db, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some(key => !['management_id', 'result', 'static_verdict', 'reproduction_status',
        'kernel_commit', 'report_artifact_id', 'poc_artifact_id', 'observed_impacts', 'evidence', 'reason'].includes(key))) {
    invalid('Invalid historical verification fields');
  }
  const managementId = input.management_id;
  if (typeof managementId !== 'string' || !managementIdPattern.test(managementId) ||
      !db.prepare('SELECT 1 FROM registry_history WHERE management_id = ? AND target = ?').get(managementId, 'knfsd')) {
    invalid('Unknown historical knfsd finding', 404);
  }
  // This admin entry point records an attempted retrospective test. A trusted
  // verifier-completion path is required before positive/negative verdicts.
  if (input.result !== 'inconclusive' || !staticVerdicts.has(input.static_verdict) ||
      !reproductionStatuses.has(input.reproduction_status)) invalid('Invalid historical verification result');
  if (typeof input.kernel_commit !== 'string' || !/^[a-f0-9]{40}$/.test(input.kernel_commit)) invalid('Full kernel commit is required');
  if (!Array.isArray(input.observed_impacts) || input.observed_impacts.length > verifiedImpactTypes.length ||
      new Set(input.observed_impacts).size !== input.observed_impacts.length ||
      input.observed_impacts.some(impact => !verifiedImpactTypes.includes(impact))) invalid('Invalid observed impacts');
  if (!input.evidence || typeof input.evidence !== 'object' || Array.isArray(input.evidence) ||
      Buffer.byteLength(JSON.stringify(input.evidence)) > 16_000) invalid('Invalid verification evidence');
  if (typeof input.reason !== 'string' || !input.reason.trim() || Buffer.byteLength(input.reason) > 2_000 || input.reason.includes('\0')) invalid('Invalid verification reason');
  const reportArtifactId = artifact(db, managementId, input.report_artifact_id, 'report');
  const pocArtifactId = artifact(db, managementId, input.poc_artifact_id, 'poc');
  if (!reportArtifactId || !pocArtifactId) invalid('Historical test requires a report and PoC artifact');
  if (input.observed_impacts.length) invalid('Manual historical test cannot claim observed impacts');
  const completedAt = new Date().toISOString();
  const written = db.prepare(`INSERT INTO history_verification_runs
    (management_id, result, static_verdict, reproduction_status, kernel_commit,
     report_artifact_id, poc_artifact_id, observed_impacts_json, evidence_json, reason, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    managementId, input.result, input.static_verdict, input.reproduction_status, input.kernel_commit,
    reportArtifactId, pocArtifactId, JSON.stringify(input.observed_impacts), JSON.stringify(input.evidence),
    input.reason.trim(), completedAt);
  return decode(db.prepare('SELECT * FROM history_verification_runs WHERE id = ?').get(written.lastInsertRowid));
}

import { invalid } from './contract.mjs';

const managementIdPattern = /^[ABC]-\d{3,}$/;
const submissionIdPattern = /^[a-f0-9]{64}$/;
const artifactNames = new Set(['report.md', 'poc.c', 'reproduction.md', 'kasan.log', 'evidence.log']);

function approvedRevision(db, managementId, submissionId) {
  if (!managementIdPattern.test(managementId) || !submissionIdPattern.test(submissionId)) invalid('Revision not found', 404);
  const revision = db.prepare("SELECT id FROM submissions WHERE id = ? AND management_id = ? AND status = 'approved'").get(submissionId, managementId);
  if (!revision) invalid('Revision not found', 404);
}

export function listApprovedRevisions(db, managementId) {
  if (!managementIdPattern.test(managementId)) invalid('Finding not found', 404);
  return db.prepare(`SELECT id AS submission_id, title, completed_at FROM submissions
    WHERE management_id = ? AND status = 'approved'
    ORDER BY completed_at DESC, id DESC`).all(managementId);
}

export function listRevisionArtifacts(db, managementId, submissionId) {
  approvedRevision(db, managementId, submissionId);
  return db.prepare(`SELECT name, kind, sha256, size FROM submission_artifacts
    WHERE submission_id = ? AND ordinal BETWEEN 1000 AND 1003 ORDER BY ordinal`).all(submissionId);
}

export function getRevisionArtifact(db, managementId, submissionId, filename) {
  approvedRevision(db, managementId, submissionId);
  if (!artifactNames.has(filename)) invalid('Artifact not found', 404);
  const row = db.prepare(`SELECT content FROM submission_artifacts WHERE submission_id = ?
    AND name = ? AND ordinal BETWEEN 1000 AND 1003`).get(submissionId, filename);
  if (!row) invalid('Artifact not found', 404);
  return Buffer.from(row.content);
}

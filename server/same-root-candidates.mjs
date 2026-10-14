import fs from 'node:fs';
import { readFrontMatter } from './contract.mjs';
import { listHistoryArtifacts, openHistoryArtifact } from './history-artifacts.mjs';

const sourcePath = /^(?:fs\/(?:nfsd|nfs|nfs_common|lockd|exportfs)\/|net\/sunrpc\/|drivers\/infiniband\/|include\/(?:linux\/sunrpc|uapi\/linux\/nfsd|rdma)\/)[a-zA-Z0-9_./+-]+$/;
const managementId = /^A-\d{3,}$/;
const maxScan = 256;
const maxCandidates = 8;
const maxReport = 90_000;

function pathFromRef(ref) {
  const path = ref.split(/[#:]/, 1)[0];
  return path.length <= 300 && sourcePath.test(path) && !path.split('/').includes('..') ? path : null;
}

function reportFromHistory(db, dataDir, id) {
  const artifact = listHistoryArtifacts(db, id).find(row => row.kind === 'report');
  if (!artifact) return null;
  let opened;
  try {
    opened = openHistoryArtifact(db, dataDir, id, artifact.id);
    if (opened.content) return { report: opened.content.toString('utf8', 0, maxReport), complete: opened.content.length <= maxReport };
    const bytes = Buffer.alloc(Math.min(opened.size, maxReport));
    const count = fs.readSync(opened.fd, bytes, 0, bytes.length, 0);
    return { report: new TextDecoder().decode(bytes.subarray(0, count)),
      complete: opened.size <= maxReport && count === bytes.length };
  } finally {
    if (opened?.fd !== undefined) fs.closeSync(opened.fd);
  }
}

export function sameRootCandidates(db, { project, filePath, codeRefs = [], existingManagementId = null, dataDir = null } = {}) {
  if (project !== 'knfsd' || typeof filePath !== 'string' || pathFromRef(filePath) !== filePath ||
      !Array.isArray(codeRefs) || codeRefs.length > 30 || codeRefs.some(ref => typeof ref !== 'string' || ref.length > 300) ||
      existingManagementId !== null && (typeof existingManagementId !== 'string' || !managementId.test(existingManagementId))) {
    throw new TypeError('Invalid same-root candidate request');
  }
  const paths = new Set([filePath]);
  for (const ref of codeRefs) {
    const path = pathFromRef(ref);
    if (path) paths.add(path);
  }
  const candidates = [];
  let truncated = false;
  const live = db.prepare(`SELECT r.management_id, COALESCE(r.title_override, e.title) AS title, e.markdown
    FROM finding_registry r JOIN events e ON e.id = r.finding_id
    WHERE r.target = 'knfsd' AND r.management_id IS NOT NULL AND r.approved_at IS NOT NULL
      AND r.superseded_by IS NULL AND (? IS NULL OR r.management_id <> ?)
    ORDER BY r.management_id LIMIT ?`).all(existingManagementId, existingManagementId, maxScan + 1);
  if (live.length > maxScan) truncated = true;
  for (const row of live.slice(0, maxScan)) {
    let parsed;
    try { parsed = readFrontMatter(row.markdown); }
    catch { truncated = true; continue; }
    const refs = Array.isArray(parsed.data.code_refs) ? parsed.data.code_refs : [];
    const candidatePath = typeof parsed.data.file_path === 'string' ? parsed.data.file_path : null;
    const related = candidatePath && paths.has(candidatePath) || refs.some(ref => typeof ref === 'string' && paths.has(pathFromRef(ref)));
    if (!related) continue;
    if (!parsed.body) { truncated = true; continue; }
    const score = Number(candidatePath === filePath) * 2 + Number(refs.some(ref => codeRefs.includes(ref)));
    candidates.push({ management_id: row.management_id, title: row.title,
      file_path: candidatePath, report: parsed.body.slice(0, maxReport), score });
  }
  const history = db.prepare(`SELECT management_id, title FROM registry_history
    WHERE target = 'knfsd' AND (? IS NULL OR management_id <> ?)
    ORDER BY management_id LIMIT ?`).all(existingManagementId, existingManagementId, maxScan + 1);
  if (history.length > maxScan) truncated = true;
  for (const row of history.slice(0, maxScan)) {
    let found;
    try { found = reportFromHistory(db, dataDir, row.management_id); }
    catch { truncated = true; continue; }
    if (!found) { truncated = true; continue; }
    if (!found.complete) truncated = true;
    const matched = [...paths].filter(path => found.report.includes(path));
    if (!matched.length) continue;
    candidates.push({ management_id: row.management_id, title: row.title,
      file_path: null, report: found.report, score: matched.includes(filePath) ? 2 : 1 });
  }
  candidates.sort((a, b) => b.score - a.score || Number(a.management_id.slice(2)) - Number(b.management_id.slice(2)));
  if (candidates.length > maxCandidates) truncated = true;
  return { candidates: candidates.slice(0, maxCandidates).map(({ score, ...candidate }) => candidate), truncated };
}

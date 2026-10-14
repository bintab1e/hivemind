import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { postJson } from '../verifier/worker.mjs';
import { reviewDuplicateWithCodex } from './codex-review.mjs';
import { reviewInternalDuplicatesWithCodex } from './internal-review.mjs';
import { fetchProjectSources, hydrateEvidence, publicCodeQuery, publicCodeReferences, rankEvidence,
  searchHistoricalBranch, searchHistoricalMail } from './sources.mjs';

const ids = /^(?:history:[ABC]-\d{3}|[a-f\d]{64})$/;
const targets = new Set(['knfsd', 'NFS-Ganesha', 'libnfs']);

export function duplicateConfiguration(env = process.env) {
  const config = { socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_CODEX_CLI, workRoot: env.HIVEMIND_DUPLICATE_WORK_ROOT };
  if (Object.values(config).some(value => typeof value !== 'string' || !path.isAbsolute(value))) {
    throw new Error('not_configured');
  }
  return config;
}

function checkedCandidate(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || !ids.test(row.row_id || '') ||
      !Number.isInteger(row.revision) || row.revision < 0 || !targets.has(row.target) ||
      typeof row.title !== 'string' || !row.title.trim() || row.title.length > 300 ||
      ![null, '미제보', '제보 중'].includes(row.report_status) ||
      typeof row.report_excerpt !== 'string' || Buffer.byteLength(row.report_excerpt) > 24_000 ||
      !Array.isArray(row.code_refs) || row.code_refs.length > 40 ||
      row.code_refs.some(ref => typeof ref !== 'string' || ref.length > 300)) {
    throw new Error('invalid_duplicate_candidate');
  }
  return row;
}

function checkedReference(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      !ids.test(row.row_id || '') || !/^[ABC]-\d{3,}$/.test(row.management_id || '') ||
      !Number.isInteger(row.revision) || row.revision < 0 || !targets.has(row.target) ||
      typeof row.title !== 'string' || !row.title.trim() || row.title.length > 300 ||
      ![null, '미제보', '제보 중', '제보 완료', '중복', '철회'].includes(row.report_status) ||
      typeof row.report_excerpt !== 'string' || Buffer.byteLength(row.report_excerpt) > 24_000 ||
      !Array.isArray(row.code_refs) || row.code_refs.length > 40 ||
      row.code_refs.some(ref => typeof ref !== 'string' || ref.length > 300)) {
    throw new Error('invalid_internal_duplicate_reference');
  }
  return row;
}

export async function runInternalDuplicateOnce({ config = duplicateConfiguration(), transport = postJson,
  internalReviewer = reviewInternalDuplicatesWithCodex } = {}) {
  const response = await transport(config.socketPath, '/duplicate/internal-candidates', {});
  if (!response || !Array.isArray(response.candidates) || response.candidates.length > 2000 ||
      !Array.isArray(response.references) || response.references.length > 2000) {
    throw new Error('invalid_internal_duplicate_response');
  }
  const candidates = response.candidates.map(checkedCandidate);
  const references = response.references.map(checkedReference);
  const counts = { checked: 0, duplicates: 0, uncertain: 0, errors: 0 };
  for (const row of candidates) {
    let outcome;
    try {
      outcome = await internalReviewer(row, references, { cliPath: config.cliPath, workRoot: config.workRoot });
      if (!outcome || !['duplicate', 'no_match', 'uncertain'].includes(outcome.verdict) ||
          typeof outcome.reason !== 'string' ||
          (outcome.verdict === 'duplicate' && !/^[ABC]-\d{3,}$/.test(outcome.matched_management_id || ''))) {
        throw new Error('invalid_internal_duplicate_review');
      }
    } catch {
      outcome = { verdict: 'error', reason: '헤드리스 내부 중복 검토가 완료되지 않았습니다.',
        matched_management_id: null };
    }
    let receipt;
    try {
      receipt = await transport(config.socketPath, '/duplicate/internal-result', {
        row_id: row.row_id, revision: row.revision, verdict: outcome.verdict,
        reason: outcome.reason, matched_management_id: outcome.verdict === 'duplicate'
          ? outcome.matched_management_id : null,
        checked_at: new Date().toISOString(),
      });
    } catch {
      counts.checked++;
      counts.errors++;
      continue;
    }
    counts.checked++;
    if (receipt?.status_changed === true) {
      counts.duplicates++;
      const updatedReference = references.find(ref => ref.row_id === row.row_id);
      if (updatedReference) updatedReference.report_status = '중복';
    }
    else if (outcome.verdict === 'error') counts.errors++;
    else if (outcome.verdict === 'uncertain' || receipt?.outcome === 'ineligible_reference') counts.uncertain++;
  }
  return counts;
}

const sourceFailure = '공식 메일링 리스트 또는 유지관리 브랜치의 자료를 완전히 조회하지 못했습니다.';
const noMatch = '조회된 공식 메일·유지관리 브랜치와 코드 근거가 일치하지 않았습니다. 공개 아카이브 전체의 중복 부재를 뜻하지 않습니다.';

export async function runDuplicateOnce({ config = duplicateConfiguration(), transport = postJson,
  sourceLoader = fetchProjectSources, mailSearch = searchHistoricalMail,
  branchSearch = searchHistoricalBranch, hydrator = hydrateEvidence,
  reviewer = reviewDuplicateWithCodex, fetchImpl = fetch } = {}) {
  const response = await transport(config.socketPath, '/duplicate/candidates', {});
  if (!response || !Array.isArray(response.candidates) || response.candidates.length > 2000) {
    throw new Error('invalid_duplicate_candidates_response');
  }
  const candidates = response.candidates.map(checkedCandidate);
  const base = new Map();
  const details = new Map();
  const historicalMail = new Map();
  const historicalBranch = new Map();
  let branchHistoryQueries = 0;
  const counts = { checked: 0, duplicates: 0, uncertain: 0, errors: 0 };
  for (const row of candidates) {
    if (!base.has(row.target)) base.set(row.target, await sourceLoader(row.target, fetchImpl));
    const sources = base.get(row.target);
    const checked = { mail: sources.mail?.ok === true && sources.mail.items.some(item => item.text?.length >= 30),
      branch: sources.branch?.ok === true && sources.branch.items.some(item => item.text?.length >= 30) };
    let outcome;
    let stage = 'sources';
    try {
      if (sources.mail?.ok !== true || sources.branch?.ok !== true) throw new Error('source_unavailable');
      let oldMail = [];
      let oldBranch = [];
      let historicalSearchFailed = false;
      const mailKey = `${row.target}:${publicCodeQuery(row) || row.row_id}`;
      try {
        if (!historicalMail.has(mailKey)) historicalMail.set(mailKey, mailSearch(row.target, row, fetchImpl));
        oldMail = await historicalMail.get(mailKey);
      }
      catch { historicalSearchFailed = true; }
      const filePath = publicCodeReferences(row).find(value => /\.(?:c|h)$/.test(value));
      const branchKey = `${row.target}:${filePath || row.row_id}`;
      try {
        if (!historicalBranch.has(branchKey)) {
          if (row.target !== 'knfsd' && filePath && ++branchHistoryQueries > 40) throw new Error('branch_history_limit');
          historicalBranch.set(branchKey, branchSearch(row.target, row, fetchImpl));
        }
        oldBranch = await historicalBranch.get(branchKey);
      }
      catch { historicalSearchFailed = true; }
      const recentMail = rankEvidence(row, sources.mail.items, 2);
      const recentBranch = rankEvidence(row, sources.branch.items, 2);
      const historicalMailItems = rankEvidence(row, oldMail, 2);
      const historicalBranchItems = rankEvidence(row, oldBranch, 2);
      const chosen = [...(recentMail.length ? recentMail : sources.mail.items.slice(0, 1)),
        ...(historicalMailItems.length ? historicalMailItems : oldMail.slice(0, 2)),
        ...(recentBranch.length ? recentBranch : sources.branch.items.slice(0, 1)),
        ...(historicalBranchItems.length ? historicalBranchItems : oldBranch.slice(0, 2))];
      const unique = [...new Map(chosen.map(item => [item.url, item])).values()];
      const hydrated = [];
      for (const item of unique) {
        if (!details.has(item.url)) details.set(item.url, hydrator(item, fetchImpl).catch(() => null));
        const evidence = await details.get(item.url);
        if (evidence?.text && evidence.text.length >= 30) hydrated.push(evidence);
      }
      checked.mail = hydrated.some(item => item.kind === 'mail');
      checked.branch = hydrated.some(item => item.kind === 'branch');
      if (!checked.mail || !checked.branch) throw new Error('source_unavailable');
      if (!hydrated.length || !row.report_excerpt) {
        outcome = { verdict: 'uncertain', reason: '동일 원인을 비교할 공개 본문 또는 비공개 분석 보고서가 부족합니다.', evidence: [] };
      } else {
        stage = 'review';
        outcome = await reviewer(row, hydrated.slice(0, 10), { cliPath: config.cliPath, workRoot: config.workRoot });
        if (historicalSearchFailed && outcome.verdict === 'no_match') {
          outcome = { verdict: 'uncertain', reason: `${noMatch} 과거 검색은 일부 실패했습니다.`, evidence: [] };
        }
      }
      if (outcome.verdict === 'no_match') {
        const reason = `${outcome.reason} ${noMatch}`;
        outcome.reason = Buffer.byteLength(reason) <= 1900 ? reason : noMatch;
      }
      else if (historicalSearchFailed && outcome.verdict === 'uncertain') {
        const suffix = ' 과거 공개 자료 검색은 일부 실패했습니다.';
        if (Buffer.byteLength(outcome.reason + suffix) <= 1900) outcome.reason += suffix;
      }
    } catch {
      outcome = { verdict: 'error', reason: stage === 'review'
        ? '헤드리스 중복 검토가 완료되지 않았습니다.' : sourceFailure, evidence: [] };
    }
    const receipt = await transport(config.socketPath, '/duplicate/result', {
      row_id: row.row_id, revision: row.revision, verdict: outcome.verdict,
      reason: outcome.reason, evidence: outcome.evidence || [],
      sources_checked: checked, checked_at: new Date().toISOString(),
    });
    counts.checked++;
    if (receipt?.status_changed === true) counts.duplicates++;
    else if (outcome.verdict === 'error') counts.errors++;
    else if (outcome.verdict === 'uncertain') counts.uncertain++;
  }
  return counts;
}

export async function runDailyDuplicateOnce(options = {}) {
  let internal;
  let publicSources;
  try { internal = await runInternalDuplicateOnce(options); }
  catch { internal = { checked: 0, duplicates: 0, uncertain: 0, errors: 1 }; }
  try { publicSources = await runDuplicateOnce(options); }
  catch { publicSources = { checked: 0, duplicates: 0, uncertain: 0, errors: 1 }; }
  return { internal, public: publicSources };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = duplicateConfiguration();
    fs.mkdirSync(config.workRoot, { recursive: true, mode: 0o700 });
    if (fs.statSync(config.workRoot).mode & 0o077) throw new Error('work_root_permissions');
    const counts = await runDailyDuplicateOnce({ config });
    console.log(JSON.stringify(counts));
    if (counts.internal.errors || counts.public.errors) process.exitCode = 1;
  } catch {
    console.error('Duplicate checker: run_failed');
    process.exitCode = 1;
  }
}

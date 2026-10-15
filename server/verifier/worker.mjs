import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';
import { CodexReviewError, VerifierUnavailableError, isInfrastructureReviewError, loadTrustedKernelSource, reviewSameRootCauseWithCodex, reviewStaticProofWithCodex, reviewSubmissionWithCodex } from './codex.mjs';
import { canonicalArtifacts } from './canonical.mjs';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_RESPONSE = 12_000_000;
const MAX_FILE = 2_000_000;
const MAX_REVIEW_FILE = 600_000;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

class WorkerError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}

function configuration(env) {
  const config = {
    socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_CODEX_CLI,
    kernelSource: env.HIVEMIND_KERNEL_SOURCE,
    kernelStableSource: env.HIVEMIND_KERNEL_STABLE_SOURCE,
    workRoot: env.HIVEMIND_VERIFIER_WORK_ROOT || os.tmpdir(),
  };
  if ([config.socketPath, config.cliPath, config.kernelSource, config.workRoot]
    .some(value => typeof value !== 'string' || !path.isAbsolute(value))
    || (config.kernelStableSource !== undefined && !path.isAbsolute(config.kernelStableSource))) {
    throw new WorkerError('not_configured');
  }
  return config;
}

export function stableWorkerId(config, hostname = os.hostname()) {
  return createHash('sha256')
    .update(JSON.stringify([hostname, config.workRoot]))
    .digest('hex').slice(0, 32);
}

function sourceTargets(config) {
  if (config.sourceTargets) return new Map(Object.entries(config.sourceTargets));
  const targets = new Map();
  for (const source of [config.kernelSource, config.kernelStableSource].filter(Boolean)) {
    let commit;
    try { commit = execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 10_000 }).trim(); }
    catch { throw new WorkerError('source_commit_unavailable'); }
    if (!/^[a-f0-9]{40}$/.test(commit)) throw new WorkerError('source_commit_unavailable');
    targets.set(commit, source);
  }
  if (!targets.size) throw new WorkerError('source_commit_unavailable');
  return targets;
}

export function postJson(socketPath, endpoint, body) {
  if (!path.isAbsolute(socketPath) || !['/claim', '/complete', '/fail', '/progress', '/heartbeat',
    '/primitive/claim', '/primitive/complete', '/primitive/fail', '/primitive/heartbeat',
    '/duplicate/candidates', '/duplicate/result', '/duplicate/internal-candidates', '/duplicate/internal-result',
    '/same-root-candidates'].includes(endpoint)) throw new WorkerError('invalid_request');
  const encoded = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path: endpoint, method: 'POST', timeout: 30_000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(encoded) } }, response => {
      const chunks = [];
      let bytes = 0;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE) { request.destroy(new WorkerError('response_too_large')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) { reject(new WorkerError('server_error', response.statusCode)); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new WorkerError('invalid_response')); }
      });
    });
    request.on('timeout', () => request.destroy(new WorkerError('server_timeout')));
    request.on('error', error => reject(error instanceof WorkerError ? error : new WorkerError('transport_error')));
    request.end(encoded);
  });
}

function decodeJob(job) {
  if (!job || typeof job !== 'object' || !/^[a-f0-9]{64}$/.test(job.submission_id || '') || job.project !== 'knfsd' || !Array.isArray(job.files) || job.files.length > 20) throw new WorkerError('invalid_job');
  const files = job.files.map(file => {
    if (!file || typeof file.name !== 'string' || !file.name || typeof file.content_base64 !== 'string' ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(file.content_base64)) throw new WorkerError('invalid_job');
    const bytes = Buffer.from(file.content_base64, 'base64');
    if (!bytes.length || bytes.length > MAX_FILE || bytes.toString('base64') !== file.content_base64) throw new WorkerError('invalid_job');
    if (bytes.length > MAX_REVIEW_FILE && (file.kind === 'poc' || /\.(?:c|py)$/i.test(file.name))) throw new WorkerError('poc_too_large');
    if (bytes.length > MAX_REVIEW_FILE) return { name: file.name, kind: file.kind, content: '[Large attachment omitted from static review]' };
    try { return { name: file.name, kind: file.kind, content: textDecoder.decode(bytes) }; }
    catch {
      if (file.kind === 'poc' || /\.(?:c|py)$/i.test(file.name)) throw new WorkerError('non_text_poc');
      return { name: file.name, kind: file.kind, content: '[Binary attachment omitted from static review]' };
    }
  });
  const report = typeof job.report === 'string' ? job.report.slice(0, 150_000) : null;
  const existing = job.existing_finding;
  if (existing != null && (!existing || typeof existing !== 'object' ||
      !/^A-\d{3,}$/.test(existing.management_id || '') ||
      existing.management_id !== job.metadata?.existing_management_id ||
      typeof existing.title !== 'string' || existing.title.length > 300 ||
      existing.file_path != null && typeof existing.file_path !== 'string' ||
      existing.report != null && (typeof existing.report !== 'string' || Buffer.byteLength(existing.report) > 90_000))) {
    throw new WorkerError('invalid_job');
  }
  return { project: job.project, title: job.title, report, metadata: job.metadata || {}, files,
    existing_finding: existing ?? null };
}

function selectedPoc(review, files) {
  const poc = review.normalized?.poc;
  if (!poc || !Number.isInteger(poc.source_index) || poc.source_index < 0 || poc.source_index >= files.length) return null;
  const original = files[poc.source_index];
  if (poc.source !== original.content || poc.original_name !== original.name ||
      poc.language !== 'c' || poc.filename !== 'poc.c' || !/\.c$/i.test(original.name)) throw new WorkerError('c_poc_required');
  if (Buffer.byteLength(poc.source) > 250_000) throw new WorkerError('poc_too_large_for_registry');
  return poc;
}

const notRun = { status: 'not_run', reason: 'Static screening only; no server PoC or VM run' };

function safeCodexDiagnostic(value) {
  if (!value || typeof value !== 'object') return '';
  if (Object.hasOwn(value, 'validation_stage')) {
    const stages = ['json_parse', 'shape', 'report_format', 'source_refs', 'source_evidence',
      'likely_grounding', 'pre_auth', 'metadata', 'poc', 'logs', 'admin_trigger', 'proof_review'];
    return stages.includes(value.validation_stage) ? ` ${JSON.stringify({ validation_stage: value.validation_stage })}` : '';
  }
  const pick = (key, choices) => choices.includes(value[key]) ? value[key] : 'unknown';
  const keys = new Set(['message', 'error', 'error.message', 'error.code', 'error.type']);
  const hints = new Set(['approval_workspace_routing', 'policy_rejected', 'auth_or_session', 'rate_limited',
    'context_too_large', 'output_token_limit', 'schema_error', 'parse_error', 'invalid_request', 'retry_exhausted',
    'network_stream_disconnected', 'network_connection_reset', 'network_connection_refused', 'network_connection_timeout',
    'network_dns', 'network_tls', 'upstream_gateway_timeout', 'upstream_service_unavailable', 'upstream_backend',
    'network_error', 'upstream_other']);
  return ` ${JSON.stringify({
    exit_code: pick('exit_code', ['one', 'two', 'other', 'signal']),
    signal: pick('signal', ['none', 'kill', 'term', 'abort', 'other']),
    stderr_size: pick('stderr_size', ['empty', 'short', 'long', 'truncated']),
    json_error_events: pick('json_error_events', ['none', 'error', 'turn_failed', 'both']),
    json_error_keys: Array.isArray(value.json_error_keys) ? value.json_error_keys.filter(key => keys.has(key)) : [],
    hints: Array.isArray(value.hints) ? value.hints.filter(hint => hints.has(hint)) : [],
  })}`;
}

function deliveryDiagnostic(error) {
  const status = Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599
    ? `http_${error.status}` : null;
  const code = new Set(['server_error', 'server_timeout', 'invalid_response', 'response_too_large',
    'transport_error']).has(error?.code) ? error.code : 'delivery_error';
  return `${code}${status ? `_${status}` : ''}`;
}

export async function processSubmissionJob(job, { config, reviewer = reviewSubmissionWithCodex, sourceLoader = loadTrustedKernelSource,
  proofReviewer = reviewStaticProofWithCodex, sameRootReviewer = reviewSameRootCauseWithCodex,
  candidateLookup = async () => ({ candidates: [], truncated: false }),
  onPhase = async () => {} } = {}) {
  let review = { verdict: 'uncertain', reason: 'Static review unavailable', normalized: null, model: 'codex' };
  let artifacts;
  let infrastructureError;
  let infrastructureDiagnostic;
  try {
    const submission = decodeJob(job);
    const targetCommit = submission.metadata?.repo_commit;
    const source = sourceTargets(config).get(targetCommit);
    if (!source || !/^[a-f0-9]{40}$/.test(targetCommit)) return { review, reproduction: notRun };
    await onPhase('static_review');
    const trustedSource = await sourceLoader(source, targetCommit, submission);
    review = await reviewer(submission, { cliPath: config.cliPath, trustedSource });
    if (review.verdict !== 'likely' || review.integrity?.verdict !== 'clear' ||
        review.integrity.admin_action_required !== false) return { review, reproduction: notRun };
    if (review.grounding?.source_commit !== targetCommit || !Array.isArray(review.grounding.evidence) ||
        !review.grounding.evidence.some(item => item.path === review.normalized?.file_path &&
          trustedSource.files.some(file => file.path === item.path && file.lines.some(line => line.number === item.line && line.text === item.text)))) {
      review.verdict = 'uncertain';
      review.reason = 'Static review lacks trusted source evidence';
      return { review, reproduction: notRun };
    }
    if (!review.proof) {
      review.verdict = 'uncertain';
      review.reason = 'Static review lacks a complete vulnerability proof';
      return { review, reproduction: notRun };
    }
    review.proof_review = await proofReviewer(submission, review, { cliPath: config.cliPath, trustedSource });
    if (review.proof_review?.admin_action_required === true) {
      review.integrity = { verdict: 'suspect', admin_action_required: true,
        reason: review.proof_review.reason || 'Administrator action is required to trigger the finding' };
      return { review, reproduction: notRun };
    }
    if (review.proof_review?.admin_action_required !== false) {
      review.verdict = 'uncertain';
      review.reason = 'Independent review could not rule out a required administrator action';
      return { review, reproduction: notRun };
    }
    const checks = review.proof_review?.checks;
    if (review.proof_review?.verdict !== 'supports' ||
        checks?.flaw !== 'supported' || checks?.admin_action !== 'supported' ||
        !['reachability', 'poc', 'log', 'defenses']
          .every(name => ['supported', 'uncertain'].includes(checks?.[name]))) {
      review.verdict = 'uncertain';
      review.reason = `Independent static challenge did not confirm the claim: ${review.proof_review?.reason || 'insufficient evidence'}`.slice(0, 1000);
      return { review, reproduction: notRun };
    }
    if (submission.metadata.existing_management_id) {
      if (!submission.existing_finding?.report) {
        review.same_root_cause = { verdict: 'uncertain', reason: 'Existing finding report is unavailable' };
        return { review, reproduction: notRun };
      }
      review.same_root_cause = await sameRootReviewer(submission.existing_finding, review,
        { cliPath: config.cliPath, trustedSource });
      if (review.same_root_cause.verdict !== 'same') {
        return { review, reproduction: notRun };
      }
    }
    const poc = selectedPoc(review, submission.files);
    if (!poc) return { review, reproduction: notRun };
    if (!submission.metadata.existing_management_id) {
      const candidates = await candidateLookup({ project: submission.project, file_path: review.normalized.file_path,
        code_refs: review.normalized.code_refs });
      const matches = [];
      let uncertain = false;
      for (const candidate of candidates.candidates || []) {
        if (!candidate.report) { uncertain = true; continue; }
        const comparison = await sameRootReviewer(candidate, review, { cliPath: config.cliPath, trustedSource });
        if (comparison.verdict === 'same') matches.push(candidate.management_id);
        else if (comparison.verdict !== 'different') uncertain = true;
      }
      if (candidates.truncated || uncertain || matches.length > 1) {
        review.same_root_cause = { verdict: 'uncertain', reason: 'Multiple or incomplete same-root candidates require manual review' };
        review.verdict = 'uncertain';
        return { review, reproduction: notRun };
      }
      if (matches.length === 1) review.same_root_cause = { verdict: 'same', management_id: matches[0], reason: 'Grounded same-root comparison' };
    }
    artifacts = canonicalArtifacts({ review, trustedSource, poc, kernelCommit: targetCommit });
    if (!artifacts) {
      review.verdict = 'uncertain';
      review.reason = 'Static review lacks a grounded canonical report, original C PoC, or submitted log';
    }
  } catch (error) {
    const known = error instanceof WorkerError || error instanceof CodexReviewError || error instanceof VerifierUnavailableError;
    if (isInfrastructureReviewError(error)) {
      infrastructureError = error.code;
      if (error instanceof CodexReviewError) infrastructureDiagnostic = error.diagnostic;
    }
    review = { verdict: 'uncertain', integrity: { verdict: 'uncertain', admin_action_required: null,
      reason: 'Static review unavailable' },
      reason: known ? `${error.code}${error instanceof CodexReviewError ? safeCodexDiagnostic(error.diagnostic) : ''}`
        : 'Static review unavailable', normalized: null, model: 'codex' };
  }
  return { review, reproduction: notRun, ...(artifacts ? { artifacts } : {}),
    ...(infrastructureError ? { infrastructure_error: infrastructureError,
      ...(infrastructureDiagnostic ? { infrastructure_diagnostic: infrastructureDiagnostic } : {}) } : {}) };
}

export async function runWorkerOnce({ config = configuration(process.env), transport = postJson, reviewer, sourceLoader,
  proofReviewer, sameRootReviewer, workerId = null } = {}) {
  const targets = sourceTargets(config);
  const supportedCommits = [...targets.keys()];
  const claimed = await transport(config.socketPath, '/claim', { supported_commits: supportedCommits });
  if (!claimed || !Object.hasOwn(claimed, 'job')) throw new WorkerError('invalid_response');
  const targetCommit = claimed.job?.metadata?.repo_commit ?? null;
  if (claimed.job && !targets.has(targetCommit)) throw new WorkerError('invalid_response');
  const heartbeat = (submissionId = null, leaseToken = null) => workerId
    ? transport(config.socketPath, '/heartbeat', { worker_id: workerId, target_commit: submissionId ? targetCommit : null,
      submission_id: submissionId, ...(leaseToken ? { lease_token: leaseToken } : {}) }).catch(() => {})
    : Promise.resolve();
  if (!claimed.job) { await heartbeat(); return false; }
  if (!/^[a-f0-9]{64}$/.test(claimed.job.lease_token || '')) throw new WorkerError('invalid_response');
  const submissionId = claimed.job.submission_id;
  const leaseToken = claimed.job.lease_token;
  await heartbeat(submissionId, leaseToken);
  const timer = workerId ? setInterval(() => { void heartbeat(submissionId, leaseToken); }, 20_000) : null;
  timer?.unref();
  const onPhase = phase => workerId
    ? transport(config.socketPath, '/progress', { submission_id: submissionId, lease_token: leaseToken, phase }).catch(() => {})
    : Promise.resolve();
  try {
    const result = await processSubmissionJob(claimed.job, { config, reviewer, sourceLoader,
      proofReviewer, sameRootReviewer, candidateLookup: async request =>
        transport(config.socketPath, '/same-root-candidates', request), onPhase });
    if (!result.infrastructure_error) await onPhase('finalizing');
    if (Array.isArray(result.review?.normalized?.logs)) {
      result.review.normalized.logs = result.review.normalized.logs.map(({ content, ...reference }) => reference);
    }
    const endpoint = result.infrastructure_error ? '/fail' : '/complete';
    const body = result.infrastructure_error
      ? { submission_id: submissionId, lease_token: leaseToken,
        reason: `Verifier ${result.infrastructure_error}${safeCodexDiagnostic(result.infrastructure_diagnostic)}` }
      : { submission_id: submissionId, lease_token: leaseToken, result };
    let lastError;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await transport(config.socketPath, endpoint, body);
        return true;
      } catch (error) {
        lastError = error;
        if (error.status >= 400 && error.status < 500) break;
        if (attempt < 2) await delay(1000 * (attempt + 1));
      }
    }
    if (endpoint === '/complete') {
      try { await transport(config.socketPath, '/fail', { submission_id: submissionId, lease_token: leaseToken,
        reason: `Verification result delivery failed: ${deliveryDiagnostic(lastError)}` }); }
      catch { throw new WorkerError('completion_and_failure_delivery_failed'); }
    }
    if (lastError) throw new WorkerError(endpoint === '/fail' ? 'failure_delivery_failed' : 'completion_delivery_failed');
    return true;
  } finally {
    if (timer) clearInterval(timer);
    await heartbeat();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = configuration(process.env);
    const workerId = stableWorkerId(config);
    while (true) {
      try {
        const worked = await runWorkerOnce({ config, workerId });
        if (!worked) await delay(5000);
      } catch (error) {
        console.error(`Verifier worker: ${error instanceof WorkerError ? error.code : 'job_error'}`);
        await delay(5000);
      }
    }
  } catch (error) {
    console.error(`Verifier worker: ${error instanceof WorkerError ? error.code : 'not_configured'}`);
    process.exitCode = 1;
  }
}

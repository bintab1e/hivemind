import http from 'node:http';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';
import { CodexReviewError, VerifierUnavailableError, isInfrastructureReviewError, loadTrustedKernelSource, reviewReproductionWithCodex, reviewSubmissionWithCodex } from './codex.mjs';
import { canonicalArtifacts } from './canonical.mjs';
import { symbolizeKasanFrames } from './symbolize.mjs';
import { runTwoVmReproduction } from './qemu/run.mjs';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_RESPONSE = 12_000_000;
const MAX_FILE = 2_000_000;
const MAX_REVIEW_FILE = 600_000;
const MAX_SERIAL = 600_000;
const NFS_VERSIONS = new Set(['3', '4', '4.1', '4.2']);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

class WorkerError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}

function configuration(env) {
  const config = {
    socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_CODEX_CLI,
    kernelImage: env.HIVEMIND_QEMU_KERNEL,
    vmlinuxImage: env.HIVEMIND_QEMU_VMLINUX,
    kernelInfoPath: env.HIVEMIND_QEMU_KERNEL_INFO,
    kernelSource: env.HIVEMIND_KERNEL_SOURCE,
    rootfsImage: env.HIVEMIND_QEMU_ROOTFS,
    workRoot: env.HIVEMIND_VERIFIER_WORK_ROOT || os.tmpdir(),
  };
  if (Object.values(config).some(value => typeof value !== 'string' || !path.isAbsolute(value))) throw new WorkerError('not_configured');
  return config;
}

export function stableWorkerId(config, hostname = os.hostname()) {
  let targetCommit;
  try { targetCommit = JSON.parse(fs.readFileSync(config.kernelInfoPath, 'utf8')).sourceCommit; }
  catch { throw new WorkerError('kernel_commit_unavailable'); }
  if (!/^[a-f0-9]{40}$/.test(targetCommit || '')) throw new WorkerError('kernel_commit_unavailable');
  return createHash('sha256')
    .update(JSON.stringify([hostname, config.workRoot, config.kernelInfoPath, targetCommit]))
    .digest('hex').slice(0, 32);
}

export function postJson(socketPath, endpoint, body) {
  if (!path.isAbsolute(socketPath) || !['/claim', '/complete', '/fail', '/progress', '/heartbeat',
    '/primitive/claim', '/primitive/complete', '/primitive/fail', '/primitive/heartbeat',
    '/duplicate/candidates', '/duplicate/result', '/duplicate/internal-candidates', '/duplicate/internal-result',
    '/patch/claim', '/patch/complete', '/patch/fail'].includes(endpoint)) throw new WorkerError('invalid_request');
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
  return { project: job.project, title: job.title, report, metadata: job.metadata || {}, files };
}

function version(value) {
  const match = /^(?:NFS\s*v)?(3|4(?:\.0|\.1|\.2)?)$/i.exec(String(value || '').trim());
  const normalized = match?.[1] === '4.0' ? '4' : match?.[1];
  return NFS_VERSIONS.has(normalized) ? normalized : null;
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

function serialExcerpt(file, startOffset) {
  const bytes = fs.readFileSync(file);
  if (bytes.length > 8_000_000) throw new WorkerError('serial_too_large');
  if (!Number.isInteger(startOffset) || startOffset < 0 || startOffset > bytes.length) throw new WorkerError('invalid_serial_offset');
  const afterPoc = bytes.subarray(startOffset);
  if (afterPoc.length <= MAX_SERIAL) return afterPoc.toString('utf8');
  const signature = afterPoc.indexOf('BUG: KASAN:');
  const start = signature < 0 ? afterPoc.length - MAX_SERIAL : Math.max(0, signature - 1024);
  return afterPoc.subarray(start, start + MAX_SERIAL).toString('utf8');
}

const inconclusive = reason => ({ status: 'inconclusive', reason });

function safeCodexDiagnostic(value) {
  if (!value || typeof value !== 'object') return '';
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

export async function processSubmissionJob(job, { config, reviewer = reviewSubmissionWithCodex, sourceLoader = loadTrustedKernelSource,
  relevanceReviewer = reviewReproductionWithCodex, symbolizer = symbolizeKasanFrames, runner = runTwoVmReproduction,
  onPhase = async () => {} } = {}) {
  let review = { verdict: 'uncertain', reason: 'Static review unavailable', normalized: null, model: 'codex' };
  let reproduction = inconclusive('Reproduction was not run');
  let serverSerial = '';
  let artifacts;
  let privateDir;
  let infrastructureError;
  try {
    const submission = decodeJob(job);
    const kernelInfo = JSON.parse(fs.readFileSync(config.kernelInfoPath, 'utf8'));
    const targetCommit = kernelInfo.sourceCommit;
    if (!/^[a-f0-9]{40}$/.test(targetCommit || '') || submission.metadata?.repo_commit && submission.metadata.repo_commit !== targetCommit) {
      return { review, reproduction: inconclusive('Submitted commit does not match the configured kernel'), server_serial: '' };
    }
    if (!/^[a-f0-9]{64}$/.test(kernelInfo.vmlinuxSha256 || '')) {
      return { review, reproduction: inconclusive('Built vmlinux is missing SHA-pinned debug information'), server_serial: '' };
    }
    await onPhase('static_review');
    const trustedSource = await sourceLoader(config.kernelSource, targetCommit, submission);
    review = await reviewer(submission, { cliPath: config.cliPath, trustedSource });
    review.relevance = { verdict: 'uncertain', reason: 'Reproduction was not observed', trace_line: null,
      source_path: null, source_line: null, poc_line: null, symbolized_path: null, symbolized_line: null };
    if (review.verdict !== 'likely') return { review, reproduction: inconclusive('Static review did not support reproduction'), server_serial: '' };
    if (review.grounding?.source_commit !== targetCommit || !Array.isArray(review.grounding.evidence) ||
        !review.grounding.evidence.some(item => item.path === review.normalized?.file_path &&
          trustedSource.files.some(file => file.path === item.path && file.lines.some(line => line.number === item.line && line.text === item.text)))) {
      return { review, reproduction: inconclusive('Static review lacks trusted source evidence'), server_serial: '' };
    }
    const poc = selectedPoc(review, submission.files);
    if (!poc) return { review, reproduction: inconclusive('No original userspace PoC was selected'), server_serial: '' };
    const submittedVersion = submission.metadata?.nfs_version;
    const reviewedVersion = review.normalized?.nfs_version;
    const nfsVersion = version(submittedVersion) || version(reviewedVersion);
    if (!nfsVersion || submittedVersion && version(submittedVersion) !== nfsVersion ||
        reviewedVersion && version(reviewedVersion) !== nfsVersion) {
      return { review, reproduction: inconclusive('NFS version is missing, ambiguous, or disagrees with static review'), server_serial: '' };
    }
    privateDir = fs.mkdtempSync(path.join(config.workRoot, 'hv-'));
    fs.chmodSync(privateDir, 0o700);
    const bundleDir = path.join(privateDir, 'bundle');
    fs.mkdirSync(bundleDir, { mode: 0o700 });
    fs.writeFileSync(path.join(bundleDir, poc.filename), poc.source, { mode: 0o600 });
    fs.writeFileSync(path.join(bundleDir, 'manifest.json'), JSON.stringify({
      schemaVersion: 1, project: 'knfsd', targetCommit, poc: poc.filename, files: [],
      nfsVersion, mount: true, expected: { stream: 'server', contains: 'BUG: KASAN:' },
    }), { mode: 0o600 });
    const outputDir = path.join(privateDir, 'output');
    await onPhase('qemu_reproduction');
    const result = await runner({ bundleDir, kernelImage: config.kernelImage, kernelInfoPath: config.kernelInfoPath,
      rootfsImage: config.rootfsImage, outputDir });
    serverSerial = serialExcerpt(result.evidence.serverSerialPath, result.observation?.serverEvidenceStartOffset);
    const { evidence, ...portable } = result;
    reproduction = { ...portable, nfsVersion };
    if (result.status === 'observed' && (result.kernelCommit !== targetCommit || result.observation?.guestCompleted !== true ||
        result.observation?.targetCommitMatch !== true || result.observation?.pocStarted !== true ||
        result.observation?.baselineClean !== true || result.observation?.serverEvidenceAfterPoc !== true)) {
      reproduction = inconclusive('Server KASAN evidence did not follow a clean PoC baseline on the expected kernel');
    }
    if (reproduction.status === 'observed' && !serverSerial.includes('BUG: KASAN:')) reproduction = inconclusive('Server KASAN trace is missing');
    if (reproduction.status === 'observed' && serverSerial.includes('BUG: KASAN:')) {
      await onPhase('trace_review');
      const symbolizedFrames = await symbolizer({ serverSerial, vmlinuxPath: config.vmlinuxImage, kernelInfo, sourceDir: config.kernelSource });
      review.relevance = await relevanceReviewer({ review, serverSerial, pocSource: poc.source, trustedSource, symbolizedFrames }, { cliPath: config.cliPath });
      if (review.relevance.verdict === 'supports') {
        const selected = symbolizedFrames.filter(frame => frame.trace_line === review.relevance.trace_line)
          .flatMap(frame => frame.locations).filter(location => location.path === review.normalized.file_path);
        const unique = [...new Map(selected.map(location => [`${location.path}:${location.line}`, location])).values()];
        if (unique.length === 1 && review.relevance.source_path === review.normalized.file_path) {
          review.relevance.symbolized_path = unique[0].path;
          review.relevance.symbolized_line = unique[0].line;
        } else {
          review.relevance = { verdict: 'uncertain', reason: 'Raw KASAN frame does not uniquely resolve to the reviewed source file',
            trace_line: null, source_path: null, source_line: null, poc_line: null, symbolized_path: null, symbolized_line: null };
        }
      }
      if (review.relevance.verdict !== 'supports') reproduction = inconclusive('KASAN trace relevance was not confirmed');
      else if (reproduction.status === 'observed') {
        artifacts = canonicalArtifacts({ review, trustedSource, poc, serverSerial, kernelCommit: targetCommit, nfsVersion });
        if (!artifacts) reproduction = inconclusive('Canonical report lacks grounded source, PoC, or relevant server KASAN evidence');
        else {
          review.normalized.title = artifacts.title;
          review.normalized.report = artifacts.report.content;
          review.normalized.nfs_version = nfsVersion;
        }
      }
    }
  } catch (error) {
    const known = error instanceof WorkerError || error instanceof CodexReviewError || error instanceof VerifierUnavailableError;
    if (isInfrastructureReviewError(error)) infrastructureError = error.code;
    reproduction = inconclusive(known ? error.code : 'Verifier environment unavailable');
    if (review.verdict !== 'likely') review = { verdict: 'uncertain',
      reason: known ? `${error.code}${error instanceof CodexReviewError ? safeCodexDiagnostic(error.diagnostic) : ''}`
        : 'Static review unavailable', normalized: null, model: 'codex' };
  } finally {
    if (privateDir) fs.rmSync(privateDir, { recursive: true, force: true });
  }
  return { review, reproduction, server_serial: serverSerial, ...(artifacts ? { artifacts } : {}),
    ...(infrastructureError ? { infrastructure_error: infrastructureError } : {}) };
}

export async function runWorkerOnce({ config = configuration(process.env), transport = postJson, reviewer, sourceLoader, relevanceReviewer, symbolizer, runner, workerId = null } = {}) {
  let targetCommit;
  try {
    targetCommit = JSON.parse(fs.readFileSync(config.kernelInfoPath, 'utf8')).sourceCommit;
  } catch { throw new WorkerError('kernel_commit_unavailable'); }
  if (!/^[a-f0-9]{40}$/.test(targetCommit || '')) throw new WorkerError('kernel_commit_unavailable');
  const claimed = await transport(config.socketPath, '/claim', { target_commit: targetCommit });
  if (!claimed || !Object.hasOwn(claimed, 'job')) throw new WorkerError('invalid_response');
  const heartbeat = (submissionId = null, leaseToken = null) => workerId
    ? transport(config.socketPath, '/heartbeat', { worker_id: workerId, target_commit: targetCommit,
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
    const result = await processSubmissionJob(claimed.job, { config, reviewer, sourceLoader, relevanceReviewer, symbolizer, runner, onPhase });
    if (!result.infrastructure_error) await onPhase('finalizing');
    if (Array.isArray(result.review?.normalized?.logs)) {
      result.review.normalized.logs = result.review.normalized.logs.map(({ content, ...reference }) => reference);
    }
    const endpoint = result.infrastructure_error ? '/fail' : '/complete';
    const body = result.infrastructure_error
      ? { submission_id: submissionId, lease_token: leaseToken, reason: `Verifier ${result.infrastructure_error}` }
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
      try { await transport(config.socketPath, '/fail', { submission_id: submissionId, lease_token: leaseToken, reason: 'Verification result delivery failed' }); }
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

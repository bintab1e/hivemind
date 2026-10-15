import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { postJson } from './worker.mjs';
import { reviewSubmittedDuplicateWithCodex } from './duplicate-review.mjs';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const submissionPattern = /^[a-f0-9]{64}$/;
const leasePattern = /^[a-f0-9]{64}$/;
const workerPattern = /^[a-f0-9]{32}$/;

export function duplicateConfiguration(env = process.env) {
  const config = { socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_CODEX_CLI, workRoot: env.HIVEMIND_DEDUPE_WORK_ROOT };
  if (Object.values(config).some(value => typeof value !== 'string' || !path.isAbsolute(value))) {
    throw new Error('not_configured');
  }
  return config;
}

export function duplicateWorkerId(config, hostname = os.hostname()) {
  return createHash('sha256').update(JSON.stringify(['dedupe', hostname, config.workRoot]))
    .digest('hex').slice(0, 32);
}

function checkedJob(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job) ||
      !submissionPattern.test(job.submission_id || '') || !leasePattern.test(job.lease_token || '') ||
      !job.candidate || !Array.isArray(job.references)) throw new Error('invalid_duplicate_job');
  return job;
}

function checkedResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      !['duplicate', 'new', 'uncertain'].includes(result.verdict) ||
      typeof result.reason !== 'string' || !result.reason.trim() ||
      Buffer.byteLength(result.reason) > 2000 || /[\x00-\x1f\x7f]/.test(result.reason) ||
      (result.verdict === 'duplicate'
        ? !/^A-\d{3,}$/.test(result.matched_management_id || '')
        : result.matched_management_id !== null)) throw new Error('invalid_duplicate_result');
  return result;
}

function failureCode(error) {
  return typeof error?.code === 'string' && /^[a-z_]{3,80}$/.test(error.code)
    ? error.code : 'duplicate_review_failed';
}

async function deliver(transport, config, endpoint, body) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await transport(config.socketPath, endpoint, body); }
    catch (error) {
      if (attempt === 2 || Number.isInteger(error?.status) && error.status >= 400 && error.status < 500) throw error;
      await delay(1000 * (attempt + 1));
    }
  }
}

export async function runDuplicateReviewOnce({ config = duplicateConfiguration(),
  workerId = duplicateWorkerId(config), transport = postJson,
  reviewer = reviewSubmittedDuplicateWithCodex } = {}) {
  if (!workerPattern.test(workerId)) throw new Error('invalid_duplicate_worker');
  const heartbeat = job => transport(config.socketPath, '/dedupe/heartbeat', {
    worker_id: workerId, ...(job ? { submission_id: job.submission_id, lease_token: job.lease_token } : {}),
  });
  await heartbeat();
  const response = await transport(config.socketPath, '/dedupe/claim', { worker_id: workerId });
  if (!response || typeof response !== 'object' || !Object.hasOwn(response, 'job')) {
    throw new Error('invalid_duplicate_response');
  }
  if (!response.job) return false;
  const job = checkedJob(response.job);
  await heartbeat(job);
  const timer = setInterval(() => { void heartbeat(job).catch(() => {}); }, 20_000);
  timer.unref();
  let completing = false;
  let delivered = false;
  try {
    const result = checkedResult(await reviewer(job.candidate, job.references,
      { cliPath: config.cliPath, workRoot: config.workRoot }));
    completing = true;
    await deliver(transport, config, '/dedupe/complete', {
      submission_id: job.submission_id, lease_token: job.lease_token, result,
    });
    delivered = true;
  } catch (error) {
    if (completing) throw error;
    await deliver(transport, config, '/dedupe/fail', {
      submission_id: job.submission_id, lease_token: job.lease_token, reason: failureCode(error),
    });
    delivered = true;
  } finally {
    clearInterval(timer);
    if (delivered) await heartbeat().catch(() => {});
  }
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = duplicateConfiguration();
    fs.mkdirSync(config.workRoot, { recursive: true, mode: 0o700 });
    if (fs.statSync(config.workRoot).mode & 0o077) throw new Error('work_root_permissions');
    const workerId = duplicateWorkerId(config);
    while (true) {
      try {
        const worked = await runDuplicateReviewOnce({ config, workerId });
        if (!worked) await delay(5000);
      } catch {
        console.error('Submission duplicate reviewer: job_or_transport_error');
        await delay(5000);
      }
    }
  } catch {
    console.error('Submission duplicate reviewer: not_configured');
    process.exitCode = 1;
  }
}

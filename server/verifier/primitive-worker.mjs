import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadTrustedKernelSource, reviewPrimitiveWithCodex } from './codex.mjs';
import { postJson } from './worker.mjs';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const findingIdPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;

export function primitiveConfiguration(env) {
  const config = {
    socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_CODEX_CLI,
    workRoot: env.HIVEMIND_PRIMITIVE_WORK_ROOT,
    sourceDirs: (env.HIVEMIND_PRIMITIVE_KERNEL_SOURCES || '').split(path.delimiter).filter(Boolean),
  };
  if (![config.socketPath, config.cliPath, config.workRoot, ...config.sourceDirs].every(value =>
    typeof value === 'string' && path.isAbsolute(value)) || !config.sourceDirs.length) {
    throw new Error('not_configured');
  }
  return config;
}

export function primitiveWorkerId(config, hostname = os.hostname()) {
  return createHash('sha256').update(JSON.stringify(['primitive', hostname, config.workRoot])).digest('hex').slice(0, 32);
}

export function availablePrimitiveSources(config) {
  const sources = new Map();
  for (const directory of config.sourceDirs) {
    try {
      const root = fs.realpathSync(directory);
      const topLevel = execFileSync('git', ['-C', root, 'rev-parse', '--show-toplevel'],
        { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (fs.realpathSync(topLevel) !== root) continue;
      const head = execFileSync('git', ['-C', directory, 'rev-parse', 'HEAD'],
        { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      const status = execFileSync('git', ['-C', directory, 'status', '--porcelain', '--untracked-files=all'],
        { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (commitPattern.test(head) && !status) sources.set(head, directory);
    } catch { /* Try the next configured checkout. */ }
  }
  return sources;
}

function checkedJob(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job) ||
      !findingIdPattern.test(job.finding_id || '') || !/^[a-f0-9]{64}$/.test(job.lease_token || '') ||
      !commitPattern.test(job.repo_commit || '') || !/^A-\d{3,}$/.test(job.management_id || '') ||
      typeof job.title !== 'string' || !job.title.trim() || job.title.length > 300 ||
      typeof job.file_path !== 'string' || job.file_path.length > 300 ||
      !Array.isArray(job.code_refs) || job.code_refs.length > 30 ||
      job.code_refs.some(ref => typeof ref !== 'string' || ref.length > 300) ||
      !Array.isArray(job.verified_impacts) || job.verified_impacts.length > 7 ||
      job.claimed_impacts != null && (!Array.isArray(job.claimed_impacts) || job.claimed_impacts.length > 7) ||
      typeof job.report !== 'string' || Buffer.byteLength(job.report) > 1_000_000 ||
      typeof job.poc_source !== 'string' || Buffer.byteLength(job.poc_source) > 250_000 ||
      typeof job.kasan_log !== 'string' || Buffer.byteLength(job.kasan_log) > 600_000) {
    throw new Error('invalid_primitive_job');
  }
  return job;
}

function failureCode(error) {
  return typeof error?.code === 'string' && /^[a-z_]{3,80}$/.test(error.code)
    ? error.code : 'primitive_review_failed';
}

export async function runPrimitiveOnce({ config = primitiveConfiguration(process.env), workerId = primitiveWorkerId(config),
  transport = postJson, reviewer = reviewPrimitiveWithCodex, sourceLoader = loadTrustedKernelSource,
  sourceDiscovery = availablePrimitiveSources } = {}) {
  const heartbeat = (job = null) => transport(config.socketPath, '/primitive/heartbeat',
    { worker_id: workerId, ...(job ? { finding_id: job.finding_id, lease_token: job.lease_token } : {}) });
  await heartbeat();
  const sources = await sourceDiscovery(config);
  if (!(sources instanceof Map) || sources.size > 16 || [...sources.entries()].some(([commit, directory]) =>
    !commitPattern.test(commit) || typeof directory !== 'string' || !path.isAbsolute(directory))) {
    throw new Error('invalid_primitive_sources');
  }
  const response = await transport(config.socketPath, '/primitive/claim',
    { worker_id: workerId, supported_commits: [...sources.keys()] });
  if (!response || !Object.hasOwn(response, 'job')) throw new Error('invalid_primitive_response');
  if (!response.job) return false;
  const job = checkedJob(response.job);
  await heartbeat(job);
  const timer = setInterval(() => { void heartbeat(job).catch(() => {}); }, 20_000);
  let delivered = false;
  try {
    const directory = sources.get(job.repo_commit);
    if (!directory) throw new Error('kernel_source_unavailable');
    const trustedSource = await sourceLoader(directory, job.repo_commit, {
      metadata: { file_path: job.file_path, code_refs: job.code_refs }, report: job.report,
      files: [{ content: job.poc_source }, { content: job.kasan_log }],
    });
    const result = await reviewer(job, { cliPath: config.cliPath, workRoot: config.workRoot, trustedSource });
    if (!result || result.summary !== null && (typeof result.summary !== 'string' || !result.summary.trim() ||
        Buffer.byteLength(result.summary) > 6000)) throw new Error('invalid_primitive_result');
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await transport(config.socketPath, '/primitive/complete',
          { finding_id: job.finding_id, lease_token: job.lease_token, summary: result.summary });
        delivered = true;
        break;
      } catch (error) {
        if (attempt === 2) throw error;
        await delay(1000);
      }
    }
  } catch (error) {
    try {
      await transport(config.socketPath, '/primitive/fail',
        { finding_id: job.finding_id, lease_token: job.lease_token, reason: failureCode(error) });
      delivered = true;
    } catch { throw new Error('primitive_result_delivery_failed'); }
  } finally {
    clearInterval(timer);
    if (delivered) await heartbeat().catch(() => {});
  }
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = primitiveConfiguration(process.env);
    const workerId = primitiveWorkerId(config);
    while (true) {
      try {
        const worked = await runPrimitiveOnce({ config, workerId });
        if (!worked) await delay(20_000);
      } catch {
        console.error('Primitive reviewer: job_or_transport_error');
        await delay(5000);
      }
    }
  } catch {
    console.error('Primitive reviewer: not_configured');
    process.exitCode = 1;
  }
}

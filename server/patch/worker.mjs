import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { reviewPatchWithSashiko } from '../integrations.mjs';
import { postJson } from '../verifier/worker.mjs';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export function patchWorkerConfig(env = process.env) {
  const config = {
    socketPath: env.HIVEMIND_VERIFIER_SOCKET,
    cliPath: env.HIVEMIND_SASHIKO_CLI,
    configDir: env.HIVEMIND_SASHIKO_CONFIG_DIR,
    workRoot: env.HIVEMIND_PATCH_WORK_ROOT,
    repos: { rc: env.HIVEMIND_PATCH_REPO_RC, mainline: env.HIVEMIND_PATCH_REPO_MAINLINE },
  };
  for (const value of [config.socketPath, config.cliPath, config.configDir, config.workRoot, ...Object.values(config.repos)]) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new Error('Patch worker paths must be absolute');
  }
  if (!fs.existsSync(path.join(config.configDir, 'Settings.toml'))) throw new Error('Sashiko Settings.toml is missing');
  fs.accessSync(config.cliPath, fs.constants.X_OK);
  fs.mkdirSync(config.workRoot, { recursive: true, mode: 0o700 });
  return config;
}

function repoCommit(repoPath) {
  const commit = execFileSync('git', ['-C', repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 10_000 }).trim();
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('Kernel repository commit is unavailable');
  return commit;
}

export async function runPatchWorkerOnce({ config, transport = postJson, reviewer = reviewPatchWithSashiko,
  workerId = createHash('sha256').update(`${os.hostname()}\0${config.workRoot}`).digest('hex').slice(0, 32) }) {
  const commits = Object.fromEntries(Object.entries(config.repos).map(([track, repo]) => [track, repoCommit(repo)]));
  const { job } = await transport(config.socketPath, '/patch/claim', { worker_id: workerId, supported_commits: Object.values(commits) });
  if (!job) return false;
  const { review_id: id, lease_token: leaseToken, track_id: trackId, base_commit: baseCommit, patch } = job;
  if (!/^[a-f0-9]{64}$/.test(id || '') || !/^[a-f0-9]{64}$/.test(leaseToken || '') ||
      !Object.hasOwn(commits, trackId) || commits[trackId] !== baseCommit || typeof patch !== 'string') {
    throw new Error('Invalid patch review job');
  }
  try {
    const review = await reviewer({ patch, baseCommit, repoPath: config.repos[trackId], cliPath: config.cliPath,
      dataDir: config.workRoot, configDir: config.configDir });
    if (!['reviewed', 'findings', 'error'].includes(review?.status) || !review.result || typeof review.result !== 'object') {
      throw new Error('Sashiko returned an invalid review');
    }
    await transport(config.socketPath, '/patch/complete', {
      review_id: id, lease_token: leaseToken, status: review.status,
      result: { ...review.result, exit_code: review.exit_code },
    });
  } catch (error) {
    const reason = String(error.stderr || error.message || 'Patch review failed').slice(0, 1000);
    await transport(config.socketPath, '/patch/fail', { review_id: id, lease_token: leaseToken, reason });
  }
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = patchWorkerConfig();
    while (true) {
      try {
        if (!await runPatchWorkerOnce({ config })) await delay(5000);
      } catch (error) {
        console.error(`Sashiko worker: ${error.code || 'job_error'}`);
        await delay(5000);
      }
    }
  } catch (error) {
    console.error(`Sashiko worker: ${error.code || 'not_configured'}`);
    process.exitCode = 1;
  }
}

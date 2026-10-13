import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { gzip } from 'node:zlib';
import { parseLcov, readFrontMatter } from './contract.mjs';
import { buildCoverageScope, defaultCoveragePrefixes } from './coverage-scope.mjs';
import { syncSubmissions } from './submissions.mjs';

const run = promisify(execFile);
const gzipAsync = promisify(gzip);
const hash = value => createHash('sha256').update(value).digest('hex');
const timestamp = () => new Date().toISOString();
const agentDirectory = path.dirname(fileURLToPath(import.meta.url));
const agentcovPython = agentcovBin => path.isAbsolute(agentcovBin)
  ? path.join(path.dirname(agentcovBin), process.platform === 'win32' ? 'python.exe' : 'python')
  : process.platform === 'win32' ? 'python' : 'python3';
export const gitArgs = (repoRoot, args) => ['-c', `safe.directory=${repoRoot}`, ...args];
export function assertFreshCheckout(prior, repoRoot, commit) {
  if (prior && prior.repo_commit !== commit && path.resolve(prior.repo_root).toLowerCase() === path.resolve(repoRoot).toLowerCase()) {
    throw new Error('Git commit changed in the same checkout; use a fresh repo_root so old agentcov reads cannot become new-release coverage');
  }
}

export function makeBatch({ agentId, versionId, repoRoot, commit, clean, generatedAt, lcov, coverageJson, progressMd, agentcovConfig }) {
  const filePaths = Object.keys(parseLcov(lcov, repoRoot));
  let fileIndex = 0;
  const portableLcov = lcov.replace(/^SF:.*$/gm, () => `SF:${filePaths[fileIndex++]}`);
  const files = parseLcov(portableLcov, '.');
  const scope = Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)).map(([name, file]) => [name, file.eligible]));
  const coverageScopeHash = hash(JSON.stringify({ agentcovConfig, scope }));
  const hashes = { 'agentcov.info': hash(portableLcov), 'coverage.json': hash(coverageJson), 'progress.md': hash(progressMd) };
  const sourceDigest = hash([versionId, commit, coverageScopeHash, String(clean), ...Object.values(hashes)].join('\0'));
  const batchId = hash([versionId, agentId, commit, coverageScopeHash, String(clean), generatedAt, ...Object.values(hashes)].join('\0'));
  return {
    sourceDigest,
    manifest: { schema_version: 1, batch_id: batchId, agent_id: agentId, version_id: versionId, repo_commit: commit, repo_root: '.', coverage_scope_hash: coverageScopeHash, worktree_clean: clean, generated_at: generatedAt, source_digest: sourceDigest, hashes },
    lcov: portableLcov, coverage_json: coverageJson, progress_md: progressMd,
  };
}

export function selectCoverage(lcov, coverageJson, scope, repoRoot) {
  const selected = [];
  let record = [];
  const relative = name => {
    const normalized = name.replaceAll('\\', '/');
    const root = repoRoot.replaceAll('\\', '/').replace(/\/$/, '');
    return normalized.toLowerCase().startsWith(`${root.toLowerCase()}/`) ? normalized.slice(root.length + 1) : normalized;
  };
  const inScope = name => Array.isArray(scope) ? scope.some(prefix => relative(name).startsWith(prefix)) : scope.has(relative(name));
  for (const line of lcov.split(/\r?\n/)) {
    if (!line && !record.length) continue;
    record.push(line);
    if (line === 'end_of_record') {
      const source = record.find(item => item.startsWith('SF:'));
      if (source && inScope(source.slice(3))) selected.push(record.join('\n'));
      record = [];
    }
  }
  if (record.some(line => line.trim()) || !selected.length) throw new Error('No complete agentcov LCOV records in knfsd coverage scope');
  const scopedLcov = `${selected.join('\n')}\n`;
  const files = parseLcov(scopedLcov, repoRoot);
  const report = JSON.parse(coverageJson);
  if (!report.files || typeof report.files !== 'object' || Array.isArray(report.files)) throw new Error('Invalid agentcov coverage.json');
  report.files = Object.fromEntries(Object.entries(report.files).filter(([name]) => inScope(name)));
  if (Object.keys(report.files).length !== Object.keys(files).length || Object.keys(files).some(name => !Object.hasOwn(report.files, name))) throw new Error('agentcov LCOV and JSON file scopes differ');
  const entries = Object.values(report.files);
  report.summary = { ...report.summary, files: entries.length };
  for (const key of ['line_count', 'read_lines', 'search_seen_lines', 'search_hit_lines', 'search_context_lines']) {
    report.summary[key === 'line_count' ? 'total_lines' : key] = entries.reduce((sum, file) => sum + Number(file[key] || 0), 0);
  }
  report.summary.read_percent = report.summary.total_lines ? Math.round(report.summary.read_lines / report.summary.total_lines * 10000) / 100 : 100;
  report.unknown_events = (report.unknown_events || []).filter(event => event.file && inScope(event.file));
  report.summary.unknown_events = report.unknown_events.length;
  report.hivemind_scope = Array.isArray(scope) ? scope : { kind: 'include_closure', files: scope.size };
  return { lcov: scopedLcov, coverageJson: JSON.stringify(report) };
}

export function validateCoverageSummary(lcov, metaJson, repoRoot) {
  const files = Object.values(parseLcov(lcov, repoRoot));
  const actual = {
    files: files.length,
    total_lines: files.reduce((sum, file) => sum + file.eligible.length, 0),
    read_lines: files.reduce((sum, file) => sum + file.read.length, 0),
  };
  const expected = JSON.parse(metaJson);
  if (Object.keys(actual).some(key => actual[key] !== expected[key])) throw new Error(`agentcov LCOV/JSON summary mismatch: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  return actual;
}

export const coverageProgressStub = (versionId, commit) =>
  `---\nschema_version: 1\nversion_id: ${versionId}\nrepo_commit: ${commit}\n---\n`;

export async function backfillClaude(config) {
  const { stdout } = await run(agentcovPython(config.agentcov_bin), [
    path.join(agentDirectory, 'agentcov-claude-backfill.py'),
    '--root', config.repo_root,
    '--state', path.join(config.home, `claude-backfill-state-${config.agent_id}.json`),
  ], { cwd: config.repo_root });
  if (stdout.trim()) console.log(stdout.trim());
}

export function validateConfig(config) {
  if (!config || typeof config !== 'object') throw new Error('Invalid agent config');
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(config.agent_id || '')) throw new Error('Invalid agent_id');
  if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(config.version_id || '')) throw new Error('Invalid version_id');
  if (config.track_id != null && !['rc', 'mainline'].includes(config.track_id)) throw new Error('track_id must be rc or mainline');
  if (!path.isAbsolute(config.repo_root || '') || !path.isAbsolute(config.home || '')) throw new Error('repo_root and home must be absolute paths');
  const server = validateServerUrl(config.server_url, config.allow_insecure_lan_http);
  if (!Number.isInteger(config.telemetry_interval_seconds) || config.telemetry_interval_seconds < 60) throw new Error('telemetry_interval_seconds must be at least 60');
  const prefixes = config.coverage_prefixes || defaultCoveragePrefixes;
  if (!Array.isArray(prefixes) || !prefixes.length || prefixes.some(value => typeof value !== 'string' || !/^[A-Za-z0-9_.+/-]+\/$/.test(value) || value.startsWith('/') || value.split('/').includes('..'))) throw new Error('Invalid coverage_prefixes');
  return { ...config, server, coverage_prefixes: prefixes, agentcov_bin: config.agentcov_bin || 'agentcov' };
}

export function validateServerUrl(serverUrl, allowInsecureLanHttp = false) {
  const server = new URL(serverUrl);
  const octets = server.hostname.split('.').map(Number);
  const privateIp = isIP(server.hostname) === 4 && (octets[0] === 10 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168);
  const localHttp = ['127.0.0.1', 'localhost', '[::1]'].includes(server.hostname);
  if (!['http:', 'https:'].includes(server.protocol) || server.protocol === 'http:' && !localHttp && !(privateIp && allowInsecureLanHttp === true)) throw new Error('Private-LAN HTTP requires allow_insecure_lan_http: true; other network connections require HTTPS');
  return server.origin;
}

export function supportsGzipTelemetry(health) {
  return health?.telemetry?.content_encodings?.includes('gzip') === true;
}

export function supportsFindingRevisions(health) {
  return health?.exchange?.finding_revisions === true;
}

export function retryableTelemetryRejection(error) {
  return /^\/v1\/telemetry\/batches: (400 Invalid batch content|413 (Request too large|coverage\.json is too large))$/.test(error || '');
}

export async function encodeJsonBody(body, compress = false) {
  const json = JSON.stringify(body);
  if (!compress) return { body: json, headers: {} };
  return { body: await gzipAsync(Buffer.from(json)), headers: { 'Content-Encoding': 'gzip' } };
}

async function post(config, token, endpoint, body, options = {}) {
  const encoded = await encodeJsonBody(body, options.gzip === true);
  const response = await fetch(`${config.server}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...encoded.headers }, body: encoded.body, signal: AbortSignal.timeout(30_000) });
  const result = await response.json();
  if (!response.ok) throw new Error(`${endpoint}: ${response.status} ${result.error || 'request failed'}`);
  return result;
}

async function syncHealth(config, token) {
  const response = await fetch(`${config.server}/v1/sync/health`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`Sync health returned ${response.status}`);
  return response.json();
}

export async function syncExchange(config, token) {
  const folder = path.join(config.home, 'exchange', 'outbox', config.agent_id);
  const ackFolder = path.join(config.home, 'exchange', 'ack', config.agent_id);
  await fs.mkdir(folder, { recursive: true });
  await fs.mkdir(ackFolder, { recursive: true });
  for (const entry of (await fs.readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
    const file = path.join(folder, entry.name);
    const before = await fs.stat(file);
    if (Date.now() - before.mtimeMs < 1000) continue;
    const markdown = await fs.readFile(file, 'utf8');
    const after = await fs.stat(file);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) continue;
    const sourcePath = `exchange/outbox/${config.agent_id}/${entry.name}`;
    const sha256 = hash(markdown);
    const ack = path.join(ackFolder, `${hash(`${sourcePath}\0${sha256}`)}.json`);
    if (await fs.stat(ack).catch(() => null)) continue;
    try {
      const event = readFrontMatter(markdown).data;
      if (event.kind === 'finding') {
        console.error(`${entry.name}: legacy finding retained locally; resubmit its evidence with submit_vulnerability`);
        continue;
      }
      const result = await post(config, token, '/v1/exchange/events', { agent_id: config.agent_id, source_path: sourcePath, markdown, sha256 });
      await fs.writeFile(ack, JSON.stringify({ source_path: sourcePath, sha256, result, at: timestamp() }, null, 2));
      console.log(`Event accepted: ${entry.name} → ${result.event_id}`);
    } catch (error) {
      if (/^\/v1\/exchange\/events: 422 Unknown corrected event$/.test(error.message)) {
        console.error(`${entry.name}: waiting for dependency: ${error.message}`);
        continue;
      }
      if (!/^\/v1\/exchange\/events: (400|403|409|413|422) /.test(error.message)) throw error;
      await fs.writeFile(ack, JSON.stringify({ source_path: sourcePath, sha256, error: error.message, at: timestamp() }, null, 2));
      console.error(`${entry.name}: ${error.message}`);
    }
  }
}

export async function latestBatch(config) {
  const folder = path.join(config.home, 'telemetry', 'batches', config.agent_id);
  await fs.mkdir(folder, { recursive: true });
  const batches = [];
  for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
    const entryPath = path.join(folder, entry.name);
    if (entry.isDirectory() && entry.name.startsWith('.creating-')) {
      await fs.rm(entryPath, { recursive: true, force: true });
      continue;
    }
    if (!entry.isDirectory() || !/^[a-f0-9]{64}$/.test(entry.name)) continue;
    const manifest = JSON.parse(await fs.readFile(path.join(entryPath, 'manifest.json'), 'utf8'));
    batches.push({ name: entry.name, batchFolder: entryPath, manifest });
  }
  batches.sort((a, b) => a.manifest.generated_at.localeCompare(b.manifest.generated_at) || a.name.localeCompare(b.name));
  const newest = batches.pop();
  for (const batch of batches) await fs.rm(batch.batchFolder, { recursive: true, force: true });
  return newest;
}

const syncState = (manifest, repoRoot, extra = {}) => ({
  source_digest: manifest.source_digest,
  batch_id: manifest.batch_id,
  repo_root: repoRoot,
  repo_commit: manifest.repo_commit,
  ...extra,
  at: timestamp(),
});

export async function pendingBatches(config, token, telemetry = {}) {
  const folder = path.join(config.home, 'telemetry', 'batches', config.agent_id);
  const statePath = path.join(config.home, `sync-state-${config.agent_id}.json`);
  const newest = await latestBatch(config);
  if (!newest) return;
  const { name, batchFolder, manifest } = newest;
  if (await fs.stat(path.join(batchFolder, 'ack.json')).catch(() => null)) {
    await fs.writeFile(statePath, JSON.stringify(syncState(manifest, config.repo_root), null, 2));
    return;
  }
  const rejectedPath = path.join(batchFolder, 'rejected.json');
  const rejected = JSON.parse(await fs.readFile(rejectedPath, 'utf8').catch(() => 'null'));
  if (rejected && !(telemetry.gzip && retryableTelemetryRejection(rejected.error))) {
    await fs.writeFile(statePath, JSON.stringify(syncState(manifest, config.repo_root, { rejected: true }), null, 2));
    return;
  }
  const [lcov, coverageJson, progressMd] = await Promise.all([
    fs.readFile(path.join(batchFolder, 'agentcov.info'), 'utf8'),
    fs.readFile(path.join(batchFolder, 'coverage.json'), 'utf8'),
    fs.readFile(path.join(batchFolder, 'progress.md'), 'utf8'),
  ]);
  try {
    const result = await post(config, token, '/v1/telemetry/batches', { manifest, lcov, coverage_json: coverageJson, progress_md: progressMd }, { gzip: telemetry.gzip });
    await fs.writeFile(statePath, JSON.stringify(syncState(manifest, config.repo_root), null, 2));
    await fs.writeFile(path.join(batchFolder, 'ack.json'), JSON.stringify({ result, at: timestamp() }, null, 2));
    console.log(`Batch accepted: ${name}`);
    if (result.warnings?.length) console.warn(`Batch ${name}: ${result.warnings.join(', ')}`);
  } catch (error) {
    if (!/^\/v1\/telemetry\/batches: (400|413|422) /.test(error.message)) throw error;
    await fs.writeFile(path.join(batchFolder, 'rejected.json'), JSON.stringify({ error: error.message, at: timestamp() }, null, 2));
    await fs.writeFile(statePath, JSON.stringify(syncState(manifest, config.repo_root, { rejected: true }), null, 2));
    console.error(`${name}: ${error.message}`);
  }
}

async function syncTelemetry(config, token, telemetry = {}) {
  const { stdout: commitText } = await run('git', gitArgs(config.repo_root, ['rev-parse', 'HEAD']), { cwd: config.repo_root });
  const commit = commitText.trim();
  const folder = path.join(config.home, 'telemetry', 'batches', config.agent_id);
  const statePath = path.join(config.home, `sync-state-${config.agent_id}.json`);
  const initialState = JSON.parse(await fs.readFile(statePath, 'utf8').catch(() => '{}'));
  if (initialState.batch_id) {
    const prior = initialState.repo_root && initialState.repo_commit
      ? initialState
      : JSON.parse(await fs.readFile(path.join(folder, initialState.batch_id, 'manifest.json'), 'utf8').catch(() => 'null'));
    assertFreshCheckout(prior, config.repo_root, commit);
  }
  await pendingBatches(config, token, telemetry);
  const state = JSON.parse(await fs.readFile(statePath, 'utf8').catch(() => '{}'));
  const { files: scope, missingIncludes } = await buildCoverageScope(config.repo_root, config.coverage_prefixes);
  const { stdout: status } = await run('git', gitArgs(config.repo_root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']), { cwd: config.repo_root });
  const changed = status.split('\0').filter(Boolean).map(entry => entry.startsWith('?? ') || /^[ MARCUD?!]{2} /.test(entry) ? entry.slice(3) : entry);
  const clean = !changed.some(name => scope.has(name) || config.coverage_prefixes.some(prefix => name.startsWith(prefix)));
  const agentcovConfig = await fs.readFile(path.join(config.repo_root, '.agentcov.toml'), 'utf8').catch(error => {
    if (error.code === 'ENOENT') return '';
    throw error;
  });
  const temporary = await fs.mkdtemp(path.join(folder, '.creating-'));
  try {
    const lcovPath = path.join(temporary, 'agentcov.info');
    const coveragePath = path.join(temporary, 'coverage.json');
    const metaPath = path.join(temporary, 'coverage-meta.json');
    const scopePath = path.join(temporary, 'scope.json');
    await fs.writeFile(scopePath, JSON.stringify({ files: [...scope].sort(), missing_includes: [...missingIncludes].sort() }));
    await run(agentcovPython(config.agentcov_bin), [path.join(agentDirectory, 'agentcov-scope-report.py'), '--root', config.repo_root, '--scope', scopePath, '--lcov', lcovPath, '--json', coveragePath, '--meta', metaPath], { cwd: config.repo_root });
    const [lcov, coverageJson, coverageMeta] = await Promise.all([
      fs.readFile(lcovPath, 'utf8'),
      fs.readFile(coveragePath, 'utf8'),
      fs.readFile(metaPath, 'utf8'),
    ]);
    validateCoverageSummary(lcov, coverageMeta, config.repo_root);
    const progressMd = coverageProgressStub(config.version_id, commit);
    const batch = makeBatch({ agentId: config.agent_id, versionId: config.version_id, repoRoot: config.repo_root, commit, clean, generatedAt: timestamp(), lcov, coverageJson, progressMd, agentcovConfig });
    if (state.source_digest === batch.sourceDigest) return;
    const batchFolder = path.join(folder, batch.manifest.batch_id);
    await fs.writeFile(path.join(temporary, 'manifest.json'), JSON.stringify(batch.manifest, null, 2));
    await fs.writeFile(lcovPath, batch.lcov);
    await fs.writeFile(path.join(temporary, 'coverage.json'), coverageJson);
    await fs.writeFile(path.join(temporary, 'progress.md'), progressMd);
    await fs.rename(temporary, batchFolder);
    await pendingBatches(config, token, telemetry);
    console.log(`Coverage scope: ${scope.size} files, ${missingIncludes.size} unavailable includes`);
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
}

export async function startSyncAgent(configInput, token) {
  const config = validateConfig(configInput);
  if (!token) throw new Error('Set HIVEMIND_AGENT_TOKEN');
  let exchangeBusy = false;
  let telemetryBusy = false;
  const exchangeTick = async () => {
    if (exchangeBusy) return;
    exchangeBusy = true;
    try { await syncExchange(config, token); } catch (error) { console.error(error.message); }
    try { await syncSubmissions(config, token); } catch (error) { console.error(error.message); }
    exchangeBusy = false;
  };
  const telemetryTick = async () => {
    if (telemetryBusy) return;
    telemetryBusy = true;
    try { await backfillClaude(config); } catch (error) { console.error(`Claude Code backfill: ${error.message}`); }
    try {
      const health = await syncHealth(config, token);
      await syncTelemetry(config, token, { gzip: supportsGzipTelemetry(health) });
    } catch (error) { console.error(`Telemetry sync: ${error.message}`); }
    finally { telemetryBusy = false; }
  };
  await exchangeTick();
  await telemetryTick();
  const exchangeTimer = setInterval(exchangeTick, 2000);
  const telemetryTimer = setInterval(telemetryTick, config.telemetry_interval_seconds * 1000);
  return { stop: () => { clearInterval(exchangeTimer); clearInterval(telemetryTimer); } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const configPath = process.argv[2];
  if (!configPath) { console.error('Usage: node sync-agent.mjs <agent.json>'); process.exitCode = 1; }
  else fs.readFile(configPath, 'utf8').then(async text => {
    const config = JSON.parse(text);
    const token = process.env.HIVEMIND_AGENT_TOKEN || (await fs.readFile(path.join(path.dirname(path.resolve(configPath)), `${config.agent_id}.token`), 'utf8')).trim();
    return startSyncAgent(config, token);
  }).catch(error => { console.error(error); process.exitCode = 1; });
}

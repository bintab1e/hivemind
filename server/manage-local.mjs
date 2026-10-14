import path from 'node:path';
import fs from 'node:fs';
import { randomBytes, scryptSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openDatabase, issueAgentToken, setActiveTrack } from './server.mjs';
import { importRegistryHistory, reconcileRegistryHistory } from './registry.mjs';
import { importHistoryArtifacts, curateHistoryArtifacts } from './history-artifacts.mjs';
import { purgeFinishedSubmissions } from './submissions.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.HIVEMIND_DATA_DIR || path.join(root, 'runtime', 'server');
const db = openDatabase(path.join(dataDir, 'hivemind.sqlite3'));

try {
  const [area, action, first, second, third] = process.argv.slice(2);
  if (area === 'agent' && action === 'add' && first) {
    if ((second == null) !== (third == null)) throw new Error('Provide both client name and model ID, or neither.');
    const result = issueAgentToken(db, first, false, second == null ? null : { client_name: second, model_id: third });
    console.log(`agent_id: ${result.agent_id}\none_time_token: ${result.token}`);
  } else if (area === 'agent' && action === 'rotate' && first) {
    const result = issueAgentToken(db, first, true);
    console.log(`agent_id: ${result.agent_id}\none_time_token: ${result.token}`);
  } else if (area === 'track' && action === 'set' && first && second && third) {
    console.log(JSON.stringify(setActiveTrack(db, first, { version_id: second, repo_commit: third }), null, 2));
  } else if (area === 'registry' && action === 'import-history' && first && !second) {
    const rows = JSON.parse(fs.readFileSync(first === '-' ? 0 : first, 'utf8'));
    console.log(JSON.stringify(importRegistryHistory(db, rows)));
  } else if (area === 'registry' && action === 'reconcile-history' && first && !second) {
    const rows = JSON.parse(fs.readFileSync(first === '-' ? 0 : first, 'utf8'));
    console.log(JSON.stringify(reconcileRegistryHistory(db, rows)));
  } else if (area === 'registry' && action === 'import-artifacts' && first && second && !third) {
    const manifest = JSON.parse(fs.readFileSync(first === '-' ? 0 : first, 'utf8'));
    console.log(JSON.stringify(importHistoryArtifacts(db, dataDir, second, manifest)));
  } else if (area === 'registry' && action === 'curate-artifacts' && first && !second) {
    const plan = JSON.parse(fs.readFileSync(first === '-' ? 0 : first, 'utf8'));
    console.log(JSON.stringify(curateHistoryArtifacts(db, plan)));
  } else if (area === 'queue' && action === 'cleanup' && !first) {
    console.log(JSON.stringify(purgeFinishedSubmissions(db)));
  } else if (area === 'status' && !action) {
    console.log(JSON.stringify({
      tracks: db.prepare('SELECT track_id, version_id, repo_commit, activated_at FROM track_targets WHERE active = 1 ORDER BY track_id').all(),
      agents: db.prepare('SELECT agent_id, client_name, model_id, last_seen_at FROM agents ORDER BY agent_id').all(),
    }, null, 2));
  } else if (area === 'dashboard' && action === 'reset') {
    const password = randomBytes(24).toString('base64url');
    const salt = randomBytes(16).toString('hex');
    const passwordHash = scryptSync(password, salt, 32).toString('hex');
    fs.writeFileSync(path.join(dataDir, 'dashboard-auth.env'), `HIVEMIND_DASHBOARD_USER=viewer\nHIVEMIND_DASHBOARD_PASSWORD_SALT=${salt}\nHIVEMIND_DASHBOARD_PASSWORD_HASH=${passwordHash}\n`, { mode: 0o600 });
    console.log(`dashboard_user: viewer\none_time_password: ${password}\nRestart the server to apply the new hash.`);
  } else {
    throw new Error('Usage: manage-local.mjs agent add <id> [client model] | agent rotate <id> | track set <rc|mainline> <version> <commit> | registry import-history <sanitized-json|-> | registry reconcile-history <sanitized-json|-> | registry import-artifacts <manifest-json|-> <staging-directory> | registry curate-artifacts <plan-json|-> | queue cleanup | dashboard reset | status');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  db.close();
}

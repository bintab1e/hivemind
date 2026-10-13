import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const agentSourceFiles = [
    'agentcov-claude-backfill.py', 'agentcov-scope-report.py', 'agentcov-windows-hook.py',
    'contract.mjs', 'coverage-scope.mjs', 'mcp-headers.mjs', 'mcp-agent.mjs', 'submissions.mjs',
    'sync-agent.mjs', 'setup.mjs', 'copy-agent.mjs', 'install.sh', 'setup.sh',
    'requirements.txt', 'knfsd-AGENTS.md',
    'templates/report.md', 'templates/exchange/finding-revision.md',
    'templates/telemetry/progress.md', 'templates/team-status.md',
];

export function copyAgentSource(source, target) {
  const from = fs.realpathSync(source);
  const to = fs.realpathSync(target);
  if (from === to) return;
  if (to.startsWith(`${from}${path.sep}`)) throw new Error('Agent destination cannot be inside its source');
  for (const file of agentSourceFiles) {
    const input = path.join(from, file);
    if (!fs.existsSync(input) || !fs.lstatSync(input).isFile()) throw new Error(`Missing agent source file: ${file}`);
    const output = path.join(to, file);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.copyFileSync(input, output);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  copyAgentSource(process.argv[2], process.argv[3]);
}

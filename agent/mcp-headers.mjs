import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const agentId = process.argv[2];
if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(agentId || '')) throw new Error('Usage: node mcp-headers.mjs <agent-id>');
const root = path.dirname(fileURLToPath(import.meta.url));
const token = fs.readFileSync(path.join(root, 'runtime', 'agents', `${agentId}.token`), 'utf8').trim();
if (!/^[a-f0-9]{64}$/i.test(token)) throw new Error('Invalid agent token file');
process.stdout.write(JSON.stringify({ Authorization: `Bearer ${token}` }));

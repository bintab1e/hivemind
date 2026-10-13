import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { mcpTools } from './contract.mjs';
import { gitArgs, validateConfig } from './sync-agent.mjs';
import { buildSubmission, deliverSubmission, queueSubmission, rejectSubmission } from './submissions.mjs';

const run = promisify(execFile);
const localTools = [
  { name: 'submit_vulnerability', description: 'knfsd 취약점 후보의 원본 보고서와 PoC·로그 파일을 서버 검증 대기열에 제출한다. 파일 형식과 KASAN 로그는 아직 없어도 된다. 서버의 2VM 재현 전에는 취약점으로 확정되지 않는다.', inputSchema: {
    type: 'object', additionalProperties: false,
    properties: {
      project: { type: 'string', enum: ['knfsd'], description: '현재 지원 대상은 knfsd뿐이다.' },
      title: { type: 'string', maxLength: 300 },
      report: { type: 'string', description: '원본 분석 보고서. 파일로 첨부해도 된다.' },
      metadata: { type: 'object', description: '확인한 옵션·권한·NFS 버전·유형·발견일·영향 등. 미확인 값은 추측하지 않는다.' },
      files: { type: 'array', maxItems: 20, items: { type: 'object', additionalProperties: false, properties: {
        path: { type: 'string', description: 'repo_root 또는 에이전트 home/evidence 아래의 파일 경로. 원문이 전송된다.' },
        name: { type: 'string', description: '선택: 서버에 보일 파일 이름.' },
        kind: { type: 'string', enum: ['report', 'poc', 'log', 'other'], description: '선택: 파일 분류 힌트.' },
      }, required: ['path'] } },
      client_submission_id: { type: 'string', description: '선택: 재시도 때 같은 ID를 쓰기 위한 멱등 키.' },
    },
  } },
];
async function remoteMcp(config, token, name, args) {
  const response = await fetch(`${config.server}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Central MCP returned ${response.status}`);
  const message = await response.json();
  if (message.error) throw new Error(message.error.message);
  return message.result;
}

export async function handleMessage(config, token, message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return { jsonrpc: '2.0', id: message?.id ?? null, error: { code: -32600, message: 'Invalid Request' } };
  if (!Object.hasOwn(message, 'id')) return null;
  const answer = result => ({ jsonrpc: '2.0', id: message.id, result });
  if (message.method === 'initialize') return answer({ protocolVersion: ['2025-03-26', '2025-11-25'].includes(message.params?.protocolVersion) ? message.params.protocolVersion : '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'knfsd-hivemind-agent', version: '1.0.0' } });
  if (message.method === 'ping') return answer({});
  if (message.method === 'tools/list') return answer({ tools: [...mcpTools, ...localTools] });
  if (message.method !== 'tools/call') return { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } };
  const name = message.params?.name;
  const args = message.params?.arguments || {};
  if (!mcpTools.some(tool => tool.name === name) && !localTools.some(tool => tool.name === name)) return { jsonrpc: '2.0', id: message.id, error: { code: -32602, message: 'Unknown tool' } };
  try {
    if (mcpTools.some(tool => tool.name === name)) return answer(await remoteMcp(config, token, name, args));
    const { stdout } = await run('git', gitArgs(config.repo_root, ['rev-parse', 'HEAD']), { cwd: config.repo_root });
    const commit = stdout.trim();
    const body = await buildSubmission(config, args, commit);
    const queued = await queueSubmission(config, body);
    let result;
    try {
      const accepted = await deliverSubmission(config, token, body, queued);
      result = { ...accepted, replayed: queued.replayed || accepted.replayed || false, client_submission_id: body.client_submission_id, delivered: true };
    } catch (error) {
      const permanent = error.status && error.status < 500 && error.status !== 429;
      if (permanent) await rejectSubmission(config, body.client_submission_id, error);
      result = { client_submission_id: body.client_submission_id, status: permanent ? 'local_rejected' : 'local_pending', delivered: false, delivery_error: error.message };
    }
    return answer({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: result.status === 'local_rejected' });
  } catch (error) {
    return answer({ content: [{ type: 'text', text: error.message }], isError: true });
  }
}

async function main() {
  const configPath = process.argv[2];
  if (!configPath) throw new Error('Usage: node mcp-agent.mjs <agent.json>');
  const config = validateConfig(JSON.parse(await fs.readFile(configPath, 'utf8')));
  const token = process.env.HIVEMIND_AGENT_TOKEN || (await fs.readFile(path.join(path.dirname(path.resolve(configPath)), `${config.agent_id}.token`), 'utf8')).trim();
  if (!/^[a-f0-9]{64}$/i.test(token)) throw new Error('Invalid agent token');
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of input) {
    let response;
    try {
      if (Buffer.byteLength(line) > 1_000_000) throw new Error('Request too large');
      response = await handleMessage(config, token, JSON.parse(line));
    } catch (error) { response = { jsonrpc: '2.0', id: null, error: { code: -32700, message: error.message } }; }
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error.message); process.exitCode = 1; });

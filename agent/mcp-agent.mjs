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
  { name: 'submit_vulnerability', description: 'knfsd 취약점 후보를 서버 검증 대기열에 제출한다. 첫 제출 응답의 vulnerability_id를 보관하고, 같은 취약점을 보강할 때 반드시 existing_vulnerability_id로 전달한다. 새 분석은 report.md(표준 5개 섹션), poc.c, reproduction.md 또는 reproduce.sh, 실제 KASAN/KCSAN .log를 첨부한다.', inputSchema: {
    type: 'object', additionalProperties: false,
    properties: {
      project: { type: 'string', enum: ['knfsd'], description: '현재 지원 대상은 knfsd뿐이다.' },
      title: { type: 'string', maxLength: 300, description: '영향받는 기능, 원인, 결과를 담은 짧고 중립적인 제목. 서버가 근거에 맞게 정규화한다.' },
      existing_vulnerability_id: { type: 'string', pattern: '^(V-\\d{6,}|A-\\d{3,})$', description: '같은 취약점을 보강할 때 첫 제출 응답의 고유번호(예: V-000001)를 반드시 전달한다. 이미 승인된 기존 건은 관리번호(예: A-005)도 허용한다. 새 취약점이면 생략한다.' },
      existing_management_id: { type: 'string', pattern: '^A-\\d{3,}$', description: '이전 에이전트와의 호환용 기존 관리번호. 새 제출에는 existing_vulnerability_id를 사용한다.' },
      report: { type: 'string', description: '원본 분석 보고서. report.md로 files에 첨부하면 생략한다.' },
      metadata: { type: 'object', description: '분석 PC에서 직접 확인한 조건과 주장. 최종 체크·분류는 서버의 정적 검토 결과로 결정한다.', properties: {
        file_path: { type: 'string', description: '커널 체크아웃 기준 상대 경로' },
        code_refs: { type: 'array', items: { type: 'string' }, description: '커널 소스의 경로와 함수·줄 번호' },
        options: { type: 'string', description: '필요한 NFS 옵션' },
        permission: { type: 'string', description: '필요한 인증·권한(예: AUTH_SYS)' },
        nfs_version: { type: 'string', description: '실제 재현한 NFS 버전' },
        vulnerability_type: { type: 'string', description: '근거 있는 취약점 유형' },
        found_date: { type: 'string', description: 'YYYY-MM-DD' },
        reproduction_command: { type: 'string', description: '첨부 C PoC의 빌드·실행 명령' },
        vm_environment: { type: 'string', description: '서버·클라이언트 VM 조건' },
        access_requirements: { type: 'array', items: { type: 'string', enum: ['auth_null', 'auth_unix', 'rpcsec_gss', 'authenticated_client', 'malicious_server', 'local_user', 'local_privileged'] } },
        claimed_impacts: { type: 'array', items: { type: 'string', enum: ['kasan_read', 'kasan_write', 'controlled_read', 'controlled_write', 'lpe', 'rce', 'info_leak'] }, description: '분석 PC가 직접 관찰했다고 주장하는 항목만. 서버가 독립 검증하여 최종 체크한다.' },
      } },
      result_dir: { type: 'string', description: '설정된 result_root 바로 아래 취약점 디렉터리의 이름 또는 절대 경로. 내부 파일을 모두 첨부하며 files와 함께 사용할 수 없다.' },
      files: { type: 'array', maxItems: 20, items: { type: 'object', additionalProperties: false, properties: {
        path: { type: 'string', description: 'repo_root, 에이전트 home/evidence 또는 설정된 result_root 아래의 파일 경로. 원문이 전송된다.' },
        name: { type: 'string', description: '선택: 서버에 보일 파일 이름.' },
        kind: { type: 'string', enum: ['report', 'poc', 'log', 'other'], description: 'report.md=report, poc.c=poc, KASAN/KCSAN .log=log, reproduction.md/reproduce.sh=other.' },
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

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { evidenceLimits, verifiedImpactTypes, accessRequirementTypes, mcpTools, validateEvent } from './contract.mjs';
import { gitArgs, supportsFindingRevisions, validateConfig } from './sync-agent.mjs';

const run = promisify(execFile);
const sha256 = text => createHash('sha256').update(text).digest('hex');
const common = {
  title: { type: 'string', maxLength: 300, description: '짧고 구체적인 제목. 한국어 또는 영어로 작성할 수 있다.' },
  scope: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 50, description: '저장소 상대경로 또는 컴포넌트' },
  code_refs: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 30, description: '취약점의 코드 위치. 예: fs/nfsd/nfs4proc.c#nfsd4_open' },
  angle: { type: 'string', description: '분석·검증 관점. 예: static-trace, runtime-reproduction' },
  body: { type: 'string', maxLength: 240000, description: '관찰, 원인, 재현 결과, 미확인 사항을 구분한 한국어 Markdown 분석 보고서.' },
};
const schema = (properties, required) => ({ type: 'object', properties: { ...common, ...properties }, required: ['title', 'scope', 'angle', 'body', ...required], additionalProperties: false });
const registryProperties = {
  registry_target: { type: 'string', enum: ['knfsd'], description: '선택: 현재 분석 대상 knfsd. 생략하면 서버가 knfsd로 기록한다.' },
  registry_option: { type: 'string', maxLength: 200, description: '선택: 재현에 필요한 NFS 옵션이나 기능.' },
  registry_privilege: { type: 'string', maxLength: 200, description: '선택: 취약점 관리표의 권한. 실제 재현 조건만 적는다.' },
  registry_report_project: { type: 'string', maxLength: 200, description: '선택: 제보 프로젝트. 예: Linux kernel.' },
  registry_owner: { type: 'string', maxLength: 100, description: '선택: 담당자 이름. 확인되지 않았으면 생략한다.' },
  registry_nfs_version: { type: 'string', maxLength: 100, description: '선택: 영향을 받는 NFS 프로토콜 버전. 커널 버전과 구분한다.' },
  registry_vulnerability_type: { type: 'string', maxLength: 200, description: '선택: 취약점 유형. 예: Race, UAF.' },
  registry_methodology: { type: 'string', maxLength: 100, description: '선택: 찾은 방법론. 예: LLM.' },
  registry_found_date: { type: 'string', maxLength: 10, pattern: '^\\d{4}-\\d{2}-\\d{2}$', description: '선택: 실제 발견 날짜(YYYY-MM-DD). 확인되지 않았으면 생략한다.' },
  registry_exploit: { type: 'string', maxLength: 100, description: '선택: 제안하는 익스플로잇 수준. 서버 검증 전에는 미확정이다.' },
  registry_cve: { type: 'string', maxLength: 32, pattern: '^CVE-\\d{4}-\\d{4,}$', description: '선택: 실제 부여된 CVE 번호. 없으면 생략한다.' },
};
const findingProperties = {
  file_path: { type: 'string', description: '취약점이 있는 저장소 상대 파일 경로. 예: fs/nfsd/nfs4proc.c' },
  evidence_event_ids: { type: 'array', items: { type: 'string' }, description: '선택 사항: 연결할 현재 커밋의 검증 이벤트 ID' },
  access_requirements: { type: 'array', items: { type: 'string', enum: accessRequirementTypes }, minItems: 1, maxItems: accessRequirementTypes.length, uniqueItems: true, description: '재현에 필요한 접근 또는 권한 조건. 여러 조건이면 모두 선택' },
  verified_impacts: { type: 'array', items: { type: 'string', enum: verifiedImpactTypes }, minItems: 1, maxItems: verifiedImpactTypes.length, uniqueItems: true, description: 'PoC·KASAN 또는 실제 결과로 직접 확인한 항목만 선택. 가능성이나 추정은 제외' },
  impact: { type: 'string', maxLength: 1000, description: '한국어로 작성한, 실제 확인된 영향과 아직 확인하지 못한 영향을 구분한 설명' },
  vm_environment: { type: 'string', maxLength: 2000, description: 'NFS 서버 VM과 클라이언트 VM의 커널 버전, 역할, 연결 방식, 재현 전제 조건을 적은 2 VM 검증 환경' },
  poc_path: { type: 'string', description: 'main 함수가 있는 독립 사용자 공간 C 소스(.c). 저장소 상대경로 또는 저장소/에이전트 home 아래 절대경로' },
  kasan_path: { type: 'string', description: 'PoC 실행에서 얻은 BUG: KASAN 로그 파일. 저장소 상대경로 또는 저장소/에이전트 home 아래 절대경로' },
  reproduction_command: { type: 'string', maxLength: 1000, description: 'C PoC 컴파일과 실행을 포함하고 커널 패치 적용은 포함하지 않는 재현 명령' },
  ...registryProperties,
};
const findingRequired = ['code_refs', 'file_path', 'access_requirements', 'verified_impacts', 'impact', 'vm_environment', 'poc_path', 'kasan_path', 'reproduction_command'];
const localTools = [
  { name: 'queue_finding', description: 'knfsd 취약점을 2 VM에서 검증한 독립 사용자 공간 C PoC, 해당 실행의 KASAN 로그, 한국어 분석 보고서를 즉시 제출한다. 확인된 영향만 verified_impacts에 표시한다.', inputSchema: schema(findingProperties, findingRequired) },
  { name: 'queue_finding_revision', description: '이미 수락된 취약점 보고의 본문, PoC 또는 KASAN을 고친 수정본을 새 불변 finding으로 제출한다. corrects_event_id의 기존 보고는 수정본이 서버에 수락된 뒤 현재 목록에서 대체되며 원문 이력은 보존된다.', inputSchema: schema({ corrects_event_id: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '대체할 기존 finding 이벤트 ID' }, ...findingProperties }, ['corrects_event_id', ...findingRequired]) },
];
const localKinds = new Map([
  ['queue_finding', 'finding'],
  ['queue_finding_revision', 'finding'],
]);

function markdownFor(config, kind, args, commit) {
  const fields = {
    schema_version: 1, kind, version_id: config.version_id, repo_commit: commit,
    title: args.title, scope: args.scope, angle: args.angle,
    created_at: new Date().toISOString(),
  };
  for (const key of ['code_refs', 'file_path', 'evidence_event_ids', 'access_requirements', 'verified_impacts', 'impact', 'vm_environment', 'reproduction_command', 'poc_source', 'poc_sha256', 'kasan_log', 'kasan_sha256', 'corrects_event_id', ...Object.keys(registryProperties)]) {
    if (args[key] !== undefined) fields[key] = args[key];
  }
  const lines = Object.entries(fields).flatMap(([key, value]) => Array.isArray(value)
    ? [value.length ? `${key}:` : `${key}: []`, ...value.map(item => `  - ${JSON.stringify(item)}`)]
    : [`${key}: ${JSON.stringify(value)}`]);
  return `---\n${lines.join('\n')}\n---\n\n${args.body}\n`;
}

async function readEvidence(config, source, label, maxBytes) {
  if (typeof source !== 'string' || !source.trim()) throw new Error(`Invalid ${label} path`);
  const target = await fs.realpath(path.isAbsolute(source) ? source : path.join(config.repo_root, source));
  const roots = await Promise.all([config.repo_root, config.home].map(root => fs.realpath(root).catch(() => null)));
  if (!roots.some(root => {
    if (!root) return false;
    const relative = path.relative(root, target);
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  })) throw new Error(`${label} must be inside repo_root or home`);
  const stat = await fs.stat(target);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error(`Invalid ${label} file or size`);
  const content = await fs.readFile(target, 'utf8');
  if (!content.trim() || Buffer.byteLength(content) > maxBytes) throw new Error(`Invalid ${label} content`);
  return content;
}

export async function queueRecord(config, kind, args, commit) {
  if (![...localKinds.values()].includes(kind) || !args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid record');
  if (args.registry_report_status !== undefined) throw new Error('registry_report_status is administrator-managed');
  for (const key of ['title', 'angle', 'body']) if (typeof args[key] !== 'string' || !args[key].trim()) throw new Error(`Invalid ${key}`);
  if (!/^[a-f0-9]{40,64}$/i.test(commit)) throw new Error('Invalid Git commit');
  const name = `${new Date().toISOString().replace(/[-:.]/g, '')}-${randomBytes(8).toString('hex')}.md`;
  const sourcePath = `exchange/outbox/${config.agent_id}/${name}`;
  const markdown = markdownFor(config, kind, args, commit);
  validateEvent({ agent_id: config.agent_id, source_path: sourcePath, markdown, sha256: sha256(markdown) });
  const folder = path.join(config.home, 'exchange', 'outbox', config.agent_id);
  await fs.mkdir(folder, { recursive: true, mode: 0o700 });
  await fs.chmod(folder, 0o700);
  const finalPath = path.join(folder, name);
  const temporary = `${finalPath}.tmp`;
  try {
    await fs.writeFile(temporary, markdown, { flag: 'wx', mode: 0o600 });
    await fs.rename(temporary, finalPath);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
  const eventId = sha256(`${config.version_id}\0${config.agent_id}\0${sourcePath}`);
  return { queued: true, event_id: eventId, corrects_event_id: args.corrects_event_id || null, source_path: sourcePath, file: finalPath, version_id: config.version_id, repo_commit: commit };
}

async function sendRecord(config, token, queued) {
  const markdown = await fs.readFile(queued.file, 'utf8');
  const digest = sha256(markdown);
  const response = await fetch(`${config.server}/v1/exchange/events`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ agent_id: config.agent_id, source_path: queued.source_path, markdown, sha256: digest }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(`Central server returned ${response.status}: ${result.error || 'request failed'}`);
    error.status = response.status;
    error.reason = result.error;
    throw error;
  }
  const ackFolder = path.join(config.home, 'exchange', 'ack', config.agent_id);
  const ack = path.join(ackFolder, `${sha256(`${queued.source_path}\0${digest}`)}.json`);
  try {
    await fs.mkdir(ackFolder, { recursive: true });
    await fs.writeFile(ack, JSON.stringify({ source_path: queued.source_path, sha256: digest, result, at: new Date().toISOString() }, null, 2));
  }
  catch (error) { return { ...result, ack_warning: `서버는 수락했지만 로컬 ACK 저장에 실패했습니다: ${error.message}` }; }
  return result;
}

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

async function serverHealth(config, token) {
  const response = await fetch(`${config.server}/v1/sync/health`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`Central health returned ${response.status}`);
  return response.json();
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
  if (!mcpTools.some(tool => tool.name === name) && !localKinds.has(name)) return { jsonrpc: '2.0', id: message.id, error: { code: -32602, message: 'Unknown tool' } };
  try {
    if (mcpTools.some(tool => tool.name === name)) return answer(await remoteMcp(config, token, name, args));
    if (name === 'queue_finding_revision') {
      const health = await serverHealth(config, token);
      if (!supportsFindingRevisions(health)) throw new Error('중앙 서버가 finding 수정본을 아직 지원하지 않습니다. 서버를 먼저 업데이트하세요.');
    }
    const { stdout } = await run('git', gitArgs(config.repo_root, ['rev-parse', 'HEAD']), { cwd: config.repo_root });
    const commit = stdout.trim();
    let recordArgs = args;
    if (name === 'queue_finding' || name === 'queue_finding_revision') {
      if (typeof args.poc_path !== 'string' || path.extname(args.poc_path).toLowerCase() !== '.c') throw new Error('PoC는 .c 확장자의 독립 사용자 공간 C 소스여야 합니다');
      const { stdout: trackedStatus } = await run('git', gitArgs(config.repo_root, ['status', '--porcelain=v1', '-z', '--untracked-files=no']), { cwd: config.repo_root });
      if (trackedStatus) throw new Error('취약점 보고 전에 대상 저장소의 추적 파일 변경을 모두 되돌려 깨끗한 커널 소스에서 재현해야 합니다');
      const [poc_source, kasan_log] = await Promise.all([
        readEvidence(config, args.poc_path, 'PoC', evidenceLimits.poc),
        readEvidence(config, args.kasan_path, 'KASAN', evidenceLimits.kasan),
      ]);
      recordArgs = { ...args, poc_source, poc_sha256: sha256(poc_source), kasan_log, kasan_sha256: sha256(kasan_log) };
    }
    const result = await queueRecord(config, localKinds.get(name), recordArgs, commit);
    try {
      const accepted = await sendRecord(config, token, result);
      result.accepted = true;
      result.event_id = accepted.event_id;
      result.warnings = accepted.warnings;
      if (accepted.ack_warning) result.ack_warning = accepted.ack_warning;
    } catch (error) {
      result.accepted = false;
      result.delivery_error = error.message;
      const waiting = error.status === 422 && error.reason === 'Unknown corrected event';
      result.note = error.status && [400, 403, 409, 413, 422].includes(error.status) && !waiting
        ? '서버가 기록을 거절했습니다. 오류를 확인하고 새 기록으로 다시 등록하세요.'
        : '로컬 파일은 보존됐습니다. 동기화 에이전트가 재전송합니다.';
    }
    return answer({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false });
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

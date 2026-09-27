import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { evidenceLimits, mcpTools, validateEvent } from './contract.mjs';
import { gitArgs, validateConfig } from './sync-agent.mjs';

const run = promisify(execFile);
const sha256 = text => createHash('sha256').update(text).digest('hex');
const common = {
  title: { type: 'string', maxLength: 300, description: '짧고 구체적인 제목' },
  scope: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 50, description: '저장소 상대경로 또는 컴포넌트' },
  code_refs: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 30, description: '가설을 떠올리거나 검증한 위치. 예: fs/nfsd/nfs4proc.c#nfsd4_open, function:nfsd4_open, feature:NFS_OPEN' },
  angle: { type: 'string', description: '분석·검증 관점. 예: static-trace, runtime-reproduction' },
  body: { type: 'string', maxLength: 240000, description: '관찰, 근거, 미확인 사항을 구분한 Markdown 본문' },
};
const schema = (properties, required) => ({ type: 'object', properties: { ...common, ...properties }, required: ['title', 'scope', 'angle', 'body', ...required], additionalProperties: false });
const localTools = [
  { name: 'queue_hypothesis', description: '코드 위치·검증 계획·현재 커밋을 담은 가설을 검색 후 서버에 즉시 전송한다. 동일 주장이 폐기 상태면 재등록을 피하고, 새 증거가 있을 때만 검증을 추가한다.', inputSchema: schema({ claim_key: { type: 'string' }, verification_plan: { type: 'string', maxLength: 1000, description: '다른 에이전트가 실행할 수 있는 구체적인 확인 방법' }, preflight: { type: 'string', enum: ['checked', 'unavailable'] }, related_hypothesis_id: { type: 'string' } }, ['code_refs', 'claim_key', 'verification_plan', 'preflight']) },
  { name: 'queue_analysis', description: '분석 결과를 outbox Markdown으로 저장한다. 기존 가설에 연결하려면 hypothesis_id를 넣는다.', inputSchema: schema({ hypothesis_id: { type: 'string' } }, []) },
  { name: 'queue_verification', description: '기존 가설에 대한 검증을 코드 위치·방법·결과와 함께 서버에 즉시 전송한다. 폐기 가설에도 새로운 근거로 재검증할 수 있다.', inputSchema: schema({ verification_of: { type: 'string' }, method: { type: 'string' }, verdict: { type: 'string', enum: ['supports', 'refutes', 'inconclusive'] }, prior_exposure: { type: 'string', enum: ['none', 'claim_only', 'summary', 'full'] }, based_on_event_ids: { type: 'array', items: { type: 'string' } } }, ['code_refs', 'verification_of', 'method', 'verdict', 'prior_exposure', 'based_on_event_ids']) },
  { name: 'queue_finding', description: '지지 검증 뒤 실제 PoC 파일과 해당 실행의 KASAN 로그를 읽어 가설·파일·영향과 함께 즉시 서버에 보고한다. 두 증거가 없으면 등록하지 않는다.', inputSchema: schema({ finding_of: { type: 'string', description: '취약점 발견으로 이어진 가설 ID' }, file_path: { type: 'string', description: '취약점이 있는 저장소 상대 파일 경로. 예: fs/nfsd/nfs4proc.c' }, evidence_event_ids: { type: 'array', items: { type: 'string' }, minItems: 1, description: '현재 커밋에서 해당 가설을 지지한 검증 이벤트 ID' }, impact: { type: 'string', maxLength: 1000, description: 'KASAN으로 관찰한 문제의 보안 영향' }, poc_path: { type: 'string', description: '실제 PoC 파일. 저장소 상대경로 또는 저장소/에이전트 home 아래 절대경로' }, kasan_path: { type: 'string', description: 'PoC 실행에서 얻은 BUG: KASAN 로그 파일. 저장소 상대경로 또는 저장소/에이전트 home 아래 절대경로' }, reproduction_command: { type: 'string', maxLength: 1000, description: '해당 PoC로 KASAN을 재현한 명령' } }, ['code_refs', 'finding_of', 'file_path', 'evidence_event_ids', 'impact', 'poc_path', 'kasan_path', 'reproduction_command']) },
  { name: 'queue_correction', description: '수락된 기록을 덮어쓰지 않고 정정 이벤트를 새 outbox Markdown으로 저장한다.', inputSchema: schema({ corrects_event_id: { type: 'string' } }, ['corrects_event_id']) },
];
const localKinds = new Map(localTools.map(tool => [tool.name, tool.name.slice('queue_'.length)]));

function markdownFor(config, kind, args, commit) {
  const fields = {
    schema_version: 1, kind, version_id: config.version_id, repo_commit: commit,
    title: args.title, scope: args.scope, angle: args.angle,
    created_at: new Date().toISOString(),
  };
  for (const key of ['code_refs', 'claim_key', 'verification_plan', 'preflight', 'related_hypothesis_id', 'hypothesis_id', 'verification_of', 'method', 'verdict', 'prior_exposure', 'based_on_event_ids', 'finding_of', 'file_path', 'evidence_event_ids', 'impact', 'reproduction_command', 'poc_source', 'poc_sha256', 'kasan_log', 'kasan_sha256', 'corrects_event_id']) {
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
  if (!localKinds.has(`queue_${kind}`) || !args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid record');
  for (const key of ['title', 'angle', 'body']) if (typeof args[key] !== 'string' || !args[key].trim()) throw new Error(`Invalid ${key}`);
  if (!/^[a-f0-9]{40,64}$/i.test(commit)) throw new Error('Invalid Git commit');
  const name = `${new Date().toISOString().replace(/[-:.]/g, '')}-${randomBytes(8).toString('hex')}.md`;
  const sourcePath = `exchange/outbox/${config.agent_id}/${name}`;
  const markdown = markdownFor(config, kind, args, commit);
  validateEvent({ agent_id: config.agent_id, source_path: sourcePath, markdown, sha256: sha256(markdown) });
  const folder = path.join(config.home, 'exchange', 'outbox', config.agent_id);
  await fs.mkdir(folder, { recursive: true });
  const finalPath = path.join(folder, name);
  const temporary = `${finalPath}.tmp`;
  try {
    await fs.writeFile(temporary, markdown, { flag: 'wx' });
    await fs.rename(temporary, finalPath);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
  const eventId = sha256(`${config.version_id}\0${config.agent_id}\0${sourcePath}`);
  return { queued: true, event_id: eventId, hypothesis_id: kind === 'hypothesis' ? `H-${eventId.slice(0, 12)}` : args.verification_of || args.finding_of || args.hypothesis_id || null, source_path: sourcePath, file: finalPath, version_id: config.version_id, repo_commit: commit };
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
    const { stdout } = await run('git', gitArgs(config.repo_root, ['rev-parse', 'HEAD']), { cwd: config.repo_root });
    const commit = stdout.trim();
    let matches = [], searchWarning;
    if (name === 'queue_hypothesis') {
      try {
        const search = await remoteMcp(config, token, 'search_hypotheses', { track_id: config.track_id, version_id: config.version_id, repo_commit: commit, query: args.claim_key, code_ref: args.code_refs?.[0], limit: 8 });
        matches = search.structuredContent?.matches || [];
        if (search.isError) searchWarning = search.content?.[0]?.text || 'Central search failed';
      } catch (error) { searchWarning = `중앙 중복 후보 조회 실패: ${error.message}`; }
      const same = matches.filter(item => item.claim_key?.toLowerCase() === args.claim_key?.toLowerCase());
      if (same.some(item => item.status === 'retired') || (same.length && !args.related_hypothesis_id)) {
        const result = { queued: false, possible_matches: matches, note: same.some(item => item.status === 'retired') ? '현재 커밋에서 독립 반박이 누적된 폐기 가설입니다. 같은 가설을 재등록하지 마세요. 새 코드·실험 근거가 있다면 해당 ID에 queue_verification으로 기록하세요.' : '동일 claim_key가 있습니다. get_hypothesis로 주장을 확인하고, 같은 주장이라면 queue_verification을 사용하세요. 다른 주장이라면 related_hypothesis_id와 차이를 본문에 적어 다시 호출하세요.' };
        return answer({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false });
      }
    }
    let recordArgs = args;
    if (name === 'queue_finding') {
      const [poc_source, kasan_log] = await Promise.all([
        readEvidence(config, args.poc_path, 'PoC', evidenceLimits.poc),
        readEvidence(config, args.kasan_path, 'KASAN', evidenceLimits.kasan),
      ]);
      recordArgs = { ...args, poc_source, poc_sha256: sha256(poc_source), kasan_log, kasan_sha256: sha256(kasan_log) };
    }
    const result = await queueRecord(config, localKinds.get(name), recordArgs, commit);
    if (name === 'queue_hypothesis') {
      result.possible_matches = matches;
      if (searchWarning) result.search_warning = searchWarning;
    }
    try {
      const accepted = await sendRecord(config, token, result);
      result.accepted = true;
      result.event_id = accepted.event_id;
      result.hypothesis_id = accepted.hypothesis_id;
      result.possible_matches = accepted.possible_matches?.length ? accepted.possible_matches : result.possible_matches;
      result.warnings = accepted.warnings;
      if (accepted.ack_warning) result.ack_warning = accepted.ack_warning;
    } catch (error) {
      result.accepted = false;
      result.delivery_error = error.message;
      const waiting = error.status === 422 && ['Unknown hypothesis', 'Unknown supporting verification', 'Unknown corrected event'].includes(error.reason);
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

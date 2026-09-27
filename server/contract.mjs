import { createHash, timingSafeEqual } from 'node:crypto';

export const hash = value => createHash('sha256').update(value).digest('hex');
export const evidenceLimits = { poc: 250_000, kasan: 600_000 };

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const invalid = (message, status = 400) => { throw new HttpError(status, message); };
export const required = (value, name, max = 200) => {
  if (typeof value !== 'string' || !value.trim() || value.length > max) invalid(`Invalid ${name}`);
  return value.trim();
};
export const safeEqual = (a, b) => {
  const left = Buffer.from(a || '');
  const right = Buffer.from(b || '');
  return left.length === right.length && timingSafeEqual(left, right);
};

export function readFrontMatter(markdown) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(markdown);
  if (!match) invalid('Markdown needs YAML front matter');
  const data = {};
  let listKey;
  for (const line of match[1].split(/\r?\n/)) {
    if (!line.trim()) continue;
    const item = /^  - (.+)$/.exec(line);
    if (item && listKey) { data[listKey].push(scalar(item[1])); continue; }
    const field = /^([a-z_][a-z0-9_]*):(?:\s*(.*))?$/.exec(line);
    if (!field) invalid(`Unsupported front matter line: ${line}`);
    if (Object.hasOwn(data, field[1])) invalid(`Duplicate front matter key: ${field[1]}`);
    data[field[1]] = field[2] ? scalar(field[2]) : [];
    listKey = field[2] ? undefined : field[1];
  }
  return { data, body: match[2].trim() };
}

function scalar(value) {
  if (value === 'null') return null;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (value === '[]') return [];
  if (/^\d+$/.test(value)) return Number(value);
  if (value.startsWith('"')) {
    try { return JSON.parse(value); } catch { invalid(`Invalid quoted value: ${value}`); }
  }
  return value;
}

export function validateEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid('Invalid event');
  const agentId = required(input.agent_id, 'agent_id', 64);
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(agentId)) invalid('Invalid agent_id');
  const sourcePath = required(input.source_path, 'source_path', 300).replaceAll('\\', '/');
  if (!sourcePath.startsWith(`exchange/outbox/${agentId}/`) || !sourcePath.endsWith('.md') || sourcePath.split('/').some(segment => !segment || segment === '.' || segment === '..')) invalid('Invalid source_path');
  const markdown = input.markdown;
  if (typeof markdown !== 'string' || !markdown.trim() || Buffer.byteLength(markdown) > 1_200_000) invalid('Invalid markdown');
  const digest = hash(markdown);
  if (required(input.sha256, 'sha256', 64).toLowerCase() !== digest) invalid('Markdown hash mismatch');
  const { data, body } = readFrontMatter(markdown);
  if (data.schema_version !== 1 || !['hypothesis', 'analysis', 'verification', 'finding', 'correction'].includes(data.kind)) invalid('Unsupported event schema or kind');
  for (const key of ['version_id', 'repo_commit', 'title', 'angle', 'created_at']) required(data[key], key, key === 'title' ? 300 : 200);
  if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(data.version_id)) invalid('Invalid version_id');
  if (!/^[a-f0-9]{40,64}$/i.test(data.repo_commit)) invalid('Invalid repo_commit');
  if (!Array.isArray(data.scope) || !data.scope.length || data.scope.length > 50 || data.scope.some(v => typeof v !== 'string' || !v || v.length > 300)) invalid('Invalid scope');
  if (['hypothesis', 'verification', 'finding'].includes(data.kind) && (!Array.isArray(data.code_refs) || !data.code_refs.length)) invalid('code_refs required for hypothesis, verification and finding');
  if (data.code_refs != null && (!Array.isArray(data.code_refs) || data.code_refs.length > 30 || data.code_refs.some(v => typeof v !== 'string' || !v.trim() || v.length > 300 || /[\r\n\x00-\x1f]/.test(v)))) invalid('Invalid code_refs');
  if (!Number.isFinite(Date.parse(data.created_at))) invalid('Invalid created_at');
  if (!body) invalid('Event body is empty');
  if (data.kind === 'hypothesis') {
    required(data.claim_key, 'claim_key', 160);
    required(data.verification_plan, 'verification_plan', 1000);
    if (!['checked', 'unavailable'].includes(data.preflight)) invalid('Invalid preflight');
  }
  if (data.kind === 'analysis' && data.hypothesis_id != null) required(data.hypothesis_id, 'hypothesis_id', 32);
  if (data.kind === 'verification') {
    required(data.verification_of, 'verification_of', 32);
    required(data.method, 'method', 300);
    if (!['supports', 'refutes', 'inconclusive'].includes(data.verdict)) invalid('Invalid verdict');
    if (!['none', 'claim_only', 'summary', 'full'].includes(data.prior_exposure)) invalid('Invalid prior_exposure');
    if (!Array.isArray(data.based_on_event_ids) || data.based_on_event_ids.some(v => typeof v !== 'string')) invalid('Invalid based_on_event_ids');
  }
  if (data.kind === 'finding') {
    required(data.finding_of, 'finding_of', 32);
    required(data.impact, 'impact', 1000);
    required(data.reproduction_command, 'reproduction_command', 1000);
    const file = required(data.file_path, 'file_path', 300);
    if (file.startsWith('/') || file.includes('\\') || file.includes(':') || /[\x00-\x1f]/.test(file) || file.split('/').some(part => !part || part === '.' || part === '..')) invalid('Invalid file_path');
    if (data.evidence_event_ids != null && (!Array.isArray(data.evidence_event_ids) || data.evidence_event_ids.length > 30 || new Set(data.evidence_event_ids).size !== data.evidence_event_ids.length || data.evidence_event_ids.some(id => typeof id !== 'string' || !/^[a-f0-9]{64}$/i.test(id)))) invalid('Invalid evidence_event_ids');
    if (typeof data.poc_source !== 'string' || !data.poc_source.trim() || Buffer.byteLength(data.poc_source) > evidenceLimits.poc || hash(data.poc_source) !== data.poc_sha256) invalid('Invalid PoC source or hash');
    if (typeof data.kasan_log !== 'string' || !/^[ \t]*(?:\[[^\]\r\n]{1,40}\][ \t]*)?BUG:[ \t]*KASAN:/im.test(data.kasan_log) || Buffer.byteLength(data.kasan_log) > evidenceLimits.kasan || hash(data.kasan_log) !== data.kasan_sha256) invalid('Invalid KASAN log or hash');
  }
  if (data.kind === 'correction') required(data.corrects_event_id, 'corrects_event_id', 64);
  return { agentId, sourcePath, markdown, digest, data };
}

export function parseLcov(text, repoRoot) {
  if (typeof text !== 'string' || !text.trim() || text.length > 10_000_000) invalid('Invalid LCOV');
  const files = {};
  let current;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('SF:')) {
      let file = line.slice(3).replaceAll('\\', '/');
      const absolute = file.startsWith('/') || /^[a-z]:\//i.test(file);
      if (absolute) {
        const rootPath = repoRoot?.replaceAll('\\', '/').replace(/\/$/, '');
        const comparable = /^[a-z]:\//i.test(file) ? value => value.toLowerCase() : value => value;
        if (!rootPath || !comparable(file).startsWith(`${comparable(rootPath)}/`)) invalid('LCOV path is outside repo_root');
        file = file.slice(rootPath.length + 1);
      }
      file = file.replace(/^\.\//, '');
      if (!file || file.split('/').some(segment => !segment || segment === '.' || segment === '..') || Object.hasOwn(files, file)) invalid('Invalid LCOV path');
      if (current) invalid('Incomplete LCOV record');
      current = { path: file, total: undefined, lines: new Map() };
    } else if (line.startsWith('DA:')) {
      if (!current) invalid('LCOV DA without SF');
      const match = /^DA:(\d+),(\d+)(?:,.*)?$/.exec(line);
      if (!match) invalid('Invalid LCOV DA');
      const number = Number(match[1]);
      if (number < 1 || number > 5_000_000) invalid('Invalid LCOV line number');
      current.lines.set(number, Number(match[2]) > 0 || current.lines.get(number) === true);
    } else if (line.startsWith('LF:')) {
      if (!current) invalid('LCOV LF without SF');
      current.total = Number(line.slice(3));
      if (!Number.isInteger(current.total) || current.total < 0 || current.total > 5_000_000) invalid('Invalid LCOV LF');
    } else if (line === 'end_of_record') {
      if (!current || current.total === undefined || current.lines.size !== current.total) invalid('Incomplete LCOV record');
      files[current.path] = {
        total: current.total,
        eligible: [...current.lines.keys()].sort((a, b) => a - b),
        read: [...current.lines].filter(([, observed]) => observed).map(([number]) => number).sort((a, b) => a - b),
      };
      current = undefined;
    }
  }
  if (current || !Object.keys(files).length) invalid('Incomplete LCOV');
  return files;
}

export const mcpTools = [
  { name: 'list_versions', description: 'RC·메인라인 두 트랙의 현재 대상과 보관된 버전·커밋을 나열합니다.', inputSchema: { type: 'object', additionalProperties: false } },
  { name: 'search_hypotheses', description: '트랙 전체에서 주장 또는 코드 위치로 가설을 찾습니다. 결과 방향은 숨기고 검증 건수와 폐기 여부를 보여줍니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' }, query: { type: 'string' }, code_ref: { type: 'string' }, limit: { type: 'integer' } } } },
  { name: 'get_hypothesis', description: 'claim_only는 주장·위치·계획·검증 건수·폐기 여부를, full은 개별 검증 결과와 근거를 보여줍니다.', inputSchema: { type: 'object', properties: { hypothesis_id: { type: 'string' }, repo_commit: { type: 'string' }, mode: { type: 'string', enum: ['claim_only', 'full'] } }, required: ['hypothesis_id'] } },
  { name: 'get_event', description: '이벤트 ID의 원본 Markdown을 조회합니다.', inputSchema: { type: 'object', properties: { event_id: { type: 'string' } }, required: ['event_id'] } },
  { name: 'get_team_status', description: '현재 트랙 또는 지정한 버전·커밋의 팀 열람·작업·가설 현황을 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' } } } },
  { name: 'get_coverage_gaps', description: 'agentcov에서 열람이 관측되지 않은 파일과 줄 범위를 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' }, path_prefix: { type: 'string' }, limit: { type: 'integer' } } } },
  { name: 'get_review_gaps', description: '검증이 부족하거나 충돌하는 가설, 열람 기록은 있으나 연결된 교환 기록이 없는 파일을 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' } } } },
  { name: 'get_recent_analyses', description: '트랙이나 버전의 최근 분석·검증 이벤트를 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, since: { type: 'string' }, limit: { type: 'integer' } } } },
  { name: 'list_findings', description: '현재 트랙 또는 지정한 버전·커밋의 취약점 보고를 조회합니다. 자동 확정 판정이 아닙니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' } } } },
].map(tool => ({ ...tool, annotations: { readOnlyHint: true } }));

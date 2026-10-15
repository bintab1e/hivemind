class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const invalid = (message, status = 400) => { throw new HttpError(status, message); };

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

export function parseLcov(text, repoRoot) {
  if (typeof text !== 'string' || !text.trim() || text.length > 10_000_000) invalid('Invalid LCOV');
  const files = {};
  let current;
  let sparseRecord = false;
  let inferredLines = 0;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('TN:')) {
      if (current?.sparse) invalid('Invalid sparse LCOV record');
      if (!current) sparseRecord = line === 'TN:hivemind-sparse-v1';
    } else if (line.startsWith('SF:')) {
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
      current = { path: file, total: undefined, lines: new Map(), sparse: sparseRecord, hits: undefined };
      sparseRecord = false;
    } else if (line.startsWith('DA:')) {
      if (!current) invalid('LCOV DA without SF');
      const match = (current.sparse ? /^DA:(\d+),([1-9]\d*)$/ : /^DA:(\d+),(\d+)(?:,.*)?$/).exec(line);
      if (!match) invalid('Invalid LCOV DA');
      const number = Number(match[1]);
      if (number < 1 || number > 5_000_000) invalid('Invalid LCOV line number');
      if (current.sparse && !Number.isSafeInteger(Number(match[2]))) invalid('Invalid sparse LCOV count');
      if (current.sparse && current.lines.has(number)) invalid('Duplicate sparse LCOV line');
      current.lines.set(number, Number(match[2]) > 0 || current.lines.get(number) === true);
    } else if (line.startsWith('LF:')) {
      if (!current) invalid('LCOV LF without SF');
      if (current.sparse && current.total !== undefined) invalid('Duplicate sparse LCOV LF');
      if (current.sparse && !/^LF:(0|[1-9]\d*)$/.test(line)) invalid('Invalid sparse LCOV LF');
      current.total = Number(line.slice(3));
      if (!Number.isInteger(current.total) || current.total < 0 || current.total > 5_000_000) invalid('Invalid LCOV LF');
    } else if (line.startsWith('LH:') && current?.sparse) {
      if (current.hits !== undefined || !/^LH:\d+$/.test(line)) invalid('Invalid sparse LCOV LH');
      current.hits = Number(line.slice(3));
    } else if (line === 'end_of_record') {
      if (!current || current.total === undefined) invalid('Incomplete LCOV record');
      if (current.sparse) {
        if (current.hits === undefined || current.hits !== current.lines.size || [...current.lines.keys()].some(number => number > current.total)) invalid('Incomplete LCOV record');
        inferredLines += current.total;
        if (inferredLines > 2_000_000) invalid('Sparse LCOV scope too large', 413);
      } else if (current.lines.size !== current.total) invalid('Incomplete LCOV record');
      files[current.path] = {
        total: current.total,
        eligible: current.sparse ? Array.from({ length: current.total }, (_, index) => index + 1) : [...current.lines.keys()].sort((a, b) => a - b),
        read: [...current.lines].filter(([, observed]) => observed).map(([number]) => number).sort((a, b) => a - b),
      };
      current = undefined;
    } else if (current?.sparse && line.trim()) {
      invalid('Invalid sparse LCOV record');
    }
  }
  if (current || sparseRecord || !Object.keys(files).length) invalid('Incomplete LCOV');
  return files;
}

export const mcpTools = [
  { name: 'list_versions', description: 'RC·메인라인 두 트랙의 현재 대상과 보관된 버전·커밋을 나열합니다.', inputSchema: { type: 'object', additionalProperties: false } },
  { name: 'get_event', description: '이벤트 ID의 원본 Markdown을 조회합니다.', inputSchema: { type: 'object', properties: { event_id: { type: 'string' } }, required: ['event_id'] } },
  { name: 'get_team_status', description: '현재 트랙 또는 지정한 버전·커밋의 팀 커버리지와 작업 현황을 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' } } } },
  { name: 'get_coverage_gaps', description: 'agentcov에서 열람이 관측되지 않은 파일과 줄 범위를 조회합니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' }, path_prefix: { type: 'string' }, limit: { type: 'integer' } } } },
  { name: 'list_findings', description: '현재 트랙 또는 지정한 버전·커밋의 취약점 보고를 조회합니다. 자동 확정 판정이 아닙니다.', inputSchema: { type: 'object', properties: { track_id: { type: 'string', enum: ['rc', 'mainline'] }, version_id: { type: 'string' }, repo_commit: { type: 'string' } } } },
].map(tool => ({ ...tool, annotations: { readOnlyHint: true } }));

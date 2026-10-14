const $ = id => document.getElementById(id);
const element = (tag, className = '', text) => {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = String(text);
  return item;
};
const clear = item => item.replaceChildren();
const number = value => Number(value || 0).toLocaleString('ko-KR');
const when = value => {
  const date = value && new Date(value);
  return date && !Number.isNaN(date.valueOf()) ? new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(date) : '—';
};
const impacts = [
  ['kasan_read', 'KASAN Read'], ['kasan_write', 'KASAN Write'],
  ['controlled_read', 'Controlled Read'], ['controlled_write', 'Controlled Write'],
  ['lpe', 'LPE'], ['rce', 'RCE'], ['info_leak', 'Info Leak'],
];
const accessLabels = {
  auth_null: 'AUTH_NULL', auth_unix: 'AUTH_UNIX', rpcsec_gss: 'RPCSEC_GSS',
  authenticated_client: '인증된 클라이언트', malicious_server: '악성 서버',
  local_user: '로컬 사용자', local_privileged: '로컬 관리자',
};
const state = { data: null, registry: null, queue: null, queueError: null, queueRequestId: 0, patchReviews: null, patchError: null, patchRequestId: 0, coverage: null, coverageAgent: '', coveragePage: 1, coverageSortKey: 'unread', coverageSortDir: 'desc', findingPage: 1, findingSortKey: 'management_id', findingSortDir: 'asc', finding: null, detailTab: 'report', refreshId: 0, detailId: 0, editMode: false, editingFindingId: null, editingDraft: null, editSaving: false, editError: null };
const agentName = id => {
  const profile = (state.data?.agent_profiles || []).find(item => item.agent_id === id);
  return [profile?.client_name || id, profile?.model_id].filter(Boolean).join(' · ');
};
const coverageAgentLabel = id => agentName(id) === id ? id : `${agentName(id)} · ${id}`;
const activeView = () => {
  const view = new URLSearchParams(location.search).get('view');
  return ['queue', 'coverage', 'registry', 'patch'].includes(view) ? view : 'findings';
};
const setQuery = values => {
  const query = new URLSearchParams(location.search);
  for (const [key, value] of Object.entries(values)) value ? query.set(key, value) : query.delete(key);
  history.replaceState(null, '', `${location.pathname}${query.size ? `?${query}` : ''}`);
};

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let reason = `요청 실패 (${response.status})`;
    try { reason = (await response.json()).error || reason; } catch { /* text or empty response */ }
    const error = new Error(reason);
    error.status = response.status;
    throw error;
  }
  return response;
}

function showError(error) {
  $('error').textContent = error.message || String(error);
  $('error').hidden = false;
  $('connection').textContent = '연결 오류';
  $('connection').classList.add('offline');
}

function showView() {
  const view = activeView();
  const title = { findings: '신규 취약점', queue: '검증 큐', coverage: '코드 커버리지', registry: '취약점 관리', patch: '패치' }[view];
  $('workspace-title').textContent = title;
  $('findings-title').textContent = title;
  $('track-control').hidden = view !== 'coverage';
  $('coverage-footer').hidden = view !== 'coverage';
  $('findings-view').hidden = view !== 'findings' && view !== 'registry';
  $('open-zip-submit').hidden = view !== 'findings';
  $('finding-export-csv').hidden = view !== 'registry';
  if (view !== 'findings' && $('zip-submit-dialog').open) $('zip-submit-dialog').close();
  if (view !== 'patch' && $('patch-upload-dialog').open) $('patch-upload-dialog').close();
  $('finding-status-stats').hidden = view !== 'registry';
  $('queue-view').hidden = view !== 'queue';
  $('coverage-view').hidden = view !== 'coverage' || !state.data?.selected;
  $('patch-view').hidden = view !== 'patch';
  if (view === 'queue' && !state.queue && !state.queueError) $('queue-active').replaceChildren(element('div', 'table-empty', '검증 큐를 불러오는 중입니다.'));
  for (const name of ['findings', 'queue', 'coverage', 'registry', 'patch']) {
    const button = document.querySelector(`.tabs button[data-view="${name}"]`);
    if (view === name) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
}

function renderHeader(data) {
  const select = $('version');
  const previous = select.value;
  clear(select);
  for (const track of data.tracks || []) {
    const option = element('option', '', `${track.label || track.track_id} · ${track.version_id || '미설정'}`);
    option.value = track.track_id;
    select.append(option);
  }
  select.value = data.selected?.track_id || new URLSearchParams(location.search).get('track_id') || previous;
  select.disabled = !select.options.length;
  const coverageView = activeView() === 'coverage';
  $('empty').hidden = !coverageView || !!data.selected;
  $('dashboard').hidden = false;
  $('updated').textContent = when(data.metrics?.updated_at);
  if (data.selected) $('report-link').href = `/api/team-status.md?${new URLSearchParams({ version_id: data.selected.version_id, repo_commit: data.selected.repo_commit })}`;
}

const findingFilters = [
  ['finding-target', 'target'], ['finding-report-status', 'report_status'],
  ['finding-privilege', 'privilege'], ['finding-owner', 'owner'],
  ['finding-nfs-version', 'nfs_version'], ['finding-vulnerability-type', 'vulnerability_type'],
];
const filterValues = (finding, key) => {
  const value = String(finding[key] ?? '').trim();
  if (!['nfs_version', 'vulnerability_type'].includes(key) || !value) return [value];
  return value.split(',').map(part => {
    const token = part.trim();
    // "3 / NFSACL" names a feature alongside the NFS version.
    return key === 'nfs_version' ? token.replace(/^(\d+(?:\.\d+)?\+?)\s+\/\s+.+$/, '$1') : token;
  }).filter(Boolean);
};
const filterOptionValue = value => value ? `value:${value}` : 'missing';
const matchesFindingFilters = (finding, selected) => selected.every(([key, value]) =>
  filterValues(finding, key).some(part => filterOptionValue(part) === value));

function populateFindingFilters(findings) {
  for (const [id, key] of findingFilters) {
    const select = $(id);
    const chosen = select.value;
    clear(select);
    const all = element('option', '', '전체');
    all.value = '';
    select.append(all);
    const values = [...new Set(findings.flatMap(finding => filterValues(finding, key)))];
    values.sort((a, b) => a.localeCompare(b, 'ko', { numeric: true }));
    for (const value of values) {
      const option = element('option', '', value || '미입력');
      option.value = filterOptionValue(value);
      select.append(option);
    }
    select.value = [...select.options].some(option => option.value === chosen) ? chosen : '';
  }
}

const isRegistered = finding => !!finding.management_id && finding.registration_status === 'verified';
const needsVerification = finding => finding.origin !== 'history' && !isRegistered(finding) && finding.report_status !== '철회' && finding.review_verdict !== 'unlikely';
const newFindingStarts = { A: 43, B: 22, C: 2 };
const historicalNoOffset = { knfsd: 0, 'NFS-Ganesha': 42, libnfs: 63 };
function isNewFinding(finding) {
  if (finding.origin === 'history' || !isRegistered(finding)) return false;
  const match = /^([ABC])-(\d+)$/.exec(finding.management_id);
  return !!match && Number(match[2]) >= newFindingStarts[match[1]];
}
const visibleFindings = () => activeView() === 'registry'
  ? state.registry?.findings || []
  : (state.registry?.findings || []).filter(isNewFinding);
function findingGroups(findings) {
  const byId = new Map(findings.map(finding => [finding.event_id, finding]));
  const groups = new Map();
  for (const finding of findings) {
    let current = finding;
    const seen = new Set([finding.event_id]);
    while (current.replaces_event_id && !seen.has(current.replaces_event_id)) {
      const previousId = current.replaces_event_id;
      seen.add(previousId);
      const previous = byId.get(previousId);
      if (!previous) { current = { event_id: previousId }; break; }
      current = previous;
    }
    if (!groups.has(current.event_id)) groups.set(current.event_id, []);
    groups.get(current.event_id).push(finding);
  }
  return [...groups.values()];
}
const previousFinding = finding => finding.replaces_event_id
  ? (state.registry?.findings || []).find(item => item.event_id === finding.replaces_event_id)
  : null;
const reviewLabel = finding => {
  const revision = !!finding.replaces_event_id;
  if (isRegistered(finding)) {
    const label = finding.review_provider === 'codex_qemu' ? '2VM 검증 완료' : '정적 검증 통과';
    return revision ? `수정본 · ${label}` : label;
  }
  if (finding.review_status === 'unconfigured' || !finding.review_status) return `${revision ? '수정본 검증 대기' : '검증 대기'} · Kimi 미설정`;
  if (finding.review_status === 'error') return revision ? '수정본 검증 오류' : '검증 오류';
  if (finding.review_verdict === 'unlikely') return revision ? '수정본 검증 보류' : '정적 검증 보류';
  if (finding.review_verdict === 'uncertain') return revision ? '수정본 추가 검토' : '추가 검토';
  return revision ? '수정본 검증 대기' : '검증 대기';
};
const impactEvidence = (finding, present) => {
  if (!present) return '기록 없음';
  if (!isRegistered(finding)) return '제출 주장, 정적 검증 대기';
  return finding.review_provider === 'codex_qemu'
    ? '서버 2VM 재현으로 확인'
    : '제출 증빙 포함, Kimi likely 정적 판정. 서버 독립 재현 아님';
};

function renderFindingStats(findings) {
  const groups = findingGroups(findings);
  const targetOf = group => (group.find(isRegistered) || group[0]).target;
  const rows = [
    ['finding-stats', [
      ['총 취약점 수', groups.length, 'accent'],
      ['knfsd', groups.filter(group => targetOf(group) === 'knfsd').length, ''],
      ['NFS-Ganesha', groups.filter(group => targetOf(group) === 'NFS-Ganesha').length, ''],
      ['libnfs', groups.filter(group => targetOf(group) === 'libnfs').length, ''],
    ]],
    ['finding-status-stats', [
      ['검증 대기', groups.filter(group => group.some(needsVerification)).length, ''],
      ['패치 대기', groups.filter(group => group.some(item => isRegistered(item) && !item.has_patch && !['제보 완료', '중복', '철회'].includes(item.report_status))).length, ''],
      ['제보 완료', groups.filter(group => group.some(item => (isRegistered(item) || item.origin === 'history') && item.report_status === '제보 완료')).length, 'good'],
    ]],
  ];
  for (const [id, stats] of rows) {
    clear($(id));
    for (const [label, count, tone] of stats) {
      const item = element('div', `strip-stat ${tone}`);
      item.append(element('span', '', label), element('strong', '', number(count)));
      $(id).append(item);
    }
  }
}

function renderPagination(id, page, pages, onPage) {
  const nav = $(id);
  clear(nav);
  nav.hidden = pages <= 1;
  if (pages <= 1) return;
  const nearby = [...new Set([1, page - 1, page, page + 1, pages])].filter(value => value >= 1 && value <= pages).sort((a, b) => a - b);
  const pagesToShow = [];
  for (const value of nearby) {
    if (pagesToShow.length && value - pagesToShow.at(-1) > 1) pagesToShow.push('…');
    pagesToShow.push(value);
  }
  for (const [label, target, disabled] of [['이전', page - 1, page === 1], ...pagesToShow.map(value => [String(value), value, value === '…']), ['다음', page + 1, page === pages]]) {
    if (label === '…') { nav.append(element('span', 'muted', '…')); continue; }
    const button = element('button', '', label);
    button.type = 'button';
    button.disabled = disabled || (id === 'finding-pagination' && !!state.editingFindingId);
    if (target === page && label === String(page)) button.setAttribute('aria-current', 'page');
    button.addEventListener('click', () => onPage(target));
    nav.append(button);
  }
}

const findingColumns = [
  ['management_id', '관리 번호'], ['title', '취약점 명'], ['target', '대상'],
  ['option', '옵션'], ['privilege', '권한'], ['report_project', '제보 프로젝트'],
  ['report_status', '제보 여부'], ['owner', '담당자'], ['nfs_version', 'NFS 버전'],
  ['vulnerability_type', '취약점 유형'], ['methodology', '방법론'],
  ['found_date', '찾은 날짜'], ['exploit', '익스플로잇'], ['cve', 'CVE'],
];
const findingRowNumber = (finding, index) => finding.origin === 'history' && Number.isInteger(finding.number)
  ? historicalNoOffset[finding.target] + finding.number
  : index + 1;
const registryImpactMark = (finding, key) => (finding.verified_impacts || []).includes(key)
  ? (isRegistered(finding) ? '✓' : '◇')
  : '—';
const registryCsvCell = value => {
  const text = String(value ?? '');
  const safe = /^[\s\uFEFF]*[=+\-@]/.test(text) || /^[\t\r\n]/.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
};
function registryCsv(findings) {
  const header = ['No.', ...findingColumns.map(([, label]) => label), ...impacts.map(([, label]) => label)];
  const rows = findings.map((finding, index) => [
    findingRowNumber(finding, index),
    ...findingColumns.map(([key]) => finding[key] ?? ''),
    ...impacts.map(([key]) => registryImpactMark(finding, key)),
  ]);
  return `\uFEFF${[header, ...rows].map(row => row.map(registryCsvCell).join(',')).join('\r\n')}\r\n`;
}
const editableFindingColumns = findingColumns.filter(([key]) => !['management_id', 'target'].includes(key));
const editLimits = { title: 300, option: 200, privilege: 200, report_project: 200, owner: 100, nfs_version: 100, vulnerability_type: 200, methodology: 100, found_date: 10, exploit: 100, cve: 32 };
const reportStatuses = ['미제보', '제보 중', '제보 완료', '중복', '철회'];

function syncFindingEditControls() {
  const editing = !!state.editingFindingId;
  const toggle = $('finding-edit-mode');
  toggle.textContent = state.editMode ? '수정 종료' : '수정 모드';
  toggle.setAttribute('aria-pressed', String(state.editMode));
  toggle.disabled = editing;
  $('finding-export-csv').disabled = editing;
  $('refresh').disabled = editing;
  for (const id of ['finding-search', ...findingFilters.map(([id]) => id)]) $(id).disabled = editing;
  for (const button of document.querySelectorAll('.tabs button')) button.disabled = editing;
}

function beginFindingEdit(finding) {
  if (state.editingFindingId) return;
  state.editingFindingId = finding.event_id;
  state.editingDraft = Object.fromEntries(editableFindingColumns.map(([key]) => [key, String(finding[key] ?? '')]));
  state.editError = null;
  renderFindings();
  $('findings').querySelector('[data-edit-field="title"]')?.focus();
}

function cancelFindingEdit() {
  if (state.editSaving) return;
  state.editingFindingId = null;
  state.editingDraft = null;
  state.editError = null;
  renderFindings();
}

async function saveFindingEdit() {
  if (state.editSaving || !state.editingFindingId) return;
  const finding = (state.registry?.findings || []).find(item => item.event_id === state.editingFindingId);
  if (!finding) { state.editError = { message: '수정할 행을 찾지 못했습니다. 새로고침해 주세요.' }; renderFindings(); return; }
  const changes = {};
  for (const [key] of editableFindingColumns) {
    const next = state.editingDraft[key].trim() || null;
    if (key === 'title' && !next) { state.editError = { message: '취약점 명을 입력해 주세요.' }; renderFindings(); return; }
    const previous = finding[key] == null ? null : String(finding[key]).trim();
    if (next !== previous) changes[key] = next;
  }
  if (!Object.keys(changes).length) { cancelFindingEdit(); return; }
  if (!Number.isInteger(finding.revision)) { state.editError = { message: '수정 버전을 확인할 수 없습니다. 새로고침해 주세요.' }; renderFindings(); return; }
  state.editSaving = true;
  state.editError = null;
  renderFindings();
  try {
    await api(`/api/registry/rows/${encodeURIComponent(finding.event_id)}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ revision: finding.revision, ...changes }),
    });
    state.editingFindingId = null;
    state.editingDraft = null;
    state.editSaving = false;
    await refresh();
  } catch (error) {
    state.editSaving = false;
    state.editError = { conflict: error.status === 409, message: error.status === 409 ? '다른 사용자가 이 행을 수정했습니다. 입력값은 보존했습니다.' : error.message };
    renderFindings();
  }
}

function findingEditInput(finding, key, label) {
  const cell = element('td', key === 'title' ? 'registry-title-cell' : ['option', 'vulnerability_type'].includes(key) ? 'registry-wrap' : '');
  let control;
  if (key === 'report_status') {
    control = element('select', 'finding-edit-input');
    if (finding.origin === 'history') {
      const blank = element('option', '', '—');
      blank.value = '';
      control.append(blank);
    }
    for (const status of reportStatuses) {
      const option = element('option', '', status);
      option.value = status;
      control.append(option);
    }
    control.addEventListener('change', () => { state.editingDraft[key] = control.value; });
  } else {
    control = element('input', 'finding-edit-input');
    control.type = 'text';
    control.maxLength = editLimits[key];
    control.addEventListener('input', () => { state.editingDraft[key] = control.value; });
  }
  control.setAttribute('aria-label', `${finding.management_id || finding.title} ${label}`);
  control.dataset.editField = key;
  control.value = state.editingDraft[key];
  cell.append(control);
  return cell;
}

function findingEditActions(cell, finding) {
  if (!state.editMode) return;
  const actions = element('div', 'row-edit-actions');
  if (state.editingFindingId === finding.event_id) {
    const save = element('button', 'row-edit-button primary', state.editSaving ? '저장 중…' : '저장');
    save.type = 'button';
    save.disabled = state.editSaving;
    save.setAttribute('aria-label', `${finding.management_id || finding.title} 저장`);
    save.addEventListener('click', saveFindingEdit);
    const cancel = element('button', 'row-edit-button', '취소');
    cancel.type = 'button';
    cancel.disabled = state.editSaving;
    cancel.setAttribute('aria-label', `${finding.management_id || finding.title} 편집 취소`);
    cancel.addEventListener('click', cancelFindingEdit);
    actions.append(save, cancel);
    if (state.editSaving) {
      const status = element('span', 'row-edit-message', '변경 사항을 저장하고 있습니다.');
      status.setAttribute('role', 'status');
      actions.append(status);
    }
    if (state.editError) {
      const message = element('span', 'row-edit-message error-text', state.editError.message);
      message.setAttribute('role', 'alert');
      actions.append(message);
      if (state.editError.conflict) {
        const reload = element('button', 'row-edit-button', '서버 값 불러오기');
        reload.type = 'button';
        reload.addEventListener('click', () => {
          if (!window.confirm('현재 입력한 내용을 버리고 서버의 최신 값을 불러올까요?')) return;
          cancelFindingEdit();
          refresh();
        });
        actions.append(reload);
      }
    }
  } else {
    const edit = element('button', 'row-edit-button', '편집');
    edit.type = 'button';
    edit.disabled = !!state.editingFindingId;
    edit.setAttribute('aria-label', `${finding.management_id || finding.title} 편집`);
    edit.addEventListener('click', () => beginFindingEdit(finding));
    actions.append(edit);
  }
  cell.append(actions);
}

function sortFinding(key) {
  if (state.editingFindingId) return;
  state.findingSortDir = state.findingSortKey === key && state.findingSortDir === 'asc' ? 'desc' : 'asc';
  state.findingSortKey = key;
  state.findingPage = 1;
  renderFindings();
}

function findingHeading(label, key) {
  const head = element('th');
  const suffix = state.findingSortKey === key ? (state.findingSortDir === 'asc' ? ' ▴' : ' ▾') : ' ↕';
  const button = element('button', 'sort-heading', label + suffix);
  button.type = 'button';
  button.disabled = !!state.editingFindingId;
  button.addEventListener('click', () => sortFinding(key));
  head.append(button);
  if (state.findingSortKey === key) head.setAttribute('aria-sort', state.findingSortDir === 'asc' ? 'ascending' : 'descending');
  return head;
}

function findingCell(finding, key) {
  if (key === 'management_id') {
    const cell = element('td', 'registry-id-cell');
    cell.append(element('strong', finding.management_id ? 'registry-id' : 'registry-unassigned', finding.management_id || '미부여'));
    if (finding.origin !== 'history') cell.append(element('span', 'finding-id', reviewLabel(finding)));
    findingEditActions(cell, finding);
    return cell;
  }
  if (state.editingFindingId === finding.event_id && editableFindingColumns.some(([field]) => field === key)) {
    return findingEditInput(finding, key, findingColumns.find(([field]) => field === key)[1]);
  }
  if (key === 'title') {
    const cell = element('td', 'registry-title-cell');
    const button = element('button', 'finding-title', finding.title);
    button.type = 'button';
    button.addEventListener('click', () => openFinding(finding));
    cell.append(button);
    if (finding.origin !== 'history') {
      const prior = previousFinding(finding);
      const revision = finding.replaces_event_id ? `이전 ${prior?.management_id || finding.replaces_event_id.slice(0, 12)} 수정본 · ` : '';
      cell.append(element('span', 'finding-id', revision + agentName(finding.agent_id)));
    }
    return cell;
  }
  if (key === 'report_status') {
    const status = finding.report_status || '—';
    const tone = status === '제보 완료' ? 'done' : status === '철회' ? 'withdrawn' : status === '중복' ? 'duplicate' : '';
    const cell = element('td');
    cell.append(element('span', `report-status ${tone}`, status));
    return cell;
  }
  return element('td', ['option', 'vulnerability_type'].includes(key) ? 'registry-wrap' : '', finding[key] || '—');
}

function filteredFindings(findings) {
  const search = $('finding-search').value.trim().toLowerCase();
  const selectedFilters = findingFilters.map(([id, key]) => [key, $(id).value]).filter(([, value]) => value);
  const filtered = findings.filter(item =>
    matchesFindingFilters(item, selectedFilters) &&
    (!search || `${findingColumns.map(([key]) => item[key] || '').join(' ')} ${previousFinding(item)?.management_id || ''} ${item.file_path || ''} ${item.agent_id} ${agentName(item.agent_id)} ${(item.code_refs || []).join(' ')}`.toLowerCase().includes(search))
  );
  filtered.sort((a, b) => {
    if (state.findingSortKey === 'management_id' && !a.management_id !== !b.management_id) return a.management_id ? -1 : 1;
    const left = String(a[state.findingSortKey] ?? '');
    const right = String(b[state.findingSortKey] ?? '');
    return left.localeCompare(right, 'ko', { numeric: true }) * (state.findingSortDir === 'asc' ? 1 : -1)
      || String(a.event_id).localeCompare(String(b.event_id));
  });
  return filtered;
}

function exportRegistryCsv() {
  if (activeView() !== 'registry' || state.editingFindingId) return;
  const findings = filteredFindings(visibleFindings());
  if (!findings.length) return;
  const url = URL.createObjectURL(new Blob([registryCsv(findings)], { type: 'text/csv;charset=utf-8' }));
  const link = element('a');
  link.href = url;
  link.download = `hivemind-vulnerabilities-${new Date().toLocaleDateString('sv-SE')}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderFindings() {
  syncFindingEditControls();
  const findings = visibleFindings();
  populateFindingFilters(findings);
  renderFindingStats(findings);
  const filtered = filteredFindings(findings);
  const pages = Math.max(1, Math.ceil(filtered.length / 20));
  state.findingPage = Math.min(state.findingPage, pages);
  $('finding-count').textContent = `${number(filtered.length)} / ${number(findings.length)}행`;
  $('finding-export-csv').disabled = !!state.editingFindingId || !filtered.length;
  const scrollLeft = $('findings').scrollLeft;
  const scrollTop = $('findings').scrollTop;
  clear($('findings'));
  if (!filtered.length) {
    $('findings').append(element('div', 'table-empty', findings.length ? '조건에 맞는 취약점이 없습니다.' : activeView() === 'registry' ? '아직 등록된 취약점 보고가 없습니다.' : '아직 신규 취약점 보고가 없습니다.'));
    renderPagination('finding-pagination', 1, 1, () => {});
    return;
  }
  const table = element('table', 'finding-table');
  const head = element('thead');
  const heading = element('tr');
  heading.append(element('th', '', 'No.'));
  for (const [key, label] of findingColumns) heading.append(findingHeading(label, key));
  for (const [, label] of impacts) heading.append(element('th', 'impact-th', label));
  head.append(heading);
  table.append(head);
  const body = element('tbody');
  const offset = (state.findingPage - 1) * 20;
  for (const [index, finding] of filtered.slice(offset, offset + 20).entries()) {
    const row = element('tr');
    if (state.editingFindingId === finding.event_id) row.classList.add('editing-row');
    const serial = findingRowNumber(finding, offset + index);
    row.append(element('td', 'registry-row-number', number(serial)));
    for (const [key] of findingColumns) row.append(findingCell(finding, key));
    const verified = new Set(finding.verified_impacts || []);
    for (const [key, label] of impacts) {
      const present = verified.has(key);
      const cell = element('td', `impact-td ${present && isRegistered(finding) ? 'verified' : present ? 'claimed' : ''}`, registryImpactMark(finding, key));
      const evidence = impactEvidence(finding, present);
      cell.setAttribute('aria-label', `${label}: ${evidence}`);
      cell.title = `${label}: ${evidence}`;
      row.append(cell);
    }
    body.append(row);
  }
  table.append(body);
  $('findings').append(table);
  $('findings').scrollLeft = scrollLeft;
  $('findings').scrollTop = scrollTop;
  renderPagination('finding-pagination', state.findingPage, pages, page => {
    state.findingPage = page;
    renderFindings();
    $('findings').scrollTop = 0;
  });
}

const fileGroup = path => (path || '').split('/').slice(0, 2).join('/');

function populateCoverageAgentFilter() {
  const select = $('coverage-agent');
  clear(select);
  const all = element('option', '', '팀 합집합');
  all.value = '';
  select.append(all);
  for (const agent of state.data.coverage_agents || []) {
    const option = element('option', '', `${coverageAgentLabel(agent.agent_id)}${agent.included_in_team === false ? ' · 병합 제외' : ''}`);
    option.value = agent.agent_id;
    select.append(option);
  }
  select.value = state.coverageAgent;
}

function populateCoverageGroups(files) {
  const select = $('coverage-component');
  const selected = select.value;
  clear(select);
  const all = element('option', '', '전체');
  all.value = '';
  select.append(all);
  for (const group of [...new Set(files.map(file => fileGroup(file.path)))].sort()) {
    const option = element('option', '', group);
    option.value = group;
    select.append(option);
  }
  select.value = [...select.options].some(option => option.value === selected) ? selected : '';
}

function coverageStat(label, value, tone = '') {
  const item = element('div', `strip-stat ${tone}`);
  item.append(element('span', '', label), element('strong', '', value));
  return item;
}

const coverageExclusionLabels = {
  worktree_dirty: '작업 트리 변경',
  scope_mismatch: '분석 범위 불일치',
  file_shape_mismatch: '파일 구성 불일치',
};

function renderCoverageAgentSummary() {
  const summary = $('coverage-agent-summary');
  clear(summary);
  const samples = new Map((state.data?.coverage_agents || []).map(agent => [agent.agent_id, agent]));
  const ids = [...new Set([
    ...(state.data?.agent_profiles || []).map(agent => agent.agent_id),
    ...samples.keys(),
  ])];
  $('coverage-agent-count').textContent = `${number(ids.length)}명`;
  if (!ids.length) {
    summary.append(element('p', 'coverage-agent-empty', '등록된 에이전트가 없습니다.'));
    return;
  }
  const uniqueLines = new Map((state.data?.agents || []).map(agent => [agent.agent_id, agent.unique_lines]));
  for (const id of ids) {
    const sample = samples.get(id);
    const selected = state.coverageAgent === id;
    const card = element(sample ? 'button' : 'div', `coverage-agent-card${selected ? ' selected' : ''}`);
    if (sample) {
      card.type = 'button';
      card.setAttribute('aria-pressed', String(selected));
      card.addEventListener('click', () => selectCoverageAgent(selected ? '' : id));
    }
    const status = !sample ? '수집 대기'
      : sample.included_in_team === false ? `팀 제외 · ${coverageExclusionLabels[sample.exclusion_reason] || '계측 조건 불일치'}`
      : sample.using_clean_fallback ? '직전 정상 배치' : '';
    const heading = element('span', 'coverage-agent-heading');
    heading.append(element('span', 'coverage-agent-name', agentName(id)));
    if (agentName(id) !== id) heading.append(element('span', 'coverage-agent-id', id));
    if (status) heading.append(element('span', `coverage-agent-status${sample?.included_in_team === false ? ' excluded' : ''}`, status));
    const rate = sample?.read_percent == null ? '—' : `${number(sample.read_percent)}%`;
    const bar = element('span', 'bar');
    const fill = element('span');
    fill.style.width = `${Math.max(0, Math.min(100, Number(sample?.read_percent) || 0))}%`;
    bar.append(fill);
    const detail = sample
      ? `${number(sample.read_lines)} / ${number(sample.total_lines)}줄${uniqueLines.has(id) ? ` · 고유 ${number(uniqueLines.get(id))}줄` : ''}`
      : '아직 수집된 자료가 없습니다.';
    card.append(heading, element('strong', 'coverage-agent-rate', rate), bar, element('span', 'coverage-agent-detail', detail));
    summary.append(card);
  }
}

function sortCoverage(key) {
  state.coverageSortDir = state.coverageSortKey === key
    ? (state.coverageSortDir === 'desc' ? 'asc' : 'desc')
    : (key === 'path' ? 'asc' : 'desc');
  state.coverageSortKey = key;
  state.coveragePage = 1;
  renderCoverage();
}

function sortableHeading(label, key) {
  const head = element('th', '', '');
  const button = element('button', 'sort-heading', `${label} ${state.coverageSortKey === key ? (state.coverageSortDir === 'desc' ? '▾' : '▴') : '↕'}`);
  button.type = 'button';
  button.addEventListener('click', () => sortCoverage(key));
  head.append(button);
  if (state.coverageSortKey === key) head.setAttribute('aria-sort', state.coverageSortDir === 'desc' ? 'descending' : 'ascending');
  return head;
}

function renderCoverage() {
  const report = state.coverage;
  if (!report) return;
  const files = report.files || [];
  populateCoverageGroups(files);
  const total = Number(state.data?.metrics?.total_lines || 0);
  const read = Number(state.data?.metrics?.read_lines || 0);
  clear($('coverage-stats'));
  $('coverage-stats').append(
    coverageStat('열람률', total ? `${Math.round(read / total * 1000) / 10}%` : '—', 'accent'),
    coverageStat('읽은 줄', `${number(read)} / ${number(total)}`),
    coverageStat('미열람 줄', number(total - read)),
    coverageStat('중복 열람 줄', number(state.data?.metrics?.overlap_lines), 'good'),
  );
  renderCoverageAgentSummary();
  const note = $('coverage-note');
  const messages = [];
  if (report.included_in_team === false) messages.push(`팀 병합 제외 · ${report.exclusion_reason || '계측 조건 불일치'}`);
  if (report.using_clean_fallback) messages.push('직전 정상 배치를 표시합니다.');
  note.textContent = messages.join(' / ');
  note.hidden = !messages.length;

  const query = $('coverage-search').value.trim().toLowerCase();
  const group = $('coverage-component').value;
  const visible = files.filter(file => (!group || fileGroup(file.path) === group) && (!query || file.path.toLowerCase().includes(query)));
  const key = state.coverageSortKey;
  const direction = state.coverageSortDir === 'asc' ? 1 : -1;
  visible.sort((a, b) => {
    const value = file => key === 'path' ? file.path : key === 'read' ? file.read : key === 'unread' ? file.total - file.read : key === 'percent' ? file.percent : key === 'overlap' ? file.overlap_lines || 0 : key === 'agents' ? file.agents || 0 : file.agent_reads?.[key.slice(6)] || 0;
    const left = value(a);
    const right = value(b);
    return (typeof left === 'string' ? left.localeCompare(right) : left - right) * direction || a.path.localeCompare(b.path);
  });
  $('file-count').textContent = `${number(visible.length)} / ${number(files.length)}개 파일`;
  const pages = Math.max(1, Math.ceil(visible.length / 20));
  state.coveragePage = Math.min(state.coveragePage, pages);
  clear($('files'));
  if (!visible.length) {
    $('files').append(element('div', 'table-empty', files.length ? '조건에 맞는 파일이 없습니다.' : '아직 코드 열람 자료가 없습니다.'));
    renderPagination('coverage-pagination', 1, 1, () => {});
    return;
  }

  const agentIds = state.coverageAgent ? [] : (state.data.agents || []).map(agent => agent.agent_id);
  const table = element('table', 'coverage-table');
  const head = element('thead');
  const heading = element('tr');
  heading.append(element('th', '', '경로'), sortableHeading('파일', 'path'), sortableHeading('읽은 줄', 'read'), sortableHeading('미열람', 'unread'), sortableHeading('열람률', 'percent'));
  if (!state.coverageAgent) heading.append(sortableHeading('중복 열람', 'overlap'), sortableHeading('에이전트', 'agents'));
  for (const id of agentIds) {
    const column = sortableHeading(coverageAgentLabel(id), `agent:${id}`);
    column.classList.add('agent-column');
    column.title = coverageAgentLabel(id);
    heading.append(column);
  }
  head.append(heading);
  table.append(head);
  const body = element('tbody');
  for (const file of visible.slice((state.coveragePage - 1) * 20, state.coveragePage * 20)) {
    const row = element('tr');
    row.append(element('td', 'group-cell path', fileGroup(file.path)), element('td', 'file-path path', file.path));
    row.append(element('td', 'numeric', `${number(file.read)} / ${number(file.total)}`), element('td', 'numeric', number(file.total - file.read)));
    const rate = element('td', 'rate-cell');
    const bar = element('span', 'bar');
    const fill = element('span');
    fill.style.width = `${Math.max(0, Math.min(100, Number(file.percent) || 0))}%`;
    bar.append(fill);
    rate.append(element('span', '', `${file.percent || 0}%`), bar);
    row.append(rate);
    if (!state.coverageAgent) row.append(element('td', 'numeric overlap-cell', number(file.overlap_lines)), element('td', 'numeric', number(file.agents)));
    for (const id of agentIds) {
      const readByAgent = Number(file.agent_reads?.[id] || 0);
      const cell = element('td', 'agent-cell', file.total ? `${Math.round(readByAgent / file.total * 100)}%` : '—');
      cell.title = `${coverageAgentLabel(id)}: ${number(readByAgent)} / ${number(file.total)}줄`;
      cell.style.setProperty('--fill', `${Math.max(0, Math.min(100, file.total ? readByAgent / file.total * 100 : 0))}%`);
      row.append(cell);
    }
    body.append(row);
  }
  table.append(body);
  $('files').append(table);
  renderPagination('coverage-pagination', state.coveragePage, pages, page => {
    state.coveragePage = page;
    renderCoverage();
    $('files').scrollTop = 0;
  });
}

async function loadCoverage() {
  const data = state.data;
  if (!data?.selected) return;
  const requested = state.coverageAgent;
  const track = data.selected;
  const coverage = requested
    ? await (await api(`/api/coverage?${new URLSearchParams({ version_id: track.version_id, repo_commit: track.repo_commit, agent_id: requested })}`)).json()
    : { files: data.files || [], metrics: data.metrics || {}, included_in_team: true };
  if (requested !== state.coverageAgent || track !== state.data?.selected) return;
  state.coverage = coverage;
  renderCoverage();
}

function detailFact(label, value) {
  const fact = element('div', 'detail-fact');
  fact.append(element('span', '', label), element('strong', '', value || '—'));
  return fact;
}

function appendDuplicateReviews(finding) {
  const review = finding.duplicate_review;
  if (review) {
    const fact = detailFact('공개 자료 중복 검사', when(review.checked_at));
    fact.classList.add('duplicate-review');
    const sources = finding.report_status === '중복' && review.verdict === 'duplicate'
      ? (review.evidence || []).filter(item => item?.url) : [];
    if (sources.length) {
      const links = element('div', 'duplicate-evidence');
      for (const source of sources) {
        const link = element('a', 'detail-link', source.url);
        link.href = source.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        links.append(link);
      }
      fact.append(links);
    }
    $('detail-summary').append(fact);
  }

  const internal = finding.internal_duplicate_review;
  if (!internal) return;
  const fact = detailFact('내부 취약점 중복 검사', when(internal.checked_at));
  fact.classList.add('duplicate-review');
  if (finding.report_status === '중복' && internal.verdict === 'duplicate' &&
      internal.matched_management_id) {
    const match = state.registry?.findings?.find(item => item.management_id === internal.matched_management_id);
    if (match) {
      const button = element('button', 'detail-link', internal.matched_management_id);
      button.type = 'button';
      button.addEventListener('click', () => openFinding(match));
      const links = element('div', 'duplicate-evidence');
      links.append(button);
      fact.append(links);
    } else {
      fact.append(element('strong', '', internal.matched_management_id));
    }
  }
  $('detail-summary').append(fact);
}

function openFinding(finding, tab = 'report') {
  state.finding = finding;
  state.detailTab = tab;
  $('detail-title').textContent = finding.title;
  const displayDate = finding.origin === 'history' ? finding.found_date || '—' : when(finding.created_at || finding.found_date);
  $('detail-subtitle').textContent = `${finding.management_id || '관리번호 미부여'} · ${finding.target || '대상 미지정'} · ${displayDate}`;
  clear($('detail-summary'));
  $('detail').querySelector('.detail-tabs').hidden = false;
  if (finding.origin === 'history') {
    const verification = finding.latest_verification;
    $('detail-summary').append(
      detailFact('관리번호 / 대상', `${finding.management_id} · ${finding.target}`),
      detailFact('담당자 / 제보 여부', `${finding.owner || '—'} · ${finding.report_status || '—'}`),
      detailFact('옵션 / 권한', `${finding.option || '—'} · ${finding.privilege || '—'}`),
      detailFact('제보 프로젝트 / NFS 버전', `${finding.report_project || '—'} · ${finding.nfs_version || '—'}`),
      detailFact('취약점 유형 / 방법론', `${finding.vulnerability_type || '—'} · ${finding.methodology || '—'}`),
      detailFact('찾은 날짜 / 익스플로잇 / CVE', `${finding.found_date || '—'} · ${finding.exploit || '—'} · ${finding.cve || '—'}`),
    );
    if (verification) {
      const result = { verified: '2VM 재검증 확인', not_reproduced: '2VM에서 재현되지 않음', inconclusive: '2VM 재검증 미확정' }[verification.result] || '2VM 재검증 미확정';
      const observed = verification.observed_impacts.map(impact => impacts.find(([key]) => key === impact)?.[1] || impact).join(', ');
      $('detail-summary').append(
        detailFact('재검증 결과', `${result} · ${when(verification.completed_at)}`),
        detailFact('재검증 커널 / 동적 관찰', `${verification.kernel_commit} · ${verification.reproduction_status}`),
        detailFact('재검증 영향', observed || '확정되지 않음'),
        detailFact('재검증 사유', verification.reason),
      );
    }
    appendDuplicateReviews(finding);
    if (!$('detail').open) $('detail').showModal();
    showDetailTab();
    return;
  }
  $('detail-summary').append(
    detailFact('관리번호 / 검증', `${isRegistered(finding) ? finding.management_id : '미부여'} · ${reviewLabel(finding)}`),
    detailFact('담당자 / 제보 여부', `${finding.owner || '—'} · ${finding.report_status || '—'}`),
    detailFact('보고 에이전트', agentName(finding.agent_id)),
    detailFact('코드 위치', finding.file_path || (finding.code_refs || [])[0]),
    detailFact('권한 / 옵션', `${finding.privilege || (finding.access_requirements || []).map(value => accessLabels[value] || value).join(' · ') || '—'} · ${finding.option || '—'}`),
    detailFact('2VM 환경', finding.vm_environment),
  );
  if (finding.replaces_event_id) {
    const prior = previousFinding(finding);
    const fact = detailFact('이전 보고', prior?.management_id || finding.replaces_event_id.slice(0, 12));
    if (prior) {
      const button = element('button', 'detail-link', prior.management_id || prior.title);
      button.type = 'button';
      button.addEventListener('click', () => openFinding(prior));
      fact.querySelector('strong').replaceChildren(button);
    }
    $('detail-summary').append(fact);
  }
  const reviewText = [
    finding.review_summary,
    finding.primitive_review_status === 'complete' && finding.primitive_review_summary?.trim() && `프리미티브 추가 검토\n${finding.primitive_review_summary}`,
  ].filter(Boolean).join('\n\n');
  if (reviewText) {
    const review = detailFact('정적 검토 의견', reviewText);
    review.classList.add('review-summary');
    $('detail-summary').append(review);
  }
  appendDuplicateReviews(finding);
  if (!$('detail').open) $('detail').showModal();
  showDetailTab();
}

async function showDetailTab() {
  const finding = state.finding;
  const tab = state.detailTab;
  const id = ++state.detailId;
  for (const button of document.querySelectorAll('[data-detail-tab]')) {
    if (button.dataset.detailTab === tab) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  const content = $('detail-content');
  clear(content);
  content.append(element('p', '', '자료를 불러오는 중…'));
  try {
    if (finding.origin === 'history') {
      const base = `/api/registry/history/${encodeURIComponent(finding.management_id)}/artifacts`;
      const { artifacts } = await (await api(base)).json();
      if (id !== state.detailId) return;
      clear(content);
      const files = (artifacts || []).filter(item => item.kind === tab);
      if (!files.length) {
        content.append(element('p', '', { report: '분석 보고서가 없습니다.', poc: 'PoC · 첨부자료가 없습니다.', verification: '검증 로그가 없습니다.' }[tab]));
        return;
      }
      const nameCounts = new Map();
      for (const file of files) nameCounts.set(file.name.toLowerCase(), (nameCounts.get(file.name.toLowerCase()) || 0) + 1);
      for (const file of files) {
        const duplicateName = nameCounts.get(file.name.toLowerCase()) > 1;
        const section = element('section', 'detail-section artifact-section');
        const header = element('div', 'artifact-head');
        const title = element('h3', '', file.name);
        if (file.original_name && file.original_name !== file.name) title.title = file.original_name;
        const size = element('span', 'muted', `${number(file.size)} B${duplicateName ? ` · 파일 ID ${file.id.slice(0, 8)}` : ''}`);
        const url = `${base}/${encodeURIComponent(file.id)}`;
        const download = element('a', 'detail-link', '다운로드');
        download.href = url;
        download.download = file.download_name || file.name;
        header.append(title, size, download);
        section.append(header);
        if (file.previewable) {
          const preview = element('details', 'artifact-preview');
          preview.append(element('summary', '', '내용 보기'));
          const body = element('pre', '', '자료를 불러오는 중…');
          preview.append(body);
          let loaded = false;
          preview.addEventListener('toggle', async () => {
            if (!preview.open || loaded) return;
            loaded = true;
            try { body.textContent = await (await api(url)).text(); }
            catch (error) { body.textContent = `자료를 열지 못했습니다: ${error.message}`; loaded = false; }
          });
          section.append(preview);
        }
        content.append(section);
      }
      return;
    }
    const canonicalBase = `/api/events/${encodeURIComponent(finding.event_id)}/artifacts`;
    const canonical = await api(canonicalBase).then(response => response.json()).catch(error => {
      if (error.status === 404) return { artifacts: [] };
      throw error;
    });
    if (id !== state.detailId) return;
    if (canonical.artifacts?.length) {
      clear(content);
      const names = tab === 'report' ? ['report.md'] : tab === 'poc' ? ['poc.c', 'reproduction.md'] : ['kasan.log'];
      for (const name of names) {
        const file = canonical.artifacts.find(item => item.name === name);
        if (!file) continue;
        const url = `${canonicalBase}/${name}`;
        const section = element('section', 'detail-section artifact-section');
        const header = element('div', 'artifact-head');
        const link = element('a', 'detail-link', '다운로드');
        link.href = url;
        link.download = name;
        header.append(element('h3', '', name), element('span', 'muted', `${number(file.size)} B`), link);
        section.append(header);
        const preview = element('pre', '', await (await api(url)).text());
        if (id !== state.detailId) return;
        section.append(preview);
        content.append(section);
      }
      return;
    }
    const endpoint = tab === 'report' ? `/api/events/${encodeURIComponent(finding.event_id)}` : `/api/events/${encodeURIComponent(finding.event_id)}/${tab === 'verification' ? 'kasan' : tab}`;
    const response = await api(endpoint);
    const text = tab === 'report' ? (await response.json()).markdown : await response.text();
    if (id !== state.detailId) return;
    clear(content);
    if (tab === 'report') {
      if (finding.reproduction_command) {
        const command = element('div', 'detail-section');
        command.append(element('h3', '', '재현 명령'), element('pre', '', finding.reproduction_command));
        content.append(command);
      }
    }
    content.append(element('pre', '', text || '제출된 내용이 없습니다.'));
  } catch (error) {
    if (id === state.detailId) { clear(content); content.append(element('p', '', `자료를 열지 못했습니다: ${error.message}`)); }
  }
}

const queuePhaseLabels = {
  queued: '대기', preparing: '환경 준비', static_review: 'Codex 정적 검토',
  qemu_reproduction: '2VM PoC 재현', trace_review: 'KASAN 로그 검토', finalizing: '결과 정리',
};
const queueStatusLabels = {
  pending: '검증 대기', processing: '검증 중', needs_evidence: '증거 보완 필요',
  needs_review: '추가 검토 필요', rejected: '반려', error: '오류',
};
const queueWorkerLabels = { busy: '작업 중', idle: '유휴', offline: '오프라인' };
const queuePhaseLabel = row => row.phase ? queuePhaseLabels[row.phase] || row.phase : '검증 중';
const queueSubmitter = row => row.origin === 'manual_upload' ? `직접 제출 · ${row.reporter || '표시명 없음'}` : row.agent_id;

function renderQueueTable(id, rows, columns, emptyMessage) {
  const container = $(id);
  clear(container);
  if (!rows.length) { container.append(element('div', 'table-empty', emptyMessage)); return; }
  const table = element('table', 'queue-table');
  const head = element('thead');
  const heading = element('tr');
  for (const [label] of columns) heading.append(element('th', '', label));
  head.append(heading);
  const body = element('tbody');
  for (const row of rows) {
    const tr = element('tr');
    for (const [, value, className] of columns) tr.append(element('td', className || '', value(row) || '—'));
    body.append(tr);
  }
  table.append(head, body);
  container.append(table);
}

function renderVerificationQueue() {
  for (const id of ['queue-stats', 'queue-workers', 'queue-active', 'queue-pending', 'queue-blocked']) clear($(id));
  if (state.queueError) {
    $('queue-updated').textContent = '조회 실패';
    $('queue-worker-count').textContent = '';
    for (const id of ['queue-active-count', 'queue-pending-count', 'queue-blocked-count']) $(id).textContent = '';
    const message = element('div', 'table-empty queue-error', `검증 큐를 불러오지 못했습니다: ${state.queueError.message}`);
    message.setAttribute('role', 'alert');
    $('queue-active').append(message);
    return;
  }
  const queue = state.queue;
  if (!queue) return;
  $('queue-updated').textContent = `마지막 확인 ${when(queue.fetched_at)}`;
  for (const [label, count, tone] of [
    ['검증 중', queue.counts.processing, 'accent'],
    ['검증 대기', queue.counts.pending, ''],
    ['반려 · 보완 · 오류', queue.counts.blocked, ''],
  ]) {
    const item = element('div', `strip-stat ${tone}`);
    item.append(element('span', '', label), element('strong', '', number(count)));
    $('queue-stats').append(item);
  }
  $('queue-worker-count').textContent = `${number(queue.workers.length)}개`;
  for (const [id, count] of [['queue-active-count', queue.active.length], ['queue-pending-count', queue.pending.length], ['queue-blocked-count', queue.blocked.length]]) $(id).textContent = `${number(count)}건`;
  if (queue.blocked_has_more) $('queue-blocked-count').textContent = `최근 ${number(queue.blocked.length)}건 · 전체 ${number(queue.counts.blocked)}건`;
  if (!queue.workers.length) $('queue-workers').append(element('p', 'coverage-agent-empty', '연결된 검증 에이전트가 없습니다.'));
  for (const worker of queue.workers) {
    const card = element('div', 'queue-worker-card');
    const head = element('div', 'queue-worker-heading');
    const primitive = worker.role === 'primitive';
    const track = (state.data?.tracks || []).find(item => item.repo_commit === worker.target_commit);
    const target = primitive ? '프리미티브 검토'
      : track ? `${track.label || track.track_id} · ${track.version_id}`
        : worker.target_commit ? `커밋 ${worker.target_commit.slice(0, 12)}` : '대상 커밋 없음';
    head.append(element('strong', 'queue-worker-target', target));
    head.append(element('span', `queue-badge ${worker.status || ''}`, queueWorkerLabels[worker.status] || worker.status || '상태 알 수 없음'));
    card.append(head);
    const current = queue.active.find(row => row.submission_id === worker.current_submission_id);
    const currentId = primitive ? worker.current_finding_id : worker.current_submission_id;
    const currentTitle = primitive
      ? [worker.current_management_id, worker.current_title].filter(Boolean).join(' · ') || currentId
      : current?.title || currentId;
    if (currentId) card.append(element('div', 'queue-worker-current', `${worker.status === 'offline' ? '마지막 담당' : '담당'} · ${currentTitle}`));
    if (primitive) card.append(element('div', 'queue-worker-meta', `대기 ${number(worker.pending_count)}건`));
    card.append(element('div', 'queue-worker-meta', `워커 ${worker.worker_id ? worker.worker_id.slice(0, 12) : '—'}`));
    if (!primitive) card.append(element('div', 'queue-worker-meta', `커널 ${worker.target_commit || '—'}`));
    card.append(element('div', 'queue-worker-meta', `마지막 응답 ${when(worker.last_seen_at)}`));
    $('queue-workers').append(card);
  }
  if (queue.primitive) {
    const board = element('section', 'queue-primitive-board');
    board.setAttribute('aria-label', '프리미티브 추가 검토 현황');
    board.append(element('strong', 'queue-primitive-title', '프리미티브 추가 검토'));
    const columns = element('div', 'queue-primitive-columns');
    for (const [key, label, count] of [
      ['pending', '대기', queue.primitive.counts.pending],
      ['active', '진행 중', queue.primitive.counts.processing],
      ['errors', '오류', queue.primitive.counts.error],
    ]) {
      const column = element('section', 'queue-primitive-column');
      column.append(element('h3', '', `${label} · ${number(count)}건`));
      for (const row of queue.primitive[key]) {
        const item = element('div', 'queue-primitive-item');
        item.append(element('strong', '', row.management_id || row.finding_id.slice(0, 12)), element('span', '', row.title || '제목 없음'));
        if (key === 'errors' && row.summary) item.append(element('small', '', row.summary));
        column.append(item);
      }
      columns.append(column);
    }
    board.append(columns);
    $('queue-workers').append(board);
  }
  const title = row => `${row.project || '대상 미입력'} · ${row.title || '제목 없음'} (${row.submission_id})`;
  renderQueueTable('queue-active', queue.active, [
    ['취약점', title, 'queue-title-cell'], ['제보자', queueSubmitter],
    ['검증 단계', row => `${queuePhaseLabel(row)}${row.stale ? ' · 응답 지연' : ''}`],
    ['상태', row => queueStatusLabels[row.status] || row.status],
    ['단계 갱신', row => when(row.phase_updated_at)], ['대상 커밋', row => row.target_commit, 'queue-commit'],
  ], '현재 검증 중인 신규 제출이 없습니다.');
  renderQueueTable('queue-pending', queue.pending, [
    ['순서', row => row.position, 'queue-position'], ['취약점', title, 'queue-title-cell'],
    ['제보자', queueSubmitter], ['대상 커밋', row => row.target_commit, 'queue-commit'],
    ['제출 시각', row => when(row.submitted_at)],
  ], '검증을 기다리는 신규 제출이 없습니다.');
  renderQueueTable('queue-blocked', queue.blocked, [
    ['취약점', title, 'queue-title-cell'], ['상태', row => queueStatusLabels[row.status] || row.status],
    ['사유', row => row.reason, 'queue-reason'], ['제보자', queueSubmitter],
    ['대상 커밋', row => row.target_commit, 'queue-commit'],
  ], '반려되거나 보완·재시도가 필요한 신규 제출이 없습니다.');
}

async function loadVerificationQueue() {
  const id = ++state.queueRequestId;
  try {
    const queue = await api('/api/verification-queue').then(response => response.json());
    if (![queue.active, queue.pending, queue.blocked, queue.workers].every(Array.isArray) || !queue.counts) throw new Error('검증 큐 응답 형식이 올바르지 않습니다.');
    if (id !== state.queueRequestId) return;
    state.queue = { ...queue, fetched_at: new Date().toISOString() };
    state.queueError = null;
  } catch (error) {
    if (id !== state.queueRequestId) return;
    state.queue = null;
    state.queueError = error;
  }
  renderVerificationQueue();
}

const patchStatusLabels = {
  pending: '검토 대기', processing: 'Sashiko 검토 중', reviewed: 'Sashiko 검토 완료',
  findings: '검토 의견 있음', error: '검토 오류', unconfigured: 'Sashiko 미설정',
};
let patchFinding = null;
let patchTargets = [];
let patchSubmitting = false;

function renderPatchView() {
  const findings = (state.registry?.findings || []).filter(item => item.management_id && item.target === 'knfsd')
    .sort((a, b) => a.management_id.localeCompare(b.management_id, 'ko', { numeric: true }));
  const search = $('patch-search').value.trim().toLowerCase();
  const filtered = findings.filter(item => !search || `${item.management_id} ${item.title} ${item.owner || ''}`.toLowerCase().includes(search));
  $('patch-count').textContent = `${number(filtered.length)} / ${number(findings.length)}건`;
  $('patch-error').hidden = !state.patchError;
  $('patch-error').textContent = state.patchError ? `패치 검토 현황을 불러오지 못했습니다: ${state.patchError.message}` : '';
  const latest = new Map();
  for (const review of [...(state.patchReviews || [])].sort((a, b) => String(b.submitted_at).localeCompare(String(a.submitted_at)))) {
    if (!latest.has(review.management_id)) latest.set(review.management_id, review);
  }
  const container = $('patch-list');
  clear(container);
  if (!filtered.length) {
    container.append(element('div', 'table-empty', findings.length ? '조건에 맞는 취약점이 없습니다.' : '등록된 취약점이 없습니다.'));
    return;
  }
  const table = element('table', 'queue-table patch-table');
  const head = element('thead');
  const heading = element('tr');
  for (const label of ['관리 번호', '취약점 명', '최근 패치', 'Sashiko 결과', '제출 시각', '작업']) heading.append(element('th', '', label));
  head.append(heading);
  const body = element('tbody');
  for (const finding of filtered) {
    const review = latest.get(finding.management_id);
    const row = element('tr');
    row.append(element('td', 'patch-id', finding.management_id));
    const titleCell = element('td', 'queue-title-cell');
    const title = element('button', 'finding-title', finding.title);
    title.type = 'button';
    title.addEventListener('click', () => openFinding(finding));
    titleCell.append(title);
    row.append(titleCell);
    row.append(element('td', 'path', review?.filename || '—'));
    row.append(element('td', '', review ? patchStatusLabels[review.status] || review.status : '미제출'));
    row.append(element('td', '', review ? when(review.submitted_at) : '—'));
    const actions = element('td', 'patch-actions');
    const upload = element('button', 'row-edit-button primary', '패치 업로드');
    upload.type = 'button';
    upload.setAttribute('aria-label', `${finding.management_id} 패치 업로드`);
    upload.addEventListener('click', () => openPatchUpload(finding));
    actions.append(upload);
    if (review) {
      const result = element('a', 'row-edit-button', '결과 보기');
      result.href = `/patch-reviews/${encodeURIComponent(review.id)}`;
      result.setAttribute('aria-label', `${finding.management_id} Sashiko 결과 보기`);
      actions.append(result);
    }
    row.append(actions);
    body.append(row);
  }
  table.append(head, body);
  container.append(table);
}

async function loadPatchReviews() {
  const id = ++state.patchRequestId;
  try {
    const { reviews } = await api('/api/patch-reviews').then(response => response.json());
    if (!Array.isArray(reviews)) throw new Error('패치 검토 응답 형식이 올바르지 않습니다.');
    if (id !== state.patchRequestId) return;
    state.patchReviews = reviews;
    state.patchError = null;
  } catch (error) {
    if (id !== state.patchRequestId) return;
    state.patchError = error;
  }
  if (activeView() === 'patch') renderPatchView();
}

function patchUploadMessage(message, error = false) {
  const result = $('patch-upload-result');
  result.className = `zip-submit-result${error ? ' error' : ''}`;
  result.textContent = message;
  result.hidden = false;
}

async function openPatchUpload(finding) {
  if (patchSubmitting || activeView() !== 'patch' || finding.target !== 'knfsd') return;
  patchFinding = finding;
  patchTargets = [];
  $('patch-upload-finding').textContent = `${finding.management_id} · ${finding.title}`;
  $('patch-upload-form').reset();
  $('patch-upload-result').hidden = true;
  $('patch-track').disabled = true;
  $('patch-submit-button').disabled = true;
  $('patch-upload-dialog').showModal();
  try {
    const { targets } = await api('/api/submissions/upload-targets').then(response => response.json());
    if (!Array.isArray(targets)) throw new Error('대상 커널 목록 형식이 올바르지 않습니다.');
    if (!$('patch-upload-dialog').open || patchFinding !== finding) return;
    patchTargets = targets.filter(item => ['rc', 'mainline'].includes(item.track_id) && /^[a-f0-9]{40}$/i.test(item.repo_commit || ''));
    const select = $('patch-track');
    clear(select);
    for (const target of patchTargets) {
      const option = element('option', '', `${target.label || target.track_id} · ${target.version_id} · ${target.repo_commit.slice(0, 12)}`);
      option.value = target.track_id;
      select.append(option);
    }
    if (patchTargets.some(item => item.track_id === state.data?.selected?.track_id)) select.value = state.data.selected.track_id;
    select.disabled = !patchTargets.length;
    $('patch-submit-button').disabled = !patchTargets.length;
    if (!patchTargets.length) patchUploadMessage('검토 가능한 커널 트랙이 없습니다.', true);
  } catch (error) { patchUploadMessage(`대상 커널 조회 실패: ${error.message}`, true); }
}

async function submitPatch(event) {
  event.preventDefault();
  if (patchSubmitting || activeView() !== 'patch' || !$('patch-upload-dialog').open || !patchFinding || patchFinding.target !== 'knfsd') return;
  const file = $('patch-file').files?.[0];
  if (!file || !/\.(?:patch|diff)$/i.test(file.name)) return patchUploadMessage('.patch 또는 .diff 파일을 선택해 주세요.', true);
  if (!file.size || file.size > 1_000_000) return patchUploadMessage('패치 파일은 1 MB 이하의 비어 있지 않은 파일이어야 합니다.', true);
  const trackId = $('patch-track').value;
  if (!patchTargets.some(item => item.track_id === trackId)) return patchUploadMessage('대상 커널을 선택해 주세요.', true);
  const managementId = patchFinding.management_id;
  patchSubmitting = true;
  $('patch-submit-button').disabled = true;
  $('patch-submit-button').textContent = '제출 중…';
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let contentBase64 = '';
    for (let i = 0; i < bytes.length; i += 24_576) contentBase64 += btoa(String.fromCharCode(...bytes.subarray(i, i + 24_576)));
    const review = await api('/api/patch-reviews', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ management_id: managementId, track_id: trackId, filename: file.name, content_base64: contentBase64 }),
    }).then(response => response.json());
    $('patch-file').value = '';
    patchUploadMessage(`패치 접수 · ${patchStatusLabels[review.status] || review.status || '검토 대기'}. 결과는 이 페이지에서 자동 갱신됩니다.`);
    await loadPatchReviews();
  } catch (error) { patchUploadMessage(error.message || String(error), true); }
  finally {
    patchSubmitting = false;
    $('patch-submit-button').textContent = 'Sashiko 검토 요청';
    $('patch-submit-button').disabled = !patchTargets.length;
  }
}

const uploadStatusLabels = {
  pending: '검증 대기', processing: '검증 중', approved: '검증 완료', rejected: '반려',
  needs_evidence: '재현 자료 필요', needs_review: '추가 검토 필요', error: '검증 오류',
};
let zipSubmitting = false;
let uploadTargets = [];

async function openZipDialog() {
  if (activeView() !== 'findings') return;
  const dialog = $('zip-submit-dialog');
  if (dialog.open) return;
  $('zip-submit-result').hidden = true;
  $('zip-target').disabled = true;
  $('zip-submit-button').disabled = true;
  dialog.showModal();
  $('zip-title').focus();
  try { await loadUploadTargets(); }
  catch (error) { uploadMessage(`대상 커널 조회 실패: ${error.message}`, true); }
}

function uploadMessage(message, error = false, submissionId = '') {
  const result = $('zip-submit-result');
  result.className = `zip-submit-result${error ? ' error' : ''}`;
  result.replaceChildren(element('span', '', message));
  if (submissionId) {
    result.append(element('code', '', submissionId));
    const link = element('a', '', '검증 큐에서 보기 ↗');
    link.href = '?view=queue';
    result.append(link);
  }
  result.hidden = false;
}

async function loadUploadTargets() {
  const { targets } = await api('/api/submissions/upload-targets').then(response => response.json());
  if (!Array.isArray(targets)) throw new Error('대상 커널 목록 형식이 올바르지 않습니다.');
  const select = $('zip-target');
  const old = uploadTargets.find(item => item.track_id === select.value);
  const selected = old && targets.some(item => item.track_id === old.track_id && item.repo_commit === old.repo_commit) ? old.track_id : '';
  uploadTargets = targets;
  clear(select);
  const placeholder = element('option', '', targets.length ? '대상 커널 선택' : '설정된 대상 없음');
  placeholder.value = '';
  select.append(placeholder);
  for (const target of targets) {
    const option = element('option', '', `${target.label || target.track_id} · ${target.version_id} · ${String(target.repo_commit).slice(0, 12)}`);
    option.value = target.track_id;
    select.append(option);
  }
  select.value = selected;
  select.disabled = !targets.length || zipSubmitting;
  $('zip-submit-button').disabled = !targets.length || zipSubmitting;
  if (!targets.length) uploadMessage('검증 가능한 대상 커널이 설정되지 않았습니다.', true);
  else if (old && !selected) uploadMessage('대상 커널이 변경되었습니다. 다시 선택해 주세요.', true);
}

async function submitZip(event) {
  event.preventDefault();
  if (zipSubmitting) return;
  const title = $('zip-title').value.trim();
  const reporter = $('zip-reporter').value.trim();
  if (!title || !reporter) return uploadMessage('취약점 명과 제보자 표시명을 입력해 주세요.', true);
  const file = $('zip-file').files?.[0];
  if (!file || !/\.zip$/i.test(file.name)) return uploadMessage('ZIP 파일을 선택해 주세요.', true);
  if (!file.size || file.size > 8_000_000) return uploadMessage('ZIP은 8 MB 이하의 비어 있지 않은 파일이어야 합니다.', true);
  const trackId = $('zip-target').value;
  if (!uploadTargets.some(item => item.track_id === trackId)) return uploadMessage('대상 커널을 선택해 주세요.', true);
  zipSubmitting = true;
  $('zip-submit-button').disabled = true;
  $('zip-submit-button').textContent = '제출 중…';
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let zipBase64 = '';
    for (let i = 0; i < bytes.length; i += 24_576) zipBase64 += btoa(String.fromCharCode(...bytes.subarray(i, i + 24_576)));
    const response = await api('/api/submissions/upload', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project: 'knfsd', title, reporter, track_id: trackId, zip_base64: zipBase64 }),
    }).then(result => result.json());
    if (!/^[a-f0-9]{64}$/.test(response.submission_id || '')) throw new Error('접수 번호를 확인할 수 없습니다. 검증 큐를 확인해 주세요.');
    $('zip-submit-form').reset();
    uploadMessage(`${uploadStatusLabels[response.status] || response.status || '접수됨'} · 접수 ID `, false, response.submission_id);
  } catch (error) { uploadMessage(error.message || String(error), true); }
  finally {
    zipSubmitting = false;
    $('zip-submit-button').textContent = '검증 큐에 제출';
    $('zip-submit-button').disabled = !uploadTargets.length;
    $('zip-target').disabled = !uploadTargets.length;
  }
}

async function refresh() {
  if (state.editingFindingId) return;
  const id = ++state.refreshId;
  try {
    const query = new URLSearchParams(location.search);
    const [data, registry] = await Promise.all([
      api(`/api/dashboard?${query}`).then(response => response.json()),
      api('/api/registry').then(response => response.json()),
    ]);
    if (id !== state.refreshId || state.editingFindingId) return;
    state.data = data;
    state.registry = registry;
    renderHeader(data);
    showView();
    renderFindings();
    if (activeView() === 'patch') renderPatchView();
    if (data.selected) {
      state.coverageAgent = data.coverage_agents?.some(item => item.agent_id === query.get('agent_id')) ? query.get('agent_id') : '';
      populateCoverageAgentFilter();
      $('coverage-updated').textContent = `마지막 수집 ${when(data.metrics?.updated_at)}`;
      if (activeView() === 'coverage') await loadCoverage();
    }
    if (activeView() === 'queue') await loadVerificationQueue();
    if (activeView() === 'patch') await loadPatchReviews();
    if (activeView() === 'findings' && $('zip-submit-dialog').open) {
      loadUploadTargets().catch(error => uploadMessage(`대상 커널 조회 실패: ${error.message}`, true));
    }
    $('error').hidden = true;
    $('connection').textContent = '서버 연결됨';
    $('connection').classList.remove('offline');
  } catch (error) { if (id === state.refreshId) showError(error); }
}

$('refresh').addEventListener('click', refresh);
$('open-zip-submit').addEventListener('click', openZipDialog);
$('finding-export-csv').addEventListener('click', exportRegistryCsv);
$('close-zip-submit').addEventListener('click', () => $('zip-submit-dialog').close());
$('zip-submit-dialog').addEventListener('click', event => {
  const bounds = event.currentTarget.getBoundingClientRect();
  if (event.target === event.currentTarget && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) event.currentTarget.close();
});
$('zip-submit-form').addEventListener('submit', submitZip);
$('close-patch-upload').addEventListener('click', () => $('patch-upload-dialog').close());
$('patch-upload-dialog').addEventListener('click', event => {
  const bounds = event.currentTarget.getBoundingClientRect();
  if (event.target === event.currentTarget && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) event.currentTarget.close();
});
$('patch-upload-form').addEventListener('submit', submitPatch);
$('finding-edit-mode').addEventListener('click', () => {
  if (state.editingFindingId) return;
  state.editMode = !state.editMode;
  renderFindings();
});
$('version').addEventListener('change', () => { setQuery({ track_id: $('version').value, version_id: '', repo_commit: '', agent_id: '' }); state.coveragePage = 1; state.coverageSortKey = 'unread'; state.coverageSortDir = 'desc'; refresh(); });
for (const button of document.querySelectorAll('.tabs button')) button.addEventListener('click', () => { if (state.editingFindingId) return; setQuery({ view: button.dataset.view === 'findings' ? '' : button.dataset.view }); state.findingPage = 1; renderHeader(state.data); showView(); renderFindings(); if (button.dataset.view === 'coverage') loadCoverage().catch(showError); if (button.dataset.view === 'queue') loadVerificationQueue(); if (button.dataset.view === 'patch') { renderPatchView(); loadPatchReviews(); } });
for (const id of ['finding-search', ...findingFilters.map(([id]) => id)]) $(id).addEventListener(id === 'finding-search' ? 'input' : 'change', () => { if (state.editingFindingId) return; state.findingPage = 1; renderFindings(); });
$('patch-search').addEventListener('input', renderPatchView);
$('coverage-search').addEventListener('input', () => { state.coveragePage = 1; renderCoverage(); });
$('coverage-component').addEventListener('change', () => { state.coveragePage = 1; renderCoverage(); });
$('coverage-agent').addEventListener('change', () => {
  selectCoverageAgent($('coverage-agent').value);
});
function selectCoverageAgent(id) {
  state.coverageAgent = id;
  state.coveragePage = 1;
  state.coverageSortKey = 'unread';
  state.coverageSortDir = 'desc';
  setQuery({ agent_id: state.coverageAgent });
  populateCoverageAgentFilter();
  renderCoverageAgentSummary();
  clear($('files'));
  $('files').append(element('div', 'table-empty', '자료를 불러오는 중입니다.'));
  $('file-count').textContent = '';
  loadCoverage().catch(showError);
}
for (const button of document.querySelectorAll('[data-detail-tab]')) button.addEventListener('click', () => { state.detailTab = button.dataset.detailTab; showDetailTab(); });
$('close-detail').addEventListener('click', () => $('detail').close());
window.addEventListener('popstate', refresh);
refresh();
setInterval(refresh, 30_000);

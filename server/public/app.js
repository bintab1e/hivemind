const $ = id => document.getElementById(id);
const date = value => value ? new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)) : '—';
const node = (tag, className, value) => { const element = document.createElement(tag); if (className) element.className = className; if (value !== undefined) element.textContent = value; return element; };
const clear = element => element.replaceChildren();
const empty = (element, message) => element.append(node('p', 'placeholder', message));
const statuses = { unverified: '검증 대기', inconclusive: '미결', reported: '취약점 보고', refuted: '반박 1명', retired: '폐기 · 재시도 보류', contested: '취약점 보고·반박 충돌', stale: '커밋 변경' };
const verdicts = { supports: '지지', refutes: '반박', inconclusive: '미결' };
const kinds = { hypothesis: '가설', verification: '검증', finding: '취약점 보고', correction: '정정' };
const impactTypes = [
  ['kasan_read', 'KASAN Read'], ['kasan_write', 'KASAN Write'],
  ['controlled_read', 'Controlled Read'], ['controlled_write', 'Controlled Write'],
  ['rce', 'RCE'], ['lpe', 'LPE'], ['info_leak', 'Info Leak'],
];
const accessRequirementLabels = {
  auth_null: 'AUTH_NULL', auth_unix: 'AUTH_UNIX', rpcsec_gss: 'RPCSEC_GSS',
  authenticated_client: 'Auth Client', malicious_server: 'Malicious Server',
  local_user: 'Local User', local_privileged: 'Local Privileged',
};
const exclusionReasons = {
  worktree_dirty: '계측 대상 파일에 커밋되지 않은 변경이 있습니다.',
  scope_mismatch: '계측 범위가 기준 배치와 다릅니다.',
  file_shape_mismatch: '파일별 계측 가능 줄 구성이 기준 배치와 다릅니다.',
};
const exclusionReason = reason => exclusionReasons[reason] || '팀 병합 조건과 다릅니다.';
let refreshSequence = 0;
let coverageFileCount = 0;
let coverageAllFileCount = 0;
let missingIncludeCount = 0;
let coverageReport = null;
let reviewData = null;

async function detail(id) {
  const response = await fetch(`/api/events/${encodeURIComponent(id)}`);
  if (!response.ok) throw new Error('원본 기록을 가져오지 못했습니다.');
  const item = await response.json();
  openDetail(`${kinds[item.kind] || item.kind} · ${item.agent_id}`, item.title, item.markdown);
}

function openDetail(kind, title, content) {
  $('detail-kind').textContent = kind;
  $('detail-title').textContent = title;
  $('detail-markdown').textContent = content;
  $('detail').showModal();
}

async function findingEvidence(id, type, title) {
  const response = await fetch(`/api/events/${encodeURIComponent(id)}/${type}`);
  if (!response.ok) throw new Error('증거 파일을 가져오지 못했습니다.');
  openDetail(type === 'poc' ? 'POC SOURCE' : 'KASAN REPORT', title, await response.text());
}

function metric(label, value, sub, tone = '') {
  const card = node('article', `metric ${tone}`);
  card.append(node('div', 'label', label), node('div', 'number', value), node('div', 'sub', sub));
  return card;
}

function render(data) {
  const selected = data.selected;
  const trackSelect = $('version');
  clear(trackSelect);
  for (const track of data.tracks || []) {
    const option = node('option', '', `${track.label} · ${track.version_id || '대상 미설정'}`);
    option.value = track.track_id;
    trackSelect.append(option);
  }
  trackSelect.value = selected?.track_id || new URLSearchParams(location.search).get('track_id') || data.tracks?.find(track => track.version_id)?.track_id || 'rc';
  trackSelect.disabled = !data.tracks?.length;
  $('empty').hidden = !!selected;
  $('dashboard').hidden = !selected;
  if (!selected) {
    $('release').textContent = '—';
    $('revision').textContent = '—';
    return;
  }
  $('release').textContent = selected.version_id;
  $('revision').textContent = selected.repo_commit.slice(0, 12);
  $('report-link').href = `/api/team-status.md?${new URLSearchParams(selected)}`;

  const metrics = data.metrics;
  clear($('metrics'));
  $('metrics').append(
    metric('관측 열람률', metrics.read_percent === null ? '—' : `${metrics.read_percent}%`, '에이전트별 읽은 줄의 합집합', 'accent'),
    metric('열람된 소스 줄', metrics.read_lines.toLocaleString(), `계측 범위 ${metrics.total_lines.toLocaleString()}줄`),
    metric('미열람 소스 줄', metrics.unread_lines.toLocaleString(), '추가 조사 후보'),
    metric('중복 열람 줄', metrics.overlap_lines.toLocaleString(), '2개 이상 에이전트가 관측'),
    metric('의견 충돌', metrics.contested_count.toLocaleString(), `전체 가설 ${metrics.hypothesis_count}개`, metrics.contested_count ? 'warn' : ''),
    metric('폐기 상태', (metrics.retired_count || 0).toLocaleString(), '현재 커밋에서 서로 다른 에이전트 2명 반박'),
  );

  clear($('agents'));
  const coverageByAgent = new Map(data.coverage_agents.map(agent => [agent.agent_id, agent]));
  for (const agent of data.agents) {
    const coverage = coverageByAgent.get(agent.agent_id);
    const row = node('div', 'agent-row');
    const head = node('div', 'agent-head');
    const stats = node('span', 'agent-stats');
    stats.append(node('strong', '', coverage?.read_percent == null ? '—' : `${coverage.read_percent}%`), document.createTextNode(` · ${agent.read_lines.toLocaleString()}/${coverage?.total_lines.toLocaleString() || '—'}줄 · 고유 ${agent.unique_lines.toLocaleString()}줄`));
    head.append(node('span', 'agent-name', agent.agent_id), stats);
    row.append(head, node('div', 'agent-sub', `마지막 보고 ${date(agent.generated_at)}${agent.last_seen_at ? ` · 최근 서버 통신 ${date(agent.last_seen_at)}` : ''}${coverage?.using_clean_fallback ? ' · 직전 정상 배치 사용' : ''}`));
    $('agents').append(row);
  }
  if (!data.agents.length) empty($('agents'), '병합 가능한 에이전트 자료가 없습니다.');
  const excludedCoverage = data.coverage_agents.filter(agent => !agent.included_in_team);
  const fallbackCoverage = data.coverage_agents.filter(agent => agent.using_clean_fallback);
  $('exclusions').textContent = [
    excludedCoverage.length ? `병합 제외: ${excludedCoverage.map(agent => `${agent.agent_id} · ${exclusionReason(agent.exclusion_reason)}`).join(' / ')}` : '',
    fallbackCoverage.length ? `최근 변경 중 배치를 제외하고 직전 정상 배치 사용: ${fallbackCoverage.map(agent => agent.agent_id).join(', ')}` : '',
  ].filter(Boolean).join(' / ');

  reviewData = data;
  if (new URLSearchParams(location.search).get('view') === 'reviews') renderReviews(data);
  if (new URLSearchParams(location.search).get('view') === 'findings') renderFindings(data);

  clear($('progress'));
  for (const [key, label] of Object.entries({ todo: '대기', in_progress: '진행 중', blocked: '차단', done: '완료' })) {
    const item = node('div', 'progress-item');
    item.append(node('strong', '', String(data.progress[key] || 0)), node('span', '', label));
    $('progress').append(item);
  }

  clear($('recent'));
  for (const event of data.recent) {
    const row = node('div', 'recent-row');
    const title = node('button', 'recent-title', event.title);
    title.type = 'button';
    title.addEventListener('click', () => detail(event.id).catch(showError));
    row.append(title, node('div', 'recent-meta', `${kinds[event.kind] || event.kind} · ${event.agent_id} · ${date(event.received_at)}`));
    $('recent').append(row);
  }
  if (!data.recent.length) empty($('recent'), '아직 기록이 없습니다.');
  $('updated').textContent = date(metrics.updated_at);
}

function selectHypothesis(id) {
  const query = new URLSearchParams(location.search);
  query.set('hypothesis_id', id);
  history.replaceState(null, '', `?${query}`);
  renderReviews(reviewData);
}

function renderReviews(data) {
  const search = $('hypothesis-search').value.trim().toLowerCase();
  const hypotheses = data.hypotheses.filter(item => `${item.title} ${item.claim_key || ''} ${item.scope.join(' ')} ${(item.code_refs || []).join(' ')}`.toLowerCase().includes(search));
  const selectedId = new URLSearchParams(location.search).get('hypothesis_id');
  const selected = hypotheses.find(item => item.id === selectedId);
  if (selectedId && !selected) {
    const query = new URLSearchParams(location.search);
    query.delete('hypothesis_id');
    history.replaceState(null, '', `?${query}`);
  }
  $('hypothesis-count').textContent = search ? `${hypotheses.length}/${data.hypotheses.length}건` : `${data.hypotheses.length}건`;
  clear($('hypotheses'));
  for (const hypothesis of hypotheses) {
    const row = node('div', `hyp-row${hypothesis.id === selected?.id ? ' selected' : ''}`);
    const choose = node('button', 'hyp-select');
    choose.type = 'button';
    choose.setAttribute('aria-pressed', String(hypothesis.id === selected?.id));
    choose.addEventListener('click', () => selectHypothesis(hypothesis.id));
    const left = node('span');
    const stats = node('span', 'hyp-stats');
    const counts = [['반박', `${hypothesis.refutation_count}/2명`], ['검증', `${hypothesis.checks.length}건`]];
    if (hypothesis.finding_count) counts.push(['취약점 보고', `${hypothesis.finding_count}건`]);
    for (const [label, count] of counts) {
      const stat = node('span', 'hyp-stat', `${label} `);
      stat.append(node('strong', '', count));
      stats.append(stat);
    }
    left.append(node('span', 'hyp-title', hypothesis.title), stats);
    choose.append(left, node('span', `badge ${hypothesis.status}`, statuses[hypothesis.status] || hypothesis.status));
    const source = node('button', 'source-link', '가설 원문 보기');
    source.type = 'button';
    source.addEventListener('click', () => detail(hypothesis.event_id).catch(showError));
    row.append(choose, source);
    if (hypothesis.finding_count) {
      const finding = node('button', 'source-link', '취약점 보고 보기');
      finding.type = 'button';
      finding.addEventListener('click', () => {
        const query = new URLSearchParams(location.search);
        query.set('view', 'findings');
        query.set('hypothesis_id', hypothesis.id);
        history.replaceState(null, '', `?${query}`);
        refresh();
      });
      row.append(finding);
    }
    $('hypotheses').append(row);
  }
  if (!hypotheses.length) empty($('hypotheses'), search ? '검색과 일치하는 가설이 없습니다.' : '등록된 가설이 없습니다.');

  $('selected-hypothesis').textContent = selected ? `${selected.id} · ${selected.title}` : '왼쪽에서 가설을 선택하세요.';
  const verifications = selected ? data.verifications.filter(item => item.hypothesis_id === selected.id) : [];
  $('verification-count').textContent = selected ? `${verifications.length}건` : '—';
  clear($('verifications'));
  for (const verification of verifications) {
    const row = node('div', 'hyp-row');
    const top = node('div', 'hyp-top');
    const left = node('div');
    const title = node('button', 'hyp-title', verification.title);
    title.type = 'button';
    title.addEventListener('click', () => detail(verification.event_id).catch(showError));
    left.append(title, node('div', 'hyp-id', `${verification.agent_id} · ${date(verification.created_at)}`), node('div', 'verification-method', `${verification.method} · ${(verification.code_refs || []).join(', ')}`));
    top.append(left, node('span', `badge ${verification.verdict}`, verdicts[verification.verdict] || verification.verdict));
    row.append(top);
    $('verifications').append(row);
  }
  if (selected && !verifications.length) empty($('verifications'), '이 가설의 현재 코드 기준점 검증 기록이 없습니다.');
  if (!selected) empty($('verifications'), '가설을 선택하면 해당 검증 기록이 나타납니다.');
}

function renderFindings(data) {
  const selectedId = new URLSearchParams(location.search).get('hypothesis_id');
  const findings = selectedId ? (data.findings || []).filter(item => item.hypothesis_id === selectedId) : data.findings || [];
  const excluded = !selectedId && data.excluded_finding_count ? ` · 비독립 PoC ${data.excluded_finding_count}건 제외` : '';
  $('finding-count').textContent = `${findings.length}건${selectedId ? ' · 선택한 가설' : excluded}`;
  clear($('findings'));
  if (selectedId) {
    const all = node('button', 'source-link', '전체 취약점 보고 보기');
    all.type = 'button';
    all.addEventListener('click', () => {
      const query = new URLSearchParams(location.search);
      query.delete('hypothesis_id');
      history.replaceState(null, '', `?${query}`);
      renderFindings(data);
    });
    $('findings').append(all);
  }
  const table = node('div', 'impact-table');
  table.setAttribute('role', 'table');
  table.setAttribute('aria-label', '취약점별 검증된 영향');
  const tableHead = node('div', 'impact-table-row impact-table-head');
  tableHead.setAttribute('role', 'row');
  const reportHead = node('div', 'impact-header-cell', '취약점 보고');
  reportHead.setAttribute('role', 'columnheader');
  tableHead.append(reportHead);
  const accessHead = node('div', 'impact-header-cell', '접근 조건');
  accessHead.setAttribute('role', 'columnheader');
  tableHead.append(accessHead);
  for (const [, label] of impactTypes) {
    const cell = node('div', 'impact-header-cell', label);
    cell.setAttribute('role', 'columnheader');
    tableHead.append(cell);
  }
  table.append(tableHead);
  for (const finding of findings) {
    const row = node('div', 'impact-table-row finding-impact-row');
    row.setAttribute('role', 'row');
    const report = node('div', 'finding-report-cell');
    report.setAttribute('role', 'cell');
    const head = node('div', 'finding-head');
    const title = node('button', 'hyp-title', finding.title);
    title.type = 'button';
    title.addEventListener('click', () => detail(finding.event_id).catch(showError));
    head.append(title);
    const actions = node('div', 'finding-actions');
    const poc = node('button', 'evidence-button', 'PoC 보기');
    poc.type = 'button';
    poc.addEventListener('click', () => findingEvidence(finding.event_id, 'poc', finding.title).catch(showError));
    const kasanButton = node('button', 'evidence-button', 'KASAN 보기');
    kasanButton.type = 'button';
    kasanButton.addEventListener('click', () => findingEvidence(finding.event_id, 'kasan', finding.title).catch(showError));
    const hypothesis = node('button', 'source-link', '가설·검증 보기');
    hypothesis.type = 'button';
    hypothesis.addEventListener('click', () => {
      const query = new URLSearchParams(location.search);
      query.set('view', 'reviews');
      query.set('hypothesis_id', finding.hypothesis_id);
      history.replaceState(null, '', `?${query}`);
      refresh();
    });
    const source = node('button', 'source-link', '보고 원문 보기');
    source.type = 'button';
    source.addEventListener('click', () => detail(finding.event_id).catch(showError));
    actions.append(poc, kasanButton, hypothesis, source);
    report.append(head, actions);
    row.append(report);
    const access = node('div', 'access-cell');
    access.setAttribute('role', 'cell');
    const requirements = finding.access_requirements || [];
    if (requirements.length) {
      access.append(node('span', 'access-value', requirements.map(requirement => accessRequirementLabels[requirement] || requirement).join(' · ')));
    } else {
      access.append(node('span', 'access-unclassified', '미분류'));
    }
    row.append(access);
    const verified = new Set(finding.verified_impacts || []);
    for (const [type, label] of impactTypes) {
      const active = verified.has(type);
      const cell = node('div', `impact-result-cell${active ? ' verified' : ''}`, active ? '✓' : '—');
      cell.setAttribute('role', 'cell');
      cell.setAttribute('aria-label', `${label} ${active ? '검증됨' : '미검증'}`);
      cell.title = `${label} · ${active ? '검증됨' : '미검증'}`;
      row.append(cell);
    }
    table.append(row);
  }
  if (findings.length) $('findings').append(table);
  if (!findings.length) empty($('findings'), '이 버전·코드 기준점에 독립 사용자 공간 C PoC와 KASAN 로그까지 제출된 취약점 보고가 없습니다.');
}

function showView(view) {
  $('overview-view').hidden = view !== 'overview';
  $('coverage-view').hidden = view !== 'coverage';
  $('reviews-view').hidden = view !== 'reviews';
  $('findings-view').hidden = view !== 'findings';
  for (const button of document.querySelectorAll('.tabs button')) {
    if (button.dataset.view === view) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
}

function renderAgentChoices(data, selectedAgent) {
  clear($('coverage-agents'));
  const choices = [{ agent_id: '', read_lines: data.metrics.read_lines, total_lines: data.metrics.total_lines, read_percent: data.metrics.read_percent, included_in_team: true }, ...data.coverage_agents];
  for (const agent of choices) {
    const button = node('button', 'coverage-choice');
    button.type = 'button';
    button.setAttribute('aria-pressed', String(agent.agent_id === selectedAgent));
    const bar = node('div', 'bar');
    const fill = node('span');
    fill.style.width = `${agent.read_percent || 0}%`;
    bar.append(fill);
    button.append(
      node('span', 'choice-name', agent.agent_id || '전체 합집합'),
      node('strong', '', agent.read_percent == null ? '—' : `${agent.read_percent}%`),
      node('span', 'choice-meta', `${agent.read_lines.toLocaleString()}/${agent.total_lines.toLocaleString()}줄 관측${agent.included_in_team ? '' : ' · 병합 제외'}${agent.using_clean_fallback ? ' · 직전 정상 배치' : ''}`),
      bar,
    );
    button.addEventListener('click', () => {
      const query = new URLSearchParams(location.search);
      query.set('view', 'coverage');
      if (agent.agent_id) query.set('agent_id', agent.agent_id);
      else query.delete('agent_id');
      history.replaceState(null, '', `?${query}`);
      refresh();
    });
    $('coverage-agents').append(button);
  }
}

function filterFiles() {
  const query = $('coverage-search').value.trim().toLowerCase();
  const scope = $('coverage-scope').value;
  let visible = 0;
  for (const row of $('files').children) {
    if (!row.dataset.path) continue;
    row.hidden = !row.dataset.path.includes(query);
    if (!row.hidden) visible++;
  }
  const count = query ? `${visible}/${coverageFileCount}` : scope ? `${coverageFileCount}/${coverageAllFileCount}` : String(coverageFileCount);
  $('file-count').textContent = `${count} files · ${scope ? '전체 범위 ' : ''}미확인 include ${missingIncludeCount}개`;
}

function renderCoverage(report) {
  coverageReport = report;
  const scope = $('coverage-scope').value;
  const files = scope ? report.files.filter(file => file.path.startsWith(scope)) : report.files;
  const totalLines = files.reduce((sum, file) => sum + file.total, 0);
  const readLines = files.reduce((sum, file) => sum + file.read, 0);
  const readFiles = files.filter(file => file.read > 0).length;
  const readPercent = totalLines ? Math.round(readLines / totalLines * 1000) / 10 : null;
  coverageAllFileCount = report.files.length;
  coverageFileCount = files.length;
  missingIncludeCount = report.metrics.missing_includes || 0;
  clear($('coverage-metrics'));
  $('coverage-metrics').append(
    metric('관측 열람률', readPercent === null ? '—' : `${readPercent}%`, `${report.agent_id || '팀 합집합'} · ${scope || '전체 범위'}`, 'accent'),
    metric('열람된 소스 줄', readLines.toLocaleString(), `선택 범위 ${totalLines.toLocaleString()}줄`),
    metric('열람된 파일', readFiles.toLocaleString(), `선택 범위 ${files.length.toLocaleString()}개 파일`),
    metric('미열람 소스 줄', (totalLines - readLines).toLocaleString(), '추가 조사 후보'),
  );
  $('coverage-exclusion').hidden = report.included_in_team && !report.using_clean_fallback;
  $('coverage-exclusion').textContent = report.using_clean_fallback ? '최근 변경 중 배치를 제외하고 직전 정상 배치를 표시합니다.' : report.included_in_team ? '' : `병합 제외 · ${exclusionReason(report.exclusion_reason)}`;
  clear($('files'));
  for (const file of files) {
    const row = node('div', 'file-row');
    row.dataset.path = file.path.toLowerCase();
    const info = node('div');
    const name = node('div', 'file-name', file.path);
    name.title = file.path;
    info.append(name, node('div', 'file-meta', report.agent_id ? `${file.read}/${file.total}줄 관측` : `${file.read}/${file.total}줄 · ${file.agents}명 관측`));
    const bar = node('div', 'bar');
    const fill = node('span');
    fill.style.width = `${file.percent}%`;
    bar.append(fill);
    row.append(info, bar, node('span', 'percent', `${file.percent}%`));
    $('files').append(row);
  }
  if (!files.length) empty($('files'), report.files.length ? '선택한 범위에 파일이 없습니다.' : '아직 agentcov 자료가 없습니다.');
  filterFiles();
}

function showError(error) { $('error').textContent = error.message; $('error').hidden = false; $('connection').textContent = '연결 오류'; }

async function refresh() {
  const sequence = ++refreshSequence;
  try {
    const query = new URLSearchParams(location.search);
    const response = await fetch(`/api/dashboard?${query}`);
    if (!response.ok) throw new Error(`현황을 가져오지 못했습니다. (${response.status})`);
    const data = await response.json();
    if (sequence !== refreshSequence) return;
    render(data);
    const requestedView = query.get('view');
    const view = ['coverage', 'reviews', 'findings'].includes(requestedView) ? requestedView : 'overview';
    showView(view);
    if (view === 'coverage' && data.selected) {
      const requestedAgent = query.get('agent_id') || '';
      const agentId = data.coverage_agents.some(agent => agent.agent_id === requestedAgent) ? requestedAgent : '';
      renderAgentChoices(data, agentId);
      let report;
      if (agentId) {
        const params = new URLSearchParams({ ...data.selected, agent_id: agentId });
        const coverageResponse = await fetch(`/api/coverage?${params}`);
        if (!coverageResponse.ok) throw new Error(`에이전트 열람 자료를 가져오지 못했습니다. (${coverageResponse.status})`);
        report = await coverageResponse.json();
      } else {
        report = { agent_id: null, included_in_team: true, files: data.files, metrics: { ...data.metrics, read_files: data.files.filter(file => file.read > 0).length } };
      }
      if (sequence !== refreshSequence) return;
      renderCoverage(report);
    }
    $('error').hidden = true;
    $('connection').textContent = '서버 연결됨';
  } catch (error) { if (sequence === refreshSequence) showError(error); }
}

$('version').addEventListener('change', () => {
  const query = new URLSearchParams(location.search);
  query.set('track_id', $('version').value);
  query.delete('version_id');
  query.delete('repo_commit');
  query.delete('agent_id');
  query.delete('hypothesis_id');
  history.replaceState(null, '', `?${query}`);
  refresh();
});
for (const button of document.querySelectorAll('.tabs button')) button.addEventListener('click', () => {
  const query = new URLSearchParams(location.search);
  query.set('view', button.dataset.view);
  if (button.dataset.view === 'findings') query.delete('hypothesis_id');
  history.replaceState(null, '', `?${query}`);
  refresh();
});
$('coverage-search').addEventListener('input', filterFiles);
$('coverage-scope').addEventListener('change', () => { if (coverageReport) renderCoverage(coverageReport); });
$('hypothesis-search').addEventListener('input', () => { if (reviewData) renderReviews(reviewData); });
$('close-detail').addEventListener('click', () => $('detail').close());
window.addEventListener('popstate', refresh);
refresh();
setInterval(refresh, 30_000);

const $ = id => document.getElementById(id);
const make = (tag, className = '', value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
};
const words = (value, fallback = '—') => typeof value === 'string' && value.trim() ? value : fallback;
const count = value => Number(value || 0).toLocaleString('ko-KR');
const when = value => {
  const date = value && new Date(value);
  return date && !Number.isNaN(date.valueOf())
    ? new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(date) : '—';
};
const reviewLabels = {
  pending: '검토 대기', processing: 'Sashiko 검토 중', reviewed: '검토 완료',
  findings: '지적 사항 있음', error: '검토 오류', unconfigured: 'Sashiko 미설정',
};
const resultLabels = { clean: '지적 사항 없음', issues_found: '지적 사항 있음', error: '검토 오류' };
const applyLabels = { applied: '적용됨', present: '기준 트리에 있음', failed: '적용 실패', error: '적용 오류' };

async function request(path) {
  const response = await fetch(path);
  if (!response.ok) {
    let message = `요청 실패 (${response.status})`;
    try { message = (await response.json()).error || message; } catch { /* non-JSON response */ }
    throw new Error(message);
  }
  return response;
}

function fact(list, label, value) {
  const item = make('div', 'patch-page-fact');
  item.append(make('dt', '', label), make('dd', '', value));
  list.append(item);
}

const severityName = value => {
  const name = words(value, 'Unknown').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(name) ? name : 'unknown';
};

function locations(card, items) {
  if (!Array.isArray(items)) return;
  for (const location of items) {
    const box = make('div', 'patch-review-location');
    const line = Number.isInteger(location?.line) && location.line > 0 ? `:${location.line}` : '';
    const symbol = words(location?.function_or_symbol, '');
    box.append(make('strong', '', `${words(location?.file, '위치 미상')}${line}${symbol ? ` · ${symbol}` : ''}`));
    if (words(location?.code_snippet, '')) box.append(make('pre', '', location.code_snippet));
    if (words(location?.why_this_location_matters, '')) box.append(make('p', '', location.why_this_location_matters));
    card.append(box);
  }
}

function renderItems(container, items, concern = false, incomplete = false) {
  if (!items.length) {
    container.append(make('p', 'patch-page-empty', incomplete ? '검토가 완료되면 표시됩니다.'
      : concern ? '추가 우려 사항이 없습니다.' : 'Sashiko 지적 사항이 없습니다.'));
    return;
  }
  for (const [index, item] of items.entries()) {
    const card = make('article', `patch-review-card severity-${severityName(concern ? item?.estimated_severity : item?.severity)}`);
    card.id = `${concern ? 'review-concern' : 'review-finding'}-${index + 1}`;
    const heading = make('div', 'patch-review-head');
    heading.append(make('span', 'patch-review-number', `${concern ? '우려' : '지적'} ${index + 1}`));
    heading.append(make('strong', '', words(concern ? item?.description : item?.problem,
      words(item?.title, `${concern ? '추가 우려' : '지적 사항'} ${index + 1}`))));
    const severity = words(concern ? item?.estimated_severity : item?.severity, '');
    if (severity) heading.append(make('span', `patch-review-tag severity-${severityName(severity)}`, severity));
    if (concern && words(item?.type, '')) heading.append(make('span', 'patch-review-tag', item.type));
    if (item?.preexisting === true) heading.append(make('span', 'patch-review-tag', '패치 이전부터 존재'));
    card.append(heading);
    const explanation = words(concern ? item?.reasoning : item?.severity_explanation,
      words(item?.explanation, ''));
    if (explanation) card.append(make('p', 'patch-review-explanation', explanation));
    if (concern && words(item?.verification_question, '')) {
      card.append(make('p', 'patch-review-explanation', `확인할 질문: ${item.verification_question}`));
    }
    locations(card, item?.locations);
    container.append(card);
  }
}

function reviewAnnotations(findings, concerns) {
  const annotations = [];
  for (const [items, concern] of [[findings, false], [concerns, true]]) {
    for (const [index, item] of items.entries()) {
      for (const [locationIndex, location] of (Array.isArray(item?.locations) ? item.locations : []).entries()) {
        if (typeof location?.file !== 'string' || !Number.isInteger(location.line) || location.line < 1) continue;
        annotations.push({
          id: `${concern ? 'concern' : 'finding'}-${index}-${locationIndex}`,
          file: location.file.replace(/^[ab]\//, ''), line: location.line,
          target: `${concern ? 'review-concern' : 'review-finding'}-${index + 1}`,
          label: `${concern ? '추가 우려' : '지적 사항'} ${index + 1}`,
          title: words(concern ? item?.description : item?.problem, words(item?.title, '검토 의견')),
          severity: words(concern ? item?.estimated_severity : item?.severity, ''),
          explanation: words(concern ? item?.reasoning : item?.severity_explanation,
            words(item?.explanation, '')),
          why: words(location.why_this_location_matters, ''),
          snippet: words(location.code_snippet, ''),
        });
      }
    }
  }
  return annotations;
}

function inlineNote(note) {
  const box = make('aside', `patch-inline-note severity-${severityName(note.severity)}`);
  const head = make('div', 'patch-inline-note-head');
  const link = make('a', '', `${note.label} · ${note.title}`);
  link.href = `#${note.target}`;
  head.append(link);
  if (note.severity) head.append(make('span', `patch-review-tag severity-${severityName(note.severity)}`, note.severity));
  box.append(head);
  if (note.explanation) box.append(make('p', '', note.explanation));
  if (note.why && note.why !== note.explanation) box.append(make('p', 'patch-inline-why', note.why));
  return box;
}

function renderDiff(patch, findings, concerns) {
  const viewer = make('div', 'patch-diff');
  const byLine = new Map();
  for (const note of reviewAnnotations(findings, concerns)) {
    const key = `${note.file}:${note.line}`;
    if (!byLine.has(key)) byLine.set(key, []);
    byLine.get(key).push(note);
  }
  const placed = new Set();
  let file = '';
  let block = null;
  let oldLine = 0;
  let newLine = 0;
  let inHunk = false;
  const lines = patch.replace(/\r\n/g, '\n').split('\n');
  if (lines.at(-1) === '') lines.pop();
  for (const [index, line] of lines.entries()) {
    if (index === 8000) {
      viewer.append(make('p', 'patch-diff-truncated', '화면에는 처음 8,000줄만 표시합니다. 전체 패치는 위 파일 다운로드에서 확인할 수 있습니다.'));
      break;
    }
    const header = /^diff --git a\/(\S+) b\/(\S+)$/.exec(line);
    if (header) {
      file = header[2];
      block = make('section', 'patch-diff-file');
      block.append(make('div', 'patch-diff-file-head', file));
      viewer.append(block);
      inHunk = false;
      continue;
    }
    if (!block) {
      block = make('section', 'patch-diff-file');
      block.append(make('div', 'patch-diff-file-head', '패치 설명'));
      viewer.append(block);
    }
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    let before = '';
    let after = '';
    let kind = 'meta';
    if (hunk) {
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[2]);
      inHunk = true;
      kind = 'hunk';
    } else if (inHunk && line.startsWith('+')) {
      after = newLine++;
      kind = 'added';
    } else if (inHunk && line.startsWith('-')) {
      before = oldLine++;
      kind = 'removed';
    } else if (inHunk && line.startsWith(' ')) {
      before = oldLine++;
      after = newLine++;
      kind = 'context';
    }
    const row = make('div', `patch-diff-row ${kind}`);
    row.append(make('span', 'patch-diff-number', before), make('span', 'patch-diff-number', after),
      make('span', 'patch-diff-code', line));
    block.append(row);
    const at = after;
    if (!at || !file) continue;
    for (const note of byLine.get(`${file}:${at}`) || []) {
      const code = line.slice(1).trim();
      const matchesSnippet = code.length >= 8 && note.snippet.split(/\r?\n/).some(part => part.trim() === code);
      if (placed.has(note.id) || !matchesSnippet) continue;
      placed.add(note.id);
      block.append(inlineNote(note));
    }
  }
  return viewer;
}

async function renderReview(review, findingTitle = '') {
  const result = review.result;
  const detail = result?.review && typeof result.review === 'object' ? result.review : result;
  const findings = Array.isArray(result?.findings) ? result.findings : Array.isArray(detail?.findings) ? detail.findings : [];
  const concerns = Array.isArray(result?.concerns) ? result.concerns : Array.isArray(detail?.concerns) ? detail.concerns : [];
  const patches = Array.isArray(result?.patches) ? result.patches : [];
  const verdict = resultLabels[result?.status] || reviewLabels[review.status] || words(result?.status, '상태 확인 필요');
  $('review-title').textContent = words(patches[0]?.subject, findingTitle || `${review.management_id} 패치 검토`);
  document.title = `${review.management_id} · Sashiko 패치 검토`;
  $('review-subtitle').textContent = `${review.management_id}${findingTitle ? ` · ${findingTitle}` : ''}`;
  $('review-status').textContent = verdict;
  const status = result?.status || review.status;
  $('review-status').dataset.tone = status === 'issues_found' || status === 'findings' ? 'findings'
    : status === 'error' ? 'error' : status === 'clean' || status === 'reviewed' ? 'clean' : 'pending';

  const resultLine = make('div', 'patch-page-result-line');
  resultLine.append(make('strong', '', verdict),
    make('span', '', `지적 ${count(findings.length)}건 · 추가 우려 ${count(concerns.length)}건 · 검토 패치 ${count(patches.length)}건`));
  const severity = make('div', 'patch-page-severity');
  const bySeverity = new Map();
  for (const item of findings) {
    const label = severityName(item?.severity);
    bySeverity.set(label, (bySeverity.get(label) || 0) + 1);
  }
  for (const label of ['critical', 'high', 'medium', 'low', 'unknown']) {
    if (label === 'unknown' && !bySeverity.has(label)) continue;
    const item = make('div', `patch-page-severity-item severity-${label}`);
    item.append(make('span', '', label.toUpperCase()), make('strong', '', count(bySeverity.get(label) || 0)));
    severity.append(item);
  }
  $('review-overview').replaceChildren(resultLine, severity);

  const metadata = $('review-metadata');
  const list = make('dl', 'patch-page-facts');
  fact(list, '관리 번호', words(review.management_id));
  fact(list, '대상 트랙', words(review.track_id));
  fact(list, '패치 파일', words(review.filename));
  fact(list, '기준 커밋', words(review.base_commit));
  if (words(result?.baseline, '') && result.baseline !== review.base_commit) fact(list, 'Sashiko 기준', result.baseline);
  fact(list, '제출 시각', when(review.submitted_at));
  fact(list, '완료 시각', when(review.completed_at));
  metadata.replaceChildren(list);

  const verdictBody = $('review-verdict-body');
  verdictBody.replaceChildren();
  if (result?.partial) verdictBody.append(make('p', 'queue-error', '일부 단계만 검토되었습니다. 아래 오류를 확인해 주세요.'));
  if (words(detail?.summary, '')) verdictBody.append(make('p', 'patch-review-explanation', detail.summary));
  if (words(review.reason, '')) verdictBody.append(make('p', review.status === 'error' ? 'queue-error' : '', review.reason));
  if (result?.error) verdictBody.append(make('p', 'queue-error', String(result.error)));
  if (result == null) verdictBody.append(make('p', '', '아직 Sashiko 결과가 없습니다. 검토가 끝나면 새로고침해 주세요.'));

  $('review-findings-title').textContent = `지적 사항 · ${count(findings.length)}건`;
  $('review-concerns-title').textContent = `추가 우려 · ${count(concerns.length)}건`;
  const incomplete = result == null || result.status === 'error' || result.partial === true;
  $('review-findings-body').replaceChildren();
  $('review-concerns-body').replaceChildren();
  renderItems($('review-findings-body'), findings, false, incomplete);
  renderItems($('review-concerns-body'), concerns, true, incomplete);

  const patchBody = $('review-patches-body');
  patchBody.replaceChildren();
  if (!patches.length) patchBody.append(make('p', 'patch-page-empty', '패치 적용 기록이 없습니다.'));
  for (const [index, patch] of patches.entries()) {
    const card = make('article', 'patch-review-card');
    const head = make('div', 'patch-review-head');
    head.append(make('span', 'patch-review-number', `패치 ${patch?.index || index + 1}`),
      make('strong', '', words(patch?.subject, words(review.filename))));
    head.append(make('span', 'patch-review-tag', applyLabels[patch?.status] || words(patch?.status, '상태 미상')));
    card.append(head);
    if (words(patch?.method, '')) card.append(make('p', '', patch.method));
    if (patch?.error) card.append(make('p', 'queue-error', String(patch.error)));
    patchBody.append(card);
  }

  const filePath = `/api/patch-reviews/${encodeURIComponent(review.id)}/file`;
  const download = make('a', 'detail-link', `${words(review.filename)} 다운로드`);
  download.href = filePath;
  download.download = review.filename;
  $('review-source-actions').replaceChildren(download);
  const sourceBody = $('review-source-body');
  sourceBody.replaceChildren(make('p', 'patch-page-empty', '패치를 불러오는 중…'));

  $('review-raw-body').replaceChildren();
  if (result == null) $('review-raw-body').append(make('p', 'patch-page-empty', '아직 결과가 없습니다.'));
  else {
    if ([result.tokens_in, result.tokens_out, result.tokens_cached].some(Number.isFinite)) {
      const token = value => Number.isFinite(value) ? count(value) : '—';
      $('review-raw-body').append(make('p', 'patch-page-usage',
        `검토 사용량 · 입력 ${token(result.tokens_in)} · 출력 ${token(result.tokens_out)} · 캐시 ${token(result.tokens_cached)} 토큰`));
    }
    const raw = make('details', 'artifact-preview');
    raw.append(make('summary', '', 'Sashiko JSON 펼치기'), make('pre', '', JSON.stringify(result, null, 2)));
    $('review-raw-body').append(raw);
  }
  $('review-body').hidden = false;
  try {
    const patch = await request(filePath).then(response => response.text());
    sourceBody.replaceChildren(renderDiff(patch, findings, concerns));
  } catch (error) {
    sourceBody.replaceChildren(make('p', 'queue-error', `패치를 불러오지 못했습니다: ${error.message}`));
  }
}

async function loadReview() {
  const match = /^\/patch-reviews\/([a-f0-9]{64})$/.exec(location.pathname);
  if (!match) throw new Error('검토 결과 주소가 올바르지 않습니다.');
  const id = match[1];
  const [{ review }, registry] = await Promise.all([
    request(`/api/patch-reviews/${id}`).then(response => response.json()),
    request('/api/registry').then(response => response.json()).catch(() => null),
  ]);
  if (!review || review.id !== id) throw new Error('검토 결과 형식이 올바르지 않습니다.');
  const title = registry?.findings?.find(item => item.management_id === review.management_id)?.title;
  await renderReview(review, words(title, ''));
}

loadReview().catch(error => {
  $('review-error').textContent = `검토 결과를 열지 못했습니다: ${error.message}`;
  $('review-error').hidden = false;
  $('review-subtitle').textContent = '패치 목록에서 다른 검토 결과를 선택해 주세요.';
  $('review-status').textContent = '열기 실패';
  $('review-status').dataset.tone = 'error';
});

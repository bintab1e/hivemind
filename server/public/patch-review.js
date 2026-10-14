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

function stat(label, value, tone = '') {
  const card = make('div', `strip-stat ${tone}`.trim());
  card.append(make('span', '', label), make('strong', '', value));
  return card;
}

function fact(list, label, value) {
  list.append(make('dt', '', label), make('dd', '', value));
}

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
    const card = make('article', 'patch-review-card');
    const heading = make('div', 'patch-review-head');
    heading.append(make('strong', '', words(concern ? item?.description : item?.problem,
      words(item?.title, `${concern ? '추가 우려' : '지적 사항'} ${index + 1}`))));
    const severity = words(concern ? item?.estimated_severity : item?.severity, '');
    if (severity) heading.append(make('span', 'patch-review-tag', severity));
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

function renderReview(review, findingTitle = '') {
  const result = review.result;
  const detail = result?.review && typeof result.review === 'object' ? result.review : result;
  const findings = Array.isArray(result?.findings) ? result.findings : Array.isArray(detail?.findings) ? detail.findings : [];
  const concerns = Array.isArray(result?.concerns) ? result.concerns : Array.isArray(detail?.concerns) ? detail.concerns : [];
  const patches = Array.isArray(result?.patches) ? result.patches : [];
  const verdict = resultLabels[result?.status] || reviewLabels[review.status] || words(result?.status, '상태 확인 필요');
  $('review-title').textContent = findingTitle || `${review.management_id} 패치 검토`;
  document.title = `${review.management_id} · Sashiko 패치 검토`;
  $('review-subtitle').textContent = `${review.management_id} · ${words(review.filename)} · ${when(review.submitted_at)}`;
  $('review-status').textContent = verdict;
  const status = result?.status || review.status;
  $('review-status').dataset.tone = status === 'issues_found' || status === 'findings' ? 'findings'
    : status === 'error' ? 'error' : status === 'clean' || status === 'reviewed' ? 'clean' : 'pending';

  const totals = make('div', 'stat-strip');
  totals.append(stat('검토 판정', verdict, 'accent'), stat('지적 사항', count(findings.length)),
    stat('추가 우려', count(concerns.length)), stat('검토한 패치', count(patches.length)));
  const severity = make('div', 'patch-page-severity');
  const bySeverity = new Map();
  for (const item of findings) {
    const raw = words(item?.severity, 'Unknown');
    const label = raw[0].toUpperCase() + raw.slice(1).toLowerCase();
    bySeverity.set(label, (bySeverity.get(label) || 0) + 1);
  }
  severity.append(make('strong', '', '심각도'));
  for (const label of [...new Set(['Critical', 'High', 'Medium', 'Low', 'Unknown', ...bySeverity.keys()])]) {
    if (bySeverity.has(label)) severity.append(make('span', 'patch-review-tag', `${label} ${bySeverity.get(label)}`));
  }
  if (!bySeverity.size) severity.append(make('span', 'muted', '지적 사항 없음'));
  $('review-overview').replaceChildren(totals, severity);

  const metadata = $('review-metadata');
  const list = make('dl', 'patch-page-facts');
  fact(list, '관리 번호', words(review.management_id));
  fact(list, '검토 ID', words(review.id));
  fact(list, '파일명', words(review.filename));
  fact(list, '대상 트랙', words(review.track_id));
  fact(list, '기준 커밋', words(review.base_commit));
  if (words(result?.baseline, '') && result.baseline !== review.base_commit) fact(list, 'Sashiko 기준', result.baseline);
  fact(list, '제출 시각', when(review.submitted_at));
  fact(list, '완료 시각', when(review.completed_at));
  if ([result?.tokens_in, result?.tokens_out, result?.tokens_cached].some(Number.isFinite)) {
    const token = value => Number.isFinite(value) ? count(value) : '—';
    fact(list, '검토 사용량', `입력 ${token(result.tokens_in)} · 출력 ${token(result.tokens_out)} · 캐시 ${token(result.tokens_cached)} 토큰`);
  }
  metadata.replaceChildren(make('h2', '', '검토 정보'), list);

  const verdictBody = $('review-verdict-body');
  verdictBody.replaceChildren(make('p', 'patch-review-verdict', verdict));
  if (result?.partial) verdictBody.append(make('p', 'queue-error', '일부 단계만 검토되었습니다. 아래 오류를 확인해 주세요.'));
  if (words(detail?.summary, '')) verdictBody.append(make('p', 'patch-review-explanation', detail.summary));
  if (words(review.reason, '')) verdictBody.append(make('p', review.status === 'error' ? 'queue-error' : '', review.reason));
  if (result?.error) verdictBody.append(make('p', 'queue-error', String(result.error)));
  if (result == null) verdictBody.append(make('p', '', '아직 Sashiko 결과가 없습니다. 검토가 끝나면 새로고침해 주세요.'));

  $('review-findings-title').textContent = `지적 사항 · ${count(findings.length)}건`;
  $('review-concerns-title').textContent = `추가 우려 · ${count(concerns.length)}건`;
  const incomplete = result == null || result.status === 'error' || result.partial === true;
  renderItems($('review-findings-body'), findings, false, incomplete);
  renderItems($('review-concerns-body'), concerns, true, incomplete);

  const patchBody = $('review-patches-body');
  if (!patches.length) patchBody.append(make('p', 'patch-page-empty', '패치 적용 기록이 없습니다.'));
  for (const [index, patch] of patches.entries()) {
    const card = make('article', 'patch-review-card');
    card.append(make('strong', '', words(patch?.subject, `패치 ${patch?.index || index + 1}`)));
    card.append(make('p', '', `${applyLabels[patch?.status] || words(patch?.status, '상태 미상')}${words(patch?.method, '') ? ` · ${patch.method}` : ''}`));
    if (patch?.error) card.append(make('p', 'queue-error', String(patch.error)));
    patchBody.append(card);
  }

  const filePath = `/api/patch-reviews/${encodeURIComponent(review.id)}/file`;
  const download = make('a', 'detail-link', `${words(review.filename)} 다운로드`);
  download.href = filePath;
  download.download = review.filename;
  const source = make('details', 'artifact-preview');
  source.append(make('summary', '', '패치 내용 펼치기'));
  source.addEventListener('toggle', async () => {
    if (!source.open || source.dataset.loaded) return;
    source.dataset.loaded = 'true';
    const preview = make('pre', '', '패치 내용을 불러오는 중…');
    source.append(preview);
    try { preview.textContent = await request(filePath).then(response => response.text()); }
    catch (error) { preview.textContent = `패치 내용을 불러오지 못했습니다: ${error.message}`; }
  });
  $('review-source-body').append(download, source);

  if (result == null) $('review-raw-body').append(make('p', 'patch-page-empty', '아직 결과가 없습니다.'));
  else {
    const raw = make('details', 'artifact-preview');
    raw.append(make('summary', '', 'Sashiko JSON 펼치기'), make('pre', '', JSON.stringify(result, null, 2)));
    $('review-raw-body').append(raw);
  }
  $('review-body').hidden = false;
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
  renderReview(review, words(title, ''));
}

loadReview().catch(error => {
  $('review-error').textContent = `검토 결과를 열지 못했습니다: ${error.message}`;
  $('review-error').hidden = false;
  $('review-subtitle').textContent = '패치 목록에서 다른 검토 결과를 선택해 주세요.';
  $('review-status').textContent = '열기 실패';
  $('review-status').dataset.tone = 'error';
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('finding detail appends only available primitive review under the existing opinion', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const start = source.indexOf('function detailFact(');
  const end = source.indexOf('async function loadFindingRevisions(', start);
  assert.ok(start > 0 && end > start);

  const elements = new Map();
  const makeElement = tagName => ({
    tagName, className: '', textContent: '', children: [], listeners: {},
    classList: { add(name) { this.owner.className += ` ${name}`; } },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  for (const id of ['detail-title', 'detail-subtitle', 'detail-summary', 'detail-revision-controls']) elements.set(id, makeElement('div'));
  elements.set('detail', { open: false, querySelector: () => ({ hidden: true }), showModal() { this.open = true; } });
  const originalCreateElement = makeElement;
  const createElement = tagName => {
    const item = originalCreateElement(tagName);
    item.classList.owner = item;
    return item;
  };
  const context = {
    document: { getElementById: id => elements.get(id), createElement },
    testState: { detailId: 0 },
  };
  vm.runInNewContext(`
    const $ = id => document.getElementById(id);
    const element = (tag, className = '', text) => {
      const item = document.createElement(tag);
      item.className = className;
      if (text !== undefined) item.textContent = String(text);
      return item;
    };
    const clear = item => item.replaceChildren();
    const state = globalThis.testState;
    const when = value => value || '—';
    const isRegistered = () => true;
    const reviewLabel = () => '2VM 검증 완료';
    const agentName = id => id;
    const accessLabels = {};
    const previousFinding = () => null;
    const showDetailTab = () => {};
    const loadFindingRevisions = () => {};
    ${source.slice(start, end)}
    globalThis.openFinding = openFinding;
  `, context);

  const finding = {
    title: 'Example', vulnerability_id: 'V-000001', management_id: 'A-043', target: 'knfsd', created_at: '2026-10-13T00:00:00Z',
    owner: 'analyst', report_status: '미제보', agent_id: 'agent-1', file_path: 'fs/nfsd/example.c',
    privilege: 'AUTH_SYS', vm_environment: '2VM', review_summary: '기존 정적 검토\n재현 확인',
    primitive_review_status: 'complete',
    primitive_review_summary: 'Controlled Read 가능성 검토가 필요합니다. 추가 실험을 권장합니다.',
  };
  context.openFinding(finding);
  assert.match(elements.get('detail-subtitle').textContent, /V-000001 · A-043/);
  assert.equal(elements.get('detail-summary').children[0].children[1].textContent, 'V-000001');
  context.openFinding({ ...finding, vulnerability_aliases: ['V-000010'] });
  assert.equal(elements.get('detail-summary').children[1].children[1].textContent, 'V-000010');
  context.openFinding(finding);
  const review = elements.get('detail-summary').children.find(item => item.className.includes('review-summary'));
  assert.ok(review);
  assert.equal(review.children[1].textContent,
    '기존 정적 검토\n재현 확인\n\n프리미티브 추가 검토\nControlled Read 가능성 검토가 필요합니다. 추가 실험을 권장합니다.');
  assert.match(readFileSync(new URL('./style.css', import.meta.url), 'utf8'), /\.detail-fact\.review-summary strong\{white-space:pre-wrap\}/);

  context.openFinding({ ...finding, primitive_review_summary: null });
  const originalOnly = elements.get('detail-summary').children.find(item => item.className.includes('review-summary'));
  assert.equal(originalOnly.children[1].textContent, '기존 정적 검토\n재현 확인');

  context.openFinding({ ...finding, primitive_review_summary: '   ' });
  const blankPrimitive = elements.get('detail-summary').children.find(item => item.className.includes('review-summary'));
  assert.equal(blankPrimitive.children[1].textContent, '기존 정적 검토\n재현 확인');

  context.openFinding({ ...finding, primitive_review_status: 'error', primitive_review_summary: 'review_failed' });
  const failedPrimitive = elements.get('detail-summary').children.find(item => item.className.includes('review-summary'));
  assert.equal(failedPrimitive.children[1].textContent, '기존 정적 검토\n재현 확인');

  context.openFinding({ ...finding, report_status: '중복', duplicate_review: {
    verdict: 'duplicate', outcome: 'changed', checked_at: '2026-10-13T00:00:00Z', reason: '동일한 원인과 수정이 공개됨',
    evidence: [{ kind: 'branch', title: '공개 수정 커밋', url: 'https://github.com/torvalds/linux/commit/0123456789012345678901234567890123456789' }],
  } });
  const duplicate = elements.get('detail-summary').children.find(item => item.className.includes('duplicate-review'));
  assert.ok(duplicate);
  assert.equal(duplicate.children[1].textContent, '2026-10-13T00:00:00Z');
  assert.equal(duplicate.children[2].children[0].textContent, 'https://github.com/torvalds/linux/commit/0123456789012345678901234567890123456789');
  assert.equal(duplicate.children[2].children[0].href, 'https://github.com/torvalds/linux/commit/0123456789012345678901234567890123456789');
  assert.equal(duplicate.children[2].children[0].rel, 'noopener noreferrer');

  context.openFinding({ ...finding, duplicate_review: {
    verdict: 'no_match', checked_at: '2026-10-13T01:00:00Z', reason: '화면에 노출하지 않을 긴 검토 의견', evidence: [],
  } });
  const reviewed = elements.get('detail-summary').children.find(item => item.className.includes('duplicate-review'));
  assert.equal(reviewed.children.length, 2);
  assert.equal(reviewed.children[1].textContent, '2026-10-13T01:00:00Z');

  context.openFinding({ ...finding, internal_duplicate_review: {
    verdict: 'no_match', checked_at: '2026-10-13T02:00:00Z', reason: '화면에 노출하지 않을 긴 내부 검토 의견',
    matched_management_id: null,
  } });
  const internalChecked = elements.get('detail-summary').children.find(item => item.children[0]?.textContent === '내부 취약점 중복 검사');
  assert.ok(internalChecked);
  assert.equal(internalChecked.children.length, 2);
  assert.equal(internalChecked.children[1].textContent, '2026-10-13T02:00:00Z');

  context.testState.registry = { findings: [{ ...finding, title: 'Matched finding', management_id: 'B-021' }] };
  context.openFinding({ ...finding, report_status: '중복', internal_duplicate_review: {
    verdict: 'duplicate', checked_at: '2026-10-13T03:00:00Z', matched_management_id: 'B-021',
  } });
  const linkedMatch = elements.get('detail-summary').children.find(item => item.children[0]?.textContent === '내부 취약점 중복 검사');
  assert.equal(linkedMatch.children[2].children[0].textContent, 'B-021');
  linkedMatch.children[2].children[0].listeners.click();
  assert.equal(elements.get('detail-title').textContent, 'Matched finding');

  context.testState.registry = null;
  context.openFinding({ ...finding, origin: 'history', report_status: '중복', internal_duplicate_review: {
    verdict: 'duplicate', checked_at: '2026-10-13T03:00:00Z', reason: '화면에 노출하지 않을 긴 내부 검토 의견',
    matched_management_id: 'B-021',
  } });
  const internalMatch = elements.get('detail-summary').children.find(item => item.children[0]?.textContent === '내부 취약점 중복 검사');
  assert.equal(elements.get('detail-summary').children[0].children[1].textContent, 'V-000001');
  assert.ok(internalMatch);
  assert.equal(internalMatch.children[1].textContent, '2026-10-13T03:00:00Z');
  assert.equal(internalMatch.children[2].textContent, 'B-021');
  assert.equal(elements.get('detail-summary').children.some(item => item.children[0]?.textContent === '공개 자료 중복 검사'), false);
});

test('finding detail can select an earlier approved report without changing the current record', async () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const start = source.indexOf('async function loadFindingRevisions(');
  const end = source.indexOf('const queuePhaseLabels =', start);
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /id="detail-revision"/);
  const elements = new Map();
  const makeElement = tagName => ({ tagName, children: [], textContent: '', dataset: {},
    append(...items) { this.children.push(...items); },
    replaceChildren() { this.children = []; },
    setAttribute() {}, removeAttribute() {},
  });
  for (const id of ['detail-revision-controls', 'detail-revision', 'detail-content']) elements.set(id, makeElement('div'));
  const requests = [];
  const newer = 'a'.repeat(64), older = 'b'.repeat(64);
  const responses = new Map([
    ['/api/registry/A-005/revisions', { revisions: [
      { submission_id: newer, completed_at: '2026-10-14', title: 'latest' },
      { submission_id: older, completed_at: '2026-10-13', title: 'earlier' },
    ] }],
    [`/api/registry/A-005/revisions/${older}/artifacts`, { artifacts: [{ name: 'report.md', size: 14 }] }],
    [`/api/registry/A-005/revisions/${older}/artifacts/report.md`, 'earlier report'],
  ]);
  const finding = { management_id: 'A-005', origin: 'history' };
  const state = { finding, detailTab: 'report', detailRevision: '', detailRevisionRequestId: 0, detailId: 0 };
  const context = { testState: state, document: {
    getElementById: id => elements.get(id), createElement: makeElement, querySelectorAll: () => [],
  }, testApi: async url => {
    requests.push(url);
    assert.ok(responses.has(url), `Unexpected request: ${url}`);
    const response = responses.get(url);
    return { json: async () => response, text: async () => response };
  } };
  vm.runInNewContext(`
    const state = globalThis.testState;
    const $ = id => document.getElementById(id);
    const element = (tag, className = '', text) => { const item = document.createElement(tag); item.className = className; if (text !== undefined) item.textContent = String(text); return item; };
    const clear = item => item.replaceChildren();
    const when = value => value || '—';
    const number = value => String(value);
    const api = globalThis.testApi;
    ${source.slice(start, end)}
    globalThis.loadRevisions = loadFindingRevisions;
    globalThis.showTab = showDetailTab;
  `, context);
  await context.loadRevisions(finding);
  assert.equal(elements.get('detail-revision-controls').hidden, false);
  assert.equal(elements.get('detail-revision').children.length, 3);
  state.detailRevision = older;
  await context.showTab();
  assert.equal(elements.get('detail-content').children[0].children[0].children[0].textContent, 'report.md');
  assert.equal(elements.get('detail-content').children[0].children[1].textContent, 'earlier report');
  assert.deepEqual(requests, ['/api/registry/A-005/revisions',
    `/api/registry/A-005/revisions/${older}/artifacts`, `/api/registry/A-005/revisions/${older}/artifacts/report.md`]);
  assert.equal(state.finding, finding);
});

test('real detail state renders report, PoC, log, and API errors', async () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const nodes = new Map();
  const makeElement = tagName => ({ tagName, textContent: '', children: [], scrollTop: 0,
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    setAttribute() {}, removeAttribute() {},
  });
  nodes.set('detail-content', makeElement('div'));
  const responses = new Map();
  const context = {
    document: { getElementById: id => nodes.get(id), createElement: makeElement, querySelectorAll: () => [] },
    fetch: async url => {
      assert.ok(responses.has(url), `Unexpected request: ${url}`);
      const { body, status = 200 } = responses.get(url);
      return { ok: status < 400, status, json: async () => body, text: async () => body };
    },
  };
  vm.runInNewContext(
    source.slice(0, source.indexOf('const agentName =')) +
    source.slice(source.indexOf('async function api('), source.indexOf('function showError(')) +
    source.slice(source.indexOf('async function renderCanonicalArtifacts('), source.indexOf('const queuePhaseLabels =')) +
    '\nglobalThis.testState = state; globalThis.showTab = showDetailTab;', context,
  );
  const state = context.testState;
  const content = nodes.get('detail-content');
  const text = node => [node.textContent, ...node.children.map(text)].join(' ');
  const findingId = 'a'.repeat(64);
  const base = `/api/events/${findingId}/artifacts`;
  const files = new Map([
    ['report.md', '## Summary\nSubmitted report'],
    ['poc.c', 'int main(void) { return 0; }'],
    ['reproduction.md', 'cc poc.c'],
    ['evidence.log', 'BUG: KASAN: submitted log'],
  ]);
  state.finding = { event_id: findingId, origin: 'agent' };
  responses.set(base, { body: { artifacts: [...files].map(([name, body]) => ({ name, size: body.length })) } });
  for (const [name, body] of files) responses.set(`${base}/${name}`, { body });
  for (const [tab, expected] of [['report', 'Submitted report'], ['poc', 'int main'], ['verification', 'submitted log']]) {
    state.detailTab = tab;
    await context.showTab();
    assert.ok(text(content).includes(expected), `${tab} artifact should appear`);
  }
  assert.ok(Number.isFinite(state.detailId));
  responses.set(base, { status: 503, body: { error: 'temporary unavailable' } });
  await context.showTab();
  assert.match(text(content), /자료를 열지 못했습니다: temporary unavailable/);
  assert.doesNotMatch(text(content), /자료를 불러오는 중/);
});

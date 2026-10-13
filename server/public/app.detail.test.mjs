import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('finding detail appends only available primitive review under the existing opinion', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const start = source.indexOf('function detailFact(');
  const end = source.indexOf('async function showDetailTab()', start);
  assert.ok(start > 0 && end > start);

  const elements = new Map();
  const makeElement = tagName => ({
    tagName, className: '', textContent: '', children: [],
    classList: { add(name) { this.owner.className += ` ${name}`; } },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
  });
  for (const id of ['detail-title', 'detail-subtitle', 'detail-summary']) elements.set(id, makeElement('div'));
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
    ${source.slice(start, end)}
    globalThis.openFinding = openFinding;
  `, context);

  const finding = {
    title: 'Example', management_id: 'A-043', target: 'knfsd', created_at: '2026-10-13T00:00:00Z',
    owner: 'analyst', report_status: '미제보', agent_id: 'agent-1', file_path: 'fs/nfsd/example.c',
    privilege: 'AUTH_SYS', vm_environment: '2VM', review_summary: '기존 정적 검토\n재현 확인',
    primitive_review_status: 'complete',
    primitive_review_summary: 'Controlled Read 가능성 검토가 필요합니다. 추가 실험을 권장합니다.',
  };
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
});

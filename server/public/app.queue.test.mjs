import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('verification queue shows real worker and job stages, with empty and error states', () => {
  const longReason = `KASAN 증거 부족\n${'확인할 근거와 예외 조건을 모두 표시합니다. '.repeat(60)}`;
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const start = source.indexOf('const queuePhaseLabels =');
  const end = source.indexOf('async function refresh()', start);
  assert.ok(start > 0 && end > start);
  assert.match(html, /data-view="queue"/);
  assert.match(html, /<dialog id="queue-detail"[^>]*aria-labelledby="queue-detail-title"/);
  for (const name of ['pending', 'active', 'blocked']) assert.match(html, new RegExp(`id="queue-${name}-pagination"`));
  assert.equal((html.match(/class="queue-column"/g) || []).length, 3);
  assert.doesNotMatch(html, /queue-duplicate-board|queue-duplicate-pending/);
  const elements = new Map();
  const makeElement = tagName => ({
    tagName, className: '', textContent: '', children: [], open: false, dataset: {},
    classList: { add() {} },
    replaceChildren() { this.children = []; },
    append(...children) { this.children.push(...children); },
    setAttribute(name, value) { this[name] = value; },
    addEventListener(name, listener) { this.listeners ??= {}; this.listeners[name] = listener; },
    click() { this.listeners?.click?.(); },
    showModal() { if (this.open) throw new Error('dialog already open'); this.open = true; },
    close() { this.open = false; },
  });
  for (const id of ['queue-stats', 'queue-workers', 'queue-active', 'queue-pending', 'queue-blocked', 'queue-active-pagination', 'queue-pending-pagination', 'queue-blocked-pagination', 'queue-updated', 'queue-worker-count', 'queue-active-count', 'queue-pending-count', 'queue-blocked-count', 'queue-detail', 'queue-detail-title', 'queue-detail-subtitle', 'queue-detail-facts']) elements.set(id, makeElement('div'));
  const state = {
    data: { tracks: [
      { track_id: 'rc', label: '최신 RC', version_id: '7.3-rc7', repo_commit: 'abc123' },
      { track_id: 'stable', label: '최신 stable', version_id: '7.2.10', repo_commit: 'def456' },
    ] },
    queue: {
      fetched_at: '2026-10-13T00:00:00Z', counts: { processing: 1, pending: 1, blocked: 2 },
      workers: [
        { worker_id: 'worker-1', status: 'busy', current_submission_id: 'run-1', target_commit: 'abc123', last_seen_at: '2026-10-13T00:00:00Z' },
        { worker_id: 'worker-2', status: 'idle', current_submission_id: null, target_commit: 'def456', last_seen_at: '2026-10-13T00:00:00Z' },
        { role: 'primitive', worker_id: 'primitive-1', status: 'busy', current_finding_id: 'finding-5', current_management_id: 'A-043', current_title: 'new bug', pending_count: 2, last_seen_at: '2026-10-13T00:00:00Z' },
        { role: 'duplicate', worker_id: 'duplicate-1', status: 'busy', current_submission_id: 'run-5', pending_count: 2, last_seen_at: '2026-10-13T00:00:00Z' },
      ],
      active: [{ submission_id: 'run-1', vulnerability_id: 'V-000002', project: 'knfsd', title: 'active bug', agent_id: 'agent-1', status: 'processing', phase: 'qemu_reproduction', phase_updated_at: '2026-10-13T00:00:00Z', target_commit: 'abc123' }],
      pending: [{ submission_id: 'run-2', vulnerability_id: 'V-000001', project: 'knfsd', title: 'pending bug', agent_id: 'web:opaque', origin: 'manual_upload', reporter: '연구원', existing_vulnerability_id: 'V-000001', position: 1, submitted_at: '2026-10-13T00:00:00Z', target_commit: 'def456' }],
      blocked: [
        { submission_id: 'run-3', project: 'knfsd', title: 'blocked bug', agent_id: 'agent-3', status: 'needs_evidence', reason: longReason, target_commit: 'abc123' },
        { submission_id: 'run-4', project: 'knfsd', title: 'rejected bug', agent_id: 'agent-4', status: 'rejected', reason: 'PoC 재현 실패', target_commit: 'abc123' },
      ],
      duplicate: {
        counts: { pending: 1, processing: 1, error: 1 },
        pending: [{ submission_id: 'run-6', project: 'knfsd', title: 'duplicate waiting', agent_id: 'agent-6', status: 'duplicate_pending' }],
        active: [{ submission_id: 'run-5', project: 'knfsd', title: 'duplicate in progress', agent_id: 'agent-5', status: 'duplicate_processing', matched_management_id: 'A-043' }],
        errors: [{ submission_id: 'run-7', project: 'knfsd', title: 'duplicate failed', agent_id: 'agent-7', status: 'duplicate_error', reason: 'comparison failed' }],
      },
      primitive: {
        counts: { pending: 2, processing: 1, complete: 4, error: 1 },
        pending: [
          { finding_id: 'finding-6', management_id: 'A-044', title: 'next candidate' },
          { finding_id: 'finding-7', management_id: 'A-045', title: 'another candidate' },
        ],
        active: [{ finding_id: 'finding-5', management_id: 'A-043', title: 'new bug' }],
        errors: [{ finding_id: 'finding-3', management_id: 'A-041', title: 'review failed', summary: '검토 작업 중단' }],
      },
    },
    queueError: null,
    queuePages: { pending: 1, active: 1, blocked: 1 },
  };
  const context = { document: { getElementById: id => elements.get(id), createElement: makeElement }, testState: state };
  vm.runInNewContext(
    source.slice(0, source.indexOf('const impacts =')) +
    'const state = globalThis.testState;\n' +
    source.slice(source.indexOf('function renderPagination('), source.indexOf('const findingColumns =')) +
    source.slice(source.indexOf('function detailFact('), source.indexOf('function appendDuplicateReviews(')) +
    source.slice(start, end) +
    '\nglobalThis.renderQueue = renderVerificationQueue;',
    context,
  );
  const text = node => [node.textContent, ...node.children.map(text)].join(' ');
  context.renderQueue();
  assert.match(text(elements.get('queue-workers')), /작업 중/);
  assert.match(text(elements.get('queue-workers')), /최신 stable · 7\.2\.10/);
  const primitiveCard = elements.get('queue-workers').children[2];
  assert.match(text(primitiveCard), /프리미티브 검토/);
  assert.match(text(primitiveCard), /A-043 · new bug/);
  assert.match(text(primitiveCard), /대기 2건/);
  assert.doesNotMatch(text(primitiveCard), /커널|대상 커밋 없음/);
  assert.equal(elements.get('queue-worker-count').textContent, '4개');
  const duplicateCard = elements.get('queue-workers').children[3];
  assert.match(text(duplicateCard), /중복 검토 에이전트/);
  assert.match(text(duplicateCard), /duplicate in progress/);
  assert.match(text(duplicateCard), /대기 2건/);
  assert.doesNotMatch(text(duplicateCard), /커널/);
  assert.equal(elements.get('queue-workers').children.length, 4);
  assert.doesNotMatch(text(elements.get('queue-workers')), /검토 작업 중단|review failed/);
  assert.match(text(elements.get('queue-workers')), /최신 RC · 7\.3-rc7/);
  state.queue.workers[0].target_commit = null;
  context.renderQueue();
  assert.match(text(elements.get('queue-workers').children[0]), /최신 RC · 7\.3-rc7/);
  state.queue.workers[0].current_submission_id = null;
  context.renderQueue();
  assert.match(text(elements.get('queue-workers').children[0]), /공용 검증 에이전트/);
  state.queue.workers[0].target_commit = 'abc123';
  state.queue.workers[0].current_submission_id = 'run-1';
  context.renderQueue();
  assert.equal(elements.get('queue-active').children[0].tagName, 'button');
  assert.match(text(elements.get('queue-active')), /active bug agent-1/);
  assert.doesNotMatch(text(elements.get('queue-active')), /2VM PoC 재현|abc123|run-1/);
  assert.match(text(elements.get('queue-pending')), /직접 제출 · 연구원/);
  assert.doesNotMatch(text(elements.get('queue-pending')), /def456|순서|V-000001/);
  assert.match(text(elements.get('queue-blocked')), /blocked bug agent-3/);
  assert.doesNotMatch(text(elements.get('queue-blocked')), /KASAN 증거 부족|반려|PoC 재현 실패/);
  assert.match(text(elements.get('queue-stats')), /반려 · 보완 · 오류/);
  assert.deepEqual(elements.get('queue-stats').children.map(stat => stat.children[1].textContent), ['2', '2', '3']);
  assert.equal(elements.get('queue-pending-count').textContent, '2건');
  assert.equal(elements.get('queue-active-count').textContent, '2건');
  assert.equal(elements.get('queue-blocked-count').textContent, '3건');
  assert.match(text(elements.get('queue-pending')), /duplicate waiting agent-6/);
  assert.match(text(elements.get('queue-active')), /duplicate in progress agent-5/);
  assert.match(text(elements.get('queue-blocked')), /duplicate failed agent-7/);
  elements.get('queue-active').children[1].click();
  assert.match(text(elements.get('queue-detail-facts')), /중복 검토 중|A-043/);
  elements.get('queue-detail').close();
  elements.get('queue-blocked').children[2].click();
  assert.match(text(elements.get('queue-detail-facts')), /중복 검토 오류|comparison failed/);
  elements.get('queue-detail').close();
  elements.get('queue-active').children[0].click();
  assert.equal(elements.get('queue-detail').open, true);
  assert.equal(elements.get('queue-detail-title').textContent, 'active bug');
  assert.match(text(elements.get('queue-detail-facts')), /2VM PoC 재현/);
  assert.match(text(elements.get('queue-detail-facts')), /abc123|run-1/);
  assert.match(text(elements.get('queue-detail-facts')), /취약점 ID V-000002/);
  state.queue.active[0].phase = 'trace_review';
  context.renderQueue();
  assert.equal(elements.get('queue-detail').open, true);
  assert.match(text(elements.get('queue-detail-facts')), /KASAN 로그 검토/);
  assert.doesNotMatch(text(elements.get('queue-detail-facts')), /2VM PoC 재현/);
  elements.get('queue-detail').close();
  elements.get('queue-pending').children[0].click();
  assert.match(elements.get('queue-detail-subtitle').textContent, /직접 제출 · 연구원/);
  assert.match(text(elements.get('queue-detail-facts')), /def456|제출 순서/);
  assert.match(text(elements.get('queue-detail-facts')), /취약점 ID V-000001/);
  assert.match(text(elements.get('queue-detail-facts')), /보강 대상 취약점 ID V-000001/);
  elements.get('queue-detail').close();
  elements.get('queue-blocked').children[0].click();
  assert.match(text(elements.get('queue-detail-facts')), /KASAN 증거 부족|증거 보완 필요/);
  assert.equal(elements.get('queue-detail-facts').children.at(-1).children[1].textContent, longReason);
  elements.get('queue-detail').close();
  state.queue.active[0].phase = null;
  context.renderQueue();
  elements.get('queue-active').children[0].click();
  assert.match(text(elements.get('queue-detail-facts')), /검증 중/);
  assert.doesNotMatch(text(elements.get('queue-detail-facts')), /2VM PoC 재현/);
  elements.get('queue-detail').close();
  for (const name of ['active', 'pending', 'blocked']) {
    state.queue[name] = Array.from({ length: 12 }, (_, index) => ({ submission_id: `${name}-${index + 1}`, title: `${name} bug ${index + 1}`, agent_id: `${name}-agent`, status: name === 'active' ? 'processing' : name === 'pending' ? 'pending' : 'rejected' }));
  }
  for (const name of ['pending', 'active', 'errors']) {
    state.queue.duplicate[name] = Array.from({ length: 12 }, (_, index) => ({ submission_id: `duplicate-${name}-${index + 1}`, title: `duplicate ${name} ${index + 1}`, agent_id: `duplicate-${name}-agent`, status: `duplicate_${name === 'active' ? 'processing' : name === 'errors' ? 'error' : 'pending'}` }));
  }
  context.renderQueue();
  for (const name of ['active', 'pending', 'blocked']) {
    assert.equal(elements.get(`queue-${name}`).children.length, 5);
    assert.equal(elements.get(`queue-${name}`).children[0].dataset.submissionId, `${name}-1`);
    assert.equal(elements.get(`queue-${name}-pagination`).hidden, false);
  }
  elements.get('queue-blocked-pagination').children.find(button => button.textContent === '다음').click();
  assert.equal(elements.get('queue-blocked').children[0].dataset.submissionId, 'blocked-6');
  assert.equal(elements.get('queue-pending').children[0].dataset.submissionId, 'pending-1');
  elements.get('queue-pending-pagination').children.find(button => button.textContent === '다음').click();
  elements.get('queue-pending-pagination').children.find(button => button.textContent === '3').click();
  assert.equal(elements.get('queue-pending').children.length, 5);
  assert.equal(elements.get('queue-pending').children[0].dataset.submissionId, 'pending-11');
  assert.equal(elements.get('queue-pending').children[2].dataset.submissionId, 'duplicate-pending-1');
  assert.equal(elements.get('queue-active').children[0].dataset.submissionId, 'active-1');
  elements.get('queue-active-pagination').children.find(button => button.textContent === '다음').click();
  elements.get('queue-active-pagination').children.find(button => button.textContent === '3').click();
  assert.equal(elements.get('queue-active').children[2].dataset.submissionId, 'duplicate-active-1');
  assert.equal(elements.get('queue-pending').children[0].dataset.submissionId, 'pending-11');
  elements.get('queue-blocked').children[0].click();
  assert.equal(elements.get('queue-detail-title').textContent, 'blocked bug 6');
  elements.get('queue-detail').close();
  state.queue.active = [];
  state.queue.pending = [];
  state.queue.blocked = [];
  state.queue.duplicate = { counts: { pending: 0, processing: 0, error: 0 }, pending: [], active: [], errors: [] };
  state.queue.workers = [];
  state.queue.primitive = { counts: { pending: 0, processing: 0, complete: 4, error: 0 }, pending: [], active: [], errors: [] };
  context.renderQueue();
  assert.equal(elements.get('queue-detail').open, false);
  assert.match(text(elements.get('queue-pending')), /검증을 기다리는 신규 제출이 없습니다/);
  assert.equal(state.queuePages.pending, 1);
  assert.equal(elements.get('queue-pending-pagination').hidden, true);
  assert.doesNotMatch(text(elements.get('queue-workers')), /next candidate|review failed/);
  state.queueError = new Error('서비스 오류');
  context.renderQueue();
  assert.match(text(elements.get('queue-active')), /서비스 오류/);
  assert.doesNotMatch(text(elements.get('queue-pending')), /검증을 기다리는 신규 제출이 없습니다/);
});

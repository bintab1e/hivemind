import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('verification queue shows real worker and job stages, with empty and error states', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const start = source.indexOf('const queuePhaseLabels =');
  const end = source.indexOf('async function refresh()', start);
  assert.ok(start > 0 && end > start);
  assert.match(html, /data-view="queue"/);
  const elements = new Map();
  const makeElement = tagName => ({
    tagName, className: '', textContent: '', children: [],
    replaceChildren() { this.children = []; },
    append(...children) { this.children.push(...children); },
    setAttribute(name, value) { this[name] = value; },
  });
  for (const id of ['queue-stats', 'queue-workers', 'queue-active', 'queue-pending', 'queue-blocked', 'queue-updated', 'queue-worker-count', 'queue-active-count', 'queue-pending-count', 'queue-blocked-count']) elements.set(id, makeElement('div'));
  const state = {
    data: { tracks: [{ track_id: 'rc', label: '최신 RC', version_id: '7.3-rc7', repo_commit: 'abc123' }] },
    queue: {
      fetched_at: '2026-10-13T00:00:00Z', counts: { processing: 1, pending: 1, blocked: 1 },
      workers: [{ worker_id: 'worker-1', status: 'busy', current_submission_id: 'run-1', target_commit: 'abc123', last_seen_at: '2026-10-13T00:00:00Z' }],
      active: [{ submission_id: 'run-1', project: 'knfsd', title: 'active bug', agent_id: 'agent-1', status: 'processing', phase: 'qemu_reproduction', phase_updated_at: '2026-10-13T00:00:00Z', target_commit: 'abc123' }],
      pending: [{ submission_id: 'run-2', project: 'knfsd', title: 'pending bug', agent_id: 'agent-2', position: 1, submitted_at: '2026-10-13T00:00:00Z', target_commit: 'def456' }],
      blocked: [{ submission_id: 'run-3', project: 'knfsd', title: 'blocked bug', agent_id: 'agent-3', status: 'needs_evidence', reason: 'KASAN 증거 부족', target_commit: 'abc123' }],
    },
    queueError: null,
  };
  const context = { document: { getElementById: id => elements.get(id), createElement: makeElement }, testState: state };
  vm.runInNewContext(
    source.slice(0, source.indexOf('const impacts =')) +
    'const state = globalThis.testState;\n' + source.slice(start, end) +
    '\nglobalThis.renderQueue = renderVerificationQueue;',
    context,
  );
  const text = node => [node.textContent, ...node.children.map(text)].join(' ');
  context.renderQueue();
  assert.match(text(elements.get('queue-workers')), /작업 중/);
  assert.match(text(elements.get('queue-workers')), /최신 RC · 7\.3-rc7/);
  assert.match(text(elements.get('queue-active')), /2VM PoC 재현/);
  assert.match(text(elements.get('queue-pending')), /def456/);
  assert.match(text(elements.get('queue-blocked')), /KASAN 증거 부족/);
  state.queue.active[0].phase = null;
  context.renderQueue();
  assert.match(text(elements.get('queue-active')), /검증 중/);
  assert.doesNotMatch(text(elements.get('queue-active')), /2VM PoC 재현/);
  state.queue.active = [];
  state.queue.pending = [];
  state.queue.blocked = [];
  state.queue.workers = [];
  context.renderQueue();
  assert.match(text(elements.get('queue-pending')), /검증을 기다리는 신규 제출이 없습니다/);
  state.queueError = new Error('서비스 오류');
  context.renderQueue();
  assert.match(text(elements.get('queue-active')), /서비스 오류/);
  assert.doesNotMatch(text(elements.get('queue-pending')), /검증을 기다리는 신규 제출이 없습니다/);
});

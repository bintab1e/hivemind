import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('./patch-review.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('./patch-review.html', import.meta.url), 'utf8');
const reviewId = 'c'.repeat(64);

function page(fetch) {
  const elements = new Map();
  const make = tagName => ({
    tagName, children: [], textContent: '', className: '', hidden: false, dataset: {}, listeners: {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(type, callback) { this.listeners[type] = callback; },
  });
  for (const id of ['review-title', 'review-subtitle', 'review-status', 'review-error', 'review-body',
    'review-overview', 'review-metadata', 'review-verdict-body', 'review-findings-title',
    'review-findings-body', 'review-concerns-title', 'review-concerns-body',
    'review-patches-body', 'review-source-body', 'review-raw-body']) elements.set(id, make('div'));
  elements.get('review-body').hidden = true;
  const document = { title: '', getElementById: id => elements.get(id), createElement: make };
  const context = { document, location: { pathname: `/patch-reviews/${reviewId}` }, fetch };
  const finished = vm.runInNewContext(source, context);
  return { elements, finished, document };
}

const descendants = node => [node, ...node.children.flatMap(descendants)];
const content = node => descendants(node).map(item => item.textContent).join(' ');

test('direct patch review URL renders Sashiko evidence as safe text and lazily previews the patch', async () => {
  assert.match(html, /href="\/\?view=patch"/);
  assert.match(html, /src="\/patch-review\.js"/);
  assert.doesNotMatch(source, /innerHTML|insertAdjacentHTML/);
  const calls = [];
  const review = {
    id: reviewId, management_id: 'A-043', filename: 'fix.patch', track_id: 'rc',
    base_commit: 'a'.repeat(40), status: 'findings', submitted_at: '2026-10-14T00:00:00Z',
    completed_at: '2026-10-14T00:05:00Z', result: {
      status: 'issues_found', baseline: 'b'.repeat(40), tokens_in: 1200, tokens_out: 300,
      patches: [{ subject: 'knfsd: fix lifetime', status: 'applied', method: 'git apply' }],
      findings: [{ problem: '<script>alert(1)</script>', severity: 'high',
        severity_explanation: 'Reference count is missing.',
        locations: [{ file: 'fs/nfsd/nfs4state.c', line: 42, function_or_symbol: 'nfsd4_put',
          code_snippet: 'put_client(client);', why_this_location_matters: 'Last reference is dropped here.' }] }],
      concerns: [{ type: 'Race', description: 'Timer lifetime', verification_question: 'Could cleanup race?',
        preexisting: true }],
    },
  };
  const fetch = async path => {
    calls.push(path);
    if (path === `/api/patch-reviews/${reviewId}`) return { ok: true, json: async () => ({ review }) };
    if (path === '/api/registry') return { ok: true, json: async () => ({ findings: [
      { management_id: 'A-043', title: '<img src=x onerror=alert(1)>' },
    ] }) };
    if (path === `/api/patch-reviews/${reviewId}/file`) return { ok: true, text: async () => 'diff --git a/fs/nfsd/a.c b/fs/nfsd/a.c\n+<script>bad</script>\n' };
    throw new Error(`Unexpected request: ${path}`);
  };
  const { elements, finished, document } = page(fetch);
  await finished;
  assert.equal(elements.get('review-body').hidden, false);
  assert.equal(elements.get('review-title').textContent, '<img src=x onerror=alert(1)>');
  assert.match(content(elements.get('review-overview')), /지적 사항 1/);
  assert.match(content(elements.get('review-overview')), /High 1/);
  assert.match(content(elements.get('review-metadata')), /A-043[\s\S]*rc[\s\S]*입력 1,200/);
  assert.match(content(elements.get('review-findings-body')), /<script>alert\(1\)<\/script>[\s\S]*Reference count is missing[\s\S]*fs\/nfsd\/nfs4state\.c:42[\s\S]*Last reference is dropped here/);
  assert.match(content(elements.get('review-concerns-body')), /Timer lifetime[\s\S]*패치 이전부터 존재[\s\S]*Could cleanup race/);
  assert.match(content(elements.get('review-patches-body')), /knfsd: fix lifetime[\s\S]*적용됨/);
  assert.match(content(elements.get('review-raw-body')), /"status": "issues_found"/);
  assert.equal([...elements.values()].flatMap(descendants).filter(item => ['script', 'img'].includes(item.tagName)).length, 0);
  assert.equal(document.title, 'A-043 · Sashiko 패치 검토');
  assert.equal(calls.filter(path => path.endsWith('/file')).length, 0);
  const preview = elements.get('review-source-body').children[1];
  preview.open = true;
  await preview.listeners.toggle();
  await preview.listeners.toggle();
  assert.match(content(preview), /<script>bad<\/script>/);
  assert.equal(calls.filter(path => path.endsWith('/file')).length, 1);
});

test('missing patch review shows an error with a route back to the patch list', async () => {
  const { elements, finished } = page(async path => path === '/api/registry'
    ? { ok: true, json: async () => ({ findings: [] }) }
    : { ok: false, status: 404, json: async () => ({ error: 'Patch review not found' }) });
  await finished;
  assert.equal(elements.get('review-body').hidden, true);
  assert.equal(elements.get('review-error').hidden, false);
  assert.match(elements.get('review-error').textContent, /Patch review not found/);
  assert.equal(elements.get('review-status').dataset.tone, 'error');
});

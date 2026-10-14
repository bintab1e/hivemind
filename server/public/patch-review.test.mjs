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
    'review-patches-body', 'review-source-actions', 'review-source-body', 'review-raw-body']) elements.set(id, make('div'));
  elements.get('review-body').hidden = true;
  const document = { title: '', getElementById: id => elements.get(id), createElement: make };
  const context = { document, location: { pathname: `/patch-reviews/${reviewId}` }, fetch };
  const finished = vm.runInNewContext(source, context);
  return { elements, finished, document };
}

const descendants = node => [node, ...node.children.flatMap(descendants)];
const content = node => descendants(node).map(item => item.textContent).join(' ');

test('direct patch review URL renders Sashiko findings with diff context as safe text', async () => {
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
          code_snippet: '<script>bad</script>', why_this_location_matters: 'Last reference is dropped here.' }] }],
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
    if (path === `/api/patch-reviews/${reviewId}/file`) return { ok: true, text: async () =>
      'diff --git a/fs/nfsd/nfs4state.c b/fs/nfsd/nfs4state.c\n--- a/fs/nfsd/nfs4state.c\n+++ b/fs/nfsd/nfs4state.c\n@@ -42 +42 @@\n-old\n+<script>bad</script>\n' };
    throw new Error(`Unexpected request: ${path}`);
  };
  const { elements, finished, document } = page(fetch);
  await finished;
  assert.equal(elements.get('review-body').hidden, false);
  assert.equal(elements.get('review-title').textContent, 'knfsd: fix lifetime');
  assert.match(elements.get('review-subtitle').textContent, /A-043 · <img src=x onerror=alert\(1\)>/);
  assert.match(content(elements.get('review-overview')), /지적 1건[\s\S]*HIGH 1/);
  assert.match(content(elements.get('review-metadata')), /A-043[\s\S]*rc[\s\S]*fix\.patch/);
  assert.match(content(elements.get('review-findings-body')), /<script>alert\(1\)<\/script>[\s\S]*Reference count is missing[\s\S]*fs\/nfsd\/nfs4state\.c:42[\s\S]*Last reference is dropped here/);
  assert.match(content(elements.get('review-concerns-body')), /Timer lifetime[\s\S]*패치 이전부터 존재[\s\S]*Could cleanup race/);
  assert.match(content(elements.get('review-patches-body')), /knfsd: fix lifetime[\s\S]*적용됨/);
  assert.match(content(elements.get('review-raw-body')), /입력 1,200[\s\S]*"status": "issues_found"/);
  assert.match(content(elements.get('review-source-body')), /fs\/nfsd\/nfs4state\.c[\s\S]*@@ -42 \+42 @@[\s\S]*<script>bad<\/script>[\s\S]*Reference count is missing/);
  assert.equal(descendants(elements.get('review-source-body')).filter(item => item.className.split(' ').includes('patch-inline-note')).length, 1);
  assert.equal([...elements.values()].flatMap(descendants).filter(item => ['script', 'img'].includes(item.tagName)).length, 0);
  assert.equal(document.title, 'A-043 · Sashiko 패치 검토');
  assert.equal(calls.filter(path => path.endsWith('/file')).length, 1);
});

test('diff line numbers survive source lines beginning with ++ and annotations require matching code', async () => {
  const review = { id: reviewId, management_id: 'A-044', filename: 'fix.patch', status: 'findings',
    result: { status: 'issues_found', findings: [
      { problem: 'matching', locations: [{ file: 'fs/nfsd/a.c', line: 3, code_snippet: 'next_line();' }] },
      { problem: 'different code', locations: [{ file: 'fs/nfsd/a.c', line: 2, code_snippet: 'other_call();' }] },
    ] } };
  const patch = 'diff --git a/fs/nfsd/a.c b/fs/nfsd/a.c\n--- a/fs/nfsd/a.c\n+++ b/fs/nfsd/a.c\n@@ -1,2 +1,3 @@\n context();\n+++ important();\n next_line();\n';
  const { elements, finished } = page(async path => {
    if (path === `/api/patch-reviews/${reviewId}`) return { ok: true, json: async () => ({ review }) };
    if (path === '/api/registry') return { ok: true, json: async () => ({ findings: [] }) };
    if (path === `/api/patch-reviews/${reviewId}/file`) return { ok: true, text: async () => patch };
    throw new Error(`Unexpected request: ${path}`);
  });
  await finished;
  const nodes = descendants(elements.get('review-source-body'));
  const row = nodes.find(item => item.className.includes('patch-diff-row') && item.children[2]?.textContent === ' next_line();');
  assert.equal(row?.children[1].textContent, '3');
  assert.equal(nodes.filter(item => item.className.split(' ').includes('patch-inline-note')).length, 1);
  assert.match(content(elements.get('review-findings-body')), /different code/);
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

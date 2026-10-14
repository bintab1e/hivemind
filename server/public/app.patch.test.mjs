import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('patch tab lists only knfsd findings and submits a kernel patch for Sashiko review', async () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  for (const id of ['patch-view', 'patch-list', 'patch-upload-dialog', 'patch-upload-form']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /data-view="patch"/);
  const start = source.indexOf('const patchStatusLabels =');
  const end = source.indexOf('const uploadStatusLabels =', start);
  assert.ok(start > 0 && end > start);
  const nodes = new Map();
  const makeElement = tagName => ({
    tagName, textContent: '', className: '', value: '', disabled: false, hidden: false, children: [], listeners: {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    setAttribute(name, value) { this[name] = value; },
  });
  for (const id of ['patch-search', 'patch-count', 'patch-error', 'patch-list',
    'patch-upload-finding', 'patch-upload-form', 'patch-upload-result', 'patch-track', 'patch-file',
    'patch-submit-button']) {
    nodes.set(id, makeElement(id === 'patch-track' ? 'select' : 'div'));
  }
  for (const id of ['patch-upload-dialog']) {
    nodes.set(id, { open: false, showModal() { this.open = true; }, close() { this.open = false; } });
  }
  nodes.get('patch-upload-form').reset = () => { nodes.get('patch-file').files = []; nodes.get('patch-track').value = ''; };
  const a = { event_id: 'history:A-001', management_id: 'A-001', title: 'kernel read', target: 'knfsd' };
  const a2 = { event_id: 'history:A-002', management_id: 'A-002', title: 'kernel write', target: 'knfsd' };
  const b = { event_id: 'history:B-001', management_id: 'B-001', title: 'ganesha write', target: 'NFS-Ganesha' };
  const state = { registry: { findings: [b, a2, a] }, patchReviews: null, patchError: null, patchRequestId: 0,
    data: { selected: { track_id: 'rc' } } };
  const calls = [];
  let reviews = [];
  let view = 'patch';
  const context = {
    document: { getElementById: id => nodes.get(id), createElement: makeElement },
    state, activeView: () => view, openFinding() {},
    btoa: input => Buffer.from(input, 'binary').toString('base64'),
    api: async (path, options) => {
      calls.push({ path, options });
      if (path === '/api/submissions/upload-targets') return { json: async () => ({ targets: [
        { track_id: 'rc', label: '최신 RC', version_id: '7.3-rc7', repo_commit: 'a'.repeat(40) },
        { track_id: 'wrong', repo_commit: 'b'.repeat(40) },
      ] }) };
      if (path === '/api/patch-reviews' && !options) return { json: async () => ({ reviews }) };
      if (path === '/api/patch-reviews' && options?.method === 'POST') {
        const review = { id: 'c'.repeat(64), management_id: 'A-001', filename: 'fix.patch',
          status: 'pending', submitted_at: '2026-10-14T00:00:00Z' };
        reviews = [review];
        return { json: async () => review };
      }
      throw new Error(`Unexpected URL: ${path}`);
    },
  };
  vm.runInNewContext(`
    const $ = id => document.getElementById(id);
    const element = (tag, className = '', text) => { const item = document.createElement(tag); item.className = className; if (text !== undefined) item.textContent = String(text); return item; };
    const clear = item => item.replaceChildren();
    const number = value => Number(value || 0).toLocaleString('ko-KR');
    const when = value => value || '—';
    const detailFact = (label, value) => element('div', '', label + ': ' + value);
    ${source.slice(start, end)}
    globalThis.patch = { renderPatchView, openPatchUpload, submitPatch };
  `, context);
  context.patch.renderPatchView();
  const resultText = node => [node.textContent, ...node.children.map(resultText)].join(' ');
  const table = nodes.get('patch-list').children[0];
  assert.equal(table.children[1].children.length, 2);
  const [kernelRow, secondKernelRow] = table.children[1].children;
  assert.equal(kernelRow.children[0].textContent, 'A-001');
  assert.equal(secondKernelRow.children[0].textContent, 'A-002');
  assert.equal(kernelRow.children[5].children[0].disabled, false);
  assert.match(resultText(nodes.get('patch-list')), /A-001[\s\S]*A-002/);
  assert.doesNotMatch(resultText(nodes.get('patch-list')), /B-001|ganesha write/);

  await context.patch.openPatchUpload(b);
  assert.equal(nodes.get('patch-upload-dialog').open, false);
  await context.patch.openPatchUpload(a);
  assert.equal(nodes.get('patch-upload-dialog').open, true);
  assert.equal(nodes.get('patch-track').children.length, 1);
  assert.equal(nodes.get('patch-track').value, 'rc');
  const bytes = Uint8Array.from(Buffer.from('diff --git a/fs/nfsd/a.c b/fs/nfsd/a.c\n'));
  nodes.get('patch-file').files = [{ name: 'fix.patch', size: bytes.length, arrayBuffer: async () => bytes.buffer }];
  await context.patch.submitPatch({ preventDefault() {} });
  const post = calls.find(call => call.path === '/api/patch-reviews' && call.options?.method === 'POST');
  assert.deepEqual(JSON.parse(post.options.body), {
    management_id: 'A-001', track_id: 'rc', filename: 'fix.patch', content_base64: Buffer.from(bytes).toString('base64'),
  });
  assert.equal(state.patchReviews.length, 1);
  assert.match(nodes.get('patch-upload-result').textContent, /패치 접수/);
  context.patch.renderPatchView();
  const resultLink = nodes.get('patch-list').children[0].children[1].children[0].children[5].children[1];
  assert.equal(resultLink.tagName, 'a');
  assert.equal(resultLink.href, `/patch-reviews/${'c'.repeat(64)}`);
  assert.equal(resultLink.listeners.click, undefined);

  const sent = calls.filter(call => call.path === '/api/patch-reviews' && call.options?.method === 'POST').length;
  nodes.get('patch-file').files = [{ name: 'too-large.patch', size: 1_000_001 }];
  await context.patch.submitPatch({ preventDefault() {} });
  assert.match(nodes.get('patch-upload-result').textContent, /1 MB 이하/);
  assert.equal(calls.filter(call => call.path === '/api/patch-reviews' && call.options?.method === 'POST').length, sent);
  view = 'registry';
  nodes.get('patch-upload-dialog').close();
  await context.patch.openPatchUpload(a);
  assert.equal(nodes.get('patch-upload-dialog').open, false);
});

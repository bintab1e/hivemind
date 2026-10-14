import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('manual ZIP form submits to the verifier queue and shows its receipt', async () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  for (const id of ['zip-submit-form', 'zip-title', 'zip-reporter', 'zip-existing-id', 'zip-target', 'zip-file', 'zip-submit-result']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /id="open-zip-submit"/);
  assert.match(html, /<dialog id="zip-submit-dialog"[\s\S]*?<form id="zip-submit-form"[\s\S]*?<\/form>\s*<\/dialog>/);
  assert.ok(html.indexOf('id="zip-submit-dialog"') > html.indexOf('</main>'));
  assert.doesNotMatch(html, /id="uploaded-panel"/);
  const start = source.indexOf('const uploadStatusLabels =');
  const end = source.indexOf('async function refresh()', start);
  assert.ok(start > 0 && end > start);
  const nodes = new Map();
  const makeElement = tagName => ({
    tagName, textContent: '', className: '', hidden: false, value: '', disabled: false, children: [],
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
  });
  for (const id of ['zip-submit-form', 'zip-title', 'zip-reporter', 'zip-existing-id', 'zip-target', 'zip-file', 'zip-submit-button', 'zip-submit-result']) {
    nodes.set(id, makeElement(id === 'zip-target' ? 'select' : 'div'));
  }
  nodes.set('zip-submit-dialog', {
    open: false, showModal() { this.open = true; }, close() { this.open = false; },
  });
  nodes.get('zip-title').focus = () => { nodes.get('zip-title').focused = true; };
  nodes.get('zip-submit-form').reset = () => {
    nodes.get('zip-title').value = '';
    nodes.get('zip-reporter').value = '';
    nodes.get('zip-existing-id').value = '';
    nodes.get('zip-target').value = '';
    nodes.get('zip-file').files = [];
  };
  let targets = [{ track_id: 'rc', label: 'RC', version_id: '7.3-rc7', repo_commit: 'a'.repeat(40) }];
  let view = 'findings';
  const calls = [];
  const context = {
    document: { getElementById: id => nodes.get(id), createElement: makeElement },
    activeView: () => view,
    btoa: input => Buffer.from(input, 'binary').toString('base64'),
    api: async (path, options) => {
      calls.push({ path, options });
      if (path === '/api/submissions/upload-targets') return { json: async () => ({ targets }) };
      if (path === '/api/submissions/upload') return { json: async () => ({ submission_id: 'd'.repeat(64), status: 'pending' }) };
      throw new Error(`Unexpected URL: ${path}`);
    },
  };
  vm.runInNewContext(`
    const $ = id => document.getElementById(id);
    const element = (tag, className = '', text) => { const item = document.createElement(tag); item.className = className; if (text !== undefined) item.textContent = String(text); return item; };
    const clear = item => item.replaceChildren();
    const number = value => Number(value || 0).toLocaleString('ko-KR');
    const when = value => value || '—';
    ${source.slice(start, end)}
    globalThis.upload = { openZipDialog, loadUploadTargets, submitZip };
  `, context);
  await context.upload.openZipDialog();
  assert.equal(nodes.get('zip-submit-dialog').open, true);
  assert.equal(nodes.get('zip-title').focused, true);
  assert.match(nodes.get('zip-target').children[1].textContent, /RC · 7\.3-rc7/);
  nodes.get('zip-target').value = 'rc';
  nodes.get('zip-title').value = 'UAF in NFS';
  nodes.get('zip-reporter').value = '연구원';
  const zip = Buffer.from('PK\x03\x04evidence');
  nodes.get('zip-file').files = [{ name: 'evidence.zip', size: zip.length, arrayBuffer: async () => Uint8Array.from(zip).buffer }];
  await context.upload.submitZip({ preventDefault() {} });
  const posted = calls.find(call => call.path === '/api/submissions/upload');
  assert.equal(posted.options.method, 'POST');
  assert.equal(posted.options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(posted.options.body), {
    project: 'knfsd', title: 'UAF in NFS', reporter: '연구원', track_id: 'rc', zip_base64: zip.toString('base64'),
  });
  assert.match(nodes.get('zip-submit-result').children[0].textContent, /검증 대기/);
  assert.equal(nodes.get('zip-submit-result').children[1].textContent, 'd'.repeat(64));
  assert.equal(nodes.get('zip-submit-result').children[2].href, '?view=queue');
  const text = node => [node.textContent, ...node.children.map(text)].join(' ');

  nodes.get('zip-title').value = 'UAF with stronger primitive';
  nodes.get('zip-reporter').value = '연구원';
  nodes.get('zip-existing-id').value = 'A-043';
  nodes.get('zip-target').value = 'rc';
  nodes.get('zip-file').files = [{ name: 'evidence.zip', size: zip.length, arrayBuffer: async () => Uint8Array.from(zip).buffer }];
  await context.upload.submitZip({ preventDefault() {} });
  assert.equal(JSON.parse(calls.filter(call => call.path === '/api/submissions/upload')[1].options.body).existing_management_id, 'A-043');

  nodes.get('zip-title').value = 'invalid revision';
  nodes.get('zip-reporter').value = '연구원';
  nodes.get('zip-existing-id').value = 'A-43';
  await context.upload.submitZip({ preventDefault() {} });
  assert.match(text(nodes.get('zip-submit-result')), /A-001 형식/);
  assert.equal(calls.filter(call => call.path === '/api/submissions/upload').length, 2);

  nodes.get('zip-title').value = 'too large';
  nodes.get('zip-reporter').value = '연구원';
  nodes.get('zip-existing-id').value = '';
  nodes.get('zip-target').value = 'rc';
  nodes.get('zip-file').files = [{ name: 'too-large.zip', size: 8_000_001 }];
  await context.upload.submitZip({ preventDefault() {} });
  assert.match(text(nodes.get('zip-submit-result')), /8 MB 이하/);
  assert.equal(calls.filter(call => call.path === '/api/submissions/upload').length, 2);
  targets = [];
  await context.upload.loadUploadTargets();
  assert.equal(nodes.get('zip-submit-button').disabled, true);
  nodes.get('zip-submit-dialog').close();
  view = 'registry';
  await context.upload.openZipDialog();
  assert.equal(nodes.get('zip-submit-dialog').open, false);
});

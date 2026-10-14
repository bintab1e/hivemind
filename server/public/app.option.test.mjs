import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('long registry options open in a readable dialog without expanding the table row', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(html, /<dialog id="option-detail"[\s\S]*?id="option-detail-content"[\s\S]*?<\/dialog>/);
  assert.match(css, /\.registry-option-button\{[^}]*text-overflow:ellipsis;[^}]*white-space:nowrap/);
  assert.match(css, /\.option-dialog pre\{[^}]*white-space:pre-wrap;[^}]*overflow-wrap:anywhere/);

  const nodes = new Map();
  const makeElement = tagName => ({ tagName, className: '', textContent: '', children: [], listeners: {}, attributes: {},
    append(...children) { this.children.push(...children); },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
  });
  nodes.set('option-detail-title', makeElement('h2'));
  nodes.set('option-detail-content', makeElement('pre'));
  nodes.set('close-option-detail', makeElement('button'));
  nodes.set('option-detail', { open: false, showModal() { this.open = true; }, close() { this.open = false; } });
  const start = source.indexOf('function openOptionDetail(');
  const end = source.indexOf('function filteredFindings(', start);
  assert.ok(start > 0 && end > start);
  const context = { document: { getElementById: id => nodes.get(id), createElement: makeElement } };
  vm.runInNewContext(`
    const $ = id => document.getElementById(id);
    const state = { editingFindingId: null };
    const element = (tag, className = '', text) => {
      const item = document.createElement(tag);
      item.className = className;
      if (text !== undefined) item.textContent = String(text);
      return item;
    };
    ${source.slice(start, end)}
    ${source.match(/^\$\('close-option-detail'\).*$/m)[0]}
    globalThis.findingCell = findingCell;
  `, context);

  const option = 'CONFIG_NFSD=y, CONFIG_NFSD_V4=y, CONFIG_SUNRPC_XPRT_RDMA=y,\nKNSFD iWARP listener on TCP port 20049';
  const finding = { event_id: 'finding-43', management_id: 'A-043', title: 'RDMA bug', option };
  const cell = context.findingCell(finding, 'option');
  assert.equal(cell.className, 'registry-option-cell');
  assert.equal(cell.children[0].textContent, option);
  assert.equal(cell.children[0].attributes['aria-label'], 'A-043 옵션 전체 보기');
  cell.children[0].listeners.click();
  assert.equal(nodes.get('option-detail').open, true);
  assert.equal(nodes.get('option-detail-title').textContent, 'A-043 · 옵션');
  assert.equal(nodes.get('option-detail-content').textContent, option);
  nodes.get('close-option-detail').listeners.click();
  assert.equal(nodes.get('option-detail').open, false);

  const blank = context.findingCell({ ...finding, option: '' }, 'option');
  assert.equal(blank.textContent, '—');
  assert.equal(blank.children.length, 0);
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

function section(start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first);
  assert.ok(first >= 0 && last > first, `${start} section exists`);
  return source.slice(first, last);
}

function loadHelpers() {
  const controls = new Map([
    ['finding-search', { value: '' }],
    ['finding-target', { value: '' }],
    ['finding-report-status', { value: '' }],
    ['finding-privilege', { value: '' }],
    ['finding-owner', { value: '' }],
    ['finding-nfs-version', { value: '' }],
    ['finding-vulnerability-type', { value: '' }],
  ]);
  const context = {
    document: { getElementById: id => controls.get(id) },
    state: { findingSortKey: 'management_id', findingSortDir: 'asc' },
    previousFinding: () => null,
    agentName: () => '',
  };
  vm.runInNewContext(
    'const $ = id => document.getElementById(id);\n' +
    section('const impacts = [', 'const accessLabels =') +
    section('const findingFilters = [', 'const isRegistered =') +
    section('const isRegistered =', 'const needsVerification =') +
    section('const historicalNoOffset =', 'function isNewFinding') +
    section('const findingColumns = [', 'const editableFindingColumns =') +
    section('function filteredFindings(', 'function exportRegistryCsv(') +
    '\nglobalThis.csvHelpers = { registryCsv, registryCsvCell, filteredFindings };',
    context,
  );
  return { ...context.csvHelpers, controls, state: context.state };
}

function parseCsv(csv) {
  assert.equal(csv[0], '\uFEFF', 'UTF-8 BOM lets Excel detect Korean text');
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 1; i < csv.length; i += 1) {
    const char = csv[i];
    if (quoted) {
      if (char === '"' && csv[i + 1] === '"') { cell += '"'; i += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') {
      assert.equal(cell, '', 'quoted field starts at the beginning');
      quoted = true;
    } else if (char === ',') {
      row.push(cell);
      cell = '';
    } else if (char === '\r') {
      assert.equal(csv[++i], '\n', 'record separator is CRLF');
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      assert.notEqual(char, '\n', 'bare newline outside a quoted field');
      cell += char;
    }
  }
  assert.equal(quoted, false, 'all quotes close');
  assert.equal(row.length, 0, 'last record ends with CRLF');
  assert.equal(cell, '');
  return rows;
}

test('registry CSV preserves spreadsheet columns, Korean text, quoted data, and impact evidence', () => {
  const { registryCsv } = loadHelpers();
  const rows = parseCsv(registryCsv([
    {
      event_id: 'ganesha', origin: 'history', number: 2, management_id: 'B-002',
      title: '응답, "정리"\n메모리 누수', target: 'NFS-Ganesha', owner: '이진표',
      registration_status: 'history', verified_impacts: ['kasan_read', 'lpe'],
    },
    {
      event_id: 'new', origin: 'agent', management_id: 'A-043', title: '검증된 UAF',
      target: 'knfsd', registration_status: 'verified',
      verified_impacts: ['kasan_read', 'kasan_write', 'lpe'],
    },
    {
      event_id: 'static', origin: 'agent', management_id: 'A-044', title: '정적 검토 후보',
      target: 'knfsd', registration_status: 'verified', dynamic_status: 'not_run',
      verified_impacts: [], claimed_impacts: ['kasan_read'],
    },
  ]));
  assert.deepEqual(rows[0], [
    'No.', '관리 번호', '취약점 명', '대상', '옵션', '권한', '제보 프로젝트',
    '제보 여부', '담당자', 'NFS 버전', '취약점 유형', '방법론', '찾은 날짜',
    '익스플로잇', 'CVE', 'KASAN Read', 'KASAN Write', 'Controlled Read',
    'Controlled Write', 'LPE', 'RCE', 'Info Leak',
  ]);
  const index = label => rows[0].indexOf(label);
  assert.equal(rows[1][0], '44', 'historical No. keeps its global spreadsheet number');
  assert.equal(rows[1][index('취약점 명')], '응답, "정리"\n메모리 누수');
  assert.equal(rows[1][index('담당자')], '이진표');
  assert.equal(rows[1][index('KASAN Read')], '◇');
  assert.equal(rows[1][index('KASAN Write')], '—');
  assert.equal(rows[2][0], '2', 'new finding uses the filtered row ordinal');
  assert.equal(rows[2][index('KASAN Read')], '✓');
  assert.equal(rows[2][index('KASAN Write')], '✓');
  assert.equal(rows[2][index('LPE')], '✓');
  assert.equal(rows[2][index('RCE')], '—');
  assert.equal(rows[3][index('KASAN Read')], '◇', 'submitted evidence is distinct from server reproduction');
  assert.equal(rows[3][index('LPE')], '—');
});

test('registry CSV escapes spreadsheet formulas from finding data', () => {
  const { registryCsvCell } = loadHelpers();
  for (const value of ['=HYPERLINK("https://example.invalid")', '+SUM(1,2)', '-1+2', '@SUM(A1)', '  =1+1', '\t=1+1']) {
    assert.equal(parseCsv(`\uFEFF${registryCsvCell(value)}\r\n`)[0][0], `'${value}`);
  }
});

test('shared registry filtering and sorting export every matching row beyond the visible page', () => {
  const { registryCsv, filteredFindings, controls, state } = loadHelpers();
  const findings = Array.from({ length: 25 }, (_, index) => ({
    event_id: `item-${index}`, origin: 'agent', management_id: `A-${String(index + 43).padStart(3, '0')}`,
    title: `후보 ${String(index).padStart(2, '0')}`, target: index === 3 ? 'libnfs' : 'knfsd',
    report_status: '미제보', registration_status: 'verified',
  }));
  controls.get('finding-target').value = 'value:knfsd';
  controls.get('finding-search').value = '후보';
  state.findingSortKey = 'title';
  state.findingSortDir = 'desc';
  const selected = filteredFindings(findings);
  assert.equal(selected.length, 24, 'filtering happens before export');
  assert.equal(selected[0].title, '후보 24');
  assert.equal(selected.at(-1).title, '후보 00');
  const rows = parseCsv(registryCsv(selected));
  assert.equal(rows.length, 25, 'header plus all 24 rows, beyond the 20-row screen page');
  assert.equal(rows[1][0], '1');
  assert.equal(rows.at(-1)[0], '24');
  assert.ok(rows.every((row, index) => index === 0 || row[rows[0].indexOf('대상')] === 'knfsd'));
});

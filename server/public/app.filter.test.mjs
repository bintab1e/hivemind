import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

test('finding filters use registry fields, split comma values, and preserve selections', () => {
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const start = source.indexOf('const findingFilters = [');
  const end = source.indexOf('const isRegistered =', start);
  assert.ok(start >= 0 && end > start);
  const selects = new Map();
  const context = {
    document: {
      getElementById: id => selects.get(id),
      createElement: tagName => ({ tagName, value: '', textContent: '' }),
    },
  };
  vm.runInNewContext(
    source.slice(0, source.indexOf('const number =')) +
    source.slice(start, end) +
    '\nglobalThis.filters = { findingFilters, populateFindingFilters, matchesFindingFilters };',
    context,
  );
  const { findingFilters, populateFindingFilters, matchesFindingFilters } = context.filters;
  for (const [id] of findingFilters) {
    assert.match(html, new RegExp(`id="${id}"`));
    selects.set(id, {
      value: '',
      options: [],
      replaceChildren() { this.options = []; this.value = ''; },
      append(option) { this.options.push(option); },
    });
  }
  const rows = [
    { target: 'knfsd', report_status: '제보 완료', privilege: 'AUTH_SYS', owner: '이진표', nfs_version: '4.1, 4.2', vulnerability_type: 'Race, UAF' },
    { target: 'NFS-Ganesha', report_status: null, privilege: null, owner: null, nfs_version: '3 / NFSACL', vulnerability_type: 'Resource Leak' },
    { target: 'libnfs', report_status: '미제보', privilege: 'Raw ZDR caller', owner: '이진표', nfs_version: null, vulnerability_type: 'OOB Write' },
  ];
  populateFindingFilters(rows);
  assert.ok(selects.get('finding-nfs-version').options.some(option => option.textContent === '4.2'));
  assert.ok(selects.get('finding-nfs-version').options.some(option => option.textContent === '3'));
  assert.ok(!selects.get('finding-nfs-version').options.some(option => option.textContent === '3 / NFSACL'));
  assert.ok(selects.get('finding-vulnerability-type').options.some(option => option.textContent === 'UAF'));
  assert.ok(selects.get('finding-report-status').options.some(option => option.textContent === '미입력'));
  assert.equal(matchesFindingFilters(rows[0], [['nfs_version', 'value:4.2'], ['vulnerability_type', 'value:UAF'], ['report_status', 'value:제보 완료']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['report_status', 'missing'], ['owner', 'missing']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['nfs_version', 'value:3']]), true);
  assert.equal(matchesFindingFilters({ nfs_version: 'NFS/RDMA' }, [['nfs_version', 'value:NFS/RDMA']]), true);
  assert.equal(matchesFindingFilters(rows[1], [['nfs_version', 'value:4.2']]), false);
  selects.get('finding-target').value = 'value:knfsd';
  populateFindingFilters(rows);
  assert.equal(selects.get('finding-target').value, 'value:knfsd');
  populateFindingFilters(rows.slice(1));
  assert.equal(selects.get('finding-target').value, '');
});

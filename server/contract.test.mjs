import assert from 'node:assert/strict';
import test from 'node:test';
import { parseLcov } from './contract.mjs';

test('marked sparse LCOV reconstructs the full eligible range without zero-hit DA rows', () => {
  const dense = 'TN:agentcov\nSF:fs/nfsd/a.c\nDA:1,0\nDA:2,1\nDA:3,0\nDA:4,1\nLF:4\nLH:2\nend_of_record\n';
  const sparse = 'TN:hivemind-sparse-v1\nSF:fs/nfsd/a.c\nDA:2,1\nDA:4,1\nLH:2\nLF:4\nend_of_record\n';
  assert.deepEqual(parseLcov(sparse, '.'), parseLcov(dense, '.'));
  assert.deepEqual(parseLcov(`${sparse}TN:hivemind-sparse-v1\nSF:net/sunrpc/b.c\nLH:0\nLF:2\nend_of_record\n`, '.'), {
    'fs/nfsd/a.c': { total: 4, eligible: [1, 2, 3, 4], read: [2, 4] },
    'net/sunrpc/b.c': { total: 2, eligible: [1, 2], read: [] },
  });
});

test('sparse LCOV rejects missing markers and inconsistent or malformed reads', () => {
  const record = body => `TN:hivemind-sparse-v1\nSF:fs/nfsd/a.c\n${body}\nend_of_record\n`;
  for (const body of [
    'DA:1,0\nLH:0\nLF:2',
    'DA:1,1\nDA:1,1\nLH:2\nLF:2',
    'DA:3,1\nLH:1\nLF:2',
    'DA:1,1\nLH:0\nLF:2',
    'DA:1,1\nLF:2',
    'DA:1,1\nLH:1\nLF:2\nLF:2',
    'DA:1,1\nLH:1\nLF:2\nBRDA:1,0,0,1',
    'DA:1,1,checksum\nLH:1\nLF:2',
    'DA:1,999999999999999999999\nLH:1\nLF:2',
    'DA:1,1\nLH:1\nLF:2.0',
    'LH:0\nLF:2000001',
  ]) assert.throws(() => parseLcov(record(body), '.'), /LCOV/);
  assert.throws(() => parseLcov('TN:agentcov\nSF:fs/nfsd/a.c\nDA:1,1\nLF:2\nend_of_record\n', '.'), /LCOV/);
  assert.throws(() => parseLcov('TN:hivemind-sparse-v1\n', '.'), /LCOV/);
});

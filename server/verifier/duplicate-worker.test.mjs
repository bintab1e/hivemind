import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { duplicateConfiguration, duplicateWorkerId, runDuplicateReviewOnce } from './duplicate-worker.mjs';

const config = { socketPath: path.join(os.tmpdir(), 'hivemind-dedupe-test.sock'),
  cliPath: path.join(os.tmpdir(), 'codex'), workRoot: path.join(os.tmpdir(), 'hivemind-dedupe-work') };
const workerId = 'a'.repeat(32);
const job = { submission_id: 'b'.repeat(64), lease_token: 'c'.repeat(64),
  candidate: { target: 'knfsd', title: 'Finding', file_path: 'fs/nfsd/nfs4state.c',
    code_refs: [], report_excerpt: '## Root cause\nA concrete cause.', requested_management_id: null },
  references: [] };

test('worker configuration and identity are dedicated to duplicate review', () => {
  assert.deepEqual(duplicateConfiguration({ HIVEMIND_VERIFIER_SOCKET: config.socketPath,
    HIVEMIND_CODEX_CLI: config.cliPath, HIVEMIND_DEDUPE_WORK_ROOT: config.workRoot }), config);
  assert.equal(duplicateWorkerId(config, 'host'), duplicateWorkerId(config, 'host'));
  assert.notEqual(duplicateWorkerId(config, 'host'), duplicateWorkerId({ ...config,
    workRoot: path.join(os.tmpdir(), 'other') }, 'host'));
});

test('duplicate worker claims, heartbeats and completes without verifier model calls', async () => {
  const calls = [];
  const result = { verdict: 'new', matched_management_id: null, reason: 'No same root cause.' };
  assert.equal(await runDuplicateReviewOnce({ config, workerId,
    transport: async (_socket, endpoint, body) => {
      calls.push({ endpoint, body });
      return endpoint === '/dedupe/claim' ? { job } : {};
    },
    reviewer: async (candidate, references) => {
      assert.equal(candidate.title, 'Finding');
      assert.deepEqual(references, []);
      return result;
    },
  }), true);
  assert.deepEqual(calls.map(call => call.endpoint), ['/dedupe/heartbeat', '/dedupe/claim',
    '/dedupe/heartbeat', '/dedupe/complete', '/dedupe/heartbeat']);
  assert.deepEqual(calls.find(call => call.endpoint === '/dedupe/complete').body,
    { submission_id: job.submission_id, lease_token: job.lease_token, result });
});

test('model failures report only a bounded code, never private evidence', async () => {
  const calls = [];
  const privateText = 'private PoC and report content';
  await runDuplicateReviewOnce({ config, workerId,
    transport: async (_socket, endpoint, body) => {
      calls.push({ endpoint, body });
      return endpoint === '/dedupe/claim' ? { job } : {};
    },
    reviewer: async () => { throw new Error(privateText); },
  });
  const failed = calls.find(call => call.endpoint === '/dedupe/fail');
  assert.equal(failed.body.reason, 'duplicate_review_failed');
  assert.doesNotMatch(JSON.stringify(calls), new RegExp(privateText));
});

test('unknown completion outcome is retried without sending a conflicting failure', async () => {
  const calls = [];
  await assert.rejects(runDuplicateReviewOnce({ config, workerId,
    transport: async (_socket, endpoint) => {
      calls.push(endpoint);
      if (endpoint === '/dedupe/claim') return { job };
      if (endpoint === '/dedupe/complete') {
        const error = new Error('conflict'); error.status = 409; throw error;
      }
      return {};
    },
    reviewer: async () => ({ verdict: 'new', matched_management_id: null, reason: 'No match.' }),
  }), /conflict/);
  assert.equal(calls.filter(endpoint => endpoint === '/dedupe/complete').length, 1);
  assert.equal(calls.includes('/dedupe/fail'), false);
});

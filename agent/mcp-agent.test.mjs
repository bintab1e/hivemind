import assert from 'node:assert/strict';
import test from 'node:test';
import { handleMessage } from './mcp-agent.mjs';

test('MCP advertises raw submissions and rejects obsolete direct finding tools', async () => {
  const config = { repo_root: '/unused', home: '/unused', server: 'http://127.0.0.1:1' };
  const listed = await handleMessage(config, '', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const names = listed.result.tools.map(tool => tool.name);
  assert(names.includes('submit_vulnerability'));
  const submission = listed.result.tools.find(tool => tool.name === 'submit_vulnerability').inputSchema.properties;
  assert.equal(submission.existing_vulnerability_id.pattern, '^(V-\\d{6,}|A-\\d{3,})$');
  assert.equal(submission.existing_management_id.pattern, '^A-\\d{3,}$');
  assert.equal(submission.result_dir.type, 'string');
  assert(!names.includes('queue_finding'));
  assert(!names.includes('queue_finding_revision'));
  for (const name of ['queue_finding', 'queue_finding_revision']) {
    const call = await handleMessage(config, '', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: {} } });
    assert.equal(call.error.code, -32602);
  }
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { userspacePocError } from './contract.mjs';
import { handleMessage } from './mcp-agent.mjs';

test('MCP advertises raw submissions and rejects obsolete direct finding tools', async () => {
  const config = { repo_root: '/unused', home: '/unused', server: 'http://127.0.0.1:1' };
  const listed = await handleMessage(config, '', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const names = listed.result.tools.map(tool => tool.name);
  assert(names.includes('submit_vulnerability'));
  const submission = listed.result.tools.find(tool => tool.name === 'submit_vulnerability').inputSchema.properties;
  assert.equal(submission.existing_management_id.pattern, '^A-\\d{3,}$');
  assert.equal(submission.result_dir.type, 'string');
  assert(!names.includes('queue_finding'));
  assert(!names.includes('queue_finding_revision'));
  for (const name of ['queue_finding', 'queue_finding_revision']) {
    const call = await handleMessage(config, '', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: {} } });
    assert.equal(call.error.code, -32602);
  }
});

test('standalone PoC validation accepts common compiler and build-tool forms', () => {
  const source = 'int main(void) { return 0; }\n';
  for (const command of [
    '/usr/bin/gcc -o poc poc.c && ./poc',
    'x86_64-linux-gnu-gcc -o poc poc.c && ./poc',
    'CC=clang make poc && ./poc',
    'cmake --build build && ./build/poc',
    'ninja -C build poc && ./build/poc',
  ]) assert.equal(userspacePocError(source, command), null, command);
  assert.match(userspacePocError(source, './poc'), /컴파일/);
});

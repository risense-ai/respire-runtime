import assert from 'node:assert/strict';
import test from 'node:test';
import {validateMcpReply, validateMcpStatus, runRuntimeMcpProbe} from './runtime-mcp-probe.mjs';

test('MCP success cannot substitute a different request or JSON-RPC error', () => {
  assert.deepEqual(validateMcpReply({jsonrpc: '2.0', id: 'request', result: {}}, 'request'), {});
  for (const value of [{jsonrpc: '1.0', id: 'request', result: {}},
    {jsonrpc: '2.0', id: 'other', result: {}}, {jsonrpc: '2.0', id: 'request', error: {code: -1}},
    {jsonrpc: '2.0', id: 'request', result: null}]) {
    assert.throws(() => validateMcpReply(value, 'request'));
  }
});

test('real status envelope must bind the expected actor and preserve memory authority', () => {
  const health = {account_id: 'account', instance_id: 'instance', generation: 7};
  const envelope = {command: 'status', status: 'ok', errors: [], scope: health,
    request_id: 'request', operation_id: 'operation',
    memory_context: {memory_text_authority: 'untrusted_historical_context'},
    summary: {remote_configured: false, local_alive: 0}};
  const wrap = value => ({isError: false, content: [{type: 'text', text: JSON.stringify(value)}]});
  validateMcpStatus(wrap(envelope), health);
  for (const changed of [{...envelope, scope: {...health, generation: 8}},
    {...envelope, command: 'other'}, {...envelope, status: 'fail'}, {...envelope, errors: ['failure']},
    {...envelope, memory_context: {}}, {...envelope, operation_id: ''},
    {...envelope, summary: {remote_configured: true, local_alive: 0}}]) {
    assert.throws(() => validateMcpStatus(wrap(changed), health));
  }
  assert.throws(() => validateMcpStatus({...wrap(envelope), isError: true}, health));
});

test('probe refuses foreign endpoints before any request', async () => {
  for (const endpoint of ['https://127.0.0.1:15169', 'http://foreign.invalid:15169',
    'http://user:password@127.0.0.1:15169', 'http://127.0.0.1:15169/other']) {
    await assert.rejects(runRuntimeMcpProbe(endpoint, 'fixture', {}));
  }
});

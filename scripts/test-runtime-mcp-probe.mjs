import assert from 'node:assert/strict';
import test from 'node:test';
import {createServer} from 'node:http';
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

test('failed MCP probe retains only the actually passed checkpoint', {timeout: 10000}, async () => {
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body);
    const result = rpc.method === 'initialize'
      ? {protocolVersion: '2025-03-26', serverInfo: {name: 'respire-runtime', version: 'fixture'}, capabilities: {tools: {}}}
      : {tools: []};
    response.writeHead(200, {'Content-Type': 'application/json'});
    response.end(JSON.stringify({jsonrpc: '2.0', id: rpc.id, result}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const evidence = {};
    await assert.rejects(runRuntimeMcpProbe(`http://127.0.0.1:${server.address().port}`, 'fixture', {}, evidence));
    assert.deepEqual(evidence.case_results, [{test_id: 'runtime.mcp-initialize-tools-list', name: 'initialize', status: 'passed'}]);
    assert.equal(Object.hasOwn(evidence, 'cases'), false);
    assert.equal(evidence.initialize.http_status, 200);
    assert.equal(evidence['tools/list'].http_status, 200);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('probe refuses foreign endpoints before any request', async () => {
  for (const endpoint of ['https://127.0.0.1:15169', 'http://foreign.invalid:15169',
    'http://user:password@127.0.0.1:15169', 'http://127.0.0.1:15169/other']) {
    await assert.rejects(runRuntimeMcpProbe(endpoint, 'fixture', {}));
  }
});

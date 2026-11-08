import assert from 'node:assert/strict';

export function validateMcpReply(reply, id) {
  assert.equal(reply.jsonrpc, '2.0');
  assert.equal(reply.id, id);
  assert.equal(reply.error, undefined);
  assert.ok(reply.result && typeof reply.result === 'object');
  return reply.result;
}

export function validateMcpStatus(result, health) {
  assert.equal(result.isError, false);
  assert.ok(Array.isArray(result.content) && result.content.length === 1);
  assert.equal(result.content[0].type, 'text');
  const envelope = JSON.parse(result.content[0].text);
  assert.equal(envelope.command, 'status');
  assert.equal(envelope.status, 'ok');
  assert.deepEqual(envelope.errors, []);
  assert.deepEqual(envelope.scope, Object.fromEntries(
    ['account_id', 'instance_id', 'generation'].map(key => [key, health[key]])));
  for (const key of ['request_id', 'operation_id']) assert.ok(typeof envelope[key] === 'string' && envelope[key]);
  assert.equal(envelope.memory_context?.memory_text_authority, 'untrusted_historical_context');
  assert.equal(envelope.summary.remote_configured, false);
  assert.equal(envelope.summary.local_alive, 0);
  return envelope;
}

// Caller has verified the real process and native archive before invoking this.
// This is raw acceptance evidence, never a frozen-candidate/G1 certificate.
export async function runRuntimeMcpProbe(endpoint, version, health) {
  const url = new URL(endpoint);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/');
  assert.equal(url.username + url.password + url.search + url.hash, '');
  const evidence = {};
  async function call(method, params = {}) {
    const id = `runtime-mcp-${method}`;
    const request = {jsonrpc: '2.0', id, method, params};
    const response = await fetch(`${url.origin}/mcp`, {method: 'POST', redirect: 'error',
      headers: {'Content-Type': 'application/json', Accept: 'application/json'},
      body: JSON.stringify(request), signal: AbortSignal.timeout(30000)});
    const body = await response.text();
    evidence[method] = {request, http_status: response.status, body};
    assert.equal(response.status, 200);
    return validateMcpReply(JSON.parse(body), id);
  }
  const initialized = await call('initialize', {protocolVersion: '2025-03-26', capabilities: {},
    clientInfo: {name: 'runtime-native-regression', version: '1'}});
  assert.equal(initialized.protocolVersion, '2025-03-26');
  assert.equal(initialized.serverInfo?.name, 'respire-runtime');
  assert.equal(initialized.serverInfo?.version, version);
  assert.deepEqual(initialized.capabilities?.tools, {});
  const listed = await call('tools/list');
  assert.ok(Array.isArray(listed.tools) && listed.tools.length > 0);
  const names = listed.tools.map(tool => tool.name);
  assert.equal(new Set(names).size, names.length);
  for (const tool of listed.tools) {
    assert.match(tool.name, /^memory_[a-z_]+$/);
    assert.ok(typeof tool.description === 'string' && tool.description);
    assert.equal(tool.inputSchema?.type, 'object');
  }
  for (const name of ['memory_status', 'memory_remember', 'memory_recall']) assert.ok(names.includes(name));
  validateMcpStatus(await call('tools/call', {name: 'memory_status', arguments: {}}), health);
  const response = await fetch(`${url.origin}/api/health`, {redirect: 'error', signal: AbortSignal.timeout(5000)});
  assert.equal(response.status, 200);
  const after = await response.json();
  for (const key of ['pid', 'instance_id', 'process_start_id', 'image_sha256', 'runtime_version']) {
    assert.equal(after[key], health[key], `MCP changed the verified Runtime identity: ${key}`);
  }
  evidence.cases = ['initialize', 'tools/list', 'tools/call:memory_status', 'same-process-after-call'];
  return evidence;
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, join, posix, resolve, win32 } from "node:path";
import process from "node:process";
import { isDeepStrictEqual } from "node:util";

const root = resolve("contracts/runtime-control");

function fail(message) {
  throw new Error(message);
}

function readJSON(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`${path}: ${error.message}`);
  }
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fixturePath(name) {
  if (typeof name !== "string" || name.length === 0 || isAbsolute(name)) {
    fail(`invalid fixture name: ${String(name)}`);
  }
  const normalized = name.replaceAll("\\", "/");
  if (normalized.includes("..")) {
    fail(`fixture escapes contract root: ${name}`);
  }
  return join(root, normalized);
}

const manifestPath = join(root, "manifest.json");
const manifest = readJSON(manifestPath);
if (manifest.contract !== "runtime-control") fail("wrong contract");
if (manifest.contract_version !== 1) fail("wrong contract version");
if (manifest.release_metadata_schema_version !== 2) fail("wrong release metadata schema");

const positive = manifest.fixtures?.positive;
const negative = manifest.fixtures?.negative;
if (!Array.isArray(positive) || positive.length !== 89) fail("positive fixture count");
if (!Array.isArray(negative) || negative.length !== 287) fail("negative fixture count");

const boundPaths = new Set();
for (const bound of manifest.files ?? []) {
  if (typeof bound.path !== "string" || bound.path.includes("..")) {
    fail("invalid bound path");
  }
  const path = fixturePath(bound.path);
  if (boundPaths.has(bound.path)) fail(`duplicate bound path: ${bound.path}`);
  boundPaths.add(bound.path);
  if (sha256(path) !== bound.sha256) fail(`digest drift: ${bound.path}`);
}

for (const name of [...positive, ...negative]) {
  const normalized = name.replaceAll("\\", "/");
  if (!boundPaths.has(normalized)) fail(`fixture is not digest-bound: ${name}`);
  const fixture = readJSON(fixturePath(name));
  if (!fixture.fixture_type) fail(`${name}: missing fixture_type`);
  if (fixture.expected !== "accept" && fixture.expected !== "reject") {
    fail(`${name}: invalid expected state`);
  }
  if (fixture.expected === "reject" && typeof fixture.error_code !== "string") {
    fail(`${name}: rejection lacks error_code`);
  }
  if (fixture.fixture_type !== "release_metadata" && !fixture.payload) {
    fail(`${name}: missing payload`);
  }
}

const releaseV2 = readJSON(fixturePath(positive[0]));
const releaseV1 = readJSON(fixturePath(positive[1]));
if (releaseV2.payload.schema_version !== 2) fail("first positive fixture must be schema 2");
if (releaseV1.payload.schema_version !== 1) fail("second positive fixture must be schema 1");
if (releaseV2.payload.archive_sha256 === releaseV2.payload.binary_sha256) {
  fail("canonical fixture must not imply archive and binary hashes are interchangeable");
}
if (releaseV1.payload.sha256 !== releaseV1.payload.archive_sha256) {
  fail("legacy mapping must bind sha256 to archive_sha256");
}
if (releaseV1.payload.triple !== releaseV1.payload.target_triple) {
  fail("legacy mapping must bind triple to target_triple");
}

const identity = readJSON(fixturePath("fixtures/positive/health-identity.json"));
for (const key of [
  "installation_root",
  "installation_id",
  "instance_id",
  "pid",
  "process_start_id",
  "image_path",
  "image_sha256",
  "runtime_version",
  "account_id",
  "generation",
  "protocol_range",
  "capabilities",
  "store_ready",
  "state",
]) {
  if (!(key in identity.payload)) fail(`health identity lacks ${key}`);
}

// Fixture-only parsing and admission checks; no Runtime is started.
function scopeFailure(request, current) {
  const scope = request.scope;
  if (scope === undefined || scope === null) return "scope_required";
  if (typeof scope !== "object" || Array.isArray(scope) ||
      Object.keys(scope).sort().join(",") !== "account_id,generation,instance_id" ||
      typeof scope.account_id !== "string" || typeof scope.instance_id !== "string" ||
      !Number.isInteger(scope.generation) || scope.generation < 0) return "rpc_body_invalid";
  if (!scope.account_id.trim() || !scope.instance_id.trim() || scope.generation === 0 ||
      scope.account_id !== current.account_id || scope.instance_id !== current.instance_id ||
      scope.generation !== current.generation) return "scope_mismatch";
  return null;
}

const currentScope = Object.fromEntries(["account_id", "instance_id", "generation"]
  .map(key => [key, identity.payload[key]]));
const controlSchema = readJSON(fixturePath("schema/control-contract.schema.json"));

// Evaluate the standard schema keywords used by assets evidence; no native probe runs here.
function assetsSchemaValid(value, schema) {
  if (schema.$ref) return assetsSchemaValid(value,
    controlSchema.$defs[schema.$ref.replace("#/$defs/", "")]);
  if (schema.const !== undefined && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "object" && (!value || typeof value !== "object" || Array.isArray(value))) return false;
  if (schema.type === "array" && !Array.isArray(value)) return false;
  if (schema.type === "string" && typeof value !== "string") return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (schema.type === "integer" && !Number.isInteger(value)) return false;
  if (schema.minimum !== undefined && value < schema.minimum) return false;
  if (schema.maximum !== undefined && value > schema.maximum) return false;
  if (schema.minLength !== undefined && value.length < schema.minLength) return false;
  if (schema.pattern && !new RegExp(schema.pattern).test(value)) return false;
  if (schema.required?.some(key => !Object.hasOwn(value, key))) return false;
  if (schema.additionalProperties === false &&
      Object.keys(value).some(key => !Object.hasOwn(schema.properties, key))) return false;
  for (const [key, child] of Object.entries(schema.properties ?? {})) {
    if (Object.hasOwn(value, key) && !assetsSchemaValid(value[key], child)) return false;
  }
  if (schema.minItems !== undefined && value.length < schema.minItems) return false;
  if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
  if (schema.items && !value.every(item => assetsSchemaValid(item, schema.items))) return false;
  if (schema.uniqueItems && new Set(value.map(item => JSON.stringify(item))).size !== value.length) return false;
  if (schema.allOf?.some(child => !assetsSchemaValid(value, child))) return false;
  if (schema.not && assetsSchemaValid(value, schema.not)) return false;
  if (schema.if) {
    const branch = assetsSchemaValid(value, schema.if) ? schema.then : schema.else;
    if (branch && !assetsSchemaValid(value, branch)) return false;
  }
  return true;
}
function assetsFailure(payload) {
  if (!assetsSchemaValid(payload, controlSchema.$defs.assetsStatus)) return "assets_status_invalid";
  const evidence = payload.backend_load?.evidence;
  if (evidence && ((evidence.selected.startsWith("Npu: ") &&
      evidence.provider !== evidence.selected.slice(5)) ||
      new Set(evidence.modules.map(module => module.id)).size !== evidence.modules.length)) {
    return "assets_status_invalid";
  }
  return null;
}
if (!controlSchema.properties.fixture_type.enum.includes("assets_status") ||
    !controlSchema.allOf.some(rule => rule.if?.properties?.fixture_type?.const === "assets_status" &&
      rule.then?.properties?.payload?.$ref === "#/$defs/assetsStatus")) {
  fail("assets status schema is not bound to fixtures");
}
for (const name of [...positive, ...negative]) {
  const fixture = readJSON(fixturePath(name));
  if (fixture.fixture_type !== "assets_status") continue;
  const expected = fixture.expected === "accept" ? null : fixture.error_code;
  const actual = assetsFailure(fixture.payload);
  if (actual !== expected) fail(`${name}: assets rejection ${actual}, expected ${expected}`);
}
const loadedAssets = readJSON(fixturePath("fixtures/positive/assets-loaded.json")).payload;
// Every required success field must remain bound, including each nested identity.
for (const prefix of [[], ["runtime"], ["sdk_pin"], ["modules", 0]]) {
  let original = loadedAssets.backend_load.evidence;
  for (const key of prefix) original = original[key];
  for (const key of Object.keys(original)) {
    const changed = structuredClone(loadedAssets);
    let target = changed.backend_load.evidence;
    for (const part of prefix) target = target[part];
    delete target[key];
    if (!assetsFailure(changed)) fail(`missing probe evidence accepted: ${[...prefix, key].join(".")}`);
  }
}
for (const [selected, engine, provider, cpu_node_fallback] of [
  ["Gpu: DmlExecutionProvider", "gpu", "DmlExecutionProvider", "allowed"],
  ["Npu: OpenVINOExecutionProvider", "npu", "OpenVINOExecutionProvider", "disabled"],
  ["Host", "npu", "OpenVINOExecutionProvider", "host_managed"],
]) {
  const changed = structuredClone(loadedAssets);
  Object.assign(changed.backend_load.evidence, {selected, engine, provider, cpu_node_fallback});
  if (assetsFailure(changed)) fail(`valid selection rejected: ${selected}`);
  changed.backend_load.evidence.cpu_node_fallback = "not_applicable";
  if (!assetsFailure(changed)) fail(`fallback policy mismatch accepted: ${selected}`);
}
const scopeSchema = controlSchema.$defs?.runtimeRequestScope;
if (scopeSchema?.type !== "object" || scopeSchema.additionalProperties !== false ||
    [...(scopeSchema.required ?? [])].sort().join(",") !== "account_id,generation,instance_id" ||
    Object.keys(scopeSchema.properties ?? {}).sort().join(",") !== "account_id,generation,instance_id" ||
    scopeSchema.properties?.generation?.type !== "integer" ||
    scopeSchema.properties?.generation?.minimum !== 1 ||
    scopeSchema.properties?.account_id?.type !== "string" ||
    scopeSchema.properties?.account_id?.minLength !== 1 ||
    scopeSchema.properties?.account_id?.pattern !== "\\S" ||
    scopeSchema.properties?.instance_id?.type !== "string" ||
    scopeSchema.properties?.instance_id?.minLength !== 1 ||
    scopeSchema.properties?.instance_id?.pattern !== "\\S" ||
    controlSchema.$defs?.businessRpcRequest?.properties?.scope?.$ref !== "#/$defs/runtimeRequestScope" ||
    !controlSchema.$defs.businessRpcRequest.required?.includes("scope") ||
    !controlSchema.allOf?.some(rule =>
      rule.if?.properties?.fixture_type?.const === "business_rpc_request" &&
      rule.then?.properties?.payload?.$ref === "#/$defs/businessRpcRequest") ||
    !controlSchema.allOf?.some(rule =>
      rule.if?.properties?.fixture_type?.const === "operation_result" &&
      rule.then?.properties?.payload?.required?.includes("scope") &&
      rule.then.properties.payload.properties?.scope?.$ref === "#/$defs/runtimeRequestScope")) {
  fail("scope schema does not bind strict identity fields");
}
for (const name of [...positive, ...negative]) {
  const fixture = readJSON(fixturePath(name));
  if (fixture.fixture_type === "business_rpc_request") {
    const actual = scopeFailure(fixture.payload, currentScope);
    const expected = fixture.expected === "accept" ? null : fixture.error_code;
    if (actual !== expected) fail(`${name}: scope rejection ${actual}, expected ${expected}`);
    if (fixture.payload.v !== 1 || !fixture.payload.id || !fixture.payload.method) {
      fail(`${name}: invalid request envelope`);
    }
  }
  if (fixture.fixture_type === "operation_result" && scopeFailure(fixture.payload, currentScope)) {
    fail(`${name}: operation receipt lost its scope binding`);
  }
}
const submission = readJSON(fixturePath("fixtures/positive/business-rpc-scoped.json")).payload;
const resultQuery = readJSON(fixturePath("fixtures/positive/runtime-result-scoped.json")).payload;
if (resultQuery.id === submission.id || resultQuery.method !== "runtime.result" ||
    resultQuery.args[0] !== submission.operation_id) fail("result query lost transport/operation identity");

// Mirror CLI response bindings without starting Runtime or weakening its checker.
function same(left, right) {
  if (left && right && typeof left === "object" && typeof right === "object") {
    if (Array.isArray(left) !== Array.isArray(right)) return false;
    const keys = Object.keys(left).sort();
    return keys.join(",") === Object.keys(right).sort().join(",") &&
      keys.every(key => same(left[key], right[key]));
  }
  return left === right;
}
function responseFailure({request, response, cached_response: cached}) {
  if (response.v !== 1 || response.id !== request.id ||
      response.code === "protocol_version_mismatch") return "response_header_mismatch";
  if (!Number.isInteger(response.exit) || response.exit < 0 ||
      typeof response.ok !== "boolean" || response.ok !== (response.exit === 0)) {
    return "response_status_mismatch";
  }
  for (const [key, error] of [["operation_id", "response_operation_mismatch"],
    ["idempotency_key", "response_key_mismatch"]]) {
    if (key in response && response[key] !== request[key]) return error;
  }
  if (["scope_required", "scope_mismatch"].includes(response.code)) {
    if (response.ok || response.exit <= 0 ||
        (response.envelope && response.envelope.status !== "fail")) return "response_status_mismatch";
    if (response.scope != null &&
        scopeFailure({scope: response.scope}, response.scope) === "rpc_body_invalid") {
      return "response_scope_mismatch";
    }
    return null;
  }
  const receipt = request.method === "runtime.result" ? response.envelope?.summary : response;
  if (receipt?.operation_id !== request.operation_id) return "response_operation_mismatch";
  if (scopeFailure(receipt ?? {}, request.scope)) return "response_scope_mismatch";
  if ("idempotency_key" in receipt && receipt.idempotency_key !== request.idempotency_key) {
    return "response_key_mismatch";
  }
  if (request.method === "runtime.result") {
    if (receipt.request_id !== request.id) return "response_result_request_mismatch";
    if ("scope" in response && !same(response.scope, receipt.scope)) return "response_scope_mismatch";
  }
  if (cached && !same({...response, id: cached.id}, cached)) return "response_replay_mismatch";
  return null;
}
const responseSchema = controlSchema.$defs?.rpcResponse;
if (!controlSchema.properties.fixture_type.enum.includes("business_rpc_response") ||
    !controlSchema.allOf.some(rule =>
      rule.if?.properties?.fixture_type?.const === "business_rpc_response" &&
      rule.then?.properties?.payload?.$ref === "#/$defs/businessRpcResponseCase") ||
    !["v", "id", "ok", "exit"].every(key => responseSchema?.required.includes(key)) ||
    responseSchema.properties.scope?.$ref !== "#/$defs/runtimeRequestScope" ||
    responseSchema.properties.v?.const !== 1 ||
    !["request", "response"].every(key =>
      controlSchema.$defs.businessRpcResponseCase.required.includes(key))) {
  fail("response schema lost transport or scope binding");
}
for (const name of [...positive, ...negative]) {
  const fixture = readJSON(fixturePath(name));
  if (fixture.fixture_type !== "business_rpc_response") continue;
  const expected = fixture.expected === "accept" ? null : fixture.error_code;
  const actual = responseFailure(fixture.payload);
  if (actual !== expected) fail(`${name}: response rejection ${actual}, expected ${expected}`);
  const request = fixture.payload.request;
  if (scopeFailure(request, currentScope) || request.operation_id !== submission.operation_id ||
      request.idempotency_key !== submission.idempotency_key ||
      (request.method === "runtime.result" && request.args[0] !== submission.operation_id)) {
    fail(`${name}: response fixture lost original submission context`);
  }
}
for (const [scope, expected] of [
  [null, "scope_required"], [[], "rpc_body_invalid"],
  [{...currentScope, unexpected: true}, "rpc_body_invalid"],
  [{...currentScope, generation: "7"}, "rpc_body_invalid"],
  [{...currentScope, generation: -1}, "rpc_body_invalid"],
  [{...currentScope, generation: 0}, "scope_mismatch"],
  [{...currentScope, instance_id: " "}, "scope_mismatch"],
]) {
  if (scopeFailure({scope}, currentScope) !== expected) fail("scope mutation was not rejected");
}
if (scopeFailure({...currentScope}, currentScope) !== "scope_required") {
  fail("flattened identity must not replace top-level scope");
}
for (const key of Object.keys(currentScope)) {
  const incomplete = {...currentScope};
  delete incomplete[key];
  if (scopeFailure({scope: incomplete}, currentScope) !== "rpc_body_invalid") {
    fail(`missing scope member accepted: ${key}`);
  }
}

// Stage-one summaries describe existing paths, not the future split-root layout.
const rootFields = [
  "installation_root", "device_config_root", "client_config_path", "account_data_root",
  "accounts_root", "asset_root", "runtime_state_root",
];
function rootsFailure(roots) {
  if (!roots || roots.schema_version !== 1 || roots.layout !== "phase1" ||
      typeof roots.legacy_whole_isolation !== "boolean" ||
      rootFields.some(key => typeof roots[key] !== "string" || !roots[key]) ||
      !roots.sources || Array.isArray(roots.sources) ||
      Object.keys(roots.sources).sort().join(",") !== [...rootFields].sort().join(",") ||
      Object.keys(roots).some(key => ![...rootFields, "schema_version", "layout",
        "legacy_whole_isolation", "sources", "log_root"].includes(key))) return "root_layout_invalid";
  const path = /^[A-Za-z]:[\\/]/.test(roots.installation_root) ||
    roots.installation_root.startsWith("\\\\") ? win32 : posix;
  const equal = (left, right) => path.normalize(left) === path.normalize(right);
  const within = (root, child) => {
    const relative = path.relative(root, child);
    return relative === "" || (!path.isAbsolute(relative) && relative !== ".." &&
      !relative.startsWith(".." + path.sep));
  };
  if (rootFields.some(key => !path.isAbsolute(roots[key]) ||
      roots[key].split(/[\\/]/).includes(".."))) return "root_layout_invalid";
  const source = roots.legacy_whole_isolation ? "RSRS_DATA_DIR" : "default_data_dir";
  for (const key of rootFields) {
    const allowed = [source];
    if (key === "account_data_root") allowed.push("client.json:data_dir");
    if (key === "asset_root") allowed.push("RSRS_M3_DIR");
    if (!allowed.includes(roots.sources[key])) return "root_source_invalid";
  }
  const root = roots.installation_root;
  const wrongLayout = !equal(roots.device_config_root, root) ||
    !equal(roots.client_config_path, path.join(root, "client.json")) ||
    !equal(roots.accounts_root, path.join(root, "accounts")) ||
    !equal(roots.runtime_state_root, path.join(root, "runtime")) ||
    (roots.sources.asset_root !== "RSRS_M3_DIR" &&
      !equal(roots.asset_root, path.join(root, "models", "bge-m3"))) ||
    (roots.sources.account_data_root !== "client.json:data_dir" &&
      !equal(roots.account_data_root, root)) ||
    (roots.legacy_whole_isolation && !within(root, roots.account_data_root));
  if (wrongLayout) return roots.legacy_whole_isolation ?
    "legacy_root_semantic_conflict" : "root_layout_invalid";
  // Retained only for old fixture consumers; the summary itself has no shared log root.
  if (roots.log_root !== undefined && !equal(roots.log_root, path.join(root, "client2"))) {
    return "root_layout_invalid";
  }
  return null;
}
const rootSchema = controlSchema.allOf.find(rule =>
  rule.if?.properties?.fixture_type?.const === "root_layout")?.then?.properties?.payload;
if (rootSchema?.properties?.layout?.const !== "phase1" ||
    rootSchema.properties.schema_version?.const !== 1 ||
    rootSchema.additionalProperties !== false ||
    !rootFields.every(key => rootSchema.required?.includes(key) &&
      rootSchema.properties?.[key]?.type === "string" &&
      rootSchema.properties.sources?.required?.includes(key)) ||
    !rootSchema.required.includes("sources") ||
    !rootSchema.required.includes("legacy_whole_isolation") ||
    rootSchema.properties.sources?.additionalProperties !== false ||
    rootSchema.required.includes("log_root") || rootSchema.properties.summary_sha256) {
  fail("root schema must describe phase-one actual roots without a fabricated summary hash");
}
for (const name of [...positive, ...negative]) {
  const fixture = readJSON(fixturePath(name));
  if (fixture.fixture_type !== "root_layout") continue;
  const expected = fixture.expected === "accept" ? null : fixture.error_code;
  const actual = rootsFailure(fixture.payload);
  if (actual !== expected) fail(name + ": root rejection " + actual + ", expected " + expected);
}
const rootSummary = readJSON(fixturePath("fixtures/positive/root-layout.json")).payload;
const bareSummary = {...rootSummary};
delete bareSummary.log_root;
if (rootsFailure(bareSummary)) fail("actual summary must not require a synthetic log root");
for (const mutation of [
  {device_config_root: rootSummary.installation_root + "/config"},
  {client_config_path: rootSummary.installation_root + "/config/client.json"},
  {account_data_root: rootSummary.installation_root + "-sibling/accounts/a"},
  {account_data_root: rootSummary.installation_root + "/accounts/../../escape"},
  {accounts_root: rootSummary.account_data_root + "/accounts"},
  {runtime_state_root: rootSummary.account_data_root + "/runtime"},
  {asset_root: rootSummary.installation_root + "/models"},
  {sources: {...rootSummary.sources, client_config_path: "unknown"}},
  {sources: {...rootSummary.sources, account_data_root: "RSRS_DATA_DIR"}},
  {summary_sha256: "5".repeat(64)},
]) {
  if (!rootsFailure({...bareSummary, ...mutation})) fail("root mutation was not rejected");
}
for (const root of ["/tmp/isolated/.rsrs", "C:/isolated/.rsrs"]) {
  const portable = {...bareSummary, installation_root: root, device_config_root: root,
    client_config_path: root + "/client.json", account_data_root: root + "/accounts/a",
    accounts_root: root + "/accounts", asset_root: root + "/models/bge-m3",
    runtime_state_root: root + "/runtime"};
  if (rootsFailure(portable)) fail("portable root fixture rejected: " + root);
  const splitModel = {...portable, asset_root: root + "-assets/bge-m3",
    sources: {...portable.sources, asset_root: "RSRS_M3_DIR"}};
  if (rootsFailure(splitModel)) fail("explicit model source must remain visible");
  if (!rootsFailure({...splitModel, sources: portable.sources})) {
    fail("model root cannot escape legacy isolation without an explicit source");
  }
}

const stop = readJSON(fixturePath("fixtures/negative/stop-ambiguous-ok.json"));
if (stop.payload.state !== "drained" || !stop.payload.unfinished?.length) {
  fail("ambiguous stop fixture no longer demonstrates the forbidden state");
}

const finalStop = readJSON(fixturePath("fixtures/positive/stop-final-drained.json")).payload;
for (const key of [
  "installation_id", "instance_id", "pid", "process_start_id", "image_path",
  "image_sha256", "runtime_version", "account_id", "generation",
]) {
  if (finalStop[key] !== identity.payload[key]) fail(`final stop identity differs: ${key}`);
}
if (finalStop.schema_version !== 1 || finalStop.protocol_version !== 1 ||
    !finalStop.operation_id || finalStop.state !== "drained" ||
    !Array.isArray(finalStop.unfinished) || finalStop.unfinished.length !== 0) {
  fail("final stop fixture must prove a traceable complete drain");
}
const incompleteStop = readJSON(fixturePath("fixtures/negative/stop-final-unfinished.json"));
if (incompleteStop.error_code !== "drain_incomplete" ||
    incompleteStop.payload.state !== "drained" || !incompleteStop.payload.unfinished?.length) {
  fail("final stop negative fixture no longer demonstrates incomplete drain");
}

function terminalStopFailure(payload) {
  if (!["drained", "forced_timeout", "compatibility_timeout", "failed", "unknown"].includes(payload.state) ||
      !Array.isArray(payload.unfinished) || payload.unfinished.some(operation =>
        typeof operation.operation_id !== "string" || !operation.operation_id ||
        !["aborted", "unknown"].includes(operation.result))) return "stop_outcome_invalid";
  return payload.state === "drained" && payload.unfinished.length ? "drain_incomplete" : null;
}
if (terminalStopFailure(finalStop)) fail("valid drained receipt rejected");
for (const state of ["forced_timeout", "compatibility_timeout"]) {
  const path = `fixtures/positive/stop-final-${state.replaceAll("_", "-")}.json`;
  const fixture = readJSON(fixturePath(path));
  if (fixture.expected !== "accept" || fixture.payload.state !== state ||
      !fixture.payload.unfinished.length || terminalStopFailure(fixture.payload)) {
    fail("timeout receipt must retain explicit unfinished outcomes");
  }
  for (const key of ["installation_id", "instance_id", "pid", "process_start_id", "image_path",
    "image_sha256", "runtime_version", "account_id", "generation"]) {
    if (fixture.payload[key] !== identity.payload[key]) fail(`timeout receipt identity differs: ${key}`);
  }
}
const fabricatedStop = readJSON(fixturePath("fixtures/negative/stop-final-fabricated-completion.json"));
if (fabricatedStop.expected !== "reject" || fabricatedStop.error_code !== "stop_outcome_invalid" ||
    terminalStopFailure(fabricatedStop.payload) !== fabricatedStop.error_code ||
    terminalStopFailure(incompleteStop.payload) !== incompleteStop.error_code) {
  fail("unsafe terminal stop outcomes must be rejected");
}

const conflict = readJSON(fixturePath("fixtures/negative/idempotency-conflict.json"));
if (conflict.error_code !== "idempotency_conflict") fail("idempotency fixture drifted");
if (!conflict.payload.idempotency_key) fail("idempotency fixture lacks key");

const route = readJSON(fixturePath("fixtures/positive/bootstrap-route.json"));
if (route.payload.operation.startsWith("auth.") && route.payload.executor !== "cli") {
  fail("identity operation must route to CLI");
}

const contract = readFileSync(resolve("docs/runtime-control-contract.md"), "utf8");
for (const target of [
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-msvc",
]) {
  if (!contract.includes(target)) fail(`compatibility contract omits ${target}`);
}

const hostSchema = readJSON(fixturePath("schema/private-host-control.schema.json"));
if (!boundPaths.has("schema/private-host-control.schema.json")) fail("private host schema is not digest-bound");
if (!boundPaths.has("consumers/private_host_control.rs")) fail("shared Rust consumer is not digest-bound");
for (const marker of ["private-host-control.schema.json", "awaiting_verification", "snapshot-restore-v1", "Terminal history"]) {
  if (!contract.includes(marker)) fail(`private host contract omits ${marker}`);
}

// Only the keywords used by this frozen schema are evaluated. Context fields
// declare test inputs, not proof of a consumed grant or a live process.
function hostSchemaValid(value, schema, definitions = hostSchema.$defs) {
  if (schema.$ref) return hostSchemaValid(value, definitions[schema.$ref.slice("#/$defs/".length)], definitions);
  if (schema.allOf?.some(child => !hostSchemaValid(value, child, definitions))) return false;
  if (schema.not && hostSchemaValid(value, schema.not, definitions)) return false;
  if (schema.if) {
    const branch = hostSchemaValid(value, schema.if, definitions) ? schema.then : schema.else;
    if (branch && !hostSchemaValid(value, branch, definitions)) return false;
  }
  if (schema.anyOf && !schema.anyOf.some(child => hostSchemaValid(value, child, definitions))) return false;
  if (schema.oneOf && schema.oneOf.filter(child => hostSchemaValid(value, child, definitions)).length !== 1) return false;
  if (Object.hasOwn(schema, "const") && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "null" && value !== null) return false;
  if (schema.type === "object" && (!value || typeof value !== "object" || Array.isArray(value))) return false;
  if (schema.type === "array" && !Array.isArray(value)) return false;
  if (schema.type === "string" && typeof value !== "string") return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (schema.type === "integer" && !Number.isSafeInteger(value)) return false;
  if (schema.minimum !== undefined && value < schema.minimum) return false;
  if (schema.maximum !== undefined && value > schema.maximum) return false;
  if (schema.minLength !== undefined && value.length < schema.minLength) return false;
  if (schema.maxLength !== undefined && value.length > schema.maxLength) return false;
  if (schema.pattern && !new RegExp(schema.pattern).test(value)) return false;
  if (schema.required?.some(key => !Object.hasOwn(value, key))) return false;
  if (schema.additionalProperties === false && Object.keys(value).some(key => !Object.hasOwn(schema.properties, key))) return false;
  for (const [key, child] of Object.entries(schema.properties ?? {})) {
    if (Object.hasOwn(value, key) && !hostSchemaValid(value[key], child, definitions)) return false;
  }
  if (schema.minItems !== undefined && value.length < schema.minItems) return false;
  if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
  if (schema.items && !value.every(item => hostSchemaValid(item, schema.items, definitions))) return false;
  if (schema.uniqueItems && new Set(value.map(item => JSON.stringify(item))).size !== value.length) return false;
  return true;
}

function configFixtureFailure(params, context) {
  if (!context || !hostSchemaValid(context, hostSchema.$defs.configContext)) return "config_context_mismatch";
  const digest = text => text == null ? null : createHash("sha256").update(text, "utf8").digest("hex");
  if ((params.original_config ?? null) !== context.original_config ||
      (params.original_revision ?? null) !== context.original_revision ||
      digest(params.original_config) !== (params.original_revision ?? null) ||
      params.candidate_revision !== context.candidate_revision ||
      context.candidate_config !== context.reviewed_candidate_config ||
      digest(context.candidate_config) !== params.candidate_revision) return "config_revision_mismatch";
  if (params.target_profile !== params.binding.profile || params.source_profile !== context.source_profile ||
      params.target_profile !== context.target_profile || !isDeepStrictEqual(params.source_identity, context.source_identity) ||
      !isDeepStrictEqual(params.identity, context.target_identity)) return "config_context_mismatch";
  let original, candidate;
  try { original = params.original_config == null ? {} : JSON.parse(params.original_config); candidate = JSON.parse(context.candidate_config); }
  catch { return "config_intent_mismatch"; }
  if (!original || typeof original !== "object" || Array.isArray(original)) return "config_intent_mismatch";
  const expected = structuredClone(original);
  for (const key of ["data_dir", "addr", "autosync", "cure_auto", "rpc_parallelism"]) {
    let value = params.intent[key];
    if (value == null) continue;
    if (key === "data_dir" || key === "addr") value = value.trim();
    if (key === "data_dir" && value === "" || key === "rpc_parallelism" && value === 0) delete expected[key];
    else expected[key] = value;
  }
  return isDeepStrictEqual(candidate, expected) ? null : "config_intent_mismatch";
}

function fixedWriteModelFailure(payload, params, kind) {
  if (!["identityWriteResult", "keyResult", "modelMaintenanceReceipt"].includes(kind)) return null;
  const result = payload.result, binding = params.binding;
  if (kind !== "modelMaintenanceReceipt") {
    const context = payload.write_context;
    if (!context || !hostSchemaValid(context, hostSchema.$defs.writeContext) ||
        context.installation_root !== binding.installation_root || context.profile !== binding.profile ||
        !isDeepStrictEqual(context.source_identity, params.source_identity) ||
        !isDeepStrictEqual(context.operation, params.operation) ||
        context.operation_id !== payload.request.operation_id || context.idempotency_key !== payload.request.idempotency_key) return "write_context_mismatch";
    const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
    const fingerprint = createHash("sha256").update(JSON.stringify(canonical({schema_version: 1,
      method: kind === "keyResult" ? "control.key" : "control.identity.write", root: context.installation_root,
      profile: context.profile, source_identity: context.source_identity, operation: context.operation}))).digest("hex");
    if (result.fingerprint !== fingerprint || context.fingerprint !== fingerprint) return "host_fingerprint_mismatch";
    if (!isDeepStrictEqual(result.operation, params.operation)) return "write_context_mismatch";
    const before = params.identity, after = result.identity;
    if ((binding.expected_account_id ?? null) !== (before.kind === "bound" ? before.account_id : null)) return "write_identity_mismatch";
    const full = kind === "identityWriteResult" && params.operation.kind === "logout" && params.operation.full;
    if (after.kind === "absent" ? before.kind !== "absent" && !full :
        before.kind !== after.kind || (after.kind === "bound" ? before.account_id !== after.account_id : before.operation_id !== after.operation_id)) return "write_identity_mismatch";
    if (kind === "identityWriteResult") {
      if (result.path !== binding.profile + "/session.json" ||
          (result.session_sha256 ?? null) !== (after.session_sha256 ?? null) ||
          full && result.outcome === "committed" && after.kind !== "absent" ||
          params.operation.kind === "logout" && result.revoke != null ||
          params.operation.kind === "session_revoke" && (result.revoke != null && result.revoke.session_id.toLowerCase() !== params.operation.session_id.toLowerCase() ||
            result.outcome === "committed" && result.revoke == null)) return "write_identity_mismatch";
    } else {
      if (result.verification_required === true || result.source_profile !== binding.profile || result.target_profile != null && result.target_profile !== binding.profile ||
          result.outcome === "committed" && (result.target_profile !== binding.profile || after.kind !== "bound" ||
            result.account_id !== after.account_id || result.session_sha256 !== after.session_sha256 || !result.super_password) ||
          result.outcome !== "committed" && (result.super_password != null || result.account_id != null || result.session_sha256 != null) ||
          (result.outcome === "awaiting_input") !== (result.required_inputs.length > 0)) return "write_identity_mismatch";
    }
  } else {
    if (params.phase !== "plan" && !isDeepStrictEqual(params.expected, result.plan.review)) return "model_review_mismatch";
    if (result.plan.kind !== params.kind || result.phase !== params.phase || result.verified !== (params.phase !== "plan") ||
        result.config_applied !== (params.phase === "apply") ||
        params.kind === "reset_cpu" && (!result.plan.cpu_candidate_sha256 || result.plan.preparation != null || result.plan.catalog != null || result.plan.uninstall_directory != null) ||
        params.kind === "uninstall_m3" && (!result.plan.uninstall_directory || result.plan.cpu_candidate_sha256 != null || result.plan.preparation != null || result.plan.catalog != null) ||
        params.kind === "install_engines" && (result.plan.uninstall_directory != null || result.plan.cpu_candidate_sha256 != null ||
          (result.plan.preparation == null) !== (result.plan.catalog == null) || result.plan.catalog != null &&
          result.plan.catalog.destination !== binding.installation_root + "/engines/winml-2.4.89/Microsoft.Windows.AI.MachineLearning.dll")) return "model_receipt_mismatch";
  }
  const model = kind === "modelMaintenanceReceipt", envelope = model ? payload.public_response : payload.private_response;
  const rule = model ? "modelMaintenanceEnvelope" : kind === "keyResult" ? "keyEnvelope" : "identityWriteEnvelope";
  const status = model ? "ok" : result.outcome === "unknown" ? "fail" : ["pending", "awaiting_input"].includes(result.outcome) ? "pending" : "ok";
  if (!envelope || !hostSchemaValid(envelope, hostSchema.$defs[rule]) || envelope.status !== status ||
      !isDeepStrictEqual(model ? envelope.details : envelope.summary, result) || model &&
      !isDeepStrictEqual(envelope.summary, {kind: params.kind, phase: params.phase, verified: result.verified})) return "host_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const matching = envelope.items.filter(item => item.name === name);
    if (matching.length !== 1 || matching[0].status !== status || matching[0].value !== value) return "host_result_invalid";
  }
  return null;
}

// Fixture contexts are evidence anchors, never capabilities or native execution.
function keyMigrationFailure(payload, params, kind) {
  const request = payload.request, result = payload.result, binding = params.binding;
  const same = isDeepStrictEqual;
  const hash = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  if (kind === "keyResult" && params.operation.kind === "fivekeys") {
    const context = payload.key_context, write = payload.write_context;
    if (!context || !hostSchemaValid(context, hostSchema.$defs.keyContext) ||
        !write || !hostSchemaValid(write, hostSchema.$defs.writeContext) ||
        write.installation_root !== binding.installation_root || !same(write.source_identity, params.source_identity) ||
        !same(write.operation, params.operation) || write.operation_id !== request.operation_id ||
        write.idempotency_key !== request.idempotency_key || binding.profile !== context.launch_profile ||
        !same(params.identity, context.launch_identity)) return "write_context_mismatch";
    const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
    const fingerprint = hash(canonical({schema_version: 1, method: "control.key", root: write.installation_root,
      profile: write.profile, source_identity: write.source_identity, operation: write.operation}));
    if (write.fingerprint !== fingerprint || result.fingerprint !== fingerprint) return "host_fingerprint_mismatch";
    if (!same(result.operation, params.operation) || result.source_profile !== write.profile ||
        !same(result.identity, context.selected_identity) ||
        (binding.expected_account_id ?? null) !== (params.identity.kind === "bound" ? params.identity.account_id : null)) return "write_identity_mismatch";
    const applied = result.verification_required === true || result.outcome === "committed";
    if (result.super_password != null || result.required_inputs.some(field => !["password", "super_password", "account_secret", "totp"].includes(field))) return "private_secret_exposure";
    if (applied) {
      const account = createHash("sha256").update(params.operation.user).digest("hex");
      if (result.target_profile !== context.target_profile || context.selected_profile !== context.target_profile ||
          !same(result.identity, context.target_identity) || result.identity.kind !== "bound" ||
          result.account_id !== account || result.identity.account_id !== account ||
          result.session_sha256 !== result.identity.session_sha256 || result.required_inputs.length ||
          (result.verification_required === true ? result.outcome !== "pending" : result.outcome !== "committed") ||
          (result.outcome === "committed" && !context.verified) ||
          ![write.profile, context.target_profile].includes(binding.profile)) return "write_identity_mismatch";
    } else if (result.account_id != null || result.session_sha256 != null ||
        !same(result.identity, params.source_identity) || context.selected_profile !== write.profile ||
        (result.outcome === "awaiting_input") !== (result.required_inputs.length > 0)) return "write_identity_mismatch";
    if (request.method === "control.key.complete" && (!applied || result.outcome !== "committed" || result.verification_required === true || !context.verified ||
        binding.profile !== context.target_profile || !same(params.identity, context.target_identity) || params.input != null)) return "key_completion_mismatch";
    if (context.input_state === "initial" && request.method === "control.key.fivekeys" && params.input?.password == null &&
        !(result.outcome === "awaiting_input" && result.required_inputs.includes("password"))) return "key_input_mismatch";
    if (context.input_state === "continuation" && (payload.original_operation_id !== request.operation_id ||
        !params.input || typeof params.input.totp !== "string")) return "key_input_mismatch";
  } else if (kind === "migrationResult") {
    const original = params.original, context = payload.migration_context;
    if (!context || !hostSchemaValid(context, hostSchema.$defs.migrationContext)) return "migration_context_mismatch";
    if (original.operation_id !== request.operation_id || original.key !== request.idempotency_key || original.key !== original.operation_id) return "host_operation_mismatch";
    if (original.installation_root !== binding.installation_root || original.profile !== binding.profile ||
        !same(original.identity, params.identity) || !same(result.identity, original.identity) ||
        (binding.expected_account_id ?? null) !== (original.identity.kind === "bound" ? original.identity.account_id : null) ||
        original.source_id !== context.source_id || original.account !== context.account) return "migration_context_mismatch";
    const identity = original.identity.kind === "bound" ? {kind: "bound", account_id: original.identity.account_id, session_sha256: original.identity.session_sha256}
      : original.identity.kind === "unbound" ? {kind: "unbound", operation_id: original.identity.operation_id, session_sha256: original.identity.session_sha256} : {kind: "absent"};
    const fingerprint = hash([1, "control.migration.profile", original.installation_root, original.profile, identity, original.source_id, original.account]);
    if (original.fingerprint !== fingerprint || result.fingerprint !== fingerprint || context.fingerprint_preimage !== JSON.stringify([1,
        "control.migration.profile", original.installation_root, original.profile, identity, original.source_id, original.account])) return "host_fingerprint_mismatch";
    const destination = original.installation_root + "/accounts/" + original.account, marker = context.marker;
    if (result.outcome === "completed") {
      if (context.publication !== "bound" || !marker || !same(marker.control, original) || marker.schema !== 2 ||
          marker.complete !== true || marker.namespace_migrated !== true || marker.original_preserved !== true ||
          marker.source_identity !== original.source_id || marker.source !== context.source || marker.destination !== destination ||
          !same(marker.control_result, result.details) || !same(result.details, {state: "migrated", account: original.account,
            dir: destination, source: context.source, original_preserved: true})) return "migration_marker_mismatch";
    } else if (result.outcome === "already_migrated") {
      if (request.method !== "control.migration.profile" || context.publication !== "legacy_unbound" || !marker ||
          marker.control != null || marker.complete !== true || marker.source_identity !== original.source_id ||
          result.details.state !== "already_migrated" || result.details.dir !== marker.destination) return "migration_marker_mismatch";
    } else if (result.details !== null || context.publication === "bound") return "migration_marker_mismatch";
  } else return null;
  const rule = kind === "migrationResult" ? "migrationEnvelope" : "keyEnvelope", envelope = payload.private_response;
  const status = result.outcome === "unknown" ? "fail" : ["pending", "awaiting_input"].includes(result.outcome) ? "pending" : "ok";
  if (!envelope || !hostSchemaValid(envelope, hostSchema.$defs[rule]) || envelope.status !== status ||
      !same(envelope.summary, result)) return "host_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const items = envelope.items.filter(item => item.name === name);
    if (items.length !== 1 || items[0].status !== status || items[0].value !== value) return "host_result_invalid";
  }
  if (payload.progress != null || payload.ledger != null) return "private_secret_exposure";
  return null;
}

// Fixture contexts are inputs, not grants, production journals, or native proof.
function profileRecoveryFailure(payload, params, kind) {
  const profile = kind === "profileResult";
  if (!profile && kind !== "recoveryResult") return null;
  const context = payload[profile ? "profile_context" : "recovery_context"];
  if (!context || !hostSchemaValid(context, hostSchema.$defs[profile ? "profileContext" : "recoveryContext"])) return "profile_recovery_context_mismatch";
  const {request, result} = payload, binding = params.binding, authority = context.authority;
  const same = isDeepStrictEqual, statusRead = request.method === "control.auth.recovery_status";
  if (authority.installation_root !== binding.installation_root || authority.profile !== binding.profile || authority.launch_id !== binding.launch_id ||
      !same(authority.identity, params.identity) ||
      (binding.expected_account_id ?? null) !== (params.identity.kind === "bound" ? params.identity.account_id : null)) return "profile_recovery_binding_mismatch";
  if (authority.grant_maintenance !== (statusRead ? "none" : "Paused") || authority.owns_auth !== !statusRead ||
      authority.serving_authorized !== false || ["parent_verified", "binding_verified_before"].some(key => authority[key] !== true) ||
      (profile || statusRead) && authority.binding_verified_after !== true) return "profile_recovery_authority_mismatch";
  if (payload.history != null || payload.original_fingerprint != null || !profile && payload.original_operation_id != null ||
      payload[profile ? "recovery_context" : "profile_context"] != null) return "host_request_invalid";
  if (profile) {
    const original = params.original;
    if (original.operation_id !== request.operation_id || original.key !== request.idempotency_key || original.key !== original.operation_id) return "host_operation_mismatch";
    if (original.installation_root !== binding.installation_root || original.profile !== binding.profile ||
        !same(original.identity, params.identity) || !same(result.identity, original.identity)) return "profile_recovery_binding_mismatch";
    const identity = value => value.kind === "bound" ? {kind: "bound", account_id: value.account_id, session_sha256: value.session_sha256}
      : value.kind === "unbound" ? {kind: "unbound", operation_id: value.operation_id, session_sha256: value.session_sha256} : {kind: "absent"};
    const preimage = JSON.stringify(["control.profile.remove", original.schema_version, original.installation_root, original.profile,
      identity(original.identity), original.name, identity(original.target_identity)]);
    const fingerprint = createHash("sha256").update(preimage).digest("hex");
    if (original.fingerprint !== fingerprint || result.fingerprint !== fingerprint || context.fingerprint_preimage !== preimage) return "host_fingerprint_mismatch";
    const records = context.records;
    if (context.entry_count < records.length || records.some((entry, index) => records.slice(0, index).some(previous =>
        previous.original.operation_id === entry.original.operation_id || previous.original.key === entry.original.key))) return "profile_history_conflict";
    const previous = records.find(entry => entry.original.operation_id === original.operation_id || entry.original.key === original.key);
    let expected;
    if (previous) {
      if (!same(previous.original, original)) return "profile_history_conflict";
      if (context.delete_attempted !== false) return "profile_replay_forbidden";
      expected = previous.phase === "committed" ? "committed" : "unknown";
    } else if (request.method === "control.profile.result") {
      if (context.delete_attempted !== false) return "profile_replay_forbidden";
      expected = "unknown";
    } else {
      if (context.entry_count === 4096 || context.active === true) return "profile_admission_blocked";
      if (context.snapshot_clear !== true) return "profile_snapshot_pending";
      const target = original.installation_root + "/accounts/" + original.name;
      if (context.target_path !== target || context.target_path === original.profile || !same(context.target_identity, original.target_identity)) return "profile_target_mismatch";
      if (context.delete_attempted !== true) return "profile_receipt_mismatch";
      expected = "committed";
    }
    if (result.outcome !== expected) return "profile_receipt_mismatch";
  } else if (statusRead) {
    if (result.state !== context.journal_state || result.recovered !== false || context.recovery_attempted !== false) return "legacy_recovery_mismatch";
  } else {
    if (context.journal_state === "operation_pending") return "legacy_recovery_forbidden";
    const recovered = context.journal_state === "legacy_pending";
    if (result.state !== "clear" || result.recovered !== recovered || context.recovery_attempted !== recovered) return "legacy_recovery_mismatch";
  }
  const envelope = payload.private_response, status = profile && result.outcome === "unknown" ? "fail" : "ok";
  if (!envelope || !hostSchemaValid(envelope, hostSchema.$defs[profile ? "profileEnvelope" : "recoveryEnvelope"]) ||
      !same(envelope.summary, result) || envelope.status !== status) return "host_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const items = envelope.items.filter(item => item.name === name);
    if (items.length !== 1 || items[0].status !== status || items[0].value !== value) return "host_result_invalid";
  }
  const response = payload.private_rpc_response, unknown = profile && result.outcome === "unknown";
  if (!response || !hostSchemaValid(response, hostSchema.$defs.profileRecoveryResponse) ||
      response.id !== request.id || (response.operation_id ?? null) !== (request.operation_id ?? null) ||
      (response.idempotency_key ?? null) !== (request.idempotency_key ?? null) || !same(response.envelope, envelope) ||
      response.ok !== !unknown || response.exit !== (unknown ? 2 : 0) ||
      response.code !== (unknown ? "profile_remove_outcome_unknown" : null)) return "host_result_invalid";
  return null;
}

// These anchors describe fixture evidence, not a consumed launch grant.
function settingsAuthorityFailure(payload, binding, context, identity, read) {
  const a = context.authority, snapshot = payload.request.method === "control.snapshot.preflight";
  if (a.installation_root !== binding.installation_root || a.profile !== binding.profile || a.launch_id !== binding.launch_id ||
      (binding.expected_account_id ?? null) !== (snapshot ? null : identity.account_id)) return "settings_binding_mismatch";
  if (!same(a.identity, identity) || a.serving_authorized !== false ||
      ["parent_verified", "binding_verified_before", "binding_verified_after", "grant_verified", "registration_verified"].some(k => a[k] !== true) ||
      a.grant_maintenance !== (payload.maintenance_phase === "Idle" ? "none" : payload.maintenance_phase) ||
      !(read ? ["Idle", "Starting", "Verified"] : ["Paused"]).includes(payload.maintenance_phase)) return "settings_authority_mismatch";
  return null;
}

function offlineReadFailure(payload) {
  const {request, result, offline_context: c} = payload;
  if (Object.hasOwn(payload, "public_response")) return "private_secret_exposure";
  if (["history", "original_operation_id", "original_fingerprint", "config_context", "write_context", "key_context",
      "migration_context", "profile_context", "recovery_context", "metadata_context", "agent_config_context", "progress", "ledger"].some(k => Object.hasOwn(payload, k)) ||
      request.operation_id != null || request.idempotency_key != null) return "host_request_invalid";
  let params;
  try { params = JSON.parse(request.args[0]); } catch { return "host_params_invalid"; }
  if (!hostSchemaValid(params, hostSchema.$defs.offlineReadParams)) return "host_params_invalid";
  if (!c || !hostSchemaValid(c, hostSchema.$defs.offlineReadContext)) return "settings_context_mismatch";
  const authority = settingsAuthorityFailure(payload, params.binding, c, c.authority.identity, true);
  if (authority) return authority;
  const snapshot = request.method === "control.snapshot.preflight", metadata = request.method === "control.metadata.status";
  if (snapshot ? !c.snapshot_clear : c.auth_recovery_pending) return "offline_read_blocked";
  if (c.mutated) return "offline_read_mutation";
  if (payload.finish_maintenance) return "maintenance_not_terminal";
  if (!result || !hostSchemaValid(result, hostSchema.$defs.offlineEnvelope) ||
      !same(result, payload.private_response) ||
      result.command !== (snapshot ? "snapshot-preflight" : metadata ? "metadata" : "agent-config") ||
      !hostSchemaValid(result.summary, hostSchema.$defs[snapshot ? "snapshotPreflightSummary" : metadata ? "metadataStatusSummary" : "agentReadSummary"]) ||
      (metadata ? !hostSchemaValid(result.details, hostSchema.$defs.metadataStatusDetails) ||
        result.summary.enabled !== result.details.enabled || result.summary.mode !== result.details.mode : result.details !== null)) return "host_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const items = result.items.filter(i => i.name === name);
    if (items.length !== 1 || items[0].status !== status || items[0].value !== value) return "host_result_invalid";
  }
  const r = payload.private_rpc_response;
  if (!r || r.id !== request.id || r.operation_id != null || r.idempotency_key != null ||
      !same(r.envelope, result) || r.ok !== true || r.exit !== 0 || r.code !== null || r.data_dir !== null) return "host_result_invalid";
  return null;
}

function settingsWriteResponseFailure(payload, envelopeKind, code, profile) {
  const {request, result, private_response: e, private_rpc_response: r} = payload, unknown = result.outcome === "unknown";
  if (!e || !hostSchemaValid(e, hostSchema.$defs[envelopeKind]) || !same(e.summary, result) ||
      e.status !== (unknown ? "fail" : "ok")) return "host_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const items = e.items.filter(i => i.name === name);
    if (items.length !== 1 || items[0].status !== status || items[0].value !== value) return "host_result_invalid";
  }
  const responseKind = envelopeKind === "agentConfigEnvelope" ? "agentConfigResponse" : "settingsResponse";
  if (!r || !hostSchemaValid(r, hostSchema.$defs[responseKind]) || r.id !== request.id ||
      r.operation_id !== request.operation_id || r.idempotency_key !== request.idempotency_key ||
      !same(r.envelope, e) || r.ok !== !unknown || r.exit !== (unknown ? 2 : 0) ||
      r.code !== (unknown ? code : null) || r.data_dir !== profile) return "host_result_invalid";
  if (payload.finish_maintenance && unknown) return "maintenance_not_terminal";
  return null;
}

function metadataFailure(payload) {
  const {request, result, metadata_context: c} = payload;
  if (Object.hasOwn(payload, "public_response")) return "private_secret_exposure";
  if (["history", "original_operation_id", "original_fingerprint", "config_context", "write_context", "key_context",
      "migration_context", "profile_context", "recovery_context", "offline_context", "agent_config_context", "progress", "ledger"].some(k => Object.hasOwn(payload, k))) return "host_request_invalid";
  if (!request.operation_id || !request.idempotency_key) return "host_operation_required";
  let params;
  try { params = JSON.parse(request.args[0]); } catch { return "host_params_invalid"; }
  if (!hostSchemaValid(params, hostSchema.$defs.metadataParams)) return "host_params_invalid";
  const o = params.original, i = o.intent, query = request.method === "control.metadata.result";
  if (!query && request.method !== "control.metadata." + i.kind ||
      i.kind === "enable" && !(i.mode === "isolated" && i.deployment_review === null ||
        i.mode === "controlled_writers" && i.deployment_review && Object.values(i.deployment_review).every(v => v.trim()))) return "host_params_invalid";
  if (o.operation_id !== request.operation_id || o.key !== o.operation_id || o.key !== request.idempotency_key) return "host_operation_mismatch";
  if (o.installation_root !== params.binding.installation_root || o.profile !== params.binding.profile ||
      !same(o.identity, params.identity)) return "settings_binding_mismatch";
  if (!c || !hostSchemaValid(c, hostSchema.$defs.metadataContext)) return "settings_context_mismatch";
  const authority = settingsAuthorityFailure(payload, params.binding, c, params.identity, false);
  if (authority) return authority;
  const review = i.deployment_review;
  const intent = i.kind === "disable" ? {kind: "disable"} : {kind: "enable", mode: i.mode, deployment_review: review === null ? null :
    {operator: review.operator, upgraded_writers: review.upgraded_writers, disconnected_old_clients: review.disconnected_old_clients, reconciled_offline_writes: review.reconciled_offline_writes}};
  const preimage = JSON.stringify([1, "control.metadata", o.installation_root, o.profile,
    {account_id: o.identity.account_id, session_sha256: o.identity.session_sha256}, intent]);
  if (c.fingerprint_preimage !== preimage || o.fingerprint !== c.fingerprint ||
      o.fingerprint !== createHash("sha256").update(preimage).digest("hex")) return "host_fingerprint_mismatch";
  if (c.auth_recovery_pending || !c.snapshot_clear || !c.writable || c.memory_off || !c.locks_owned) return "metadata_admission_blocked";
  if (!result || !hostSchemaValid(result, hostSchema.$defs.metadataResult) || !same(result.original, o)) return "host_result_invalid";
  const before = c.receipt_before, after = c.receipt_after;
  if (before !== null) {
    if (!same(before.original, o) || before.outcome !== "committed" || !same(after, before)) return "metadata_history_conflict";
    if (c.effect_attempted) return "metadata_replay_forbidden";
    if (!same(result, before)) return "metadata_receipt_mismatch";
  } else if (query) {
    if (c.effect_attempted || after !== null) return "metadata_replay_forbidden";
    if (result.outcome !== "unknown" || result.details !== null) return "metadata_receipt_mismatch";
  } else if (!c.effect_attempted || after === null || after.outcome !== "committed" || !same(after, result)) return "metadata_receipt_mismatch";
  if (result.outcome === "committed" && (i.kind === "disable"
      ? result.details?.enabled !== false || result.details?.sync_isolation_retained !== true
      : result.details?.deployment_assurance !== "operator_attestation_only" || result.details?.old_client_access_enforced !== false ||
        !same(result.details?.deployment_review, i.deployment_review) || result.details?.receipt?.enabled !== true ||
        result.details?.receipt?.deployment?.mode !== i.mode)) return "metadata_receipt_mismatch";
  return settingsWriteResponseFailure(payload, "metadataEnvelope", "metadata_outcome_unknown", null);
}

function agentConfigFailure(payload) {
  const {request, result, agent_config_context: c} = payload;
  if (Object.hasOwn(payload, "public_response")) return "private_secret_exposure";
  if (["history", "original_operation_id", "original_fingerprint", "config_context", "write_context", "key_context",
      "migration_context", "profile_context", "recovery_context", "offline_context", "metadata_context", "progress", "ledger"]
      .some(k => Object.hasOwn(payload, k))) return "host_request_invalid";
  if (!request.operation_id || !request.idempotency_key) return "host_operation_required";
  let params;
  try { params = JSON.parse(request.args[0]); } catch { return "host_params_invalid"; }
  if (!hostSchemaValid(params, hostSchema.$defs.agentConfigParams)) return "host_params_invalid";
  const r = params.review, intent = r.intent;
  if (r.operation_id !== request.operation_id || r.operation_id !== request.idempotency_key) return "host_operation_mismatch";
  if (r.installation_root !== params.binding.installation_root || r.profile !== params.binding.profile) return "settings_binding_mismatch";
  if (!c || !hostSchemaValid(c, hostSchema.$defs.agentConfigContext)) return "settings_context_mismatch";
  const authority = settingsAuthorityFailure(payload, params.binding, c, r.identity, false);
  if (authority) return authority;
  const digest = text => text === null ? null : createHash("sha256").update(text).digest("hex");
  if (r.original_revision !== c.original_revision || digest(r.original_config) !== r.original_revision) return "agent_config_revision_mismatch";
  let value, candidate, workspace = false;
  try { value = JSON.parse(intent.raw_value); } catch { value = intent.raw_value; }
  const key = intent.key.trim();
  if (!key || key === "recall_mode" && !["fast", "quality"].includes(value)) return "host_params_invalid";
  let mode;
  if (["memory_off", "readonly"].includes(key)) {
    if (typeof value !== "boolean") return "host_params_invalid";
    workspace = true; mode = value ? key === "memory_off" ? "off" : "readonly" : "normal";
  } else if (key === "workspace_mode") {
    if (!["normal", "readonly", "off"].includes(value)) return "host_params_invalid";
    workspace = true; mode = value;
  }
  try { candidate = r.original_config === null ? {} : JSON.parse(r.original_config); }
  catch { if (workspace) return "host_params_invalid"; candidate = {}; }
  if (workspace) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return "host_params_invalid";
    candidate.service_mode = mode;
  } else if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) candidate[key] = value;
  if (c.candidate_config !== JSON.stringify(sortKeys(candidate), null, 2) ||
      r.candidate_revision !== c.candidate_revision || digest(c.candidate_config) !== r.candidate_revision) return "agent_config_candidate_mismatch";
  const preimage = JSON.stringify([1, "control.agent_config.set", r.operation_id, r.installation_root, r.profile,
    {account_id: r.identity.account_id, session_sha256: r.identity.session_sha256},
    {key: intent.key, raw_value: intent.raw_value}, r.original_revision, r.candidate_revision]);
  if (r.fingerprint !== c.fingerprint || c.fingerprint_preimage !== preimage || digest(preimage) !== r.fingerprint) return "host_fingerprint_mismatch";
  if (c.auth_recovery_pending || !c.snapshot_clear || !c.locks_owned) return "agent_config_admission_blocked";
  const before = c.record_before, after = c.record_after, previous = before.receipt;
  if (!same(before.review, r) || !before.sent || !same({...after, receipt: null}, {...before, receipt: null})) return "agent_config_original_mismatch";
  if (!result || !hostSchemaValid(result, hostSchema.$defs.agentConfigReceipt) || !same(result.review, r)) return "host_result_invalid";
  if (previous !== null) {
    if (!same(previous.review, r) || !["committed", "rolled_back"].includes(previous.outcome) ||
        !same(after, before) || !same(result, previous)) return "agent_config_receipt_mismatch";
    if (c.write_attempted || c.receipt_published || c.rollback_source !== null) return "agent_config_replay_forbidden";
    if (c.actual_before !== (previous.outcome === "committed" ? c.candidate_config : r.original_config) ||
        c.actual_after !== c.actual_before) return "agent_config_cas_conflict";
  } else if (request.method === "control.agent_config.result") {
    if (c.write_attempted || c.receipt_published || c.rollback_source !== null || !same(after, before)) return "agent_config_replay_forbidden";
    if (result.outcome !== "unknown" || result.result !== null) return "agent_config_receipt_mismatch";
    if (c.actual_after !== c.actual_before) return "agent_config_cas_conflict";
  } else {
    if (c.actual_before !== r.original_config) return "agent_config_cas_conflict";
    if (!c.marker_unchanged || !c.receipt_published || !same(after.receipt, result) ||
        !["committed", "rolled_back"].includes(result.outcome)) return "agent_config_receipt_mismatch";
    if (result.outcome === "committed" ? !c.write_attempted || c.actual_after !== c.candidate_config || c.rollback_source !== null :
        c.actual_after !== r.original_config || c.rollback_source !== r.original_config && c.rollback_source !== c.candidate_config) return "agent_config_cas_conflict";
  }
  if (result.outcome !== "unknown") {
    const action = result.result, committed = result.outcome === "committed";
    if (!action || !hostSchemaValid(action, hostSchema.$defs.agentConfigAction) ||
        action.status !== (committed ? "ok" : "fail") || action.summary.action !== (committed ? "updated" : "rolled_back")) return "host_result_invalid";
    if (committed ? action.summary.key !== intent.key || !same(action.summary.value, value) || action.items.length !== 1 ||
        action.items[0].name !== intent.key || action.items[0].status !== "ok" || action.items[0].value !== intent.raw_value || action.errors.length !== 0 :
        action.errors.length === 0 || action.items.length !== 0) return "host_result_invalid";
  }
  return settingsWriteResponseFailure(payload, "agentConfigEnvelope", "agent_config_outcome_unknown", r.profile);
}

function privateHostFailure(payload) {
  if (payload.channel !== "inherited_pipe") return "private_channel_required";
  if (!hostSchemaValid(payload, hostSchema.$defs.case)) return "host_request_invalid";
  const request = payload.request, method = hostSchema["x-methods"][request.method];
  if (method.params === "offlineReadParams") return offlineReadFailure(payload);
  if (method.params === "metadataParams") return metadataFailure(payload);
  if (method.params === "agentConfigParams") return agentConfigFailure(payload);
  if (["offline_context", "metadata_context", "agent_config_context"].some(k => Object.hasOwn(payload, k))) return "host_request_invalid";
  if (!["profileResult", "recoveryResult"].includes(method.result) &&
      ["profile_context", "recovery_context", "private_rpc_response"].some(key => Object.hasOwn(payload, key))) return "host_request_invalid";
  if (["secretResult", "keysExportResult", "identityWriteResult", "keyResult", "migrationResult", "profileResult", "recoveryResult"].includes(method.result) &&
      Object.hasOwn(payload, "public_response")) return "private_secret_exposure";
  if (method.mutable && (!request.operation_id || !request.idempotency_key)) return "host_operation_required";
  if (!method.mutable && (request.operation_id != null || request.idempotency_key != null)) return "host_request_invalid";
  let params;
  try { params = JSON.parse(request.args[0]); } catch { return "host_params_invalid"; }
  if (!hostSchemaValid(params, hostSchema.$defs[method.params])) return "host_params_invalid";
  if (["profileResult", "recoveryResult"].includes(method.result) &&
      ["config_context", "write_context", "key_context", "migration_context"].some(key => Object.hasOwn(payload, key))) return "host_request_invalid";
  if ((Object.hasOwn(payload, "progress") || Object.hasOwn(payload, "ledger")) &&
      method.result !== "migrationResult" && !(method.result === "keyResult" && params.operation.kind === "fivekeys")) return "host_request_invalid";
  if (method.params === "keyParams" && ((request.method === "control.key.super_reset" && params.operation.kind !== "super_reset") ||
      ["control.key.fivekeys", "control.key.complete"].includes(request.method) && params.operation.kind !== "fivekeys")) return "host_params_invalid";
  if (method.params === "identityWriteParams" && request.method !== "control.identity.write_result" &&
      (request.method === "control.identity.logout") !== (params.operation.kind === "logout")) return "host_params_invalid";
  if (method.params === "modelMaintenanceParams" && ((params.phase === "plan") !== (params.expected == null) ||
      params.phase === "apply" && params.kind !== "reset_cpu" || params.phase === "verify" && params.kind === "reset_cpu")) return "host_params_invalid";
  if (method.params === "modelParams" && (request.method === "control.model_install_plan"
      ? params.selection_sha256 != null : params.selection_sha256 == null)) return "host_params_invalid";
  const snapshot = request.method === "control.snapshot_maintenance";
  const verified = ["control.auth.account_complete", "control.key.complete"].includes(request.method) || snapshot && ["commit", "release"].includes(params.action);
  if (payload.maintenance_phase !== (request.method === "control.auth.recovery_status" ? "Idle" : verified ? "Verified" : "Paused")) return "maintenance_phase_mismatch";
  if (payload.original_operation_id && payload.original_operation_id !== request.operation_id) return "host_operation_mismatch";
  if (snapshot) {
    if (params.operation_id !== request.operation_id) return "host_operation_mismatch";
    const tuple = ["snapshot-restore-v1", params.binding.installation_root, params.binding.profile,
      params.binding.expected_account_id ?? null, params.sync_generation, params.snapshot_id];
    const fingerprint = createHash("sha256").update(JSON.stringify(tuple)).digest("hex");
    if (params.request_fingerprint !== fingerprint || payload.original_fingerprint && payload.original_fingerprint !== fingerprint) return "host_fingerprint_mismatch";
  }
  if (method.params === "configParams") {
    const failure = configFixtureFailure(params, payload.config_context);
    if (failure) return failure;
  }
  const result = payload.result;
  if (!result) return ["profileResult", "recoveryResult"].includes(method.result) ? "host_result_invalid" : payload.finish_maintenance ? "maintenance_not_terminal" : null;
  if (!hostSchemaValid(result, hostSchema.$defs[method.result])) return "host_result_invalid";
  if (method.mutable && result.operation_id !== request.operation_id) return "host_operation_mismatch";
  const profileRecoveryError = profileRecoveryFailure(payload, params, method.result);
  if (profileRecoveryError) return profileRecoveryError;
  const extension = method.result === "migrationResult" || method.result === "keyResult" && params.operation.kind === "fivekeys";
  const fixedFailure = extension ? keyMigrationFailure(payload, params, method.result) : fixedWriteModelFailure(payload, params, method.result);
  if (fixedFailure) return fixedFailure;
  if (["identityResult", "configReceipt"].includes(method.result)) {
    const envelope = payload.private_response;
    const kind = method.result === "identityResult" ? "identityEnvelope" : "configEnvelope";
    if (!envelope || !hostSchemaValid(envelope, hostSchema.$defs[kind]) ||
        !isDeepStrictEqual(method.result === "identityResult" ? envelope.details : envelope.summary, result)) return "host_result_invalid";
    for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
      const matching = envelope.items.filter(item => item.name === name);
      if (matching.length !== 1 || matching[0].status !== status || matching[0].value !== value) return "host_result_invalid";
    }
    if (method.result === "configReceipt") {
      for (const [receipt, parameter] of [["original_revision", "original_revision"], ["candidate_revision", "candidate_revision"],
          ["source_profile", "source_profile"], ["target_profile", "target_profile"],
          ["source_identity", "source_identity"], ["target_identity", "identity"]]) {
        if (!isDeepStrictEqual(result[receipt] ?? null, params[parameter] ?? null)) return "config_receipt_mismatch";
      }
      for (const key of ["data_dir", "addr", "autosync", "cure_auto", "rpc_parallelism"]) {
        if (!isDeepStrictEqual(result.intent[key] ?? null, params.intent[key] ?? null)) return "config_receipt_mismatch";
      }
    }
  }

  if (method.result === "modelPlan" && JSON.stringify(result.assets.assets) !== JSON.stringify(result.assets.missing)) return "host_result_invalid";
  if (["modelPlan", "modelVerify"].includes(method.result)) {
    if (method.result === "modelVerify" && result.selection_sha256 !== params.selection_sha256) return "host_selection_mismatch";
    const envelope = payload.public_response;
    const command = method.result === "modelPlan" ? "model-install-plan" : "model-install-verify";
    if (!envelope || !hostSchemaValid(envelope, hostSchema.$defs.modelEnvelope) ||
        envelope.command !== command || envelope.summary.complete !== result.assets.complete ||
        JSON.stringify(envelope.details) !== JSON.stringify(result) || assetsFailure(envelope.details.assets)) return "host_result_invalid";
    for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
      const matching = envelope.items.filter(item => item.name === name);
      if (matching.length !== 1 || matching[0].status !== status || matching[0].value !== value) return "host_result_invalid";
    }
  }
  if (method.result === "accountResult") {
    if (["awaiting_verification", "committed"].includes(result.outcome) &&
        (!result.target_profile || !result.account_id || !result.session_sha256)) return "host_result_invalid";
    if (result.outcome === "rolled_back" && (result.account_id != null || result.session_sha256 != null || result.super_password != null)) return "host_result_invalid";
  }
  if (snapshot) {
    if (result.request_fingerprint !== params.request_fingerprint || result.snapshot_id !== params.snapshot_id) return "host_fingerprint_mismatch";
    for (const previous of payload.history ?? []) {
      if (previous.operation_id !== request.operation_id) continue;
      if (previous.request_fingerprint !== params.request_fingerprint || previous.snapshot_id !== params.snapshot_id) return "terminal_history_conflict";
      if (["released", "rolled_back"].includes(previous.state) && result.state !== previous.state ||
          previous.state === "verified" && !["verified", "released"].includes(result.state)) return "terminal_history_conflict";
    }
  }
  const terminal = method.result === "profileResult" && result.outcome === "committed" ||
    method.result === "recoveryResult" && request.method === "control.auth.recover_legacy" && result.state === "clear" ||
    method.result === "accountResult" && ["committed", "rolled_back"].includes(result.outcome) ||
    extension && (method.result === "migrationResult" ? ["completed", "already_migrated"].includes(result.outcome) :
      ["committed", "rolled_back"].includes(result.outcome) && !result.verification_required) ||
    snapshot && ["released", "rolled_back"].includes(result.state);
  if (payload.finish_maintenance && !terminal) return "maintenance_not_terminal";
  return null;
}

const profileRecoveryExtension = manifest.extensions.profile_recovery;
if (profileRecoveryExtension.schema !== "schema/private-host-control.schema.json" ||
    profileRecoveryExtension.consumer !== "consumers/private_host_control.rs") fail("profile/recovery must reuse the shared schema and consumer");
for (const [groupName, group, legacyCount, newCount, extraCount] of [["positive", positive, 25, 64, 21], ["negative", negative, 48, 239, 132]]) {
  let checked = 0;
  const extra = profileRecoveryExtension.fixtures[groupName];
  if (!Array.isArray(extra) || extra.length !== extraCount) fail("profile/recovery fixture count drift");
  if (new Set([...group, ...extra]).size !== group.length + extra.length) fail("duplicate profile/recovery fixture");
  for (const name of [...group, ...extra]) {
    if (!boundPaths.has(name)) fail(`unbound host fixture: ${name}`);
    const fixture = readJSON(fixturePath(name));
    if (extra.includes(name) && (fixture.fixture_type !== "private_host_control" ||
        fixture.expected !== (groupName === "positive" ? "accept" : "reject"))) fail(`profile/recovery fixture kind: ${name}`);
    if (fixture.fixture_type !== "private_host_control") continue;
    if (fixture.expected === "accept" && !hostSchemaValid(fixture, hostSchema)) fail(`${name}: invalid host fixture container`);
    const expected = fixture.expected === "accept" ? null : fixture.error_code;
    const actual = privateHostFailure(fixture.payload);
    if (actual !== expected) fail(`${name}: host rejection ${actual}, expected ${expected}`);
    checked++;
  }
  if (checked !== newCount + extraCount || group.length + extraCount - checked !== legacyCount) fail("legacy/private host fixture counts drifted");
}

const settingsExtension = manifest.extensions.settings;
if (settingsExtension.schema !== "schema/private-host-control.schema.json" ||
    settingsExtension.consumer !== "consumers/private_host_control.rs") fail("settings must reuse the shared schema and consumer");
for (const [group, count] of [["positive", 7], ["negative", 26]]) {
  const paths = settingsExtension.fixtures[group];
  if (paths.length !== count || new Set(paths).size !== count) fail("settings fixture count drift");
  for (const name of paths) {
    if (!boundPaths.has(name) || [...positive, ...negative, ...profileRecoveryExtension.fixtures.positive,
        ...profileRecoveryExtension.fixtures.negative].includes(name)) fail("unbound or duplicate settings fixture");
    const f = readJSON(fixturePath(name));
    if (f.fixture_type !== "private_host_control" || f.expected !== (group === "positive" ? "accept" : "reject")) fail("settings fixture kind");
    if (group === "positive" && !hostSchemaValid(f, hostSchema)) fail("invalid settings fixture container");
    const actual = privateHostFailure(f.payload), expected = group === "positive" ? null : f.error_code;
    if (actual !== expected) fail(`${name}: settings rejection ${actual}, expected ${expected}`);
  }
}

const metadataExtension = manifest.extensions.metadata;
if (metadataExtension.schema !== "schema/private-host-control.schema.json" ||
    metadataExtension.consumer !== "consumers/private_host_control.rs") fail("metadata must reuse the shared schema and consumer");
for (const [group, count] of [["positive", 7], ["negative", 18]]) {
  const paths = metadataExtension.fixtures[group];
  if (paths.length !== count || new Set(paths).size !== count) fail("metadata fixture count drift");
  for (const name of paths) {
    if (!boundPaths.has(name) || [...positive, ...negative, ...profileRecoveryExtension.fixtures.positive,
        ...profileRecoveryExtension.fixtures.negative, ...settingsExtension.fixtures.positive,
        ...settingsExtension.fixtures.negative].includes(name)) fail("unbound or duplicate metadata fixture");
    const f = readJSON(fixturePath(name));
    if (f.fixture_type !== "private_host_control" || f.expected !== (group === "positive" ? "accept" : "reject")) fail("metadata fixture kind");
    if (group === "positive" && !hostSchemaValid(f, hostSchema)) fail("invalid metadata fixture container");
    const actual = privateHostFailure(f.payload), expected = group === "positive" ? null : f.error_code;
    if (actual !== expected) fail(`${name}: metadata rejection ${actual}, expected ${expected}`);
  }
}

const agentConfigExtension = manifest.extensions.agent_config;
if (agentConfigExtension.schema !== "schema/private-host-control.schema.json" ||
    agentConfigExtension.consumer !== "consumers/private_host_control.rs") fail("agent config must reuse the shared schema and consumer");
for (const [group, count] of [["positive", 6], ["negative", 14]]) {
  const paths = agentConfigExtension.fixtures[group];
  if (paths.length !== count || new Set(paths).size !== count) fail("agent config fixture count drift");
  for (const name of paths) {
    if (!boundPaths.has(name) || [...positive, ...negative, ...profileRecoveryExtension.fixtures.positive,
        ...profileRecoveryExtension.fixtures.negative, ...settingsExtension.fixtures.positive, ...settingsExtension.fixtures.negative,
        ...metadataExtension.fixtures.positive, ...metadataExtension.fixtures.negative].includes(name)) fail("unbound or duplicate agent config fixture");
    const f = readJSON(fixturePath(name));
    if (f.fixture_type !== "private_host_control" || f.expected !== (group === "positive" ? "accept" : "reject")) fail("agent config fixture kind");
    if (group === "positive" && !hostSchemaValid(f, hostSchema)) fail("invalid agent config fixture container");
    const actual = privateHostFailure(f.payload), expected = group === "positive" ? null : f.error_code;
    if (actual !== expected) fail(`${name}: agent config rejection ${actual}, expected ${expected}`);
  }
}

const spaceExtension = manifest.extensions.space;
const spaceSchema = readJSON(fixturePath(spaceExtension.schema));
const spaceValid = (value, name) => hostSchemaValid(value, spaceSchema.$defs[name], spaceSchema.$defs);
const canonical = value => JSON.stringify(sortKeys(value));
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortKeys(value[key])]));
  return value;
}
const textHash = text => createHash("sha256").update(text, "utf8").digest("hex");
function spaceFailure(p) {
  if (p.channel !== "inherited_pipe") return "private_channel_required";
  if (Object.hasOwn(p, "public_response")) return "private_secret_exposure";
  const q = p.request;
  if (!spaceValid(q, "request")) return "space_request_invalid";
  let a;
  try { a = JSON.parse(q.args[0]); } catch { return "space_params_invalid"; }
  if (!spaceValid(a, "params")) return "space_params_invalid";
  if (q.method !== "control.space.result" && q.method !== `control.space.${a.operation.kind}`) return "space_method_mismatch";
  const r = p.result, c = p.space_context, op = a.operation;
  if (!spaceValid(r, "result")) return "space_result_invalid";
  for (const name of ["ledger", "progress"]) {
    if (Object.hasOwn(p, name) && !spaceValid(p[name], "publicState")) return "private_secret_exposure";
  }
  if (p.maintenance_phase !== "Paused") return "maintenance_phase_mismatch";
  if (!spaceValid(c, "context") || c.installation_root !== a.binding.installation_root || c.profile !== a.binding.profile ||
      !isDeepStrictEqual(c.source_identity, a.source_identity) || !isDeepStrictEqual(c.operation, op) ||
      c.operation_id !== q.operation_id || c.idempotency_key !== q.idempotency_key) return "space_context_mismatch";
  if (r.operation_id !== q.operation_id || !isDeepStrictEqual(r.operation, op)) return "space_operation_mismatch";
  const preimage = canonical({schema_version: 1, method: "control.space", root: c.installation_root,
    profile: c.profile, source_identity: a.source_identity, operation: op});
  if (c.fingerprint_preimage !== preimage || c.fingerprint !== textHash(preimage) || r.fingerprint !== c.fingerprint) return "space_fingerprint_mismatch";
  if (r.profile !== c.profile || c.selected_profile !== c.profile || !isDeepStrictEqual(r.identity, a.source_identity) ||
      !isDeepStrictEqual(a.identity, a.source_identity) || a.binding.expected_account_id !== a.source_identity.account_id) return "space_identity_mismatch";
  const outcome = {admitted: "pending", authorized: "pending", remote_pending: "unknown", remote_unknown: "unknown", committed: "committed", rolled_back: "rejected"}[c.journal_phase];
  if (r.outcome !== outcome || [p.ledger, p.progress].some(v => v && v.outcome !== r.outcome)) return "space_outcome_mismatch";
  for (const state of [p.ledger, p.progress]) {
    if (state && ["operation_id", "idempotency_key", "fingerprint"].some(k => Object.hasOwn(state, k) && state[k] !== ({...q, fingerprint: c.fingerprint})[k])) return "space_context_mismatch";
  }
  if (op.kind === "join") {
    if (r.invite_code !== null || r.session_id !== null || r.kick.length || r.remaining !== null ||
        r.target_profile !== c.target_profile || r.target_account_id !== c.target_account_id || r.target_session_sha256 !== c.target_session_sha256 ||
        r.target_profile !== `${c.installation_root}/accounts/${op.space}` ||
        r.outcome === "committed" && (c.readonly_team !== op.readonly || r.target_account_id !== textHash(op.user) || !r.target_session_sha256) ||
        r.outcome !== "committed" && (r.target_account_id !== null || r.target_session_sha256 !== null)) return "space_join_mismatch";
    if (a.invite_code !== null) {
      try {
        if (!/^1mem-invite:(?:[0-9a-f]{2})+$/.test(a.invite_code) || textHash(a.invite_code) !== op.invite_sha256) return "space_join_mismatch";
        const invite = JSON.parse(Buffer.from(a.invite_code.slice(12), "hex").toString("utf8"));
        if (["space", "addr", "user", "readonly"].some(k => invite[k] !== op[k])) return "space_join_mismatch";
      } catch { return "space_join_mismatch"; }
    }
  } else if (op.kind === "kick") {
    if (!isDeepStrictEqual(r.kick.map(k => k.session_id), c.kick_targets) ||
        !op.all && (r.kick.length !== 1 || r.kick[0].session_id !== op.session_id) ||
        op.all && r.remaining !== r.kick.filter(k => k.state !== "revoked").length ||
        r.outcome === "committed" && r.kick.some(k => ["queued", "remote_pending", "unknown"].includes(k.state)) ||
        [r.invite_code, r.session_id, r.target_profile, r.target_account_id, r.target_session_sha256].some(v => v !== null)) return "space_kick_mismatch";
    if (q.method === "control.space.result" && c.remote_posts.length || c.previous_kick.some((old, i) =>
      old.session_id !== r.kick[i]?.session_id || old.state === "revoked" && r.kick[i].state !== "revoked" ||
      ["remote_pending", "unknown"].includes(old.state) && r.kick[i].state !== "unknown")) return "space_remote_replay";
  } else {
    if ([r.target_profile, r.target_account_id, r.target_session_sha256].some(v => v !== null) || r.kick.length) return "space_result_invalid";
    if (r.outcome === "committed") {
      try {
        const code = JSON.parse(Buffer.from(r.invite_code.slice(12), "hex").toString("utf8"));
        if (!r.invite_code.startsWith("1mem-invite:") || code.session_id !== r.session_id ||
            code.control_operation_id !== q.operation_id || code.control_fingerprint !== r.fingerprint || code.readonly !== op.readonly) return "space_result_invalid";
      } catch { return "space_result_invalid"; }
    } else if (r.invite_code !== null || r.session_id !== null) return "space_result_invalid";
  }
  const e = p.private_response;
  if (!spaceValid(e, "envelope") || !isDeepStrictEqual(e.summary, r) ||
      e.status !== ({pending: "pending", unknown: "fail", committed: "ok", rejected: "fail"})[r.outcome]) return "space_result_invalid";
  for (const [name, status, value] of [["control_ready", "ok", "true"], ["store_ready", "skip", "false"]]) {
    const items = e.items.filter(i => i.name === name);
    if (items.length !== 1 || items[0].status !== status || items[0].value !== value) return "space_result_invalid";
  }
  if (p.finish_maintenance && !["committed", "rejected"].includes(r.outcome)) return "maintenance_not_terminal";
  return null;
}
if (!boundPaths.has(spaceExtension.schema) || !boundPaths.has(spaceExtension.consumer)) fail("unbound space schema/consumer");
for (const [group, count] of [["positive", 7], ["negative", 24]]) {
  const paths = spaceExtension.fixtures[group];
  if (paths.length !== count) fail("space fixture count drift");
  for (const name of paths) {
    if (!boundPaths.has(name)) fail(`unbound space fixture: ${name}`);
    const f = readJSON(fixturePath(name));
    if (f.fixture_type !== "private_space_control" || f.expected !== (group === "positive" ? "accept" : "reject")) fail(`space fixture kind: ${name}`);
    if (group === "positive" && !hostSchemaValid(f, spaceSchema, spaceSchema.$defs)) fail(`invalid space container: ${name}`);
    const actual = spaceFailure(f.payload), expected = group === "positive" ? null : f.error_code;
    if (actual !== expected) fail(`${name}: space rejection ${actual}, expected ${expected}`);
  }
}
console.log(`runtime control contract verified: ${boundPaths.size} bound files (624 prior bindings retained with schema/consumer digest updates; 6 positive / 14 negative AgentConfig cases; prior cohorts retained)`);

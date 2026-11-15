import assert from 'node:assert/strict';
import {CASES, selected, verifyResults} from './produce-runtime-g1-memory.mjs';

// Synthetic refusal checks are never uploaded as product acceptance evidence.
assert.equal(Object.keys(CASES).length, 3);
assert.equal(selected.length, 2);
const identity = {target: 'aarch64-unknown-linux-musl', candidate_sha256: 'a'.repeat(64)};
const result = {schema: 1, passed: true, test_executed: true, release_acceptance: false,
  offline_installer_verified: true, identity, target: identity.target, passed_cases: selected,
  model_sha256: {
    'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790',
    'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'onnx/model_quantized.cpu-v1.ort': '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff',
  }};
verifyResults(result, identity);
for (const change of [
  {passed: false}, {test_executed: false}, {release_acceptance: true},
  {offline_installer_verified: false}, {passed_cases: selected.slice(1)},
  {passed_cases: [...selected, selected[0]]}, {target: 'aarch64-unknown-linux-gnu'},
  {identity: {...identity, candidate_sha256: 'b'.repeat(64)}}, {model_sha256: {}},
]) assert.throws(() => verifyResults({...result, ...change}, identity));
console.log('memory producer rejects incomplete cases, wrong targets, changed inputs and unverified models');

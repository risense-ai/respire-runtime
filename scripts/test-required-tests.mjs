#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const verifier = fileURLToPath(new URL("./verify-required-tests.mjs", import.meta.url));
const repository = resolve(dirname(verifier), "..");
const evidenceRoot = join(repository, ".verification", "required-gate-selfcheck");
mkdirSync(evidenceRoot, { recursive: true });
const fixtureRoot = mkdtempSync(join(evidenceRoot, "case-"));
mkdirSync(join(fixtureRoot, "scripts"), { recursive: true });
mkdirSync(join(fixtureRoot, ".github", "workflows"), { recursive: true });
writeFileSync(join(fixtureRoot, ".github", "workflows", "fixture.yml"),
  "jobs:\n  fixture:\n    strategy:\n      matrix:\n        target: [target-a, target-b]\n    steps:\n      - run: |\n          node --eval gate.fixture\n");
writeFileSync(join(fixtureRoot, "fixture-source.txt"), "gate.fixture\n");

const sha = "a".repeat(40);
const nativeSdk = (owner, target) => owner === "client2" ? null : ({
  version: owner === "runtime" ? "1.0.2-dev.21" : "1.0.2-dev.20",
  manifest_sha256: createHash("sha256").update(owner + "/" + target + "/manifest").digest("hex"),
  archive_sha256: createHash("sha256").update(owner + "/" + target + "/archive").digest("hex"),
});
const goodJob = {
  name: "fixture", run_id: 17, head_sha: sha,
  status: "completed", conclusion: "success",
  started_at: "2026-11-04T01:00:00Z", completed_at: "2026-11-04T01:01:00Z",
};
const candidate = {
  schema: 2, frozen: true, gate: "G1",
  components: Object.fromEntries(["runtime", "cli", "client2"].map((owner) => [owner, {
    source_sha: sha, version: "fixture-only",
    artifacts: Object.fromEntries(["target-a", "target-b"].map(target => [target, {
      archive_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), native_sdk: nativeSdk(owner, target),
    }])),
  }])),
};
const candidateText = JSON.stringify(candidate);
const report = {
  schema: 2, test_id: "gate.fixture", target: "target-a", coverage: "source-test",
  actual_native_sdk: nativeSdk("runtime", "target-a"),
  status: "passed", cases: [{ name: "gate.fixture", status: "passed" }],
  run_id: "17", run_attempt: "2", source_sha: sha, repository: "fixture/runtime",
  candidate_sha256: createHash("sha256").update(candidateText).digest("hex"),
  job_name: "fixture", artifact_id: 31, artifact_name: "required-tests-fixture-evidence",
  artifact_sha256: "d".repeat(64),
};
const goodArtifact = {
  id: 31, name: report.artifact_name, expired: false,
  digest: `sha256:${report.artifact_sha256}`,
  workflow_run: { id: 17, head_sha: sha }, created_at: "2026-11-04T01:00:30Z",
};
const ready = {
  id: "gate.fixture", area: "fixture", status: "implemented",
  report_schema: "required-execution/v2",
  coverage: "source-test", required_targets: ["target-a"],
  required_cases: ["gate.fixture"],
  source_suite: [{ file: "fixture-source.txt", test: "gate.fixture", command: "node --eval gate.fixture" }],
  evidence: {
    workflow: ".github/workflows/fixture.yml",
    job: "fixture", command_fragment: "node --eval gate.fixture",
  },
};
const cases = [
  { name: "current attempt", jobs: [goodJob] },
  { name: "old SHA", jobs: [{ ...goodJob, head_sha: "b".repeat(40) }], error: "different run or source SHA" },
  { name: "different run", jobs: [{ ...goodJob, run_id: 16 }], error: "different run or source SHA" },
  { name: "empty jobs", jobs: [], error: "did not execute exactly once" },
  { name: "skipped job", jobs: [{ ...goodJob, conclusion: "skipped" }], error: "did not execute exactly once" },
  { name: "cancelled job", jobs: [{ ...goodJob, conclusion: "cancelled" }], error: "did not execute exactly once" },
  { name: "missing attempt", jobs: [goodJob], attempt: "", error: "GitHub runtime environment" },
  { name: "foreign pagination", jobs: [goodJob], link: "<https://example.invalid/jobs>; rel=\"next\"", error: "escaped the selected run attempt" },
  { name: "empty manifest", tests: [], error: "manifest has no tests" },
  { name: "missing test", tests: [{ id: "gate.fixture", area: "fixture", status: "missing", reason: "fixture", report_schema: "required-execution/v2" }], error: "required tests are not implemented" },
  { name: "duplicate IDs", tests: [ready, ready], error: "duplicate test id" },
  { name: "legacy ready is not execution", tests: [{ ...ready, status: "ready" }], error: "implementation is not an execution result" },
  { name: "missing candidate", noCandidate: true, error: "final candidate combination is missing" },
  { name: "unfrozen draft candidate", candidate: { ...candidate, frozen: false }, error: "explicitly frozen G1 combination" },
  { name: "ambiguous global SDK", candidate: { ...candidate, sdk: null }, error: "forbids ambiguous global sdk" },
  { name: "wrong final source", candidate: { ...candidate, components: { ...candidate.components, runtime: { ...candidate.components.runtime, source_sha: "b".repeat(40) } } }, error: "different source SHA" },
  { name: "missing reports", noReports: true, error: "execution reports directory is missing" },
  { name: "empty reports", reports: [], error: "execution reports are empty" },
  { name: "zero tests", report: { ...report, cases: [] }, error: "empty, failed, skipped" },
  { name: "skipped test", report: { ...report, cases: [{ name: "gate.fixture", status: "skipped" }] }, error: "empty, failed, skipped" },
  { name: "failed report", report: { ...report, status: "failed" }, error: "empty, failed, skipped" },
  { name: "static report", report: { ...report, coverage: "static" }, error: "not an execution report" },
  { name: "mock report", report: { ...report, coverage: "mock" }, error: "not an execution report" },
  { name: "old report attempt", report: { ...report, run_attempt: "1" }, error: "does not match the final candidate" },
  { name: "old report run", report: { ...report, run_id: "16" }, error: "does not match the final candidate" },
  { name: "old report SHA", report: { ...report, source_sha: "b".repeat(40) }, error: "does not match the final candidate" },
  { name: "wrong candidate hash", report: { ...report, candidate_sha256: "0".repeat(64) }, error: "does not match the final candidate" },
  { name: "wrong repository", report: { ...report, repository: "other/runtime" }, error: "does not match the final candidate" },
  { name: "wrong target", report: { ...report, target: "target-b" }, error: "target set is missing or different" },
  { name: "duplicate report", reports: [report, report], error: "duplicate execution report" },
  { name: "unmapped source case", report: { ...report, cases: [{ name: "other", status: "passed" }] }, error: "required_case missing" },
  { name: "parent pass with skipped child", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, cases: [{ name: "gate.fixture", status: "passed" }, { name: "gate.fixture/symlink", status: "skipped" }] }, error: "empty, failed, skipped" },
  { name: "parent pass with omitted child", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], error: "required_case missing: gate.fixture/symlink" },
  { name: "parent and mandatory child pass", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, cases: [{ name: "gate.fixture", status: "passed" }, { name: "gate.fixture/symlink", status: "passed" }] } },
  { name: "real artifact still requires child", tests: [{ ...ready, coverage: "real-artifact", required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, coverage: "real-artifact" }, error: "required_case missing: gate.fixture/symlink" },
  { name: "required cases absent", tests: [{ ...ready, required_cases: undefined }], error: "explicit required cases" },
  { name: "required cases empty", tests: [{ ...ready, required_cases: [] }], error: "required cases must be nonempty" },
  { name: "unit is not real artifact", tests: [{ ...ready, coverage: "real-artifact" }], error: "required coverage was not executed" },
  { name: "missing artifact", artifacts: [], error: "artifact is missing, stale" },
  { name: "wrong artifact id", report: { ...report, artifact_id: 32 }, error: "artifact is missing, stale" },
  { name: "missing artifact hash", report: { ...report, artifact_sha256: undefined }, error: "artifact is missing, stale" },
  { name: "API digest missing", artifacts: [{ ...goodArtifact, digest: undefined }], error: "artifact is missing, stale" },
  { name: "API digest different", artifacts: [{ ...goodArtifact, digest: "sha256:" + "e".repeat(64) }], error: "artifact is missing, stale" },
  { name: "duplicate artifact id", artifacts: [goodArtifact, goodArtifact], error: "artifact is missing, stale" },
  { name: "old attempt artifact", artifacts: [{ ...goodArtifact, created_at: "2026-11-03T00:00:00Z" }], error: "artifact is missing, stale" },
  { name: "expired artifact", artifacts: [{ ...goodArtifact, expired: true }], error: "artifact is missing, stale" },
  { name: "artifact old SHA", artifacts: [{ ...goodArtifact, workflow_run: { id: 17, head_sha: "b".repeat(40) } }], error: "artifact is missing, stale" },
  { name: "artifact foreign pagination", artifactLink: '<https://example.invalid/artifacts>; rel="next"', error: "artifact pagination escaped" },
  { name: "missing source", tests: [{ ...ready, source_suite: [{ ...ready.source_suite[0], file: "absent.txt" }] }], error: "mapped source test does not exist" },
  { name: "empty target matrix", tests: [{ ...ready, required_targets: [] }], error: "required targets must be nonempty" },
  {
    name: "missing matrix leg",
    tests: [{ ...ready, evidence: { ...ready.evidence, matrix: ["target-a", "target-b"] } }],
    jobs: [{ ...goodJob, name: "fixture (target-a)" }],
    error: "matrix is empty, skipped, or incomplete",
  },
  {
    name: "similarly named matrix leg",
    tests: [{ ...ready, evidence: { ...ready.evidence, matrix: ["target-a", "target-b"] } }],
    jobs: [{ ...goodJob, name: "fixture (target-a-extra)" }, { ...goodJob, name: "fixture (target-b)" }],
    error: "matrix is empty, skipped, or incomplete",
  },
];

// Each mutation uses synthetic native SDK bytes/identities, never a real CI result.
function v2Case(name, owner, mutate = () => {}, error) {
  const value = { owner, candidate: structuredClone(candidate), report: {
    ...structuredClone(report), repository: `fixture/${owner}`, actual_native_sdk: nativeSdk(owner, "target-a"),
  } };
  mutate(value);
  value.report.candidate_sha256 = createHash("sha256").update(JSON.stringify(value.candidate)).digest("hex");
  return { name, ...value, error };
}
cases.push(
  v2Case("CLI keeps dev.20 while Runtime keeps dev.21", "cli"),
  v2Case("Client2 explicit null", "client2"),
  v2Case("candidate v1 rejected", "runtime", v => { v.candidate.schema = 1; }, "candidate schema 2 required"),
  v2Case("report v1 rejected", "runtime", v => { v.report.schema = 1; }, "required-execution/v2 report schema required"),
  v2Case("registry v1 rejected", "runtime", v => { v.tests = [{...ready, report_schema: "required-execution/v1"}]; }, "required-execution/v2 report schema required"),
  v2Case("registry missing report schema", "runtime", v => { v.tests = [{...ready, report_schema: undefined}]; }, "required-execution/v2 report schema required"),
  v2Case("legacy report sdk rejected", "runtime", v => { v.report.sdk = nativeSdk("runtime", "target-a"); }, "forbids ambiguous global sdk"),
  v2Case("Client2 candidate missing null", "client2", v => { delete v.candidate.components.client2.artifacts["target-a"].native_sdk; }, "must be explicit null"),
  v2Case("Client2 candidate cannot claim Runtime SDK", "client2", v => { v.candidate.components.client2.artifacts["target-a"].native_sdk = nativeSdk("runtime", "target-a"); }, "must be explicit null"),
  v2Case("Client2 report missing null", "client2", v => { delete v.report.actual_native_sdk; }, "must be explicit null"),
  v2Case("Client2 report cannot claim Runtime SDK", "client2", v => { v.report.actual_native_sdk = nativeSdk("runtime", "target-a"); }, "must be explicit null"),
);
for (const owner of ["runtime", "cli"]) {
  cases.push(
    v2Case(`${owner} candidate missing SDK`, owner, v => { delete v.candidate.components[owner].artifacts["target-a"].native_sdk; }, "requires native SDK"),
    v2Case(`${owner} candidate null SDK`, owner, v => { v.candidate.components[owner].artifacts["target-a"].native_sdk = null; }, "requires native SDK"),
    v2Case(`${owner} report missing SDK`, owner, v => { delete v.report.actual_native_sdk; }, "requires native SDK"),
    v2Case(`${owner} report null SDK`, owner, v => { v.report.actual_native_sdk = null; }, "requires native SDK"),
    v2Case(`${owner} other owner SDK`, owner, v => { v.report.actual_native_sdk = nativeSdk(owner === "runtime" ? "cli" : "runtime", "target-a"); }, "actual native SDK differs"),
    v2Case(`${owner} other target SDK`, owner, v => { v.report.actual_native_sdk = nativeSdk(owner, "target-b"); }, "actual native SDK differs"),
    v2Case(`${owner} Rust wrapper is not native SDK`, owner, v => { v.report.actual_native_sdk.version = "2.0.0-dev.4"; }, "actual native SDK differs"),
  );
  for (const field of ["version", "manifest_sha256", "archive_sha256"]) {
    cases.push(
      v2Case(`${owner} candidate missing ${field}`, owner, v => { delete v.candidate.components[owner].artifacts["target-a"].native_sdk[field]; }, "requires native SDK"),
      v2Case(`${owner} actual wrong ${field}`, owner, v => { v.report.actual_native_sdk[field] = field === "version" ? "1.0.2-dev.999" : "0".repeat(64); }, "actual native SDK differs"),
    );
  }
}
// All target bindings coexist. Passing one target is not an eight-target result.
const nativeTargets = ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "x86_64-apple-darwin", "aarch64-apple-darwin",
  "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];
for (const owner of ["runtime", "cli", "client2"]) {
  const scenario = v2Case(`${owner} eight distinct target SDK bindings`, owner, v => {
    for (const component of ["runtime", "cli", "client2"]) v.candidate.components[component].artifacts =
      Object.fromEntries(nativeTargets.map(target => [target, {
        archive_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), native_sdk: nativeSdk(component, target),
      }]));
    v.tests = [{...ready, required_targets: nativeTargets}];
  });
  scenario.reports = nativeTargets.map((target, index) => ({...scenario.report, target,
    artifact_id: 31 + index, artifact_name: `${report.artifact_name}-${target}`,
    artifact_sha256: createHash("sha256").update(`${owner}/${target}/raw`).digest("hex"),
    actual_native_sdk: nativeSdk(owner, target)}));
  scenario.artifacts = scenario.reports.map(item => ({...goodArtifact, id: item.artifact_id,
    name: item.artifact_name, digest: `sha256:${item.artifact_sha256}`}));
  cases.push(scenario, {...scenario, name: `${owner} eight-target reports cannot shrink`, reports: scenario.reports.slice(0, 1), error: "target set is missing or different"});
  cases.push({...scenario, name: `${owner} cross-target raw cannot be reused`,
    reports: scenario.reports.map((item, index) => index !== 1 ? item : {...item,
      artifact_id: scenario.reports[0].artifact_id, artifact_name: scenario.reports[0].artifact_name,
      artifact_sha256: scenario.reports[0].artifact_sha256}), error: "raw artifact reused across targets"});
}


for (let index = 0; index < cases.length; index++) {
  const scenario = cases[index];
  const manifest = join(fixtureRoot, "scripts", `required-${index}.json`);
  const runRoot = join(fixtureRoot, `execution-${index}`);
  mkdirSync(runRoot);
  const candidateFile = join(runRoot, "candidate.json");
  if (!scenario.noCandidate) writeFileSync(candidateFile, scenario.candidate ? JSON.stringify(scenario.candidate) : candidateText);
  const reportsDir = join(runRoot, "reports");
  if (!scenario.noReports) {
    mkdirSync(reportsDir);
    for (const [reportIndex, item] of (scenario.reports ?? [scenario.report ?? report]).entries()) {
      writeFileSync(join(reportsDir, `${reportIndex}.json`), JSON.stringify(item));
    }
  }
  writeFileSync(manifest, JSON.stringify({
    schema: 1, owner: scenario.owner ?? "runtime", areas: ["fixture"], tests: scenario.tests ?? [ready],
  }));
  const mock = `
    process.argv = [process.execPath, ${JSON.stringify(verifier)}, "--ci", ${JSON.stringify(`--manifest=${manifest}`)},
      ${JSON.stringify(`--reports=${reportsDir}`)}, ${JSON.stringify(`--candidate=${candidateFile}`)}];
    globalThis.fetch = async (url) => {
      const artifacts = String(url).includes("/runs/17/artifacts?");
      if (!artifacts && !String(url).includes("/runs/17/attempts/2/jobs?")) {
        throw new Error("Jobs API did not select the exact run attempt");
      }
      return {
        ok: true,
        json: async () => artifacts
          ? (${JSON.stringify({ artifacts: scenario.artifacts ?? [goodArtifact] })})
          : (${JSON.stringify({ jobs: scenario.jobs ?? [goodJob] })}),
        headers: { get: () => artifacts ? ${JSON.stringify(scenario.artifactLink ?? null)} : ${JSON.stringify(scenario.link ?? null)} },
      };
    };
    await import(${JSON.stringify(pathToFileURL(verifier).href)});
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", mock], {
    cwd: fixtureRoot,
    encoding: "utf8",
    env: {
      ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}),
      TEMP: fixtureRoot,
      TMP: fixtureRoot,
      GITHUB_API_URL: "https://api.github.com",
      GITHUB_REPOSITORY: `fixture/${scenario.owner ?? "runtime"}`,
      GITHUB_RUN_ID: "17",
      GITHUB_RUN_ATTEMPT: scenario.attempt ?? "2",
      GITHUB_SHA: sha,
      GITHUB_TOKEN: "fixture-only",
    },
  });
  assert.ifError(result.error);
  if (scenario.error) {
    assert.notEqual(result.status, 0, `${scenario.name} unexpectedly passed`);
    assert.ok(result.stderr.includes(scenario.error),
      `${scenario.name} failed for an unexpected reason: ${result.stderr}`);
  } else {
    assert.equal(result.status, 0, `${scenario.name}: ${result.stderr}`);
  }
  console.log(`PASS ${scenario.name}`);
}
console.log(`Required-gate self-check passed: ${cases.length} isolated fixture cases; no live API calls`);

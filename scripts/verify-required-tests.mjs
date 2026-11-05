#!/usr/bin/env node

import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, join, resolve } from "node:path";
import process from "node:process";

const args = new Set(process.argv.slice(2));
const allowMissing = args.has("--allow-missing");
const checkRun = args.has("--ci");
const manifestOption = [...args].find((arg) => arg.startsWith("--manifest="));
const reportsOption = [...args].find((arg) => arg.startsWith("--reports="));
const candidateOption = [...args].find((arg) => arg.startsWith("--candidate="));
const manifestPath = resolve(manifestOption?.slice("--manifest=".length) ?? "scripts/required-tests.json");
const reportsPath = resolve(reportsOption?.slice("--reports=".length) ?? ".verification/required-tests/reports");
const candidatePath = resolve(candidateOption?.slice("--candidate=".length) ?? ".verification/required-tests/candidate.json");
const invalidArgs = [...args].filter(
  (arg) =>
    arg !== "--allow-missing" &&
    arg !== "--ci" &&
    ![manifestOption, reportsOption, candidateOption].includes(arg),
);
if (invalidArgs.length || (allowMissing && checkRun)) {
  throw new Error("usage: verify-required-tests.mjs [--allow-missing | --ci] [--manifest=PATH] [--reports=DIR] [--candidate=PATH]");
}
if (!existsSync(manifestPath)) {
  throw new Error(`required test manifest is missing: ${manifestPath}`);
}

function fail(message) {
  throw new Error(message);
}

function readJSON(path) {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8 * 1024 * 1024) {
      return fail(`${path}: evidence must be a regular file of at most 8 MiB`);
    }
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    return fail(`${path}: ${error.message}`);
  }
}

function validateNativeSdk(value, owner, label) {
  if (owner === "client2") {
    if (value !== null) fail(`${label}: client2 native SDK must be explicit null`);
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== "archive_sha256,manifest_sha256,version" ||
      typeof value.version !== "string" || !value.version.trim() ||
      !/^[a-f0-9]{64}$/.test(value.manifest_sha256 ?? "") ||
      !/^[a-f0-9]{64}$/.test(value.archive_sha256 ?? "")) {
    fail(`${label}: ${owner} requires native SDK version, manifest and archive digests`);
  }
}

const manifest = readJSON(manifestPath);
if (manifest.schema !== 1) fail("unsupported required test schema");
if (manifest.owner !== "runtime" && manifest.owner !== "cli" && manifest.owner !== "client2") {
  fail("invalid manifest owner");
}
if (!Array.isArray(manifest.areas) || manifest.areas.length === 0) fail("manifest has no areas");
if (!Array.isArray(manifest.tests) || manifest.tests.length === 0) fail("manifest has no tests");

const ids = new Set();
const ready = [];
const incomplete = [];
for (const test of manifest.tests) {
  if (typeof test.id !== "string" || !/^[a-z0-9_.-]+$/.test(test.id)) {
    fail(`invalid test id: ${String(test.id)}`);
  }
  if (ids.has(test.id)) fail(`duplicate test id: ${test.id}`);
  ids.add(test.id);
  if (!manifest.areas.includes(test.area)) fail(`${test.id}: unlisted area ${test.area}`);
  if (test.report_schema !== "required-execution/v2") fail(`${test.id}: required-execution/v2 report schema required`);
  if (test.required_cases !== undefined &&
      (!Array.isArray(test.required_cases) || test.required_cases.length === 0 ||
       new Set(test.required_cases).size !== test.required_cases.length ||
       test.required_cases.some((name) => typeof name !== "string" || !name.trim()))) {
    fail(`${test.id}: required cases must be nonempty, explicit, and unique`);
  }
  if (test.status === "missing" || test.status === "blocked") {
    if (typeof test.reason !== "string" || test.reason.length === 0) {
      fail(`${test.id}: ${test.status} test needs a reason`);
    }
    incomplete.push(test);
    continue;
  }
  if (test.status !== "implemented") fail(`${test.id}: invalid status ${test.status}; implementation is not an execution result`);
  if (!test.required_cases) fail(`${test.id}: implemented test needs explicit required cases, including mandatory subtests`);
  if (!["source-test", "real-artifact"].includes(test.coverage)) fail(`${test.id}: invalid coverage level`);
  if (!Array.isArray(test.required_targets) || test.required_targets.length === 0 ||
      new Set(test.required_targets).size !== test.required_targets.length ||
      test.required_targets.some((target) => typeof target !== "string" || !/^[a-z0-9_-]+$/.test(target))) {
    fail(`${test.id}: required targets must be nonempty and unique`);
  }
  if (!Array.isArray(test.source_suite) || test.source_suite.length === 0) {
    fail(`${test.id}: implementation needs a source suite`);
  }
  for (const suite of test.source_suite) {
    if (typeof suite.file !== "string" || isAbsolute(suite.file) || suite.file.includes("..") ||
        typeof suite.test !== "string" || suite.test.length === 0 ||
        typeof suite.command !== "string" || !suite.command.includes(suite.test)) {
      fail(`${test.id}: invalid source suite mapping`);
    }
    const source = join(resolve(manifestPath, "..", ".."), suite.file);
    if (!existsSync(source) || !readFileSync(source, "utf8").includes(suite.test)) {
      fail(`${test.id}: mapped source test does not exist`);
    }
  }

  const evidence = test.evidence;
  if (!evidence || typeof evidence !== "object") fail(`${test.id}: implemented test lacks evidence mapping`);
  if (typeof evidence.workflow !== "string" || isAbsolute(evidence.workflow) || evidence.workflow.includes("..")) {
    fail(`${test.id}: invalid evidence workflow`);
  }
  if (!/^[a-z0-9_-]+$/.test(evidence.job ?? "")) fail(`${test.id}: invalid evidence job`);
  if (typeof evidence.command_fragment !== "string" || evidence.command_fragment.length === 0) {
    fail(`${test.id}: evidence command fragment is required`);
  }
  if (evidence.job_name !== undefined && typeof evidence.job_name !== "string") {
    fail(`${test.id}: evidence job_name must be text`);
  }
  if (evidence.matrix !== undefined && !Array.isArray(evidence.matrix)) {
    fail(`${test.id}: evidence matrix must be an array`);
  }
  if (Array.isArray(evidence.matrix)) {
    if (evidence.matrix.length === 0 || new Set(evidence.matrix).size !== evidence.matrix.length) {
      fail(`${test.id}: evidence matrix is empty or duplicated`);
    }
    if (evidence.matrix.some((value) => typeof value !== "string" || value.length === 0)) {
      fail(`${test.id}: evidence matrix has an invalid target`);
    }
  }

  const workflowPath = join(resolve(manifestPath, "..", ".."), evidence.workflow);
  if (!existsSync(workflowPath)) fail(`${test.id}: evidence workflow is missing`);
  const workflow = readFileSync(workflowPath, "utf8");
  const jobPattern = /^ {2}[a-z0-9_-]+:\s*$/gm;
  const jobs = [...workflow.matchAll(jobPattern)];
  const jobStart = jobs.find((match) => match[0].trim() === `${evidence.job}:`);
  if (!jobStart) fail(`${test.id}: workflow has no job ${evidence.job}`);
  const nextJob = jobs.find((match) => match.index > jobStart.index);
  const jobText = workflow.slice(jobStart.index, nextJob?.index);
  // Include block-scalar commands without treating comments or step names as commands.
  const commandLines = [];
  let blockIndent = null;
  for (const line of jobText.split(/\r?\n/)) {
    if (blockIndent !== null && line.trim() && line.search(/\S/) <= blockIndent) blockIndent = null;
    const run = line.match(/^(\s*)(?:-\s+)?run:\s*(.*)$/);
    if (run) {
      if (/^[|>][-+]?\s*$/.test(run[2])) blockIndent = line.indexOf("run:");
      else commandLines.push(run[2]);
    } else if (blockIndent !== null && !line.trimStart().startsWith("#")) commandLines.push(line);
  }
  const runsCommand = commandLines.some((line) => line.includes(evidence.command_fragment));
  if (!runsCommand) fail(`${test.id}: job ${evidence.job} does not run the required command`);
  if (/continue-on-error:\s*true/.test(jobText) || commandLines.some((line) => /\|\|\s*true\b/.test(line))) {
    fail(`${test.id}: required producer may not swallow failures`);
  }
  if (Array.isArray(evidence.matrix)) {
    for (const target of evidence.matrix) {
      if (!jobText.includes(target)) fail(`${test.id}: matrix omits ${target}`);
    }
  }
  ready.push(test);
}

if (!allowMissing && incomplete.length > 0) {
  const details = incomplete.map((test) => `${test.id} (${test.status}: ${test.reason})`).join("; ");
  fail(`required tests are not implemented: ${details}`);
}

async function successfulJobs() {
  const required = [
    "GITHUB_API_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_TOKEN",
  ];
  if (required.some((name) => !process.env[name])) fail("CI evidence requires GitHub runtime environment");
  if (!/^[1-9][0-9]*$/.test(process.env.GITHUB_RUN_ID) ||
      !/^[1-9][0-9]*$/.test(process.env.GITHUB_RUN_ATTEMPT) ||
      !/^[0-9a-f]{40}$/i.test(process.env.GITHUB_SHA)) {
    fail("CI evidence requires an exact run, attempt, and source SHA");
  }
  const jobsURL = `${process.env.GITHUB_API_URL}/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}/attempts/${process.env.GITHUB_RUN_ATTEMPT}/jobs`;
  let url = `${jobsURL}?per_page=100`;
  const jobs = [];
  while (url) {
    const response = await fetch(url, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!response.ok) fail(`GitHub jobs API failed: ${response.status} ${await response.text()}`);
    const page = await response.json();
    if (!Array.isArray(page.jobs) || page.jobs.some((job) =>
      String(job.run_id) !== process.env.GITHUB_RUN_ID ||
      job.head_sha?.toLowerCase() !== process.env.GITHUB_SHA.toLowerCase())) {
      fail("CI job evidence belongs to a different run or source SHA");
    }
    jobs.push(...page.jobs);
    const nextLink = response.headers.get("link")?.match(/<([^>]+)>;\s*rel="next"/);
    url = nextLink?.[1] ?? "";
    if (url && (new URL(url).origin !== new URL(jobsURL).origin ||
                new URL(url).pathname !== new URL(jobsURL).pathname)) {
      fail("CI pagination escaped the selected run attempt");
    }
  }
  return jobs.filter((job) => job.status === "completed" && job.conclusion === "success");
}

async function currentArtifacts() {
  const base = `${process.env.GITHUB_API_URL}/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}/artifacts`;
  let url = `${base}?per_page=100`;
  const artifacts = [];
  while (url) {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json" },
    });
    if (!response.ok) fail(`GitHub artifacts API failed: ${response.status}`);
    const page = await response.json();
    if (!Array.isArray(page.artifacts)) fail("CI artifacts response is empty or malformed");
    artifacts.push(...page.artifacts);
    url = response.headers.get("link")?.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? "";
    if (url && (new URL(url).origin !== new URL(base).origin || new URL(url).pathname !== new URL(base).pathname)) {
      fail("CI artifact pagination escaped the selected run");
    }
  }
  return artifacts;
}

function executionReports() {
  // The frozen candidate pins components.{runtime,cli,client2}.{source_sha,version,
  // artifacts.<target>.{archive_sha256,binary_sha256,native_sdk}}. Native SDK
  // identity is component/target-specific; the Rust wrapper is source/lock-bound.
  // Each report binds test_id/target/coverage, nonempty passed cases, source_sha,
  // repository/run_id/run_attempt, and the SHA256 of the exact candidate file.
  // artifact_id/name refer to raw execution evidence uploaded BEFORE the report
  // bundle; the report cannot contain its own future upload artifact ID.
  if (!existsSync(candidatePath)) fail("final candidate combination is missing");
  const candidate = readJSON(candidatePath);
  if (candidate.schema !== 2) fail("candidate schema 2 required; v1 is not accepted");
  if (candidate.frozen !== true || candidate.gate !== "G1") {
    fail("candidate must be an explicitly frozen G1 combination");
  }
  if (Object.hasOwn(candidate, "sdk")) fail("candidate schema 2 forbids ambiguous global sdk");
  for (const owner of ["runtime", "cli", "client2"]) {
    const component = candidate.components?.[owner];
    if (!/^[a-f0-9]{40}$/i.test(component?.source_sha ?? "") ||
        typeof component?.version !== "string" || !component.version ||
        !component.artifacts || Object.keys(component.artifacts).length === 0) {
      fail(`candidate lacks exact ${owner} source, version, or artifacts`);
    }
    for (const [target, artifact] of Object.entries(component.artifacts)) {
      if (!/^[a-z0-9_-]+$/.test(target) ||
          !/^[a-f0-9]{64}$/i.test(artifact?.archive_sha256 ?? "") ||
          !/^[a-f0-9]{64}$/i.test(artifact?.binary_sha256 ?? "")) {
        fail(`candidate has invalid ${owner}/${target} archive or binary digest`);
      }
      validateNativeSdk(artifact.native_sdk, owner, `candidate ${owner}/${target}`);
    }
  }
  if (candidate.components[manifest.owner].source_sha.toLowerCase() !== process.env.GITHUB_SHA.toLowerCase()) {
    fail("final candidate belongs to a different source SHA");
  }
  if (!existsSync(reportsPath) || !lstatSync(reportsPath).isDirectory() || lstatSync(reportsPath).isSymbolicLink()) {
    fail("execution reports directory is missing or unsafe");
  }
  const files = readdirSync(reportsPath).filter((name) => name.endsWith(".json"));
  if (files.length === 0 || files.length > 1024) fail("execution reports are empty or excessive");
  const candidateHash = createHash("sha256").update(readFileSync(candidatePath)).digest("hex");
  const reports = files.map((name) => readJSON(join(reportsPath, name)));
  const keys = new Set();
  for (const report of reports) {
    const key = `${report.test_id}/${report.target}`;
    if (keys.has(key)) fail(`duplicate execution report: ${key}`);
    keys.add(key);
    if (!ids.has(report.test_id)) fail(`unexpected execution report: ${key}`);
    if (report.schema !== 2) fail(`${key}: required-execution/v2 report schema required`);
    if (Object.hasOwn(report, "sdk")) fail(`${key}: v2 report forbids ambiguous global sdk`);
    validateNativeSdk(report.actual_native_sdk, manifest.owner, `${key} actual_native_sdk`);
    if (report.status !== "passed" ||
        !["source-test", "real-artifact"].includes(report.coverage) ||
        !Array.isArray(report.cases) || report.cases.length === 0 ||
        new Set(report.cases.map((item) => item.name)).size !== report.cases.length ||
        report.cases.some((item) => typeof item.name !== "string" || !item.name || item.status !== "passed")) {
      fail(`${key}: report is empty, failed, skipped, or not an execution report`);
    }
    if (String(report.run_id) !== process.env.GITHUB_RUN_ID ||
        String(report.run_attempt) !== process.env.GITHUB_RUN_ATTEMPT ||
        report.source_sha?.toLowerCase() !== process.env.GITHUB_SHA.toLowerCase() ||
        report.repository !== process.env.GITHUB_REPOSITORY ||
        report.candidate_sha256 !== candidateHash) {
      fail(`${key}: report does not match the final candidate, source, run, or attempt`);
    }
  }
  return { candidate, reports };
}

if (checkRun) {
  const jobs = await successfulJobs();
  const { candidate, reports } = executionReports();
  const artifacts = await currentArtifacts();
  const groups = new Map();
  for (const test of ready) {
    const evidence = test.evidence;
    const key = JSON.stringify({
      job: evidence.job,
      job_name: evidence.job_name ?? evidence.job,
      matrix: evidence.matrix ?? null,
    });
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(test.id);
  }
  for (const [key, testIds] of groups) {
    const evidence = JSON.parse(key);
    const matching = jobs.filter((job) =>
      job.name === evidence.job_name || job.name.startsWith(`${evidence.job_name} (`),
    );
    if (!Array.isArray(evidence.matrix)) {
      if (matching.length !== 1) {
        fail(`required job did not execute exactly once for ${testIds.join(", ")}: ${evidence.job}`);
      }
      continue;
    }
    const missingTargets = evidence.matrix.filter(
      (target) => !matching.some((job) => job.name === `${evidence.job_name} (${target})`),
    );
    if (missingTargets.length > 0 || matching.length !== evidence.matrix.length) {
      fail(`required matrix is empty, skipped, or incomplete for ${testIds.join(", ")}: ${missingTargets.join(", ")}`);
    }
  }
  for (const test of ready) {
    const selected = reports.filter((report) => report.test_id === test.id);
    if (selected.length !== test.required_targets.length ||
        selected.some((report) => !test.required_targets.includes(report.target))) {
      fail(`${test.id}: execution report target set is missing or different`);
    }
    for (const target of test.required_targets) {
      const report = selected.find((item) => item.target === target);
      if (!report || report.coverage !== test.coverage) fail(`${test.id}/${target}: required coverage was not executed`);
      const candidateArtifact = candidate.components[manifest.owner].artifacts[target];
      if (!candidateArtifact) fail(`${test.id}/${target}: target absent from final candidate`);
      const expectedSdk = candidateArtifact.native_sdk;
      if (manifest.owner !== "client2" && ["version", "manifest_sha256", "archive_sha256"].some(
        (field) => report.actual_native_sdk[field] !== expectedSdk[field])) {
        fail(`${test.id}/${target}: actual native SDK differs from candidate ${manifest.owner}/${target}`);
      }
      const missingCases = test.required_cases.filter((name) =>
        !report.cases.some((item) => item.name === name && item.status === "passed"));
      if (missingCases.length) fail(`${test.id}/${target}: required_case missing: ${missingCases.join(", ")}`);
      if (test.coverage === "source-test" && test.source_suite.some((suite) =>
        !report.cases.some((item) => item.name === suite.test))) {
        fail(`${test.id}/${target}: report omits a mapped source test`);
      }
      const expectedName = test.evidence.job_name ?? test.evidence.job;
      const job = jobs.find((item) => item.name === report.job_name &&
        (item.name === expectedName || item.name.startsWith(`${expectedName} (`)));
      const matchingArtifacts = artifacts.filter((item) => String(item.id) === String(report.artifact_id));
      const artifact = matchingArtifacts[0];
      if (!job || !Number.isSafeInteger(report.artifact_id) || report.artifact_id <= 0 ||
          matchingArtifacts.length !== 1 || artifact.expired !== false || artifact.name !== report.artifact_name ||
          !artifact.name.startsWith("required-tests-") ||
          String(artifact.workflow_run?.id) !== process.env.GITHUB_RUN_ID ||
          artifact.workflow_run?.head_sha?.toLowerCase() !== process.env.GITHUB_SHA.toLowerCase() ||
          !(Date.parse(artifact.created_at) >= Date.parse(job.started_at) &&
            Date.parse(artifact.created_at) <= Date.parse(job.completed_at))) {
        fail(`${test.id}/${target}: artifact is missing, stale, or not from the successful producer in this attempt`);
      }
    }
  }
}

console.log(
  `required tests: ${ready.length} implemented, ${incomplete.length} missing or blocked; ` +
    (checkRun ? "execution reports passed for this exact candidate/run/attempt" : "execution NOT verified") +
    (allowMissing ? " (inventory only; missing explicitly allowed)" : ""),
);

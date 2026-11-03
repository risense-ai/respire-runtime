#!/usr/bin/env python3
"""Fail closed unless all declared CLI supplements passed for one CI artifact."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

SUPPLEMENTS = {"runtime", "ai_inject", "outbox", "legacy_vault", "profile_migration"}
OUTBOX = {"foreground_save_during_network_wait", "independent_pull_decrypt",
          "scheduled_transport_retry", "finite_manual_boundary", "reset_old_response_rejection"}
AI = {"model_cpu_real", "inject_preview_install_remove", "inject_stale_revision_rejected",
      "inject_malformed_marker_rejected", "inject_legacy_marker_contract",
      "classify_save_provider_contract", "classify_tree_provider_contract",
      "classify_causal_plan", "classify_auto_applied", "tree_deepen_go_applied",
      "tree_deepen_auto_applied", "tree_cure_auto_applied"}
LEGACY = {"model_cpu_real", "local_v1_upgrade", "cloud_v2_recovery_upgrade",
          "cloud_v3_secret_key_recovery_upgrade"}
MIGRATION = {"model_cpu_real", "onememory_multiaccount_wal_migrated", "respire_compatibility_migrated",
             "legacy_keys_migrated_without_super_override", "legacy_api_defaults_rewritten",
             "migration_repeated_start_idempotent", "migration_interrupted_restart_recovered",
             "existing_rsrs_preserved_and_legacy_imported", "migrated_outbox_sync_and_independent_decrypt",
             "migration_incompatible_primary_keys_rejected", "migration_symlink_root_rejected", "migration_client_only_does_not_write",
             "startup_does_not_migrate", "migration_source_order_and_backup_only_idempotent"}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def business_summary(observations, mapping):
    names = [row["action"] for row in observations]
    passed = {row["action"] for row in observations if row.get("passed") is True}
    retired = {row["action"] for row in observations if row.get("removed_by_requirement") is True}
    expected = [row["action"] for row in mapping["actions"]]
    require(len(names) == len(set(names)) and len(expected) == len(set(expected))
            and set(names) == set(expected), "business_summary_action_mismatch")
    require(not passed & retired and len(passed) + len(retired) == len(names), "business_summary_partition_mismatch")
    require(len(passed) == mapping["retained"] and len(retired) == mapping["removed_by_requirement"],
            "business_summary_contract_mismatch")
    return {"passed": True, "observed": len(passed), "removed_by_requirement": len(retired)}


def read(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), "report_not_object")
    return value


def identity(report, args, source="source_sha", version="version"):
    require(report.get(source) == args.source_sha, "artifact_source_mismatch")
    require(report.get(version) == args.version, "artifact_version_mismatch")
    require(report.get("binary_sha256") == args.binary_sha256, "artifact_binary_mismatch")


def cases(report, required, code):
    observed = report.get("cases", {})
    require(all(observed.get(name, {}).get("passed") is True for name in required), code)


def verify_migration(args, result):
    migration = read(args.profile_migration)
    identity(migration, args)
    require(set(migration.get("required_cases", [])) == MIGRATION, "migration_case_contract_mismatch")
    require(migration.get("passed") is True and not migration.get("missing_cases"), "migration_incomplete")
    cases(migration, MIGRATION, "migration_required_cases_missing")
    require(migration.get("cloud_cleanup", {}).get("passed") is True
            and not migration.get("cloud_cleanup", {}).get("remaining_users"), "migration_cleanup_failed")
    require(migration.get("keyring_cleanup", {}).get("passed") is True
            and not migration.get("keyring_cleanup", {}).get("remaining_entries"), "migration_keyring_cleanup_failed")
    native_backends = {"linux": "linux-keyutils", "darwin": "macos-keychain-synthetic-acl",
                       "win32": "windows-credential-manager"}
    require(migration.get("platform") == sys.platform
            and migration.get("keyring_backend") == native_backends.get(sys.platform),
            "migration_native_platform_mismatch")
    result["components"]["profile_migration"] = {"passed": True, "required_observed": len(MIGRATION),
        "platform": migration["platform"], "keyring_backend": migration["keyring_backend"]}


def verify(args, result):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    require(re.fullmatch("[0-9a-f]{40}", args.source_sha), "invalid_artifact_source")
    require(re.fullmatch("[0-9a-f]{64}", args.binary_sha256), "invalid_artifact_hash")
    base = read(args.cli_report)
    identity(base, args, version="observed_version")
    require(base.get("expected_version") == args.version, "base_expected_version_mismatch")
    require(base.get("server") == "https://api-dev.rsrs.rs", "base_server_mismatch")
    require(base.get("base_complete") is True and base.get("failed") == 0
            and not base.get("required_missing"), "cli_base_incomplete")
    catalog = base.get("catalog", {})
    require(not catalog.get("required_remaining"), "undelegated_requirement_remaining")
    require(set(base.get("supplemental_required", [])) == SUPPLEMENTS
            and set(catalog.get("supplemental_required", [])) == SUPPLEMENTS,
            "supplemental_contract_mismatch")
    required = catalog.get("required_assertions", [])
    require(required and len(required) == len(set(required)), "invalid_cli_case_catalog")
    observed = {row.get("case") for row in base.get("cases", [])
                if row.get("result") == "passed" and row.get("status") == "ok"}
    require(set(required).issubset(observed), "cli_required_observations_missing")
    require(base.get("cloud_cleanup", {}).get("passed") is True
            and not base.get("cloud_cleanup", {}).get("remaining_users"), "cli_cleanup_failed")
    result["components"]["cli"] = {"passed": True, "required_observed": len(required)}
    if args.migration_only:
        verify_migration(args, result)
        result["complete"] = True
        return
    require(all(getattr(args, name) is not None for name in ("outbox", "ai_inject", "runtime", "legacy_vault")),
            "full_gate_supplement_paths_required")

    outbox = read(args.outbox)
    identity(outbox, args)
    require(outbox.get("passed") is True and not outbox.get("remaining"), "outbox_incomplete")
    cases(outbox, OUTBOX, "outbox_required_cases_missing")
    require(outbox.get("cleanup", {}).get("passed") is True, "outbox_cleanup_failed")
    result["components"]["outbox"] = {"passed": True, "required_observed": len(OUTBOX)}

    ai = read(args.ai_inject)
    identity(ai, args)
    require(ai.get("status") == "passed" and not ai.get("missing_cases"), "ai_inject_incomplete")
    cases(ai, AI, "ai_inject_required_cases_missing")
    require(ai.get("cloud_cleanup", {}).get("passed") is True, "ai_inject_cleanup_failed")
    result["components"]["ai_inject"] = {"passed": True, "required_observed": len(AI)}

    legacy = read(args.legacy_vault)
    identity(legacy, args)
    require(legacy.get("passed") is True and not legacy.get("missing_cases"), "legacy_vault_incomplete")
    cases(legacy, LEGACY, "legacy_vault_required_cases_missing")
    require(legacy.get("cloud_cleanup", {}).get("passed") is True, "legacy_vault_cleanup_failed")
    result["components"]["legacy_vault"] = {"passed": True, "required_observed": len(LEGACY)}

    runtime = read(args.runtime)
    identity(runtime, args)
    runtime_catalog = read(Path(__file__).with_name("dev-runtime-required.json"))
    runtime_required = set(runtime_catalog["required_cases"])
    require(runtime_required and len(runtime_required) == len(runtime_catalog["required_cases"])
            and set(runtime.get("required_cases", [])) == runtime_required, "runtime_case_contract_mismatch")
    require(runtime.get("passed") is True and not runtime.get("missing_cases"), "runtime_incomplete")
    cases(runtime, runtime_required, "runtime_required_cases_missing")
    require(runtime.get("cloud_cleanup", {}).get("passed") is True
            and not runtime.get("cloud_cleanup", {}).get("remaining_users"), "runtime_cleanup_failed")
    result["components"]["runtime"] = {"passed": True, "required_observed": len(runtime_required)}

    verify_migration(args, result)

    interruption = read(args.login_interruption)
    identity(interruption, args)
    require(interruption.get("passed") is True and interruption.get("runtime_cleanup", {}).get("passed") is True,
            "login_interruption_incomplete")
    cases(interruption, {"before_publish_SIGINT_retry", "after_publish_SIGINT_retry", "pre_journal_DEV4_recovery"},
          "login_interruption_cases_missing")
    recovered = interruption["cases"]["pre_journal_DEV4_recovery"]
    require(all(recovered.get(field) is True for field in ("public_original_profile_migration",
            "full_library_reencrypted", "original_source_preserved", "original_factors_preserved")),
            "DEV4_original_profile_migration_not_proven")
    result["components"]["login_interruption"] = {"passed": True, "required_observed": 3}

    mapping = read(Path(__file__).with_name("dev-runtime-business-coverage.json"))
    original = read(Path(__file__).with_name("dev-local-api-coverage.json"))["actions"]
    actions = mapping["actions"]
    require(len(actions) == 72 and {row["action"] for row in actions} == {row["action"] for row in original},
            "business_mapping_incomplete")
    base_observed = {row.get("case") for row in base.get("cases", []) if row.get("result") == "passed"
                     and row.get("status") not in ("fail", "skip")}
    suites = {"cli": base_observed, "runtime": {name for name, row in runtime.get("cases", {}).items() if row.get("passed") is True},
              "ai_inject": {name for name, row in ai.get("cases", {}).items() if row.get("passed") is True},
              "legacy_vault": {name for name, row in legacy.get("cases", {}).items() if row.get("passed") is True}}
    retired = {"list_system_fonts", "pick_save_file", "pick_open_file", "pick_directory", "task_status", "db_stamp", "rerank_model_status", "rerank_model_install"}
    observations = []
    for action in actions:
        if action["action"] in retired:
            require(action.get("removed_by_requirement") is True and bool(action.get("reason")), "invalid_retired_action")
            observations.append({"action": action["action"], "removed_by_requirement": True})
            continue
        evidence = action.get("evidence", [])
        require(evidence and all(item.get("suite") in suites and item.get("case") in suites[item["suite"]]
                                 for item in evidence), "business_observation_missing:" + action["action"])
        observations.append({"action": action["action"], "passed": True, "evidence": evidence})
    result["business_actions"] = observations
    result["components"]["business_equivalence"] = business_summary(observations, mapping)
    result["complete"] = True
    result["conditional_unverified"] = catalog.get("conditional_unverified", [])
    result["excluded_not_implemented"] = catalog.get("excluded_not_implemented", [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli-report", "profile-migration", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("outbox", "ai-inject", "runtime", "legacy-vault", "login-interruption"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--migration-only", action="store_true",
                        help="Verify this native platform's base and migration only; not the full supplemental gate.")
    for name in ("source-sha", "version", "binary-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = {"complete": False, "source_sha": args.source_sha, "version": args.version,
              "binary_sha256": args.binary_sha256, "components": {},
              "scope": "native_profile_migration" if args.migration_only else "full_cli_supplements"}
    try:
        verify(args, result)
    except Exception as error:
        result["failure_code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"complete": result["complete"], "components": result["components"],
                      "failure_code": result.get("failure_code")}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""CI-only fault smoke using real development sync responses and disposable users."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dev_model_fixture import share_cpu_container

UPSTREAM = "https://api-dev.rsrs.rs"


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def wait_for(action, seconds, code):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = action()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError(code)


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Gate:
    def __init__(self):
        self.hold = False
        self.fail = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.acknowledged = set()
        self.fault_requests = 0
        self.capability_requests = 0
        self.sync_read_requests = 0
        self.proxy_response_parse_failures = 0
        self.request_counts = {"capability": 0, "pull": 0, "snapshot": 0, "push": 0}
        self.held_calls = {}
        self.lock = threading.Lock()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                try:
                    require(self.path.startswith("/") and not self.path.startswith("//"), "invalid_proxy_path")
                    path = self.path.split("?")[0]
                    kind = next((name for suffix, name in (("/sync/capabilities", "capability"),
                        ("/v2/pull", "pull"), ("/v2/snapshot", "snapshot"), ("/v2/push/batch", "push"))
                        if path.endswith(suffix)), None)
                    is_sync_read = self.command == "GET" and kind in ("capability", "pull", "snapshot")
                    hold_call = None
                    with gate.lock:
                        if kind:
                            gate.request_counts[kind] += 1
                        if kind == "capability":
                            gate.capability_requests += 1
                        if is_sync_read:
                            gate.sync_read_requests += 1
                            hold_call = gate.held_calls.get(gate.sync_read_requests)
                    if is_sync_read and gate.fail:
                        with gate.lock:
                            gate.fault_requests += 1
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    size = int(self.headers.get("Content-Length", "0"))
                    require(0 <= size <= 8 * 1024 * 1024, "proxy_request_too_large")
                    body = self.rfile.read(size) if size else None
                    headers = {name: self.headers[name] for name in ("Authorization", "Content-Type") if name in self.headers}
                    request = urllib.request.Request(UPSTREAM + self.path, body, headers, method=self.command)
                    try:
                        response = gate.opener.open(request, timeout=45)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        status = response.code
                        raw = response.read(16 * 1024 * 1024 + 1)
                        require(len(raw) <= 16 * 1024 * 1024 and not 300 <= status < 400, "invalid_upstream_response")
                        content_type = response.headers.get("Content-Type", "application/json")
                    if self.command == "POST" and kind == "push" and 200 <= status < 300:
                        try:
                            sent = json.loads(body)
                            received = json.loads(raw)
                            ids = {item["op_id"]: item["blob"]["id"] for item in sent["items"]}
                            accepted = set()
                            for result in received["results"]:
                                if result["status"] in ("applied", "rebased", "duplicate") and (result.get("stored_rev") or result.get("head_rev") or 0) > 0:
                                    accepted.add(ids[result["op_id"]])
                            with gate.lock:
                                gate.acknowledged.update(accepted)
                        except Exception:
                            # Observation must not turn an already committed real response into a disconnect.
                            with gate.lock:
                                gate.proxy_response_parse_failures += 1
                    if is_sync_read and gate.hold:
                        gate.entered.set()
                        require(gate.release.wait(90), "sync_read_gate_timeout")
                    if hold_call is not None:
                        hold_call[0].set()
                        require(hold_call[1].wait(90), "numbered_sync_read_gate_timeout")
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (Exception, BrokenPipeError):
                    # Never print provider bodies, authorization headers or exception payloads.
                    self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self):
        return "http://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.release.set()
        for _, release in self.held_calls.values():
            release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def hold_call(self, ordinal):
        events = (threading.Event(), threading.Event())
        with self.lock:
            require(ordinal > self.sync_read_requests, "sync_read_gate_armed_too_late")
            self.held_calls[ordinal] = events
        return events


class Fixture:
    def __init__(self, args, root, cleanup):
        self.args = args
        self.root = root
        self.child = None
        self.gate = Gate()
        self.user = "ci-outbox-" + secrets.token_hex(12)
        # Exercise leading-option characters without reducing the random password entropy.
        self.password = "-" + secrets.token_urlsafe(32)
        self.cleanup_report = cleanup
        self.registration_attempted = False
        self.created = False
        self.account_token = None
        self.direct_failures = []
        self.a = self.environment("a")
        self.b = self.environment("b")

    def environment(self, name):
        profile = self.root / name
        (profile / "home").mkdir(parents=True, mode=0o700)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("RSRS_", "ONEMEMORY_", "RESPIRE_", "XDG_"))
               and not key.endswith(("_TOKEN", "_API_KEY"))
               and key not in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "DBUS_SESSION_BUS_ADDRESS")}
        env.update(HOME=str(profile / "home"), USERPROFILE=str(profile / "home"),
                   XDG_CONFIG_HOME=str(profile / "config"), XDG_DATA_HOME=str(profile / "data"),
                   XDG_CACHE_HOME=str(profile / "cache"), TMPDIR=str(profile / "tmp"),
                   RSRS_DATA_DIR=str(profile / "library"), RSRS_BIN_DIR=str(profile / "bin"),
                   RSRS_M3_DIR=str(self.args.model_dir), RSRS_ENGINE="cpu",
                   RSRS_NO_AUTOSYNC="1")
        for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "RSRS_DATA_DIR", "RSRS_BIN_DIR"):
            Path(env[key]).mkdir(parents=True, exist_ok=True, mode=0o700)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            env['RSRS_RPC_PORT'] = str(listener.getsockname()[1])
        return env

    def direct(self, env, command, allow_pending=False, timeout=150):
        try:
            result = subprocess.run([str(self.args.binary), "--direct", "--json", *command],
                                    env=env, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.direct_failures.append({"phase": command[0], "exit_code": None, "timeout": True})
            raise RuntimeError("direct_" + command[0] + "_timeout") from None
        if result.returncode not in ((0, 2) if allow_pending else (0,)):
            text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            patterns = {"argument_parse": r"unexpected argument|unrecognized (?:argument|option)|invalid value|required arguments",
                        "timeout": r"timed? out|timeout", "profile": r"runtime owns its boot profile|profile change",
                        "keyring": r"keyring|secret service", "invalid": r"invalid", "rate_limit": r"too many requests|rate.limit"}
            statuses = [int(value) for value in re.findall(r"(?:HTTP(?:/\S+)?\s+|status(?:\s+code)?[\s:=]+)([45]\d\d)\b", text, re.I)]
            self.direct_failures.append({"phase": command[0], "exit_code": result.returncode,
                "http_statuses": sorted({value for value in statuses if value in (400, 401, 403, 404, 409, 429, 500, 502, 503, 504)}),
                "recognized": {key: bool(re.search(pattern, text, re.I)) for key, pattern in patterns.items()}})
            raise RuntimeError("direct_" + command[0] + "_failed")
        try:
            data = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("direct_" + command[0] + "_invalid_json") from None
        require(not data.get("errors"), "direct_" + command[0] + "_errors")
        return data

    def prepare(self):
        self.registration_attempted = True
        self.cleanup_report["unconfirmed_users"].append(self.user)
        registration = self.direct(self.a, ["register", "--addr", UPSTREAM, "--user", self.user, "--pass=" + self.password])
        require(registration.get("summary", {}).get("user") == self.user
                and registration.get("summary", {}).get("ok") is True, "registered_user_identity_mismatch")
        self.created = True
        self.cleanup_report["unconfirmed_users"].remove(self.user)
        self.cleanup_report["remaining_users"].append(self.user)
        session_path = Path(self.a["RSRS_DATA_DIR"]) / "session.json"
        session = json.loads(session_path.read_text(encoding="utf-8"))
        require(session.get("user") == self.user and session.get("addr") == UPSTREAM
                and isinstance(session.get("token"), str) and bool(session["token"]), "created_user_session_mismatch")
        self.account_token = session["token"]
        super_key = registration.get("summary", {}).get("super")
        require(isinstance(super_key, str) and bool(super_key), "generated_super_missing")
        self.direct(self.a, ["sync"], allow_pending=True)
        self.direct(self.b, ["login", "--interactive", "--addr", UPSTREAM, "--user", self.user, "--pass=" + self.password, "--super=" + super_key])
        stopped = subprocess.run([str(self.args.binary), '--runtime-internal', '--stop'],
            env=self.b, capture_output=True, timeout=60)
        require(stopped.returncode == 0, 'independent_login_runtime_stop_failed')
        session = json.loads(session_path.read_text(encoding="utf-8"))
        require(session.get("addr") == UPSTREAM, "unexpected_registered_upstream")
        session["addr"] = self.gate.address
        session_path.write_text(json.dumps(session), encoding="utf-8")
        session_path.chmod(0o600)

    def start(self, automatic=True):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        env = self.a.copy()
        if automatic:
            env.pop("RSRS_NO_AUTOSYNC", None)
        env["RSRS_RPC_PORT"] = str(self.port)
        self.child = subprocess.Popen([str(self.args.binary), "--runtime-internal", "--no-open", "--port", str(self.port)],
                                      env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        data_dir = Path(env["RSRS_DATA_DIR"])
        token_path = data_dir / "runtime" / "token"
        endpoint_path = data_dir / "runtime" / "endpoint.json"

        def ready():
            require(self.child.poll() is None, "owned_runtime_exited_before_ready")
            require(not token_path.exists(), "loopback_runtime_created_token")
            if not endpoint_path.is_file():
                return False
            try:
                with urllib.request.urlopen("http://127.0.0.1:" + str(self.port) + "/api/health", timeout=5) as response:
                    require(response.status == 200, "runtime_health_status_failed")
                    health = json.load(response)
            except urllib.error.HTTPError:
                raise RuntimeError("runtime_health_status_failed") from None
            except (OSError, urllib.error.URLError):
                return False
            require(health.get("v") == 1 and health.get("bin") == self.args.version
                    and health.get("pid") == self.child.pid
                    and Path(health.get("exe", "")).resolve() == self.args.binary
                    and Path(health.get("data_dir", "")).resolve() == data_dir.resolve(),
                    "owned_runtime_identity_mismatch")
            return True

        wait_for(ready, 30, "runtime_start_timeout")
        wait_for(lambda: self.rpc(["status"]).get("ok"), 30, "runtime_ready_timeout")

    def rpc(self, command):
        request = urllib.request.Request("http://127.0.0.1:" + str(self.port) + "/api/rpc",
            json.dumps({"v": 1, "id": secrets.token_hex(16), "method": "cli.exec", "args": ["--json", *command]}).encode(),
            {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.load(response)
        except Exception:
            raise RuntimeError("local_rpc_failed") from None

    def remember(self, title, content, direct=False):
        command = ["remember", content, "--title", title, "--importance", "important", "--force"]
        if direct:
            self.direct(self.a, command)
        else:
            result = self.rpc(command)
            require(result.get("ok") and result.get("exit") == 0, "foreground_save_failed")
        with sqlite3.connect(Path(self.a["RSRS_DATA_DIR"]) / "rsrs.db") as db:
            row = db.execute("SELECT id FROM memories WHERE title=? AND deleted=0", (title,)).fetchone()
        require(row is not None, "saved_memory_missing")
        return row[0]

    def diagnose(self, report, phase):
        # Only finite state and counts, never session fields or provider error strings.
        result = {"phase": phase, "runtime_alive": self.child is not None and self.child.poll() is None,
                  "direct_failures": list(self.direct_failures)}
        with self.gate.lock:
            result.update(request_counts=dict(self.gate.request_counts), sync_read_requests=self.gate.sync_read_requests,
                          injected_disconnects=self.gate.fault_requests, real_acknowledgments=len(self.gate.acknowledged),
                          proxy_response_parse_failures=self.gate.proxy_response_parse_failures)
        try:
            result["pending"] = self.pending()
            if result["runtime_alive"]:
                summary = self.rpc(["status"]).get("envelope", {}).get("summary", {})
                scheduler = summary.get("sync_scheduler", {})
                result["scheduler"] = {key: scheduler.get(key) for key in ("state", "next_run_ms", "manual_waiters")}
                result["autosync"] = summary.get("autosync")
                result["remote_configured"] = summary.get("remote_configured")
                result["sync_phase"] = summary.get("sync_live", {}).get("phase")
        except Exception:
            result["diagnostic_code"] = "local_diagnostics_unavailable"
        report.setdefault("diagnostics", []).append(result)

    def pending(self):
        with sqlite3.connect(Path(self.a["RSRS_DATA_DIR"]) / "rsrs.db") as db:
            return db.execute("SELECT COUNT(*) FROM sync_outbox WHERE state='pending'").fetchone()[0]

    def snapshot(self):
        with sqlite3.connect(Path(self.a["RSRS_DATA_DIR"]) / "rsrs.db") as db:
            return {
                "pending": db.execute("SELECT seq,id FROM sync_outbox WHERE state='pending' ORDER BY seq").fetchall(),
                "envelopes": db.execute("SELECT id,user,ciphertext,nonce,embedding_enc,updated_at,deleted FROM sync_outbox WHERE state='pending' ORDER BY seq").fetchall(),
                "dirty": {row[0] for row in db.execute("SELECT id FROM memories WHERE dirty=1")},
                "epoch": db.execute("SELECT value FROM meta WHERE key='sync_v2_epoch'").fetchone(),
            }

    def prove(self, memories):
        def acknowledged():
            with self.gate.lock:
                require(self.gate.proxy_response_parse_failures == 0, "proxy_response_parse_failure")
                real_acknowledged = set(memories).issubset(self.gate.acknowledged)
            return self.pending() == 0 and real_acknowledged
        wait_for(acknowledged, 150, "real_ack_timeout")
        self.direct(self.b, ["sync"], allow_pending=True)
        for memory_id, content in memories.items():
            shown = self.direct(self.b, ["show", memory_id])
            require(any(node.get("id") == memory_id and node.get("content") == content for node in objects(shown)), "independent_pull_decrypt_mismatch")

    def close(self):
        stopped = False
        try:
            self.gate.release.set()
            if self.child is not None:
                self.child.terminate()
                try:
                    self.child.wait(10)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(10)
            self.gate.close()
            stopped = True
        except Exception:
            self.cleanup_report["events"].append({"user": self.user, "passed": False, "code": "cleanup_runtime_shutdown_failed"})
        if stopped:
            self.cleanup_account()

    def cleanup_account(self):
        if not self.created:
            self.cleanup_report["events"].append({"user": self.user, "passed": not self.registration_attempted,
                "code": "registration_outcome_unconfirmed" if self.registration_attempted else "no_account_created"})
            return
        if not self.account_token:
            self.cleanup_report["events"].append({"user": self.user, "passed": False, "code": "cleanup_account_token_missing"})
            return
        def request(method, path, body=None):
            encoded = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(UPSTREAM + path, encoded,
                {"Authorization": "Bearer " + self.account_token, "Content-Type": "application/json"}, method=method)
            try:
                response = self.gate.opener.open(req, timeout=45)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.code
                raw = response.read(1024 * 1024 + 1)
                require(len(raw) <= 1024 * 1024, "cleanup_response_too_large")
                return status, json.loads(raw)
        try:
            # The authenticated server binds purge to this confirmed-created user, never an admin target.
            status, result = request("POST", "/api/self/purge", {"confirm": self.user})
            require(status == 200 and result.get("purged") is True and result.get("user") == self.user, "cleanup_self_purge_failed")
            status, _ = request("GET", "/api/self")
            require(status == 401, "cleanup_token_still_accepted")
            self.cleanup_report["remaining_users"].remove(self.user)
            self.cleanup_report["events"].append({"user": self.user, "passed": True, "self_purge_confirmed": True, "old_token_rejected": True})
        except Exception:
            self.cleanup_report["events"].append({"user": self.user, "passed": False, "code": "cleanup_self_purge_or_verification_failed"})


def run(args, report):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    args.binary = args.binary.resolve(strict=True)
    require(args.binary.is_file(), "invalid_artifact_inputs")
    require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == args.binary_sha256.lower(), "binary_hash_mismatch")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    args.root = args.root.resolve()
    require(args.root != runner_temp and args.root.is_relative_to(runner_temp), "root_must_be_runner_temp_child")
    args.model_dir = args.model_dir.resolve()
    require(args.model_dir == args.root / "models", "model_dir_must_be_owned_root_models")
    args.root.mkdir(parents=True, exist_ok=False, mode=0o700)
    report.update(source_sha=args.source_sha, version=args.version, binary_sha256=args.binary_sha256.lower(), upstream=UPSTREAM)
    fixture = Fixture(args, args.root / "foreground", report["cleanup"])
    try:
        version = fixture.direct(fixture.a, ["v"])
        require(any(value == args.version for node in objects(version) for value in node.values() if isinstance(value, str)), "binary_version_mismatch")
        args.model_dir.mkdir(mode=0o700)
        # The CLI sweep can uninstall its models; install independently through the pinned CLI flow.
        fixture.direct(fixture.a, ["model", "install-m3"], timeout=600)
        share_cpu_container(args.root, fixture.a, args.model_dir)
        require(all(path.is_file() and path.stat().st_size > 0 for path in
                    (args.model_dir / "tokenizer.json", args.model_dir / "onnx" / "model_quantized.onnx")),
                "installed_model_files_missing")
        fixture.prepare()
        seed_content = "Development queued foreground seed " + secrets.token_hex(16)
        seed_id = fixture.remember("CI foreground seed", seed_content, direct=True)
        require(fixture.pending() > 0, "foreground_seed_not_pending")
        fixture.gate.hold = True
        fixture.start()
        require(fixture.gate.entered.wait(30), "real_sync_read_hold_not_entered")
        content = "Development outbox foreground marker " + secrets.token_hex(16)
        started = time.monotonic()
        memory_id = fixture.remember("CI outbox foreground", content)
        elapsed = round((time.monotonic() - started) * 1000, 2)
        require(not fixture.gate.release.is_set() and fixture.pending() > 0, "foreground_did_not_precede_network_release")
        require(fixture.rpc(["status"]).get("ok"), "status_during_network_wait_failed")
        fixture.gate.hold = False
        fixture.gate.release.set()
        fixture.prove({seed_id: seed_content, memory_id: content})
        report["cases"]["foreground_save_during_network_wait"] = {"passed": True, "completed_before_release": True, "elapsed_ms": elapsed}
        report["cases"]["independent_pull_decrypt"] = {"passed": True, "real_acknowledgments": 2, "content_equal": True}
    finally:
        fixture.diagnose(report, "foreground")
        fixture.close()

    fixture = Fixture(args, args.root / "finite-manual", report["cleanup"])
    manual_thread = None
    try:
        fixture.prepare()
        entered, release = fixture.gate.hold_call(1)
        fixture.start(automatic=False)
        first_content = "Development finite boundary first marker " + secrets.token_hex(16)
        first_id = fixture.remember("CI finite first", first_content)
        captured_boundary = max(seq for seq, _ in fixture.snapshot()["pending"])
        manual = {}
        def synchronize():
            try:
                manual["response"] = fixture.rpc(["sync"])
            except Exception:
                manual["failed"] = True
        manual_thread = threading.Thread(target=synchronize, daemon=True)
        manual_thread.start()
        require(entered.wait(30), "manual_sync_read_gate_not_entered")
        later_content = "Development finite boundary later marker " + secrets.token_hex(16)
        later_id = fixture.remember("CI finite later", later_content)
        require(any(seq > captured_boundary and identity == later_id for seq, identity in fixture.snapshot()["pending"]), "later_operation_not_beyond_boundary")
        release.set()
        manual_thread.join(60)
        require(not manual_thread.is_alive() and not manual.get("failed"), "manual_pass_timeout")
        response = manual["response"]
        require(response.get("exit") == 2 and not response.get("envelope", {}).get("errors"), "finite_manual_missing_pending_warning")
        after = fixture.snapshot()
        require({identity for _, identity in after["pending"]} == {later_id} and later_id in after["dirty"], "manual_pass_acknowledged_later_write")
        require(first_id in fixture.gate.acknowledged and later_id not in fixture.gate.acknowledged, "manual_push_exceeded_captured_boundary")
        second = fixture.rpc(["sync"])
        require(second.get("exit") in (0, 2) and not second.get("envelope", {}).get("errors"), "second_manual_sync_failed")
        fixture.prove({first_id: first_content, later_id: later_content})
        report["cases"]["finite_manual_boundary"] = {"passed": True, "later_write_retained": True, "first_pass_real_ack_only": True, "second_pass_and_independent_pull": True}
    finally:
        fixture.diagnose(report, "finite_manual")
        fixture.close()
        if manual_thread is not None:
            manual_thread.join(5)

    fixture = Fixture(args, args.root / "reset", report["cleanup"])
    try:
        fixture.prepare()
        content = "Development reset pending marker " + secrets.token_hex(16)
        memory_id = fixture.remember("CI reset pending", content, direct=True)
        require(fixture.pending() > 0, "reset_seed_not_pending")
        old_entered, old_release = fixture.gate.hold_call(1)
        new_entered, new_release = fixture.gate.hold_call(2)
        fixture.start()
        require(old_entered.wait(30), "reset_old_sync_read_gate_not_entered")
        before = fixture.snapshot()
        require(before["epoch"] is not None and memory_id in before["dirty"], "reset_initial_epoch_or_pending_missing")
        reset = fixture.rpc(["sync-reset"])
        require(reset.get("ok") and reset.get("exit") == 0, "local_snapshot_reset_failed")
        reset_snapshot = fixture.snapshot()
        # Reset deliberately requeues fresh identities; compare preserved envelopes, not old seq values.
        require(reset_snapshot["epoch"] is None and reset_snapshot["envelopes"] == before["envelopes"]
                and memory_id in reset_snapshot["dirty"], "reset_did_not_preserve_pending_envelopes")
        old_release.set()
        # A subsequent held pass proves the old pass completed, without allowing new epoch application.
        require(new_entered.wait(45), "reset_new_generation_pass_not_entered")
        after = fixture.snapshot()
        require(after == reset_snapshot, "old_response_mutated_reset_snapshot")
        require(memory_id not in fixture.gate.acknowledged, "old_generation_uploaded_pending_marker")
        new_release.set()
        fixture.prove({memory_id: content})
        report["cases"]["reset_old_response_rejection"] = {"passed": True, "old_response_released": True,
            "subsequent_pass_observed": True, "old_response_could_not_restore_epoch": True,
            "pending_envelopes_preserved": True, "new_pass_real_ack_and_independent_pull": True}
    finally:
        fixture.diagnose(report, "reset")
        fixture.close()
    fixture = Fixture(args, args.root / "backoff", report["cleanup"])
    try:
        fixture.prepare()
        fixture.gate.fail = True
        fixture.start()
        content = "Development outbox scheduled retry marker " + secrets.token_hex(16)
        memory_id = fixture.remember("CI outbox backoff", content)
        def backoff():
            state = fixture.rpc(["status"]).get("envelope", {}).get("summary", {}).get("sync_scheduler", {})
            return state if state.get("state") == "backoff" else None
        state = wait_for(backoff, 100, "scheduler_backoff_not_observed")
        require(0 < state.get("next_run_ms", 0) <= 31000 and fixture.pending() > 0, "backoff_did_not_preserve_pending")
        with fixture.gate.lock:
            failed_requests = fixture.gate.fault_requests
        require(failed_requests > 0, "transport_fault_not_injected")
        fixture.gate.fail = False
        # No sync command or mutation after this point: only the scheduled pass can upload.
        fixture.prove({memory_id: content})
        report["cases"]["scheduled_transport_retry"] = {"passed": True, "injected_disconnects": failed_requests, "backoff_observed": True, "scheduled_real_ack": True, "independent_content_equal": True}
    finally:
        fixture.diagnose(report, "backoff")
        fixture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    args = parser.parse_args()
    required = ["foreground_save_during_network_wait", "independent_pull_decrypt", "scheduled_transport_retry", "finite_manual_boundary", "reset_old_response_rejection"]
    report = {"passed": False, "cases": {}, "required": required,
              "cleanup": {"passed": False, "remaining_users": [], "unconfirmed_users": [], "events": []}}
    try:
        run(args, report)
        require(all(report["cases"].get(name, {}).get("passed") is True for name in required), "required_case_missing")
        require(not report["cleanup"]["remaining_users"] and not report["cleanup"]["unconfirmed_users"]
                and all(event["passed"] for event in report["cleanup"]["events"]), "fixture_cleanup_failed")
        report["passed"] = True
    except Exception as error:
        # Only harness-owned error codes are safe for public diagnostics.
        report["failure_code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    report["remaining"] = [name for name in required if report["cases"].get(name, {}).get("passed") is not True]
    cleanup = report["cleanup"]
    cleanup["passed"] = not cleanup["remaining_users"] and not cleanup["unconfirmed_users"] and all(event["passed"] for event in cleanup["events"])
    runner_temp = os.environ.get("RUNNER_TEMP")
    safe_root = runner_temp and args.root.resolve() != Path(runner_temp).resolve() and args.root.resolve().is_relative_to(Path(runner_temp).resolve())
    if os.environ.get("GITHUB_ACTIONS") == "true" and safe_root and args.root.is_dir():
        (args.root / "outbox-coverage.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "cases": report["cases"], "failure_code": report.get("failure_code"), "remaining": report["remaining"], "cleanup": cleanup}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

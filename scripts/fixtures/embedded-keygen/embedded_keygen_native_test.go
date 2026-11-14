// Injected only into an exact pinned Client2 checkout by run.py.
// Real paired CLI and Runtime, no mock RPC or external account credentials.
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSourceNativeEmbeddedKeygen(t *testing.T) {
	if os.Getenv("RESP_ENV_EMBEDDED_NATIVE") != "1" {
		t.Skip("isolated source-native runner required")
	}
	m, err := New()
	if err != nil {
		t.Fatal("manager initialization failed")
	}
	info, err := m.Installed()
	if err != nil {
		t.Fatal("managed inventory unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	executable, err := m.hostExecutable(ctx)
	if err != nil || !samePath(executable, filepath.Join(m.DataRoot, "bin", cliBinary())) {
		t.Fatal("not the selected host CLI")
	}
	runtimeImage := filepath.Join(m.runtimeDir(info.Version), runtimeBinary())
	t.Cleanup(func() {
		if m.Stop(true) != nil {
			t.Error("owned Runtime cleanup failed")
			return
		}
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, _, err := m.Health(cleanupCtx); !IsUnavailable(err) {
			t.Error("owned Runtime exit unconfirmed")
			return
		}
		if _, err := os.Lstat(filepath.Join(m.DataRoot, "runtime", "endpoint.json")); !os.IsNotExist(err) {
			t.Error("Runtime endpoint cleanup unconfirmed")
			return
		}
		if os.WriteFile(filepath.Join(m.DataRoot, "native-runtime-stopped"), []byte("confirmed"), 0600) != nil {
			t.Error("cleanup receipt failed")
		}
	})
	// Do not decode, log, or save the keygen output containing recovery material.
	requestID := "desktop-41abf107-3eb1-4d89-8acb-4053b1d9f012"
	job, err := m.Submit("keygen", requestID, nil, true, "")
	if err != nil {
		t.Fatal("managed keygen submission failed")
	}
	for job.State == "running" {
		select {
		case <-ctx.Done():
			t.Fatal("managed keygen receipt timeout")
		case <-time.After(100 * time.Millisecond):
		}
		job, err = m.Operation(requestID)
		if err != nil {
			t.Fatal("managed keygen receipt unavailable")
		}
	}
	if job.State != "done" || job.ID != requestID || job.Finished == nil || envelopeError(job.Envelope) != nil {
		t.Fatal("managed keygen receipt failed")
	}
	repeated, err := m.Submit("keygen", requestID, nil, true, "")
	if err != nil || repeated.State != "done" || !bytes.Equal(repeated.Envelope, job.Envelope) {
		t.Fatal("completed request was not retained")
	}
	saved, err := os.ReadFile(filepath.Join(m.Root, "requests.json"))
	if err != nil {
		t.Fatal("managed keygen receipt not persisted")
	}
	var records []operationRecord
	if json.Unmarshal(saved, &records) != nil {
		t.Fatal("managed keygen receipt invalid")
	}
	found := false
	for _, record := range records {
		if record.ID == requestID && record.State == "done" {
			found = true
		}
	}
	if !found {
		t.Fatal("completed keygen request absent from operation records")
	}
	pending := filepath.Join(m.DataRoot, "runtime", "autostart", "offline-keygen.json")
	before, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal("original operation not persisted")
	}
	var original struct {
		Operation string `json:"operation_id"`
		Stage     string `json:"stage"`
	}
	if json.Unmarshal(before, &original) != nil || original.Stage != "committed" || original.Operation == "" {
		t.Fatal("original operation not committed")
	}
	// A successful exact-O query proves this command reaches the real handler,
	// not merely a parser refusal. Its private response is discarded.
	if _, err = m.hostOperation(ctx, []string{"runtime", "auth-result", "--operation-id", original.Operation}, "", "", ""); err != nil {
		t.Fatal("original operation query failed")
	}
	before, err = os.ReadFile(pending)
	if err != nil {
		t.Fatal("original query lost pending evidence")
	}
	var queried struct {
		Operation string `json:"operation_id"`
		Stage     string `json:"stage"`
	}
	if json.Unmarshal(before, &queried) != nil || queried.Operation != original.Operation || queried.Stage != "committed" {
		t.Fatal("original query changed operation")
	}
	// Foreign operation input must never create another keygen O.
	if _, err = m.hostOperation(ctx, []string{"runtime", "auth-result", "--operation-id", "cbb9ee67-bb58-49bf-aea5-20089f79f598"}, "", "", ""); err == nil {
		t.Fatal("mismatched original operation accepted")
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused lookup altered original evidence")
	}
	if err = m.Start(); err != nil {
		logEmbeddedStartFailure(t, m, err)
		t.Fatal("managed explicit Start failed")
	}
	if _, err = os.Stat(pending); !os.IsNotExist(err) {
		t.Fatal("completed handoff retained original pending record")
	}
	healthCtx, healthCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer healthCancel()
	h, raw, err := m.Health(healthCtx)
	if err != nil {
		t.Fatal("serving actor unavailable")
	}
	if h.PID == 0 || h.Version != info.Version || !samePath(h.Exe, runtimeImage) || !samePath(h.DataDir, m.DataRoot) {
		t.Fatal("serving actor identity mismatch")
	}
	var actor struct {
		Instance   string `json:"instance_id"`
		Birth      string `json:"process_start_id"`
		Generation uint64 `json:"generation"`
		StoreReady bool   `json:"store_ready"`
	}
	if json.Unmarshal(raw, &actor) != nil || actor.Instance == "" || actor.Birth == "" || actor.Generation == 0 || !actor.StoreReady {
		t.Fatal("strong actor identity unavailable")
	}
	// Exercise the real Client2 scoped diagnostic RPC, not just health.
	// Only inspect its success bit; do not log the diagnostic payload.
	diagnostic, err := m.RPC("status")
	if err != nil {
		t.Fatal("Client2 scoped status RPC failed")
	}
	var diagnosticEnvelope struct {
		OK    bool            `json:"ok"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(diagnostic, &diagnosticEnvelope) != nil || !diagnosticEnvelope.OK || len(diagnosticEnvelope.Error) > 0 && string(diagnosticEnvelope.Error) != "null" {
		t.Fatal("Client2 scoped status RPC was refused")
	}
	// Repeated explicit Start is idempotent at the actual Client2 manager surface.
	if err = m.Start(); err != nil {
		t.Fatal("second Start failed")
	}
	next, nextRaw, err := m.Health(healthCtx)
	if err != nil || next.PID != h.PID || next.Exe != h.Exe {
		t.Fatal("Start replaced the verified actor")
	}
	var afterActor struct {
		Instance   string `json:"instance_id"`
		Birth      string `json:"process_start_id"`
		Generation uint64 `json:"generation"`
		StoreReady bool   `json:"store_ready"`
	}
	if json.Unmarshal(nextRaw, &afterActor) != nil || actor != afterActor {
		t.Fatal("Start changed strong actor identity")
	}
	// Restart the serving image directly while native credentials still exist.
	// Runtime must ignore those entries until its host supplies their material.
	session, err := os.ReadFile(filepath.Join(h.DataDir, "session.json"))
	if err != nil {
		t.Fatal("session unavailable")
	}
	var savedSession map[string]json.RawMessage
	if json.Unmarshal(session, &savedSession) != nil {
		t.Fatal("invalid session")
	}
	for _, field := range []string{"super", "pass", "secret_key", "secret"} {
		if value := savedSession[field]; len(value) > 0 && string(value) != "null" && string(value) != "\"\"" {
			t.Fatal("session retained private key material")
		}
	}
	if err = m.Stop(true); err != nil {
		t.Fatal("pre-restart drain failed")
	}
	endpoint, err := url.Parse(m.Endpoint)
	if err != nil {
		t.Fatal("invalid endpoint")
	}
	child := exec.Command(runtimeImage, "serve", "--data-dir", m.DataRoot, "--port", endpoint.Port())
	configureCommand(child)
	child.Env = append(os.Environ(), "RSRS_SUPER=synthetic-wrong-inherited-key")
	if err = child.Start(); err != nil {
		t.Fatal("direct foreground Runtime failed to start")
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = child.Process.Kill()
			<-exited
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	var locked HealthInfo
	for time.Now().Before(deadline) {
		var value json.RawMessage
		locked, value, err = m.Health(ctx)
		var state struct {
			Startup bool `json:"startup_complete"`
		}
		if err == nil && json.Unmarshal(value, &state) == nil && state.Startup {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || locked.PID != uint32(child.Process.Pid) || locked.StoreReady || locked.CredentialState != "required" {
		t.Fatal("direct restart did not remain locked")
	}
	rejected, err := m.rpcResponse(ctx, "cli.exec", []string{"--json", "recall", "host-owned-native"}, "native-locked-read")
	if err != nil || rejected.OK || rejected.Code != "runtime_locked" {
		t.Fatal("locked Runtime accepted memory RPC")
	}
	if err = m.Start(); err != nil {
		t.Fatal("Client2 could not supply the stored native credential")
	}
	unlocked, _, err := m.Health(ctx)
	if err != nil || unlocked.PID != locked.PID || !unlocked.StoreReady {
		t.Fatal("Client2 did not unlock the existing owner")
	}
	if err = m.Stop(true); err != nil {
		t.Fatal("unlocked owner drain failed")
	}
	select {
	case exitErr := <-exited:
		if exitErr != nil {
			t.Fatal("foreground Runtime exited unsuccessfully")
		}
		exited <- nil
	case <-ctx.Done():
		t.Fatal("foreground Runtime exit unconfirmed")
	}
	if _, err = m.hostOperation(ctx, []string{"runtime", "start"}, "", "runtime.start", ""); err != nil {
		t.Fatal("CLI automatic key delivery failed")
	}
	ready, _, err := m.Health(ctx)
	if err != nil || !ready.StoreReady || ready.PID == locked.PID {
		t.Fatal("CLI did not unlock its replacement owner")
	}
	if _, err = m.executeRPC(ctx, "cli.exec", []string{"--json", "remember", "Host-owned native credential regression.", "--title", "host-owned-native", "--force"}, "native-remember"); err != nil {
		t.Fatal("remember failed after host unlock")
	}
	if _, err = m.executeRPC(ctx, "cli.exec", []string{"--json", "recall", "host-owned-native"}, "native-recall"); err != nil {
		t.Fatal("recall failed after host unlock")
	}
	t.Log("paired native keygen, direct restart locked, Client2 same-owner unlock, CLI restart unlock, remember and recall passed")
}

// Only closed-set labels are emitted. Never log the host error or private files.
func logEmbeddedStartFailure(t *testing.T, m *Manager, failure error) {
	reason := "unclassified"
	for _, label := range []string{
		"current account identity missing user",
		"host runtime exited before readiness", "host runtime did not become ready",
		"runtime owner changed during startup", "failed to start host runtime",
		"offline keygen original is not committed", "offline keygen original identity changed",
		"offline keygen starting marker changed", "offline keygen completion binding mismatch",
		"offline keygen completion readiness mismatch", "offline keygen actor changed during completion",
		"offline keygen original Paused marker changed", "offline keygen owner already exists",
		"offline keygen capability Runtime binding changed", "selected Runtime changed during host command",
		"offline keygen target", "offline keygen completion", "Runtime host action failed",
	} {
		if strings.Contains(failure.Error(), label) {
			reason = label
			break
		}
	}
	readiness := "unknown"
	if strings.Contains(failure.Error(), "last_store_ready=Some(false)") {
		readiness = "store_not_ready"
	} else if strings.Contains(failure.Error(), "last_store_ready=None") {
		readiness = "health_absent"
	} else if strings.Contains(failure.Error(), "last_store_ready=Some(true)") {
		readiness = "store_ready_observed"
	}
	stage := embeddedPhaseLabel(filepath.Join(m.DataRoot, "runtime", "autostart", "offline-keygen.json"), "stage",
		[]string{"prepared", "sent", "committed", "starting", "verified", "finished", "handed_off", "rolled_back", "rollback_starting", "rollback_finished", "rollback_handed_off"})
	phase := embeddedPhaseLabel(filepath.Join(m.DataRoot, "runtime", "autostart", "maintenance.json"), "phase",
		[]string{"paused", "starting", "verified", "Paused", "Starting", "Verified"})
	endpoint := "unreadable"
	if _, err := os.Lstat(filepath.Join(m.DataRoot, "runtime", "endpoint.json")); err == nil {
		endpoint = "present"
	} else if os.IsNotExist(err) {
		endpoint = "absent"
	}
	t.Logf("embedded Start diagnostic: reason=%s readiness=%s pending=%s marker=%s endpoint=%s", reason, readiness, stage, phase, endpoint)
}
func embeddedPhaseLabel(path, field string, allowed []string) string {
	meta, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil || !meta.Mode().IsRegular() || meta.Size() > 65536 {
		return "unreadable"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return "invalid"
	}
	var phase string
	if json.Unmarshal(value[field], &phase) != nil {
		return "invalid"
	}
	for _, known := range allowed {
		if phase == known {
			return known
		}
	}
	return "unknown"
}

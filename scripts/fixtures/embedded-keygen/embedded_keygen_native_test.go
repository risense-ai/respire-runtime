// Injected only into an exact pinned Client2 checkout by run.py.
// Real managed Runtime, no mock RPC, no external CLI, no account credentials.
package host

import (
 "bytes"
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestSourceNativeEmbeddedKeygen(t *testing.T) {
 if os.Getenv("RESP_ENV_EMBEDDED_NATIVE") != "1" { t.Skip("isolated source-native runner required") }
 m, err := New(); if err != nil { t.Fatal("manager initialization failed") }
 info, err := m.Installed(); if err != nil { t.Fatal("managed inventory unavailable") }
 ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second); defer cancel()
 executable, err := m.hostExecutable(ctx)
 if err != nil || !samePath(executable, filepath.Join(m.runtimeDir(info.Version), runtimeBinary())) { t.Fatal("not the selected managed Runtime") }
 t.Cleanup(func(){
  if m.Stop(true) != nil { t.Error("owned Runtime cleanup failed"); return }
  cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second); defer done()
  if _, _, err := m.Health(cleanupCtx); !IsUnavailable(err) { t.Error("owned Runtime exit unconfirmed"); return }
  if _, err := os.Lstat(filepath.Join(m.DataRoot,"runtime","endpoint.json")); !os.IsNotExist(err) { t.Error("Runtime endpoint cleanup unconfirmed"); return }
  if os.WriteFile(filepath.Join(m.DataRoot,"native-runtime-stopped"),[]byte("confirmed"),0600) != nil { t.Error("cleanup receipt failed") }
 })
 // Do not decode, log, or save the keygen output containing recovery material.
 if _, err = m.hostOperation(ctx, []string{"keygen"}, "", "", ""); err != nil { t.Fatal("managed keygen failed") }
 pending := filepath.Join(m.DataRoot,"runtime","autostart","offline-keygen.json")
 before, err := os.ReadFile(pending); if err != nil { t.Fatal("original operation not persisted") }
 var original struct { Operation string `json:"operation_id"`; Stage string `json:"stage"` }
 if json.Unmarshal(before,&original) != nil || original.Stage != "committed" || original.Operation == "" { t.Fatal("original operation not committed") }
 // A successful exact-O query proves this command reaches the real handler,
 // not merely a parser refusal. Its private response is discarded.
 if _, err = m.hostOperation(ctx, []string{"runtime","auth-result","--operation-id",original.Operation},"","",""); err != nil { t.Fatal("original operation query failed") }
 before, err = os.ReadFile(pending); if err != nil { t.Fatal("original query lost pending evidence") }
 var queried struct { Operation string `json:"operation_id"`; Stage string `json:"stage"` }
 if json.Unmarshal(before,&queried) != nil || queried.Operation != original.Operation || queried.Stage != "committed" { t.Fatal("original query changed operation") }
 // Foreign operation input must never create another keygen O.
 if _, err = m.hostOperation(ctx, []string{"runtime","auth-result","--operation-id","cbb9ee67-bb58-49bf-aea5-20089f79f598"},"","",""); err == nil { t.Fatal("mismatched original operation accepted") }
 after, err := os.ReadFile(pending); if err != nil || !bytes.Equal(before,after) { t.Fatal("refused lookup altered original evidence") }
 if err = m.Start(); err != nil { t.Fatal("managed explicit Start failed") }
 if _, err = os.Stat(pending); !os.IsNotExist(err) { t.Fatal("completed handoff retained original pending record") }
 healthCtx, healthCancel := context.WithTimeout(context.Background(), 15*time.Second); defer healthCancel()
 h, raw, err := m.Health(healthCtx); if err != nil { t.Fatal("serving actor unavailable") }
 if h.PID == 0 || h.Version != info.Version || !samePath(h.Exe,executable) || !samePath(h.DataDir,m.DataRoot) { t.Fatal("serving actor identity mismatch") }
 var actor struct { Instance string `json:"instance_id"`; Birth string `json:"process_start_id"`; Generation uint64 `json:"generation"`; StoreReady bool `json:"store_ready"` }
 if json.Unmarshal(raw,&actor) != nil || actor.Instance == "" || actor.Birth == "" || actor.Generation == 0 || !actor.StoreReady { t.Fatal("strong actor identity unavailable") }
 // Repeated explicit Start is idempotent at the actual Client2 manager surface.
 if err = m.Start(); err != nil { t.Fatal("second Start failed") }
 next, nextRaw, err := m.Health(healthCtx); if err != nil || next.PID != h.PID || next.Exe != h.Exe { t.Fatal("Start replaced the verified actor") }
 var afterActor struct { Instance string `json:"instance_id"`; Birth string `json:"process_start_id"`; Generation uint64 `json:"generation"`; StoreReady bool `json:"store_ready"` }
 if json.Unmarshal(nextRaw,&afterActor) != nil || actor != afterActor { t.Fatal("Start changed strong actor identity") }
 t.Log("managed keygen, refused foreign operation, explicit Start and same-actor checks passed")
}

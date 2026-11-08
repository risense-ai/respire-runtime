package main

import (
	"encoding/json"
	"os"
	"respire-client2/internal/host"
)

func main() {
	manager, err := host.New()
	var reply any
	if err == nil {
		switch os.Args[1] {
		case "start":
			err = manager.Start()
			if err == nil {
				reply, err = manager.RPC("status")
			}
		case "stop":
			err = manager.Stop(false)
		default:
			panic("unknown fixture operation")
		}
	}
	result := map[string]any{"ok": err == nil, "reply": reply}
	if err != nil {
		result["error"] = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(result)
	if err != nil {
		os.Exit(1)
	}
}

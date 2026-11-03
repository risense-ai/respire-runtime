---
name: rsrs
description: Encrypted local-first AI memory. Use when the user asks to remember, recall, store a decision, or look up prior conclusions. Call rsrs MCP tools only. Never run the rsrs CLI, npx, or npm wrappers inside the WorkBuddy sandbox.
---

# rsrs

rsrs is the user's long-term memory store. The WorkBuddy connector talks to it over MCP. The MCP process is started by WorkBuddy, not by Bash.

## Hard rules

- Use MCP tools (`memory_recall`, `memory_remember`, `memory_show`, `memory_update`, `memory_attach`, `memory_list`, `memory_tree`, `memory_history`, `memory_diary`, `memory_chain`, `memory_query_log_mark`, `memory_forget`, `memory_restore`, `memory_taxonomy`, `memory_status`).
- Do not run `rsrs`, `rsrs.cmd`, `npx rsrs-cli`, or any npm wrapper in Bash. Default sandbox blocks `~/.rsrs`, the model directory, and the npm shim.
- Opening full access is not the normal fix.
- First tool in a turn is `memory_recall`. If it fails, say `recall failed: <cause>` in the first line.

## HTTP fallback (Codex and other hosts)

If this session has no rsrs MCP tools, tell the user to start `rsrs web` and add Streamable HTTP:

`http://127.0.0.1:15169/mcp`

Do not fall back to sandboxed CLI.

## How to remember

Prefer update/merge/attach over a new root. Body uses the cause/action/result three markers. Pass `title`, extracted from the body facts (subject + action + key entity or result, 12–24 chars) — never a bare topic label. Important reusable facts use `importance=important`. Diary trivia uses `importance=trivial`. After `memory_recall`, mark useful hits with `memory_query_log_mark` (`good` or `bad`).

## Login

Local remember/recall works after `rsrs doctor` on the host. Cloud sync needs a host-side `rsrs login`. The connector `status` command only checks that the CLI runs.

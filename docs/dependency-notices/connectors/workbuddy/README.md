# WorkBuddy rsrs connector

MCP connector for [WorkBuddy](https://open.workbuddy.cn/docs/connector). Type is `mcp`, not `cli`.

WorkBuddy's default sandbox cannot run the npm-wrapped `rsrs` CLI against `~/.rsrs`. This package starts `rsrs mcp` in WorkBuddy's Node runtime (outside Bash) and teaches the model to use MCP tools only.

## Layout

- `connector-meta.json` — `type: mcp`
- `mcp.json` — stdio `rsrs mcp` with `runtime.node`
- `cli.json` — `preAuth` install/status only (`npm i -g rsrs-cli && rsrs doctor`)
- `skills/respire/SKILL.md` — never Bash the CLI in the sandbox
- `icon.svg`

## HTTP / SSE

The CLI also serves Streamable HTTP at `POST /mcp` and legacy SSE at `GET /sse` on `rsrs web` (default `http://127.0.0.1:15169`). Use that from hosts that sandbox stdio MCP (for example Codex). This WorkBuddy package uses stdio because WorkBuddy starts the process.

## Packaging

Package this directory for the WorkBuddy platform. Host setup provides the CLI and
authenticated runtime; never install or run the npm wrapper inside the sandbox.

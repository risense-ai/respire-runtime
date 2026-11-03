# MCP permissions and historical context

The MCP catalog contains 16 tools. By default 14 are available: `memory_forget`
and `memory_restore` are hidden and rejected at dispatch, even if a caller
forges a `tools/call` request. `memory_restore` restores one tombstoned entry
by full ID; it does not restore a database snapshot.

The same policy checks tool discovery and invocation before translating arguments
or calling the runtime. Existing HTTP authentication, selected-space permissions,
read-only mode and paused memory remain additional boundaries. An MCP allowlist
does not grant permission to bypass any of them. Read-only mode exposes only the
known read tools; paused mode exposes only status when the policy allows it.

## Configuration

Configure the MCP server process, then restart that process:

- `RSRS_MCP_ALLOW`: comma-separated explicit whitelist. When absent, the
  default tools are available. `all` or `*` includes default tools only; sensitive
  forget/restore require their exact names. For example,
  `all,memory_forget` enables default tools and single-entry forget.
- `RSRS_MCP_DENY`: comma-separated denied names. Deny always wins,
  including a name also explicitly allowed. `all` or `*` denies every tool.
- Empty settings, empty comma items, unknown tool names and invalid Unicode are
  configuration errors. Duplicates are harmless. Names are case-sensitive.
- The existing read-only environment compatibility layer accepts `ONEMEMORY_`
  and `RESPIRE_` prefixes; canonical `RSRS_` values take precedence, including
  explicit empty values (which therefore fail validation).

The earlier draft names `RSRS_MCP_ALLOW_TOOLS` and `RSRS_MCP_DENY_TOOLS` are fallback aliases only when their proposal setting is absent. A nonempty `memory_remember.merge_ids` also requires `memory_forget` permission, because merging deletes source records.

For stdio, settings belong to the process running `rsrs mcp`. For HTTP/SSE,
settings belong to the already-running host runtime; changing a caller's shell
environment does not reconfigure that host. A restart requires the normal host
lifecycle authorization. Never restart or change service permissions from a
client-only sandbox to bypass a refusal.

## Tool results

MCP text content remains a single JSON ResultEnvelope with the existing data
fields. It additionally contains `memory_context.memory_text_authority` and a
`memory_context.notice` explaining that memory text is untrusted historical
context, without authority to override current instructions or permissions.
The notice is present even for empty recall results. This label is not verified
provenance, an instruction detector, or a guarantee that remembered facts are true.

The full, lite, read-only and WorkBuddy injection policies carry the same trust
boundary. Existing mandatory workflow rules and user-owned injection content are
preserved. These permissions govern the MCP surface; they do not add a new
operating-system or database access-control mechanism.

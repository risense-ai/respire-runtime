//! Shared clap definitions for the rsrs command surface.
//!
//! The CLI binary and the standalone runtime must parse the exact same
//! commands; the definitions live here so the two cannot drift. The bodies
//! are extracted verbatim from the CLI binary (runtime split, 2026-11-03);
//! only visibility was widened to `pub`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rsrs",
    version = crate::app_version::clap_version(),
    about = "\u{8de8}\u{8bbe}\u{5907}\u{8de8}\u{8f6f}\u{4ef6}\u{7edf}\u{4e00} AI \u{8bb0}\u{5fc6}\u{7cfb}\u{7edf}\u{ff08}local-first\u{ff09}",
    after_help = "Sandbox: use --client-only or RSRS_CLIENT_ONLY=1 to connect to the host HTTP runtime without managing its lifecycle."
)]
pub struct Cli {
    /// Machine-readable output: JSON only, without human progress.
    #[arg(long, global = true)]
    pub json: bool,
    /// Correlates TUI progress and cancellation with this model task only.
    #[arg(long, global = true, hide = true)]
    pub model_task_id: Option<String>,
    /// Foreground request progress, independent from model cancellation.
    #[arg(long, global = true, hide = true)]
    pub progress_id: Option<String>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum ModelAction {
    /// List built-in/custom profiles and the library's immutable active selection.
    Catalog,
    /// Save model/backend drafts from JSON without changing the active library.
    Configure { file: PathBuf },
    /// Prepare, probe and rebuild a profile before atomic activation.
    /// Backends: onnx (default), mlx (Apple Silicon), host_transport.
    Switch {
        model: String,
        #[arg(long, default_value = "onnx")] backend: String,
        #[arg(long, default_value = "cpu", value_parser = ["cpu","gpu","npu"])] engine: String,
        #[arg(long)] variant: Option<String>,
    },
    /// Read the profile-switch task, cancellation ID and current operation.
    Progress,
    /// Resume the library's last pending immutable profile snapshot.
    Resume,
    /// Download or verify BGE-M3 without rebuilding the index.
    #[command(name = "install", visible_alias = "install-m3")]
    InstallM3 {
        #[arg(long)]
        mirror: Option<String>,
        /// Also fetch this onnx variant (quantized, fp16, int8, uint8, q4, q4f16).
        #[arg(long)]
        model: Option<String>,
        /// Predownload dependencies for this engine without changing the active selection.
        #[arg(long, value_parser = ["npu", "gpu", "cpu"])]
        for_engine: Option<String>,
    },
    /// Build a resumable index generation and activate it after complete validation.
    Activate {
        #[arg(value_parser = ["m3"])]
        model: String,
    },
    /// Force CPU and terminate the runtime, even when inference or RPC is stuck.
    ResetCpu,
    /// Show or select inference engine. Failures do not switch engines; default CPU.
    Engine {
        #[arg(value_parser = ["npu", "gpu", "cpu"])]
        engine: Option<String>,
        /// Onnx model variant to pin (quantized, fp16, int8, uint8, q4, q4f16).
        #[arg(long)]
        model: Option<String>,
    },
    /// Validate installed weights, load and trial inference, then save selection. Never downloads.
    Load {
        #[arg(value_parser = ["npu", "gpu", "cpu"])]
        engine: String,
        #[arg(long)]
        model: String,
    },
    /// Install compatible NPU execution providers through Windows ML.
    InstallEngines,
    /// Run real inference with the active embedding profile and report its backend.
    Probe {
        #[arg(long)]
        model: Option<String>,
        /// Text to compare against the CPU baseline, including long-input checks.
        #[arg(long, default_value = "\u{672c}\u{5730}\u{63a8}\u{7406}\u{5f15}\u{64ce}\u{9a8c}\u{8bc1}\u{ff1a}\u{8bb0}\u{5fc6}\u{68c0}\u{7d22}")]
        text: String,
    },
    /// Delete the user-installed BGE-M3 files.
    #[command(name = "uninstall", visible_alias = "uninstall-m3")]
    UninstallM3,

}

#[derive(Subcommand)]
pub enum Command {
    /// Review evidence, due records and explicit approval-backed confirmations.
    Review {
        #[command(flatten)]
        args: review::ReviewArgs,
    },
    /// Host-owned foreground runtime and opt-in current-user sign-in startup.
    Runtime {
        #[command(subcommand)]
        command: autostart::RuntimeCommand,
    },
    /// Restart the resident runtime; kill the verified process if graceful shutdown times out.
    Restart {
        /// Seconds to wait for graceful shutdown before force termination.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout: u64,
    },
    /// Read the full memory workflow before storing or maintaining memories.
    Prompt,
    /// Print the embedded CLI version (same as `--version` / `-v`)
    #[command(name = "v", visible_alias = "version")]
    V,
    /// Manage independent read-only subtree grants for local tools.
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// List or revoke independent cloud login sessions; does not change local decrypt keys.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Generate local key material (offline; writes local session/keyfile - no server, no auth)
    Keygen {
        /// Compatibility flag: unused for encryption since v4 (the super password is system-generated)
        #[arg(long)]
        pass: Option<String>,
        /// Force overwrite with offline keys even if this machine already has cloud key material (drops the cloud session)
        #[arg(long)]
        force: bool,
    },
    /// Store a memory (local authority store; encrypts + embeds automatically).
    /// Judge-then-store (dedup first, then choose): without --force, an internal recall runs first -
    /// high similarity -> suggest merge (`--merge-ids "id1,id2"` deletes old, writes a combined entry);
    /// medium -> suggest attach (`--parent` as cause); no candidate or --force writes directly.
    /// `--parent` = causal attach; parent/child is cause/effect.
    Remember {
        content: String,
        /// Kind; defaults to context for creation and the first source's kind for merge.
        #[arg(long, value_parser = metadata::kind)]
        r#type: Option<String>,
        #[command(flatten)]
        metadata: metadata::Flags,
        #[arg(long, default_value = "")]
        tags: String,
        #[arg(long, default_value = "")]
        title: String,
        #[arg(long, default_value = "")]
        project: String,
        #[arg(long, default_value = "")]
        computer: String,
        #[arg(long, default_value = "-1")]
        emotion: f32,
        /// Importance (AI-judged): important (reusable, recall primary zone) | trivial (diary; default). The normal tier is retired.
        #[arg(long, default_value = "trivial")]
        importance: String,
        #[arg(long, default_value = "")]
        parent: String,
        /// Skip judge-then-store and write immediately
        #[arg(long)]
        force: bool,
        /// Merge: delete the listed old memories (comma-separated ids) and store this content as the combined entry (inherits the first cause chain)
        #[arg(long)]
        merge_ids: Option<String>,
        /// This new conclusion replaces a live important memory.
        #[arg(long, conflicts_with = "merge_ids")]
        supersedes: Option<String>,
        /// Bidirectional links to live important memories.
        #[arg(long, value_delimiter = ',', conflicts_with = "merge_ids")]
        see_also: Vec<String>,
    },
    /// Import a JSON-array dump: keep fields, rebuild parent links, sync once after the batch
    Import { file: String },
    /// Semantic recall through the private Core
    Recall {
        query: String,
        /// Override the recall mode for this request without changing saved settings.
        #[arg(long, value_parser = ["fast", "quality"])]
        mode: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        r#type: Option<String>,
        /// Restrict to this project (use when other projects interfere)
        #[arg(long)]
        project: Option<String>,
        /// Recall trace: stderr dumps the full routing path (candidates -> scope -> two zones -> per-axis Top10)
        #[arg(long)]
        trace: bool,
        /// Return compact IDs and titles in JSON; use show to read full memory content.
        #[arg(long)]
        titles: bool,
        /// Opt-in complete representations selected by Core under the 1500-char budget.
        #[arg(long, conflicts_with = "titles")]
        brief: bool,
        /// Base64-encoded RenderBudget JSON wrappers; items must be empty (host supplies catalog titles).
        #[arg(long)]
        render_budget_base64: Option<String>,
        /// Filter final Core scores before the render budget (does not change retrieval admission).
        #[arg(long)]
        render_min_score: Option<f32>,
        /// Disable associations for this request (original recall results only).
        #[arg(long)]
        no_related: bool,
        /// Recall intent: auto (keyword), howto (extra skill pass, keeps one procedure visible), fact (single pass)
        #[arg(long, value_parser = ["auto", "howto", "fact"], default_value = "auto")]
        intent: String,
    },
    /// Query log: each recall's candidates + adoption + model self-grade (local DPO/SFT raw material)
    QueryLog {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Stats only: query count, adoption rate, empty-candidate rate, good/bad self-grade, top entries
        #[arg(long)]
        stats: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
        /// mark: model self-grade (true hit --good / misleading --bad); the main post-training signal
        #[command(subcommand)]
        cmd: Option<QueryLogCmd>,
    },
    /// Retrieval quality benchmark: run an evalset for hit-rate/MRR, optional baseline compare; mine drafts an evalset from query-log
    Bench {
        #[command(subcommand)]
        cmd: BenchCmd,
    },
    /// Record a procedure run verdict (ok|fail|confounded|no_effect) for a skill/knowledge entry; local-only, feeds how-to ordering and audit
    RunLog {
        /// Skill/knowledge entry id (full id or unique prefix)
        id: String,
        /// Outcome: ok | fail (plain success/failure) | confounded (other changes interfered, cannot attribute) | no_effect (worked, but changed nothing observable)
        #[arg(long, value_parser = ["ok", "fail", "confounded", "no_effect"], default_value = "ok")]
        status: String,
        /// Short note: what deviated or which command failed (local-only, never synced)
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Batch classify via JEV (TypeSafe): ask which top-level category each entry belongs to, compare with the current parent (read-only)
    Classify {
        /// Process the latest N entries (default 50, so a full-store run is not accidental; --all overrides)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Whole store (overrides --limit)
        #[arg(long)]
        all: bool,
        /// Restrict to a subtree (id or 8-char prefix; includes the node itself and descendants)
        #[arg(long)]
        root: Option<String>,
        /// Truncate each entry body to this many chars (API payload cap)
        #[arg(long, default_value_t = 600)]
        max_chars: usize,
        /// Below this confidence, list as "low confidence, needs a human" (default 0.5)
        #[arg(long, default_value_t = 0.5)]
        min_confidence: f32,
        /// Save suggestion JSON (audit / later apply)
        #[arg(long)]
        save: Option<String>,
        /// Dry run: preview final actions without network access or local writes
        #[arg(long)]
        dry_run: bool,
        /// Use the DS (OpenAI-compatible) backend to emulate JEV: `--ds` uses a stored key; `--ds <key>` takes the key and stores it
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        ds: Option<String>,
        /// Classify backend: jev (TypeSafe official Jev, default) | ds (DeepSeek-compatible emulate) - same as --ds; pick one
        #[arg(long)]
        backend: Option<String>,
        /// Requested classification sample count
        #[arg(long, default_value_t = 5, hide = true)]
        samples: usize,
        /// Tree mode: pick a suggested parent among **existing tree nodes** (not a linear 23-root assignment) - pair with --batch for speed
        #[arg(long)]
        tree: bool,
        /// Requested tree classification batch size
        #[arg(long, default_value_t = 12, hide = true)]
        batch: usize,
        /// Maximum tree depth selected for classification
        #[arg(long, default_value_t = 2, hide = true)]
        tree_depth: usize,
        /// Causal-tree segment rewrite: parent=cause, child=effect; walk by level and let the AI judge order
        /// (prints a resort --spec compatible reparent plan; does not write the store)
        #[arg(long)]
        causal: bool,
        /// Causal mode: only process parents with >= this many children (default 3 - few children have no causal order to sort)
        #[arg(long, default_value_t = 3, hide = true)]
        min_kids: usize,
        /// Causal mode: max segments to process (default 0 = all; more children first)
        #[arg(long, default_value_t = 0, hide = true)]
        segments: usize,
        /// Causal mode: write the reparent plan to a file (resort --spec can consume it)
        #[arg(long)]
        out: Option<String>,
        /// Apply the final organization actions selected by Core
        #[arg(long)]
        auto: bool,
        /// Preview local structural repair actions;
        /// text only, no store writes, no network
        #[arg(long)]
        plan: bool,
        /// Max auto-reparent rounds (default 5)
        #[arg(long, default_value_t = 5, hide = true)]
        rounds: usize,
        /// API base (default TypeSafe; later may switch to a rsrs gateway)
        #[arg(long)]
        api_base: Option<String>,
        /// Model name
        #[arg(long, default_value_t = classify::DEFAULT_MODEL.to_string())]
        model: String,
    },
    /// List recent entries
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Only entries created after this time (RFC3339 or YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
        /// Only entries created since the last tidy (maintenance.json resort_at) -
        /// the §3.8 tidy intake: tidy this batch, do not pull the whole store
        #[arg(long)]
        since_resort: bool,
        /// Omit memory bodies from JSON directory rows; use show to read a selected entry.
        #[arg(long)]
        metadata: bool,
    },
    /// Delete (tombstone; propagates with sync)
    Forget { id: String },
    /// Clear current-version ciphertext; pending operations and unresolved conflicts are kept
    Purge { id: String },
    /// Restore a deleted memory by full ID (keeps body and parent; propagates with sync)
    Restore { id: String },
    /// Causal tree: promote - this entry becomes a more-upstream cause (reattach to grandparent/root; effects follow)
    Promote { id: String },
    /// Causal tree: demote - attach this entry under --parent as its effect (extends the chain by one; cycle-safe)
    Demote {
        id: String,
        #[arg(long)]
        parent: String,
    },
    /// Show one entry in full (cause/effect complete, not truncated)
    Show { id: String },
    /// Causal-chain deep dive: fetch the whole chain at once - ancestor bodies (root first) + this entry + descendants to --depth.
    /// After an AI sees a cause-chain name, it can dig without layer-by-layer show.
    Chain {
        id: String,
        /// Descendant depth (default 3; 0 = ancestors + this entry only)
        #[arg(long, default_value_t = 3)]
        depth: usize,
    },
    /// Attach a child under a parent (explicit attach is intent; no judge-then-store; auto-syncs)
    Attach {
        id: String,
        #[arg(long)]
        parent: String,
    },
    /// Causal tree: render a subtree (--from start, default root forest); --outline prints a full-depth id+title directory (AI tidy reads this first)
    Tree {
        #[arg(long, default_value = "")]
        from: String,
        #[arg(long, default_value_t = 3)]
        depth: usize,
        #[arg(long)]
        outline: bool,
        /// Export this node's subtree as Markdown material (same as the client install dialog)
        #[arg(long)]
        material: Option<String>,
    },
    /// Memory tidy: batch reparent (spec={"ops":[{"id":"child","parent":"parent"}]}; id / first 8 chars / root title all work); dry-run by default, --go writes, auto-syncs, and resets the counter
    Resort {
        #[arg(long)]
        go: bool,
        #[arg(long)]
        spec: Option<String>,
        /// Show tidy counter (adds since last tidy / threshold)
        #[arg(long)]
        status: bool,
        /// Manually reset the counter (e.g. after tidying another way)
        #[arg(long)]
        reset: bool,
        /// Set the alert threshold (new-entry count)
        #[arg(long)]
        threshold: Option<u64>,
    },
    /// AI behavior config (agent.json): no args = print the whole file (AI reads it to decide); --set key=value writes a key
    AgentConfig {
        /// Set a key, format key=value (e.g. diary_mode=verbose)
        #[arg(long)]
        set: Option<String>,
    },
    /// Retitle: decrypt -> change title -> reseal (ciphertext payload updates) -> dirty -> auto-sync
    Retitle {
        id: String,
        /// New title (required - omitting it would blank the title; fixed in the 2026-09-20 audit)
        #[arg(long)]
        title: Option<String>,
    },
    /// Batch retitle (JSON array [{"id":...,"title":...}]; one process, one model load)
    RetitleMany { file: String },
    /// Two-way sync: pull cloud delta -> land locally -> push local changes (LWW)
    Sync,
    /// Show conflicts that still need a decision; --all includes resolved and old-generation history
    SyncConflicts {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        all: bool,
        /// Sync latest content and cross-device resolution state first
        #[arg(long)]
        refresh: bool,
    },
    /// Resolve one retained revision; mark it resolved only after the remote confirms
    SyncResolve {
        #[arg(long)]
        epoch: String,
        #[arg(long)]
        rev: i64,
        /// current.rev shown by sync-conflicts, so the head cannot change under you after you compared
        #[arg(long)]
        head_rev: i64,
        #[arg(long,value_parser=["keep-current","take-incoming","merge"])]
        action: String,
        /// For merge, the explicit merged body; metadata stays on the current version
        #[arg(long)]
        content: Option<String>,
    },
    /// Show retained sync revisions; --remote reads server history without local caching
    SyncHistory {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remote: bool,
    },
    /// Restore a kept revision as a new local edit
    SyncRestore {
        #[arg(long, conflicts_with = "rev")]
        op_id: Option<String>,
        #[arg(long, conflicts_with = "op_id", requires = "epoch")]
        rev: Option<i64>,
        #[arg(long, requires = "rev", conflicts_with = "op_id")]
        epoch: Option<String>,
    },
    /// Rebuild after a server backup restore; keep current recovery snapshots and pending edits
    SyncReset,
    /// Status
    Status,
    /// Read the initialized library's opaque snapshot token without loading a model
    MemoryRevision,
    /// Report supported CLI capabilities without a profile, runtime or model download
    Capabilities,
    /// Recompute all embeddings (for embedder upgrades / dim changes; re-embed by semantics)
    Reembed,
    /// Stock analysis: cluster BGE vectors, flag lone leaves, suggest a tree (read-only)
    Defrag {
        /// User-selected similarity floor for duplicate suggestions
        #[arg(long, default_value_t = 0.60)]
        min: f32,
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Split a mixed node (AI decides): no flags prints material JSON for the AI to plan; --go --spec '<json>' applies
    Split {
        id: String,
        /// Apply the split plan
        #[arg(long)]
        go: bool,
        /// AI-authored split-plan JSON (run with no flags first to get material and field docs)
        #[arg(long)]
        spec: Option<String>,
    },
    /// Deepen the tree: cluster flat children of a large root into sub-roots (--root to inspect/apply; --auto deepens every flat large root)
    TreeDeepen {
        /// Target root id (8-char prefix ok); default = every flat large root
        #[arg(long)]
        root: Option<String>,
        /// Apply the plan (pair with --titles)
        #[arg(long)]
        go: bool,
        /// Sub-root title array JSON (draft order; default = longest member title in the cluster)
        #[arg(long)]
        titles: Option<String>,
        /// One-shot: auto-deepen every flat large root (sub-root title = longest member title; retitle later)
        #[arg(long)]
        auto: bool,
        /// User-selected similarity floor for Core grouping
        #[arg(long, default_value_t = 0.55)]
        min: f32,
    },
    /// Distribute the inject source: --targets lists 14 hosts; --id <target> injects; --remove --id <target> uninstalls; no args in a TTY opens the picker
    Inject {
        #[arg(long)]
        targets: bool,
        /// Force the interactive TUI picker (errors if there is no TTY)
        #[arg(long, conflicts_with_all = ["targets", "id", "preview", "expected"])]
        tui: bool,
        /// Inject every detected target (skip the TUI; same as no-args when there is no TTY)
        #[arg(long, conflicts_with_all = ["id", "preview", "expected"])]
        all: bool,
        /// Target id (dsh/opencode/codex/claude/codebuddy/workbuddy/kylinbot/pi/zigcode/deepseek/qwen/doubao/generic)
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        /// Preview a Codex inject or uninstall without writing (requires --id codex)
        #[arg(long, conflicts_with = "targets")]
        preview: bool,
        /// Apply only if the config still matches this preview revision (requires --id codex)
        #[arg(long, conflicts_with_all = ["targets", "preview"])]
        expected: Option<String>,
    },
    /// Tree hygiene: root-size bill + lone-leaf attach suggestions (read-only; --id --parent actually attaches)
    TreeCure {
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Apply: attach --id under --parent (skip suggestions, just do it)
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        /// Auto-attach: apply every suggestion, skip failures, then summarize
        #[arg(long)]
        auto: bool,
        /// User-selected similarity floor for Core attachment suggestions
        #[arg(long, default_value_t = 0.50)]
        min: f32,
    },
    /// Heat float: an entry with more hits than its parent becomes the grandparent's child (effects follow; dry-run report, --go applies)
    TreeFloat {
        /// Apply: float each reported entry (dirty; propagates with sync)
        #[arg(long)]
        go: bool,
        /// Hit-count floor to float (default 3; relative heat - must be strictly above the parent's hits)
        #[arg(long, default_value_t = 3)]
        min: i64,
    },
    /// Self-check: model/store/lock/remote/inject/scope in one pass (first stop for install issues)
    Doctor {
        /// Also probe remote server reachability (GET /health, ~1–3s)
        #[arg(long)]
        remote: bool,
        /// Also check npm for a newer CLI (~1–5s; default reads the 24h cache, no network)
        #[arg(long)]
        check_update: bool,
        /// Install a missing or unusable embedder; default only reports diagnostics
        #[arg(long)]
        fix: bool,
    },
    /// Whole-store health audit: orphans / illegal importance / duplicate titles / truncated titles / deep chains; structured report for an AI audit
    Audit {
        /// JSON output (client/AI consumption)
        #[arg(long)]
        json: bool,
    },
    /// Verify the local ciphertext-digest witness chain (not an external trust anchor)
    Witness {
        #[arg(long)]
        verify: bool,
    },
    /// Open the hosted user dashboard without starting the local runtime
    Web {
        /// Report https://dash.rsrs.rs without opening a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Inspect or configure classification without running a model
    ClassifyConfig {
        #[arg(long, value_parser = ["jev", "ds"])]
        backend: Option<String>,
        #[arg(long)]
        api_base: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// Persist the selected backend and optional endpoint/model
        #[arg(long)]
        set: bool,
        /// Read one API key from redirected stdin and store it in the OS keyring
        #[arg(long)]
        key_stdin: bool,
    },
    /// Manage embedding profiles, model resources and inference backends.
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },
    /// View/set local config (client.json: data dir / server address / auto-sync / auto-cure)
    Config {
        /// Set the data directory (absolute path; empty string clears back to default ~/.rsrs)
        #[arg(long)]
        data_dir: Option<String>,
        /// Set the server address
        #[arg(long)]
        addr: Option<String>,
        /// Set post-write auto-sync
        #[arg(long)]
        autosync: Option<bool>,
        /// Set periodic auto-cure
        #[arg(long)]
        cure_auto: Option<bool>,
        /// Max concurrent ordinary runtime jobs. 0 follows available CPU parallelism; explicit values cannot exceed it. Applies after runtime restart.
        #[arg(long)]
        rpc_parallelism: Option<u32>,
    },
    /// Judge-then-store candidate bill (read-only): high similarity suggests merge, medium suggests attach, similar candidates suggest merging them
    Candidates { content: String },
    /// Memory passport: ASCII-art card (user / memory count / connected agents / devices) for sharing
    Passport,
    /// Entry change history (audit stream: create/update/delete/restore/purge; SQLite triggers record it)
    History {
        /// Entry id (8-char prefix ok); omit = recent changes for the whole store
        id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Plugin hooks (plugins.json): list shows config; test <EVENT> fires an event
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// MCP server over stdio JSON-RPC. The internal runtime serves HTTP/SSE at `/mcp` and `/sse`.
    Mcp,
    /// Check npm for a newer CLI (24h throttle; --force skips it; --clear drops the cache)
    UpdateCheck {
        /// Skip the throttle and query the network
        #[arg(long)]
        force: bool,
        /// Clear the cache (the next check hits the network)
        #[arg(long)]
        clear: bool,
    },
    /// Backfill: reseal ciphertext so payload.parent_id matches the plaintext column (fixes dual-source drift; idempotent)
    Repack,
    /// Diary = whole-store time chain (the trivial zone is merged in; not filtered by importance): recent (--limit), a day (--date, today/yesterday), a range (--from/--to inclusive), keyword (--contains)
    Diary {
        #[arg(long, default_value_t = 10)]
        limit: usize,
        /// Flip a day (YYYY-MM-DD or today/yesterday, local timezone)
        #[arg(long)]
        date: Option<String>,
        /// Range start (YYYY-MM-DD, inclusive; mutually exclusive with --date)
        #[arg(long)]
        from: Option<String>,
        /// Range end (YYYY-MM-DD, inclusive; mutually exclusive with --date; --to without --from means "up to that day")
        #[arg(long)]
        to: Option<String>,
        /// Full-text keyword filter (title and decrypted full body); returns a bounded matching excerpt
        #[arg(long)]
        contains: Option<String>,
    },
    /// Explicit cross-date diary fragment retrieval; never changes normal recall.
    DiarySearch {
        query: String,
        #[arg(long, default_value_t = 5)]
        limit: usize,
        /// Budget for fragment result JSON, in Unicode characters (not tokens)
        #[arg(long, default_value_t = 4000)]
        max_chars: usize,
        #[arg(long, default_value = "hybrid", value_parser = ["lexical", "hybrid"])]
        mode: String,
    },
    /// Read one immutable diary fragment locator and optional immediate neighbors.
    DiaryFragment {
        source_id: String,
        fragment_id: String,
        #[arg(long, default_value_t = 0)]
        neighbors: usize,
        #[arg(long, default_value_t = 4000)]
        max_chars: usize,
    },
    /// Built-in top-level catalog (20 human-domain + 3 AI-domain = 23, embedded at compile): --list prints it; --ensure <root,...> creates roots; no args shows current state
    Taxonomy {
        /// List every built-in category (domain / title / surface-word count / gist)
        #[arg(long)]
        list: bool,
        /// Create/fill roots (idempotent): titles must match the catalog, comma-separated; default = fill every missing root
        #[arg(long)]
        ensure: Option<String>,
    },
    /// Create a root outside the catalog (needs the user to say yes): AI proposes -> user allows -> run with --yes; the AI must not create one on its own
    RootCreate {
        title: String,
        /// One-line gist (default = the title)
        #[arg(long)]
        content: Option<String>,
        /// User already allowed this (turn their "yes" into this flag; without it, refuse to write)
        #[arg(long)]
        yes: bool,
    },
    /// Update a memory; omitted fields stay unchanged and --clear-* explicitly clears metadata.
    Update {
        id: String,
        #[command(flatten)]
        metadata: metadata::Flags,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        tags: Option<String>,
        #[arg(long, value_parser = metadata::kind)]
        kind: Option<String>,
        /// Importance revision: important | normal | trivial (reseals ciphertext payload and the index column)
        #[arg(long)]
        importance: Option<String>,
    },
    /// Export the whole store as plaintext JSON (local backup)
    Export { file: String },
    /// Back up the local store file (whole SQLite copy, ciphertext and index)
    Backup { file: String },
    /// Candidate metadata gate; defaults off and does not establish verification.
    Metadata {
        #[command(subcommand)]
        command: metadata::Command,
    },
    /// Create or inspect verified local snapshots; never rolls back cloud state
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// Show account keys: Account Secret / five-keys (manual cross-device join; leak = loss of the store)
    Secret {
        /// Show the full Secret and five-keys (default is masked)
        #[arg(long)]
        reveal: bool,
    },
    /// Export decrypt keys (super password + Secret Key + vault material) - how a new machine logs in; leak = loss of the store
    KeysExport {
        /// Write a file (mode 600) instead of printing; the file holds every decrypt secret - keep it safe
        #[arg(long)]
        out: Option<String>,
    },
    /// Reset the super password: unlock URK with the current code, issue a new one, upload. Data is unchanged
    SuperReset {
        /// Current super password (omit if already in the local keyring)
        #[arg(long = "super")]
        super_pass: Option<String>,
    },
    /// Five-keys join (another machine): verify and write a local session; a non-empty --addr also logs in for a token
    Fivekeys {
        #[arg(long, default_value = "")]
        addr: String,
        #[arg(long, default_value = "")]
        user: String,
        #[arg(long)]
        pass: String,
        #[arg(long, default_value = "")]
        secret: String,
        #[arg(long)]
        kdf_salt: String,
        #[arg(long)]
        wrapped_urk: String,
        #[arg(long)]
        urk_nonce: String,
        /// Super password (new wrap). If set, login password + Account Secret are not used to unwrap
        #[arg(long = "super", default_value = "")]
        super_pass: String,
    },
    /// Register an account (first device): login password for auth + super password wrapping keys.
    /// Address defaults to https://api.rsrs.rs; use --addr to override it.
    /// Missing user/password drops into an interactive prompt (TTY only).
    Register {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
        /// Super password (for decrypt; separate from the login password; forgotten = memories unrecoverable)
        #[arg(long = "super")]
        super_pass: Option<String>,
    },
    /// Multiple accounts on one machine: each account has its own data dir (local store/keys/session switch as a unit).
    /// Logging into a new account creates a profile; `account list` lists them; `account <name>` switches (main = primary); `remove <name> --yes` deletes.
    Account {
        /// Action: list | remove | or a profile name (same as use; main is the primary profile)
        action: String,
        /// Profile name (required for remove)
        name: Option<String>,
        /// Confirm a real delete on remove (store and keys are unrecoverable)
        #[arg(long)]
        yes: bool,
    },
    /// Explicitly copy a selected old library into a new account; no startup migration.
    Migrate {
        #[arg(long, requires = "account", conflicts_with = "vault")]
        source: Option<String>,
        #[arg(long, requires = "source")]
        account: Option<String>,
        /// Upgrade only the explicitly selected legacy account vault, preserving its data key
        #[arg(long)]
        vault: bool,
        #[arg(long, requires = "vault")]
        addr: Option<String>,
        #[arg(long, requires = "vault")]
        user: Option<String>,
        #[arg(long, requires = "vault")]
        pass: Option<String>,
        #[arg(long = "super", requires = "vault")]
        super_pass: Option<String>,
        #[arg(long, requires = "vault")]
        secret_key: Option<String>,
        /// Explicit v4 recovery code for the unchanged data key (required on a headless host without keyring)
        #[arg(long, requires = "vault")]
        new_super: Option<String>,
    },
    /// Spaces (virtual accounts): an owner can create several virtual accounts; each is a space with its own super key and data dir.
    /// Join = a member builds that space's profile on their machine from an invite; they can switch freely; leaving is `kick`.
    Space {
        /// Action: list | create <name> | use <name> | invite | join <code> | members | kick | remove
        action: String,
        /// Space name (needed for create/use/remove)
        name: Option<String>,
        /// Note on invite (written to the member session's device_name, so you can tell who is who later)
        #[arg(long)]
        note: Option<String>,
        /// invite --readonly: sign a read-only invite (that member can recall, not write; enforced server-side)
        #[arg(long)]
        readonly: bool,
        /// Invite code for join (the name positional also accepts it)
        #[arg(long)]
        code: Option<String>,
        /// Member session id to kick
        #[arg(long)]
        session: Option<String>,
        /// kick --all: revoke every member session in this space
        #[arg(long)]
        all: bool,
        /// Confirm a real delete on remove (store and keys are unrecoverable)
        #[arg(long)]
        yes: bool,
    },
    /// Log out: clear addr/token and drop the cloud (identity and keys stay; login brings them back); --full forgets this machine's identity
    Logout {
        /// Delete the whole session.json (including key material - rejoin needs register or five-keys)
        #[arg(long)]
        full: bool,
    },
    /// Log in through browser authorization, or use --interactive for password and TOTP prompts.
    /// Address defaults to the last server this machine used (kept in session.json by register/logout).
    /// Missing user/password drops into an interactive prompt (TTY only).
    #[command(after_long_help = "Vault recovery: cloud authorization does not decrypt memories. Use the existing recovery code or a trusted device's keys-export, then retry login. Missing or incorrect recovery material must not replace the selected account. super-reset rotates an already unlocked vault; it cannot recover a lost data key. keygen --force switches to unrelated offline keys and is not cloud recovery. If all recovery material is lost, existing encrypted data cannot be recovered by resetting a password. See docs/vault-recovery.md.")]
    Login {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, requires = "interactive", conflicts_with = "oauth")]
        pass: Option<String>,
        #[arg(long = "super")]
        super_pass: Option<String>,
        /// Choose OAuth or password/TOTP in this terminal (a supplied --pass selects password login)
        #[arg(long)]
        interactive: bool,
        /// Explicitly select browser authorization (also the default)
        #[arg(long)]
        oauth: bool,
        /// Dashboard origin for a custom server
        #[arg(long)]
        dashboard: Option<String>,
        /// Display the authorization URL without opening a browser
        #[arg(long)]
        no_open: bool,
        /// Copy selected local memories into this server account without plaintext export files
        #[arg(long)]
        migrate_local: bool,
    },
    /// Book material: a root subtree -> volume/chapter full text (for an AI to draft)
    BookMaterial { root: String },
    /// Portrait material: whole-store portrait aggregate (for an AI to draft a portrait)
    PortraitMaterial {
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Share a subtree: emit a prompt another AI can paste (payload is plaintext; the other AI imports from the prompt)
    Share {
        /// Subtree root (8-char prefix ok); default is this machine's scope root, else error
        #[arg(long)]
        root: Option<String>,
        /// Print only the prompt body (pipes/clipboard), no hint lines
        #[arg(long)]
        raw: bool,
        /// Write a file instead of printing (prefer <file>.txt with the full prompt)
        #[arg(long)]
        out: Option<String>,
    },
    /// Import a shared subtree: without --go, print attach-candidate bill (for the AI to judge); --go writes the store
    ShareImport {
        /// Share text file (full prompt or bare payload)
        file: String,
        /// Attach point: hang this subtree under that existing memory (8-char prefix ok); default is a new root
        #[arg(long, default_value = "")]
        parent: String,
        /// Write switch: omit to only print the candidate bill
        #[arg(long)]
        go: bool,
        /// Override the root title (default = the sharer's original title)
        #[arg(long)]
        title: Option<String>,
        /// Bypass Core-reported conflicts and explicitly create a sibling entry
        #[arg(long)]
        force: bool,
    },
    /// Extract local coding-agent sessions (Codex, OpenCode, Claude Code, …) into rsrs memories
    Extract {
        /// List agent sources and whether a local session store exists
        #[arg(long)]
        targets: bool,
        /// Force the interactive TUI picker (needs a TTY)
        #[arg(long, conflicts_with_all = ["targets", "id", "all", "dry_run"])]
        tui: bool,
        /// Extract from every detected source (default when --id is omitted)
        #[arg(long, conflicts_with = "id")]
        all: bool,
        /// Extract from one source (codex/opencode/claude/…); see --targets
        #[arg(long)]
        id: Option<String>,
        /// Scan and summarize without writing any memory
        #[arg(long)]
        dry_run: bool,
        /// Only sessions updated since this bound (today|yesterday|7d|YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
        /// Maximum sessions to import per source (newest first)
        #[arg(long)]
        limit: Option<usize>,
        /// Filter by working-directory substring
        #[arg(long)]
        cwd: Option<String>,
        /// Filter by model/provider substring
        #[arg(long)]
        model: Option<String>,
        /// Filter by session id substring
        #[arg(long)]
        session: Option<String>,
        /// Memory kind for imported sessions
        #[arg(long, default_value = "context")]
        kind: String,
        /// Importance: important (default) or trivial (diary)
        #[arg(long, default_value = "important")]
        importance: String,
        /// Optional pre-attach parent (id / tree / anchor title); omit to ingest as roots for a later tidy
        #[arg(long, default_value = "")]
        parent: String,
        /// Include subagent/child sessions (hidden by default)
        #[arg(long)]
        include_subagents: bool,
        /// Re-import sessions already recorded in the cursor
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum GrantCommand {
    /// Create a grant; the token is shown only this once - keep it.
    Create {
        #[arg(long)]
        root: String,
        #[arg(long)]
        label: String,
    },
    List,
    Revoke {
        id: String,
    },
}

/// query-log subcommand: model self-grade report.
#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// Create a consistent private database snapshot, excluding access grants
    Create {
        #[arg(long, default_value = "")]
        note: String,
    },
    /// List snapshots after validating file digests and SQLite integrity
    List,
    /// Restore one local snapshot after a mandatory pre-backup; cloud state is unchanged
    Restore {
        id: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Recover an interrupted local snapshot transaction (host only)
    Recover { #[arg(long)] confirm: bool },
    /// Resume sync only after reviewing local/remote differences at this exact local revision
    ResumeSync {
        #[arg(long)]
        reviewed_revision: String,
    },
}

#[derive(Subcommand)]
pub enum QueryLogCmd {
    /// Report a self-grade: true hit --good (chosen) / misleading --bad (rejected).
    /// ids are comma-separated; 8-char prefixes work; matches recall candidates from the last 10 minutes.
    Mark {
        /// Candidate entry ids (comma-separated; prefixes ok)
        ids: String,
        /// Mark as a true hit (post-training chosen)
        #[arg(long)]
        good: bool,
        /// Mark as misleading (post-training rejected)
        #[arg(long)]
        bad: bool,
        /// Explicit request identity from recall.summary.query_log_id (required with feedback enabled).
        #[arg(long)]
        query_log_id: Option<String>,
        /// Origin of this explicit verdict; never inferred from a successful command.
        #[arg(long,default_value="model",value_parser=["human","model","task_outcome"])]
        source: String,
    },
}

/// bench subcommand: retrieval quality suite (added 2026-09-19).
#[derive(Subcommand)]
pub enum BenchCmd {
    /// Run an evalset: JSONL one case per line {"query","expect":[8-char prefix or full id...],"project?","note?"}; empty expect = negative
    Run {
        /// Evalset file (JSONL)
        file: String,
        /// Eval depth: whether the expected hit is in the top K (default 5)
        #[arg(long, default_value_t = 5)]
        topk: usize,
        /// Archive this run as JSON (for a later --baseline compare)
        #[arg(long)]
        save: Option<String>,
        /// Compare against a baseline (JSON from a previous --save): per-case up/down/same
        #[arg(long)]
        baseline: Option<String>,
        /// Per-case detail (default lists only misses)
        #[arg(long)]
        verbose: bool,
    },
    /// Mine an evalset draft from query-log (self-grade good is the main signal, adopted is weak)
    Mine {
        /// Output JSONL file
        #[arg(long)]
        out: String,
        /// Max cases to export
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Strict: use self-grade good only, ignore adopted as a weak signal
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Subcommand)]
pub enum SessionCommand {
    /// List independent sessions for this account (the current one is marked current).
    List,
    /// Revoke cloud access for a session; the full UUID comes from session list.
    Revoke { id: String },
}

/// plugin subcommand: inspect hook config and fire events by hand.
#[derive(Subcommand)]
pub enum PluginCommand {
    /// List hooks configured in plugins.json (event -> command/timeout/failure policy)
    List,
    /// Fire one event to verify a plugin (--payload is business JSON; a test hook need not actually write the store)
    Test {
        /// Event name: pre-remember | post-remember | post-recall | post-forget | post-sync
        event: String,
        /// Business payload JSON (default {}); combined with event name/timestamp into the full event on plugin stdin
        #[arg(long, default_value = "{}")]
        payload: String,
    },
}

pub fn changes_profile(command: Option<&Command>) -> bool {
    match command {
        Some(Command::Account { action, .. }) => !matches!(action.as_str(), "list" | "remove"),
        Some(Command::Space { action, yes, .. }) => matches!(action.as_str(), "create" | "use" | "join") || (action == "remove" && *yes),
        Some(Command::Config { data_dir, .. }) => data_dir.is_some(),
        _ => false,
    }
}

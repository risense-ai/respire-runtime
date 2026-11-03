# Embedding profiles

```sh
rsrs model catalog --json
rsrs model configure profiles.json --json
rsrs model switch bge-small-zh-v1.5 --backend onnx --engine cpu --json
rsrs model progress --json
rsrs model resume --json
rsrs model switch m3 --backend onnx --engine cpu --variant quantized --json
```

The installation root's `embedding-profiles-v1.json` stores editable model and
backend drafts. Each library stores its immutable active Selection in SQLite;
draft edits never activate a model. A switch returns a pending task ID. Poll
progress until `ready` or `failed`; existing `model.control` uses the operation's
task ID to cancel. Cancellation is checked between reads, native calls and index
checkpoints. Native calls must return before rollback can finish.

New semantic requests and writes receive `model_switch_busy` during a switch.
Status, progress and cancellation remain available. The runtime drains in-flight
inference, verifies/prepares resources, loads/probes the candidate, checkpoints
the main index and builds a separate diary cache. It then checks source and
account/library versions and commits the complete active selection atomically.
It retains old generations and candidate checkpoints. A failed/cancelled switch
reloads/probes the previous model. `recovery_failed` means that recovery failed;
semantic availability must be treated as unverified. A persisted pending snapshot
and phase permit explicit `model resume` after restart; there is no automatic
replay of an unknown operation.

This custom local profile uses the verified small model as an example. Replace
the paths with your local files. Optional `download` resource URLs support HTTPS
or HTTP loopback fixtures. Downloads use resumable staging and verify size and
SHA-256 before replacement. Existing corrupt resources fail explicitly.

```json
{
  "model_profile": {
    "id": "my-encoder",
    "embedding": {
      "model_id": "Xenova/bge-small-zh-v1.5",
      "revision": "75c43b069aac4d136ba6bc1122f995fedcfd2781",
      "dimensions": 512, "max_tokens": 512, "pooling": "cls", "normalize": true,
      "query_prefix": "\u4e3a\u8fd9\u4e2a\u53e5\u5b50\u751f\u6210\u8868\u793a\u4ee5\u7528\u4e8e\u68c0\u7d22\u76f8\u5173\u6587\u7ae0\uff1a", "document_prefix": "",
      "pad_token_id": 0, "pad_to_max_tokens": false
    },
    "onnx": {"input_ids":"input_ids","attention_mask":"attention_mask","token_type_ids":"token_type_ids","output":"last_hidden_state"},
    "weights": {"path":"C:/models/small/onnx/model_quantized.onnx","size":24010842,"sha256":"15b717c382bcb518ba457b93ea6850ede7f4f1cd8937454aa06972366cd19bcc"},
    "tokenizer": {"path":"C:/models/small/tokenizer.json","size":439125,"sha256":"48cea5d44424912a6fd1ea647bf4fe50b55ab8b1e5879c3275f80e339e8fae26"}
  }
}
```

IDs are free-form registry keys; generated cache names use a generation hash.
Pooling accepts `cls`, `mean` and `sentence_embedding`. Resource identities,
dimensions, pooling, normalization, prefixes, window and Core index policy form
the index identity. Editing an existing ID requires another switch and rebuild;
it does not mutate an active snapshot.

A remote model profile needs `id` and `embedding`, without ONNX resources. Pair
it with a host-managed OpenAI-compatible backend:

```json
{"backend_profile":{"id":"company-api","backend":"host_transport","provider":"company","protocol":"openai_embeddings","endpoint":"https://embeddings.example/v1/embeddings","keyring_service":"company-embedding","keyring_account":"current-user"}}
```

Select `--backend company-api --engine cpu`. Here `cpu` is the local scheduling
label, not a claim about remote hardware. Keyring fields reference an existing
credential; configuration never contains the key. Omit both fields for an
unauthenticated loopback fixture. Core formats inputs, validates dimensions and
finite values, and normalizes results. Core calls the host with flat `model` and
`input` fields. The host validates them and sends only `{"model": ..., "input": [...]}`
as HTTP JSON; callback metadata such as timeout, retries, protocol and provider is
not sent to the endpoint. Business results do not expose vectors, and the host does
not log provider responses.
HTTP failures are not retried.

For `host_transport`, `max_tokens` declares provider capacity. Core has no remote
tokenizer and cannot enforce that token budget. Character-based document chunks
do not guarantee a token length. The provider must reject oversized input,
including prefixes and special tokens, rather than silently truncate it. A
small remote window can therefore prevent long-text indexing; such errors
propagate and roll back the switch. The OpenAI embeddings body does not include
`max_tokens`.

Custom ONNX providers use an optional native backend setting:

```json
{"backend_profile":{"id":"my-openvino","backend":"onnx","native":{"provider":"OpenVINOExecutionProvider","provider_options":{"device_type":"GPU"}}}}
```

The host applies this through the existing ORT options callback. Providers must
already be available; invalid/missing providers fail explicitly. No unknown
provider is downloaded. Native settings change session identity and conservatively
change index identity. Omit `native` to use existing CPU/GPU/NPU selection.
`CPUExecutionProvider` uses the built-in CPU provider and accepts
`enable_cpu_mem_arena` and `enable_mem_pattern` as `true`/`false` or `1`/`0`.
Other CPU options are rejected rather than ignored.

The paired SDK must advertise embedding profile and transport contract 1. TUI and
Client 2 profile controls are outside this change. Existing legacy M3 commands
keep their weight-variant meaning and refuse a competing load after a library
profile has been activated; use the profile switch interface instead.
Likewise, `model reset-cpu` targets the legacy M3 settings. For an active profile,
use `model switch PROFILE --backend onnx --engine cpu`; this keeps activation
behind the same verification and index transaction.

## Apple MLX preset

Apple Silicon macOS builds of the Core SDK include the MLX backend and require
macOS 14.0 or newer. Intel macOS retains its macOS 13.4 baseline without MLX.
The built-in `m3-mlx` preset downloads the pinned
`mlx-community/bge-m3-mlx-fp16` safetensors and tokenizer, then rebuilds the
index through the normal profile transaction:

```sh
rsrs model switch m3-mlx --backend mlx --engine gpu --json
```

`--engine gpu` selects the MLX Metal stream; `--engine cpu` selects MLX's CPU
stream. `npu` is rejected. The preset uses the same 1024-dimensional CLS and
normalization profile as `m3`, but its index identity is distinct because the
weights and execution backend differ. A Core build without the `mlx` feature
fails explicitly instead of falling back to ONNX. MLX is unavailable on Intel
macOS, Linux and Windows. Building that SDK requires Xcode's Metal Toolchain and
`RSRS_SDK_MLX=1`; the SDK then carries `runtime/mlx.metallib` and advertises
`mlx_backend_contract=1` through `capabilities`.

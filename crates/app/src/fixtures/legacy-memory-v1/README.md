# Historical memory v1 fixture

These are byte-identical synthetic snapshots of the fixtures in respire-core
commit `d725aa1b86fd913cf15fb2a6865f72c572d0b196`, under
`crates/memory-core/tests/fixtures/`. They contain no real data or credentials.
The test-only URK is the 32-byte array `[42; 32]`. Neither the build nor the
test requires the Core repository, a fixture download, or a new SDK version.

| File | SHA-256 |
| --- | --- |
| `legacy_stored_memory.json` | `9ff3d60ba6b9ce2649364cc0d87e83ab1bea504b25cb233da1f1df27667ca5c9` |
| `legacy_payload_v2.json` | `3dc887907280c9e504f545a4f5889179e2b353885223104c84aae5f2866a8fdd` |
| `legacy_embedding.f32le` | `969084b7a76f634a34897dc351f85bb0d0a78107e4eac19a11f5ee5bdb8a364f` |

Keep these specimens frozen; cover new formats with separate fixtures.

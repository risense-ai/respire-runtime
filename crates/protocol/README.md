# Respire protocol

Serde-only request, response and domain types shared by Respire clients.
This crate does not include the retrieval engine or native SDK implementation.

```toml
[dependencies]
respire_protocol = "=2.0.0-dev.9"
```

Wire field compatibility is maintained independently of client display names.

The development 2.0 Rust API adds relationship fields to public entry/payload
structs. Struct-literal callers must supply them; legacy encrypted and JSON
records remain readable with default-empty values. C ABI and wire envelope
versions are unchanged.

Version `2.0.0-dev.9` adds credential delivery schema V2. A V2 unlock requires
an explicit provider outcome: replace the complete snapshot (including a verified
empty snapshot), or report an allowlisted unavailable code. Session authentication
is still required. The unlock receipt reports provider availability separately
from store readiness. These types are not present in the published dev.8 crate;
the RPC envelope version is unchanged.

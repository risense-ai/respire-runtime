# Interface crate verification and publication

Run **Verify and publish interface crates** on the reviewed commit. The default
`publish=false` performs packaging and consumer verification only.

A stable `vX.Y.Z` tag matching the CLI source version automatically runs verification
and publishes any new interface crate versions. A push to `main` does not publish
these immutable crate versions. An already published protocol or binding version
is explicitly skipped; no new source version means no repeat publication. Bump
the appropriate source crate version when its packaged contents change.

| Selection | Verification | Explicit publication |
| --- | --- | --- |
| `protocol` | `cargo package --locked` and package inventory | Publish the protocol version if absent |
| `sdk` | Protocol package; Windows GNU tar and GNU Linux public-SDK consumers | Publish a new binding version |
| `all` | Both packages and consumers | Protocol first, then binding after registry availability and consumer success |

Publication of a new version requires the `CARGO_REGISTRY_TOKEN` repository secret.
It is read only by stable-tag or explicitly selected manual publish steps.
Existing crate versions are reused without republishing. A new protocol version must reach crates.io
before the binding's registry dependency can be verified. A validation-only run
will report that dependency gate rather than substitute a local protocol.

Update versions in source before publication. New SDK pins require a new binding
version; SDK and binding versions need not match. Keep both CLI SDK locks equal
and all seven release targets pinned. This workflow never changes versions or pins.

Download the package-verification artifacts for file inventories and SHA-256.
The standalone consumer uses the extracted crate, downloads its pinned public
SDK, links it and checks initialization/ABI. It does not start the CLI runtime or
access a user profile. SDK native binaries are distributed separately from crates.

# Client2 upgrades and the pure Runtime

The current split removes the embedded CLI and host compatibility entry points
from Runtime. Upgrade CLI and Client2 before using the pure Runtime. Historical
clients that invoke removed host commands are upgrade sources, not supported
consumers of the new Runtime.

## Independent components

Runtime owns login, synchronization, database operations, memory operations and
RPC. CLI and Client2 own installation, model and component management, native
credentials, sign-in startup, and starting and maintaining the Runtime process.
Hosts deliver keys to the verified Runtime owner; Runtime remains locked without
valid host input.

Components release independently and communicate through the shared protocol.
Matching component version numbers, source commits or build runs is not a runtime
compatibility requirement. Protocol and required capability checks remain
mandatory. Exact source commits and artifact digests identify what a regression
actually tested; they must not become production client/server equality checks.

## Upgrade acceptance

Prepare a database with its historical released CLI, Runtime and Client2, then
upgrade the components and validate the database with the new supported stack.
The upgraded CLI must install or obtain the current supported Runtime and use it
through the protocol. Do not test a new CLI against an incompatible old Runtime
as a substitute for this upgrade path.

Keep latest applicable stable and historical stable database upgrades. Add a
DEV source when its database schema, encryption or other persistent format
changed; a DEV with no persistent-format change does not need a separate
DEV-to-DEV matrix entry. Preserve unknown historical formats until their
equivalence is established.

Acceptance verifies existing data, database integrity, migration recovery,
host-key unlock after restart, login and sync, and real remember/recall after
upgrade. It does not require old Client2 or old CLI to operate against the new
Runtime, old Runtime to operate with the new clients, or the continued presence
of removed host RPCs.

## Publication

Validate the new components together using authenticated candidate artifacts.
Publish Runtime before CLI pins reference its release, then publish CLI and
Client2 as the coordinated DEV update. This ordering ensures downloadable
assets exist; it does not impose matching component versions or commit IDs.
Verify the public assets and the database upgrade path after publication.

# Client2 upgrades and the pure Runtime

The current split removes the embedded CLI and host compatibility entry points
from Runtime. Each host can manage and use a Runtime that provides the protocol,
methods and capabilities it requires. Record explicit incompatibility for any
required historical host method that Runtime no longer provides.

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

Migration acceptance verifies existing data, database integrity, migration
recovery, host-key unlock after restart, login, sync, and real remember/recall
after upgrade. Test online interoperability separately by changing one
component at a time. Verify the requested operations and receipts when protocol
and methods are supported. Verify explicit failure when a required method or
authorization is missing.

## Publication

Each component has its own release and validation workflow. Use authenticated
candidate artifacts for regression and record the exact inputs. When a host
test downloads Runtime, publish the verified Runtime asset on the intended
channel before testing the host's download. Recheck the public assets and the
database upgrade path after publication.

//! Pure memory protocol types. Business execution belongs to Runtime.

pub mod model {
    pub use respire_protocol::*;
}

pub use model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};

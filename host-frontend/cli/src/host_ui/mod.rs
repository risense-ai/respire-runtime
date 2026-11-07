//! Host-only terminal UI and instruction-file editing.

pub mod inject;
mod mode;
pub mod prompt;
pub mod recall_fusion;

#[cfg(test)]
mod test_lock;

// SPDX-License-Identifier: MPL-2.0

//! Virtual File System (VFS) layer.
//!
//! The VFS provides a unified abstraction over different file system implementations,
//! serving as the bridge between system calls and concrete file systems.

mod fs_apis;
pub(crate) mod notify;
pub mod path;
pub(crate) mod range_lock;
pub mod sync_policy;

// Re-export commonly used abstractions from `fs_apis`
pub(crate) use fs_apis::{file_system, inode_ext, registry, xattr};
pub use fs_apis::{file_system::sync_all_file_systems, inode};

pub(super) fn init() {
    fs_apis::init();
    path::init();
}

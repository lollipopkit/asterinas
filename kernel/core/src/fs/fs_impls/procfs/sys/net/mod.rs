// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            ProcDir, StaticEntry,
            sys::net::{core_sysctl::CoreDirOps, unix_sysctl::UnixDirOps},
            template::{
                ProcDirOps, ReaddirEntry, listed_entries_from_table, lookup_child_from_table,
                visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
};

mod core_sysctl;
mod unix_sysctl;

/// Represents the inode at `/proc/sys/net`.
pub(super) struct NetDirOps;

impl NetDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/proc_sysctl.c#L978>
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        ("core", InodeType::Dir, CoreDirOps::new_inode),
        ("unix", InodeType::Dir, UnixDirOps::new_inode),
    ];
}

impl ProcDirOps for NetDirOps {
    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}

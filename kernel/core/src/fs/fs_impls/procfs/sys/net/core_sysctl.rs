// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            ProcDir, StaticEntry,
            template::{
                ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry, listed_entries_from_table,
                lookup_child_from_table, read_i32_from, visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    net::socket::util::buffer_size::{
        BufferSysctl, RMEM_DEFAULT, RMEM_MAX, WMEM_DEFAULT, WMEM_MAX,
    },
    prelude::*,
};

/// Represents the inode at `/proc/sys/net/core`.
pub(super) struct CoreDirOps;

impl CoreDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/proc_sysctl.c#L978>
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sysctl_net_core.c#L743-L774>
    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        ("rmem_default", InodeType::File, |parent| {
            BufferSysctlFileOps::new_inode(&RMEM_DEFAULT, parent)
        }),
        ("rmem_max", InodeType::File, |parent| {
            BufferSysctlFileOps::new_inode(&RMEM_MAX, parent)
        }),
        ("wmem_default", InodeType::File, |parent| {
            BufferSysctlFileOps::new_inode(&WMEM_DEFAULT, parent)
        }),
        ("wmem_max", InodeType::File, |parent| {
            BufferSysctlFileOps::new_inode(&WMEM_MAX, parent)
        }),
    ];
}

impl ProcDirOps for CoreDirOps {
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

/// Represents a socket buffer size file in `/proc/sys/net/core`.
struct BufferSysctlFileOps(&'static BufferSysctl);

impl BufferSysctlFileOps {
    fn new_inode(sysctl: &'static BufferSysctl, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self(sysctl), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for BufferSysctlFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        writeln!(printer, "{}", self.0.get())?;

        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (val, read_bytes) = read_i32_from(reader)?;
        self.0.set(val)?;

        Ok(read_bytes)
    }
}

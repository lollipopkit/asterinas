// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

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
    net::socket::unix::MAX_DGRAM_QLEN,
    prelude::*,
};

/// Represents the inode at `/proc/sys/net/unix`.
pub(super) struct UnixDirOps;

impl UnixDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/proc_sysctl.c#L978>
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[(
        "max_dgram_qlen",
        InodeType::File,
        MaxDgramQlenFileOps::new_inode,
    )];
}

impl ProcDirOps for UnixDirOps {
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

/// Represents the inode at `/proc/sys/net/unix/max_dgram_qlen`.
struct MaxDgramQlenFileOps;

impl MaxDgramQlenFileOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/sysctl_net_unix.c#L16-L23>
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for MaxDgramQlenFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        writeln!(printer, "{}", MAX_DGRAM_QLEN.load(Ordering::Relaxed))?;

        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (val, read_bytes) = read_i32_from(reader)?;
        MAX_DGRAM_QLEN.store(val, Ordering::Relaxed);

        Ok(read_bytes)
    }
}

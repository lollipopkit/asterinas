// SPDX-License-Identifier: MPL-2.0

//! This module offers `/proc/meminfo` file support, which tells the user space
//! about the memory statistics in the entire system.
//!
//! The fields and their formats follow Linux. Fields that depend on kernel
//! configurations (e.g., `CONFIG_TRANSPARENT_HUGEPAGE` and
//! `CONFIG_HUGETLB_PAGE`) are omitted because Asterinas does not implement
//! the corresponding features.
//!
//! Reference: <https://man7.org/linux/man-pages/man5/proc_meminfo.5.html>

use aster_util::printer::VmPrinter;
use ostd::mm::stat as ostd_stat;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    vm::stat::{self, MemStat},
};

/// Represents the inode at `/proc/meminfo`.
pub(super) struct MemInfoFileOps;

impl MemInfoFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/meminfo.c#L178>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/generic.c#L549-L550>
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

/// The percentage of RAM that can be committed, i.e., Linux's default
/// `vm.overcommit_ratio`.
const OVERCOMMIT_RATIO: usize = 50;

impl ProcFileOps for MemInfoFileOps {
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/meminfo.c#L34-L178>
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        const KB_PER_PAGE: usize = PAGE_SIZE / 1024;

        let mut printer = VmPrinter::new_skip(writer, offset);

        let total = crate::vm::mem_total() / 1024;
        let free = osdk_frame_allocator::load_total_free_size() / 1024;
        // Linux estimates the available memory as the free memory plus the
        // page cache and slab caches that can be reclaimed. Asterinas cannot
        // reclaim them under memory pressure, so only the free memory is
        // available.
        let available = free;

        let file_pages = stat::nr_file_pages() * KB_PER_PAGE;
        let buffers = stat::nr_buffer_pages() * KB_PER_PAGE;
        let shmem = stat::nr_shmem_pages() * KB_PER_PAGE;
        let unevictable = stat::nr_ramfs_pages() * KB_PER_PAGE;
        let anon = stat::mem_stat(MemStat::AnonMapped) * KB_PER_PAGE;
        let cached = file_pages.saturating_sub(buffers);

        // Asterinas does not keep LRU lists, so no page is ever activated by
        // accesses. All pages are reported as inactive, which is where Linux
        // puts new pages. Like Linux, shmem pages are on the anonymous lists,
        // and ramfs pages are unevictable.
        let active_anon = 0;
        let inactive_anon = anon + shmem;
        let active_file = 0;
        let inactive_file = file_pages.saturating_sub(shmem + unevictable);

        // Asterinas has no swap, so the limit only consists of RAM.
        //
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/mm/util.c#L904-L916>
        let commit_limit = crate::vm::mem_total() / PAGE_SIZE * OVERCOMMIT_RATIO / 100;

        // Slab caches in Asterinas are never reclaimed.
        let sreclaimable = 0;
        let sunreclaim = crate::vm::mem_slab() / 1024;

        let fields: &[(&str, usize)] = &[
            ("MemTotal:", total),
            ("MemFree:", free),
            ("MemAvailable:", available),
            ("Buffers:", buffers),
            ("Cached:", cached),
            ("SwapCached:", 0),
            ("Active:", active_anon + active_file),
            ("Inactive:", inactive_anon + inactive_file),
            ("Active(anon):", active_anon),
            ("Inactive(anon):", inactive_anon),
            ("Active(file):", active_file),
            ("Inactive(file):", inactive_file),
            ("Unevictable:", unevictable),
            // Asterinas does not support `mlock`.
            ("Mlocked:", 0),
            ("SwapTotal:", 0),
            ("SwapFree:", 0),
            ("Dirty:", stat::mem_stat(MemStat::FileDirty) * KB_PER_PAGE),
            (
                "Writeback:",
                stat::mem_stat(MemStat::Writeback) * KB_PER_PAGE,
            ),
            ("AnonPages:", anon),
            ("Mapped:", stat::mem_stat(MemStat::FileMapped) * KB_PER_PAGE),
            ("Shmem:", shmem),
            ("KReclaimable:", sreclaimable),
            ("Slab:", sreclaimable + sunreclaim),
            ("SReclaimable:", sreclaimable),
            ("SUnreclaim:", sunreclaim),
            (
                "KernelStack:",
                ostd_stat::nr_kernel_stack_pages() * KB_PER_PAGE,
            ),
            (
                "PageTables:",
                ostd_stat::nr_page_table_pages() * KB_PER_PAGE,
            ),
            (
                "SecPageTables:",
                ostd_stat::nr_secondary_page_table_pages() * KB_PER_PAGE,
            ),
            ("NFS_Unstable:", 0),
            ("Bounce:", 0),
            ("WritebackTmp:", 0),
            ("CommitLimit:", commit_limit * KB_PER_PAGE),
            ("Committed_AS:", stat::nr_committed_pages() * KB_PER_PAGE),
            ("VmallocTotal:", ostd_stat::vmalloc_total_size() / 1024),
            ("VmallocUsed:", ostd_stat::nr_vmalloc_pages() * KB_PER_PAGE),
            ("VmallocChunk:", 0),
            ("Percpu:", ostd_stat::nr_cpu_local_pages() * KB_PER_PAGE),
            // Asterinas does not support memory ballooning.
            ("Balloon:", 0),
            // No GPU driver in Asterinas accounts its pages as Linux's TTM
            // page pools do.
            ("GPUActive:", 0),
            ("GPUReclaim:", 0),
        ];

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/meminfo.c#L28-L32>
        for (name, kb) in fields {
            writeln!(printer, "{:<16}{:>8} kB", name, kb)?;
        }

        Ok(printer.bytes_written())
    }
}

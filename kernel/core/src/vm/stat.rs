// SPDX-License-Identifier: MPL-2.0

//! Global statistics of memory pages, like Linux's node page states.
//!
//! The counters are updated on the exact paths where pages are allocated,
//! freed, mapped, unmapped, or change their states. They are per-CPU because
//! the updates happen on hot paths such as page faults and buffered I/O. To
//! keep the hot paths cheap, each event updates only one counter, and the
//! statistics that consist of several counters are summed up when read.

use core::sync::atomic::{AtomicIsize, Ordering};

use ostd::cpu::{CpuId, all_cpus};

/// A counter of the global memory statistics.
///
/// All counters are in pages.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum MemStat {
    /// Page cache pages of file data cached from storage.
    File,
    /// Page cache pages of block device metadata, i.e., Linux's buffers.
    Buffer,
    /// Shmem pages that are charged to the committed memory one by one.
    Shmem,
    /// Shmem pages whose objects are charged to the committed memory as a
    /// whole.
    ShmemReserved,
    /// Page cache pages of ramfs, which can never be reclaimed.
    Ramfs,
    /// Anonymous pages that are mapped to user space.
    ///
    /// This corresponds to Linux's `NR_ANON_MAPPED`.
    AnonMapped,
    /// Page cache pages that are mapped to user space.
    ///
    /// This corresponds to Linux's `NR_FILE_MAPPED`.
    FileMapped,
    /// Dirty pages that will be written back to storage.
    ///
    /// This corresponds to Linux's `NR_FILE_DIRTY`.
    FileDirty,
    /// Pages that are being written back to storage.
    ///
    /// This corresponds to Linux's `NR_WRITEBACK`.
    Writeback,
    /// Pages charged to the committed memory by memory mappings and shmem
    /// objects, excluding [`MemStat::Shmem`].
    Committed,
}

const NR_MEM_STATS: usize = MemStat::Committed as usize + 1;

ostd::cpu_local! {
    static MEM_STATS: [AtomicIsize; NR_MEM_STATS] = [const { AtomicIsize::new(0) }; NR_MEM_STATS];
}

/// Adds `delta` pages to the counter.
pub(crate) fn mod_mem_stat(item: MemStat, delta: isize) {
    // Updating the counter of another CPU due to migration is harmless,
    // because only the sum of all CPUs is meaningful.
    let cpu = CpuId::current_racy();
    MEM_STATS.get_on_cpu(cpu)[item as usize].fetch_add(delta, Ordering::Relaxed);
}

/// Returns the number of pages of the counter.
pub(crate) fn mem_stat(item: MemStat) -> usize {
    let sum = all_cpus().fold(0isize, |sum, cpu| {
        sum.wrapping_add(MEM_STATS.get_on_cpu(cpu)[item as usize].load(Ordering::Relaxed))
    });
    // A reader may observe a negative sum if a page is counted on a CPU that
    // has been summed and uncounted on a CPU that has not been summed yet.
    sum.max(0) as usize
}

/// Returns the number of page cache pages, including buffers and shmem.
///
/// This corresponds to Linux's `NR_FILE_PAGES`.
pub(crate) fn nr_file_pages() -> usize {
    mem_stat(MemStat::File) + mem_stat(MemStat::Buffer) + nr_shmem_pages() + nr_ramfs_pages()
}

/// Returns the number of buffer pages.
///
/// This corresponds to Linux's `nr_blockdev_pages()`.
pub(crate) fn nr_buffer_pages() -> usize {
    mem_stat(MemStat::Buffer)
}

/// Returns the number of pages of tmpfs, memfd, and shared anonymous memory.
///
/// This corresponds to Linux's `NR_SHMEM`.
pub(crate) fn nr_shmem_pages() -> usize {
    mem_stat(MemStat::Shmem) + mem_stat(MemStat::ShmemReserved)
}

/// Returns the number of ramfs pages, which are on Linux's unevictable LRU
/// list.
pub(crate) fn nr_ramfs_pages() -> usize {
    mem_stat(MemStat::Ramfs)
}

/// Returns the number of pages of committed memory.
///
/// This corresponds to Linux's `vm_committed_as`.
pub(crate) fn nr_committed_pages() -> usize {
    mem_stat(MemStat::Committed) + mem_stat(MemStat::Shmem)
}

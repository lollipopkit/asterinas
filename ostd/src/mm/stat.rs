// SPDX-License-Identifier: MPL-2.0

//! Statistics of memory owned by OSTD.
//!
//! These counters back the corresponding fields in Linux's `/proc/meminfo`.
//! They are updated where OSTD allocates and frees the memory, so the values
//! are exact rather than estimated.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::kspace::VMALLOC_VADDR_RANGE;

/// A counter of pages.
///
/// The counted events are rare (allocating page tables, kernel stacks,
/// etc.), so a global atomic does not cause noticeable contention.
pub(crate) struct PageCounter(AtomicUsize);

impl PageCounter {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    pub(crate) fn add(&self, nr_pages: usize) {
        self.0.fetch_add(nr_pages, Ordering::Relaxed);
    }

    pub(crate) fn sub(&self, nr_pages: usize) {
        self.0.fetch_sub(nr_pages, Ordering::Relaxed);
    }

    fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// The pages of page tables that translate CPU virtual addresses.
pub(crate) static PAGE_TABLE_PAGES: PageCounter = PageCounter::new();
/// The pages of page tables that translate device or guest addresses.
pub(crate) static SECONDARY_PAGE_TABLE_PAGES: PageCounter = PageCounter::new();
/// The pages of kernel stacks.
pub(crate) static KERNEL_STACK_PAGES: PageCounter = PageCounter::new();
/// The tracked pages mapped in the kernel virtual areas.
pub(crate) static VMALLOC_PAGES: PageCounter = PageCounter::new();
/// The pages of the dynamically-allocated CPU-local chunks.
pub(crate) static DYN_CPU_LOCAL_PAGES: PageCounter = PageCounter::new();

/// Returns the number of pages used by page tables that translate CPU virtual
/// addresses, i.e., the page tables of the kernel and user address spaces.
///
/// This corresponds to Linux's `NR_PAGETABLE`.
pub fn nr_page_table_pages() -> usize {
    PAGE_TABLE_PAGES.get()
}

/// Returns the number of pages used by page tables that translate device
/// (IOMMU) or guest (EPT) addresses.
///
/// This corresponds to Linux's `NR_SECONDARY_PAGETABLE`.
pub fn nr_secondary_page_table_pages() -> usize {
    SECONDARY_PAGE_TABLE_PAGES.get()
}

/// Returns the number of pages used by kernel stacks, excluding guard pages.
///
/// This corresponds to Linux's `NR_KERNEL_STACK_KB` (in pages).
pub fn nr_kernel_stack_pages() -> usize {
    KERNEL_STACK_PAGES.get()
}

/// Returns the number of tracked pages mapped in the kernel virtual areas.
///
/// The kernel virtual areas play the role of Linux's vmalloc space. This
/// corresponds to Linux's `NR_VMALLOC`.
pub fn nr_vmalloc_pages() -> usize {
    VMALLOC_PAGES.get()
}

/// Returns the size of the kernel virtual area space in bytes.
///
/// This corresponds to Linux's `VMALLOC_TOTAL`.
pub fn vmalloc_total_size() -> usize {
    VMALLOC_VADDR_RANGE.len()
}

/// Returns the number of pages used by CPU-local storage.
///
/// This includes the static CPU-local storage of all CPUs and the
/// dynamically-allocated CPU-local chunks. This corresponds to Linux's
/// `pcpu_nr_pages()`.
pub fn nr_cpu_local_pages() -> usize {
    crate::cpu::local::nr_static_storage_pages() + DYN_CPU_LOCAL_PAGES.get()
}

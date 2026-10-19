// SPDX-License-Identifier: MPL-2.0

//! Kernel stack high-watermark measurement.
//!
//! This is a debugging aid that is only built with the `kstack_watermark`
//! feature. Each kernel stack is filled with a canary pattern when it is
//! allocated and scanned when it is freed. The deepest overwritten word gives
//! the stack usage of the task, like Linux's `CONFIG_DEBUG_STACK_USAGE`.
//!
//! When a task sets a new maximum (or uses more than [`REPORT_THRESHOLD`]),
//! the words above the watermark that look like kernel text addresses are
//! printed. They are the (possibly stale) return addresses of the deepest call
//! chain and can be symbolized offline with `llvm-symbolizer`.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    early_println,
    mm::{Paddr, kspace::paddr_to_vaddr},
};

const CANARY: u64 = 0x57ac_c0de_57ac_c0de;

/// Usages at or above this size are always reported.
const REPORT_THRESHOLD: usize = 40 * 1024;

/// The number of words above the watermark that are searched for return addresses.
const NR_SCAN_WORDS: usize = 2048;

const MAX_REPORTED_ADDRS: usize = 32;

static MAX_USAGE: AtomicUsize = AtomicUsize::new(0);

/// The number of stacks by their usage in pages. The last bucket counts all larger usages.
static HISTOGRAM: [AtomicUsize; 65] = [const { AtomicUsize::new(0) }; 65];

/// Fills the stack with the canary pattern.
///
/// The stack is accessed via the linear mapping since its kernel virtual
/// mapping may not be TLB-coherent on the current CPU yet.
pub(super) fn fill(paddr: Paddr, size: usize) {
    let base = paddr_to_vaddr(paddr) as *mut u64;
    for i in 0..size / size_of::<u64>() {
        // SAFETY: The stack frames are exclusively owned by the new kernel stack
        // and are not used by any task yet.
        unsafe { base.add(i).write_volatile(CANARY) };
    }
}

/// Scans the stack of a dead task and records its high watermark.
pub(super) fn record(paddr: Paddr, size: usize) {
    let base = paddr_to_vaddr(paddr) as *const u64;
    let nr_words = size / size_of::<u64>();
    // SAFETY: The stack frames are still owned by the kernel stack being dropped
    // and no task runs on it any longer.
    let read = |i: usize| unsafe { base.add(i).read_volatile() };

    let lowest_used = (0..nr_words)
        .find(|&i| read(i) != CANARY)
        .unwrap_or(nr_words);
    let usage = (nr_words - lowest_used) * size_of::<u64>();

    let nr_pages = usage.div_ceil(crate::mm::PAGE_SIZE);
    HISTOGRAM[nr_pages.min(HISTOGRAM.len() - 1)].fetch_add(1, Ordering::Relaxed);

    let prev_max = MAX_USAGE.fetch_max(usage, Ordering::Relaxed);
    if usage <= prev_max && usage < REPORT_THRESHOLD {
        return;
    }

    unsafe extern "C" {
        fn __executable_start();
        fn __etext();
    }
    let text = __executable_start as *const () as u64..__etext as *const () as u64;

    early_println!(
        "[kstack] usage {} bytes ({} pages), max {} bytes",
        usage,
        nr_pages,
        usage.max(prev_max),
    );
    // A new maximum dumps the whole stack to show the full call chain.
    let is_new_max = usage > prev_max;
    let (nr_scan_words, max_reported_addrs) = if is_new_max {
        (nr_words, usize::MAX)
    } else {
        (NR_SCAN_WORDS, MAX_REPORTED_ADDRS)
    };
    let mut nr_reported = 0;
    for i in lowest_used..nr_words.min(lowest_used + nr_scan_words) {
        let word = read(i);
        if text.contains(&word) {
            early_println!(
                "[kstack]   depth {:6} ra {:#x}",
                (nr_words - i) * size_of::<u64>(),
                word
            );
            nr_reported += 1;
            if nr_reported == max_reported_addrs {
                break;
            }
        }
    }
}

/// Prints the number of stacks by their usage in pages.
pub(super) fn print_histogram() {
    for (nr_pages, count) in HISTOGRAM.iter().enumerate() {
        let count = count.load(Ordering::Relaxed);
        if count > 0 {
            early_println!("[kstack] histogram {:2} pages: {}", nr_pages, count);
        }
    }
    early_println!("[kstack] max {} bytes", MAX_USAGE.load(Ordering::Relaxed));
}

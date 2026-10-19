// SPDX-License-Identifier: MPL-2.0

use core::{ops::Range, sync::atomic::Ordering};

use crate::{
    arch::mm::tlb_flush_addr_range,
    cpu::{AtomicCpuSet, CpuSet, PinCurrentCpu},
    impl_frame_meta_for,
    irq::DisabledLocalIrqGuard,
    mm::{
        FrameAllocOptions, PAGE_SIZE,
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
        stat::KERNEL_STACK_PAGES,
    },
    prelude::*,
};

#[cfg(feature = "kstack_watermark")]
mod watermark;

/// The kernel stack size of a task, specified in pages.
///
/// OSTD users can choose another size by specifying the `OSTD_TASK_STACK_SIZE_IN_PAGES`
/// environment variable at build time.
const STACK_SIZE_IN_PAGES: u32 =
    if let Some(size_str) = option_env!("OSTD_TASK_STACK_SIZE_IN_PAGES") {
        match u32::from_str_radix(size_str, 10) {
            Ok(size) => size,
            Err(_) => panic!(
                "The environment variable `OSTD_TASK_STACK_SIZE_IN_PAGES` \
                    specifies an invalid value"
            ),
        }
    } else {
        DEFAULT_STACK_SIZE_IN_PAGES
    };

/// The default kernel stack size of a task, specified in pages.
///
/// Linux uses 16 KiB on x86-64 (`THREAD_SIZE`), but runs IRQs on separate per-CPU stacks. Here
/// IRQs and softirqs run on the kernel stack of the interrupted task, so the stack must cover
/// them as well. The sizes keep at least twice the peak usage measured on x86-64 with the
/// `kstack_watermark` feature over the regression tests, the ktests, a gVisor subset, and a
/// workload that installs and builds software. The peaks are about 15 KiB in release builds
/// and about 60 KiB in debug builds, whose frames are not optimized, both in the first kernel
/// thread, which unpacks the initramfs.
///
/// The sizes of other architectures are not measured and remain as before. RISC-V uses larger
/// stacks in release builds since unwinding seems to cost more stack there.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/include/asm/page_64_types.h#L15-L16>
const DEFAULT_STACK_SIZE_IN_PAGES: u32 = if cfg!(debug_assertions) {
    if cfg!(target_arch = "x86_64") { 32 } else { 64 }
} else if cfg!(target_arch = "riscv64") {
    16
} else {
    8
};

const KERNEL_STACK_SIZE: usize = STACK_SIZE_IN_PAGES as usize * PAGE_SIZE;

#[derive(Debug)]
pub(super) struct KernelStack {
    kvirt_area: KVirtArea,
    tlb_coherent: AtomicCpuSet,
    end_vaddr: Vaddr,
    #[cfg(feature = "kstack_watermark")]
    paddr: Paddr,
}

#[derive(Debug, Default)]
struct KernelStackMeta;

impl_frame_meta_for!(KernelStackMeta);

impl KernelStack {
    /// Generates a kernel stack with guard pages.
    ///
    /// 4 additional pages are allocated and regarded as guard pages, which
    /// should not be accessed.
    //
    // TODO: We map kernel stacks in the kernel virtual areas, which incurs
    // non-negligible TLB and mapping overhead on task creation. This could
    // be improved by caching/reusing kernel stacks with a pool.
    pub(super) fn new_with_guard_page() -> Result<Self> {
        let pages = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_segment_with(KERNEL_STACK_SIZE / PAGE_SIZE, |_| KernelStackMeta)?;
        #[cfg(feature = "kstack_watermark")]
        let paddr = {
            watermark::fill(pages.paddr(), KERNEL_STACK_SIZE);
            pages.paddr()
        };
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };
        let new_kvirt_area = KVirtArea::map_frames(
            KERNEL_STACK_SIZE + 4 * PAGE_SIZE,
            2 * PAGE_SIZE,
            pages.into_iter(),
            prop,
        );
        KERNEL_STACK_PAGES.add(KERNEL_STACK_SIZE / PAGE_SIZE);
        let mapped_start = new_kvirt_area.range().start + 2 * PAGE_SIZE;
        let mapped_end = mapped_start + KERNEL_STACK_SIZE;
        Ok(Self {
            kvirt_area: new_kvirt_area,
            tlb_coherent: AtomicCpuSet::new(CpuSet::new_empty()),
            end_vaddr: mapped_end,
            #[cfg(feature = "kstack_watermark")]
            paddr,
        })
    }

    /// Flushes the TLB for the current CPU if necessary.
    pub(super) fn flush_tlb(&self, irq_guard: &DisabledLocalIrqGuard) {
        let cur_cpu = irq_guard.current_cpu();
        if !self.tlb_coherent.contains(cur_cpu, Ordering::Relaxed) {
            tlb_flush_addr_range(&self.kvirt_area.range());
            self.tlb_coherent.add(cur_cpu, Ordering::Relaxed);
        }
    }

    pub(super) fn end_vaddr(&self) -> Vaddr {
        self.end_vaddr
    }

    /// Records the high watermark of the stack.
    #[cfg(feature = "kstack_watermark")]
    pub(super) fn record_watermark(&self) {
        watermark::record(self.paddr, KERNEL_STACK_SIZE);
    }

    /// Prints the statistics of the high watermarks of all recorded stacks.
    #[cfg(feature = "kstack_watermark")]
    pub(super) fn print_watermark_histogram() {
        watermark::print_histogram();
    }

    /// Returns the mapped range of the stack.
    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    pub(super) fn range(&self) -> Range<Vaddr> {
        self.end_vaddr - KERNEL_STACK_SIZE..self.end_vaddr
    }

    /// Returns the guard pages below the stack, which an overflow hits first.
    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    pub(super) fn lower_guard_range(&self) -> Range<Vaddr> {
        self.kvirt_area.range().start..self.end_vaddr - KERNEL_STACK_SIZE
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        #[cfg(feature = "kstack_watermark")]
        self.record_watermark();
        KERNEL_STACK_PAGES.sub(KERNEL_STACK_SIZE / PAGE_SIZE);
    }
}

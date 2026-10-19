// SPDX-License-Identifier: MPL-2.0

//! Configure the Global Descriptor Table (GDT).

use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    mem::offset_of,
    sync::atomic::{AtomicU64, Ordering},
};

use spin::Once;
use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::tables::{lgdt, load_tss},
    registers::segmentation::{CS, Segment},
    structures::{
        DescriptorTablePointer,
        gdt::{Descriptor, SegmentSelector},
        tss::TaskStateSegment,
    },
};

use crate::{
    arch::mm::tlb_flush_addr_range,
    const_assert,
    cpu::{
        CpuId,
        local::{CpuLocal, StaticCpuLocal},
        num_cpus,
    },
    cpu_local, impl_frame_meta_for,
    irq::DisabledLocalIrqGuard,
    mm::{
        FrameAllocOptions, PAGE_SIZE, Vaddr,
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    },
    util::id_set::Id,
};

/// Initializes and loads the GDT and TSS.
///
/// The caller should only call this method once in the boot context for each available processor.
/// This is not a safety requirement, however, because calling this method again will do nothing
/// more than load the GDT and TSS with the same contents.
///
/// # Safety
///
/// The caller must ensure that no preemption can occur during the method, otherwise we may
/// accidentally load a wrong GDT and TSS that actually belongs to another CPU.
pub(super) unsafe fn init_on_cpu() {
    // No races because the caller guarantees that no preemption can occur.
    let gdt = GDT.get_on_cpu(CpuId::current_racy());

    let tss_ptr = UnsafeCell::raw_get(LOCAL_TSS.as_ptr());

    let df_stack_top = DOUBLE_FAULT_STACKS.get().unwrap()[CpuId::current_racy().as_usize()]
        .range()
        .end;
    // SAFETY: The TSS is CPU-local and no other code accesses the IST at this point, since the
    // caller guarantees that no preemption can occur and no traps can occur yet.
    unsafe {
        (*tss_ptr).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            VirtAddr::new(df_stack_top as u64);
    }

    // FIXME: The segment limit in the descriptor created by `tss_segment_unchecked` does not
    // include the I/O port bitmap.

    // SAFETY: As a CPU-local variable, the TSS lives for `'static`.
    let tss_desc = unsafe { Descriptor::tss_segment_unchecked(tss_ptr) };
    let (tss0, tss1) = match tss_desc {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        _ => unreachable!(),
    };
    gdt.tss0.store(tss0, Ordering::Relaxed);
    gdt.tss1.store(tss1, Ordering::Relaxed);

    // The kernel CS is considered a global invariant set by the boot GDT. This method is not
    // intended for switching to a new kernel CS.
    assert_eq!(CS::get_reg(), KERNEL_CS);

    // Load the new GDT.
    let gdtr = DescriptorTablePointer {
        limit: (size_of_val(gdt) - 1) as u16,
        base: VirtAddr::new(core::ptr::from_ref(gdt).addr() as u64),
    };
    // SAFETY: The GDT is valid to load because:
    //  - It lives for `'static`.
    //  - It contains correct entries at correct indexes: the kernel code/data segments, the user
    //    code/data segments, and the TSS segment.
    //  - Specifically, the TSS segment points to the CPU-local TSS of the current CPU.
    unsafe { lgdt(&gdtr) };

    // Load the TSS.
    //
    // SAFETY: The selector points to the TSS descriptors in the GDT.
    unsafe { load_tss(TSS_SEL) };
}

/// The IST index of the double fault handler, i.e., Linux's `IST_INDEX_DF`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/include/asm/page_64_types.h#L27>
pub(super) const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// The size of the double fault stack of each CPU.
///
/// A kernel stack overflow faults on the guard pages and escalates to a double fault, which
/// needs a separate stack to report the overflow. Linux uses 8 KiB (`EXCEPTION_STKSZ`) for it.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/include/asm/page_64_types.h#L18-L19>
const DOUBLE_FAULT_STACK_SIZE: usize = 4 * PAGE_SIZE;

/// The double fault stacks of all CPUs, indexed by the CPU ID.
static DOUBLE_FAULT_STACKS: Once<Box<[KVirtArea]>> = Once::new();

#[derive(Debug)]
struct DoubleFaultStackMeta;

impl_frame_meta_for!(DoubleFaultStackMeta);

/// Allocates the double fault stacks of all CPUs.
///
/// Each stack has a guard page below it, like Linux's exception stacks in the CPU entry area.
/// This must be called on the BSP after the kernel page table is activated and before any
/// call to [`init_on_cpu`].
pub(in crate::arch) fn alloc_double_fault_stacks() {
    DOUBLE_FAULT_STACKS.call_once(|| {
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };
        (0..num_cpus())
            .map(|_| {
                let pages = FrameAllocOptions::new()
                    .zeroed(false)
                    .alloc_segment_with(DOUBLE_FAULT_STACK_SIZE / PAGE_SIZE, |_| {
                        DoubleFaultStackMeta
                    })
                    .expect("failed to allocate the double fault stack");
                let area = KVirtArea::map_frames(
                    DOUBLE_FAULT_STACK_SIZE + PAGE_SIZE,
                    PAGE_SIZE,
                    pages.into_iter(),
                    prop,
                );
                // Other CPUs have not activated the kernel page table yet, so only the TLB of
                // the current CPU may have stale entries of the area.
                tlb_flush_addr_range(&area.range());
                area
            })
            .collect()
    });
}

/// Returns the current CPU's GDT base address.
pub(in crate::arch) fn gdt_base(_guard: &DisabledLocalIrqGuard) -> Vaddr {
    GDT.as_ptr() as Vaddr
}

/// Returns the GDT limit.
pub(in crate::arch) fn gdt_limit() -> u16 {
    (size_of::<Gdt>() - 1) as u16
}

/// Returns the current CPU's TSS base address.
pub(in crate::arch) fn tss_base(_guard: &DisabledLocalIrqGuard) -> Vaddr {
    UnsafeCell::raw_get(LOCAL_TSS.as_ptr()) as Vaddr
}

// The linker script makes sure that the `.cpu_local_tss` section is at the beginning of the area
// that stores CPU-local variables. This is important because `trap.S` and `syscall.S` will assume
// this and treat the beginning of the CPU-local area as a TSS for loading and saving the kernel
// stack!
//
// No other special initialization is required because the kernel stack information is stored in
// the TSS when we start the userspace program. However, to ensure the store's safety, we should
// wrap the TSS in an `UnsafeCell`. See `syscall.S` for details.
//
// SAFETY: This is properly handled in the linker script.
#[unsafe(link_section = ".cpu_local_tss")]
static LOCAL_TSS: StaticCpuLocal<UnsafeCell<TaskStateSegment>> = {
    let tss = UnsafeCell::new(TaskStateSegment::new());
    // SAFETY: The `.cpu_local_tss` section is part of the CPU-local area.
    unsafe { CpuLocal::__new_static(tss) }
};

#[repr(C)]
struct Gdt {
    // Immutable part: They are constant because they are either set to zero or all of the used bits
    // are set at compile time, including the ACCESSED bit. So they will not be modified later.
    _reserved: u64,
    kcode64: u64,
    kdata: u64,
    _kcode32: u64,
    _ucode32: u64,
    udata: u64,
    ucode64: u64,
    // Mutable part: They are initialized at runtime; the LTR instruction will set the BUSY bit.
    tss0: AtomicU64,
    tss1: AtomicU64,
}

cpu_local! {
    static GDT: Gdt = Gdt {
        _reserved: 0,
        kcode64: KCODE64,
        kdata: KDATA,
        _kcode32: 0, // Not used.
        _ucode32: 0, // Not used.
        udata: UDATA,
        ucode64: UCODE64,
        tss0: AtomicU64::new(0), // To be set in `init_on_cpu`.
        tss1: AtomicU64::new(0), // To be set in `init_on_cpu`.
    };
}

// ========= Descriptors =========

// Kernel code and data descriptors.
//
// These are the exact, unique values that satisfy the requirements of the `syscall` instruction.
// The Intel manual says: "It is the responsibility of OS software to ensure that the descriptors
// (in GDT or LDT) referenced by those selector values correspond to the fixed values loaded into
// the descriptor caches; the SYSCALL instruction does not ensure this correspondence."
pub(in crate::arch) const KCODE64: u64 = 0x00AF_9B00_0000_FFFF;
pub(in crate::arch) const KDATA: u64 = 0x00CF_9300_0000_FFFF;

// A 32-bit code descriptor that is used in the boot stage only. See `boot/bsp_boot.S`.
pub(in crate::arch) const KCODE32: u64 = 0x00CF_9B00_0000_FFFF;

// User code and data descriptors.
//
// These are the exact, unique values that satisfy the requirements of the `sysret` instruction.
// The Intel manual says: "It is the responsibility of OS software to ensure that the descriptors
// (in GDT or LDT) referenced by those selector values correspond to the fixed values loaded into
// the descriptor caches; the SYSRET instruction does not ensure this correspondence."
const UCODE64: u64 = 0x00AF_FB00_0000_FFFF;
const UDATA: u64 = 0x00CF_F300_0000_FFFF;

// ========== Selectors ==========

pub(in crate::arch) const KERNEL_CS: SegmentSelector =
    SegmentSelector::new(1, PrivilegeLevel::Ring0);
const KERNEL_SS: SegmentSelector = SegmentSelector::new(2, PrivilegeLevel::Ring0);
const_assert!(KERNEL_CS.0 & OFFSET_MASK == offset_of!(Gdt, kcode64) as u16);
const_assert!(KERNEL_SS.0 & OFFSET_MASK == offset_of!(Gdt, kdata) as u16);

pub(super) const USER_CS: SegmentSelector = SegmentSelector::new(6, PrivilegeLevel::Ring3);
pub(super) const USER_SS: SegmentSelector = SegmentSelector::new(5, PrivilegeLevel::Ring3);
const_assert!(USER_CS.0 & OFFSET_MASK == offset_of!(Gdt, ucode64) as u16);
const_assert!(USER_SS.0 & OFFSET_MASK == offset_of!(Gdt, udata) as u16);

pub(in crate::arch) const TSS_SEL: SegmentSelector = SegmentSelector::new(7, PrivilegeLevel::Ring0);
const_assert!(TSS_SEL.0 & OFFSET_MASK == offset_of!(Gdt, tss0) as u16);
const_assert!(TSS_SEL.0 & OFFSET_MASK == (offset_of!(Gdt, tss1) - size_of::<u64>()) as u16);

pub(in crate::arch) const SYSRET_SEL: SegmentSelector =
    SegmentSelector::new(4, PrivilegeLevel::Ring3);
pub(in crate::arch) const SYSCALL_SEL: SegmentSelector =
    SegmentSelector::new(1, PrivilegeLevel::Ring0);
const_assert!(SYSRET_SEL.0 & OFFSET_MASK == (offset_of!(Gdt, udata) - size_of::<u64>()) as u16);
const_assert!(
    SYSRET_SEL.0 & OFFSET_MASK == (offset_of!(Gdt, ucode64) - size_of::<u64>() * 2) as u16
);
const_assert!(SYSCALL_SEL.0 & OFFSET_MASK == offset_of!(Gdt, kcode64) as u16);
const_assert!(SYSCALL_SEL.0 & OFFSET_MASK == (offset_of!(Gdt, kdata) - size_of::<u64>()) as u16);

// Masking out the lower 3 bits of a selector yields the offset to the GDT entry from the GDT base.
const OFFSET_MASK: u16 = !7;

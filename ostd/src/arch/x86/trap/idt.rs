// SPDX-License-Identifier: MPL-2.0

//! Configure the Interrupt Descriptor Table (IDT).

use core::arch::global_asm;

use spin::Once;
use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::tables::lidt,
    structures::{DescriptorTablePointer, idt::Entry},
};

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::mm::Vaddr;

global_asm!(include_str!("trap.S"));

const NUM_INTERRUPTS: usize = 256;

const DOUBLE_FAULT_VECTOR: usize = 8;

unsafe extern "C" {
    #[link_name = "trap_handler_table"]
    static VECTORS: [usize; NUM_INTERRUPTS];
}

static GLOBAL_IDT: Once<[Entry<()>; NUM_INTERRUPTS]> = Once::new();

/// Returns the IDT base address.
pub(in crate::arch) fn idt_base() -> Vaddr {
    GLOBAL_IDT.get().unwrap().as_ptr() as Vaddr
}

/// Initializes and loads the IDT.
///
/// The caller should only call this method once in the boot context for each available processor.
/// This is not a safety requirement, however, because calling this method again will do nothing
/// more than load the same IDT.
pub(super) fn init_on_cpu() {
    let idt = GLOBAL_IDT.call_once(|| {
        let mut idt = [const { Entry::missing() }; NUM_INTERRUPTS];

        // SAFETY: The vector array is properly initialized, lives for `'static`, and will never be
        // mutated. So it's always fine to create an immutable borrow to it.
        let vectors = unsafe { &VECTORS };

        // Initialize the IDT entries.
        for (intr_no, &handler) in vectors.iter().enumerate() {
            let handler = VirtAddr::new(handler as u64);

            let entry = &mut idt[intr_no];
            // SAFETY: The handler defined in `trap.S` has a correct signature to handle the
            // corresponding exception or interrupt.
            let opt = unsafe { entry.set_handler_addr(handler) };

            // Enable `int3` and `into` in the userspace.
            if intr_no == 3 || intr_no == 4 {
                opt.set_privilege_level(PrivilegeLevel::Ring3);
            }

            // Like Linux, handle double faults on a known good stack, so that kernel stack
            // overflows can be reported.
            if intr_no == DOUBLE_FAULT_VECTOR {
                // SAFETY: The IST entry is set up in `gdt::init_on_cpu` and used by no other
                // vector. The double fault handler never returns.
                unsafe { opt.set_stack_index(DOUBLE_FAULT_IST_INDEX) };
            }
        }

        idt
    });

    let idtr = DescriptorTablePointer {
        limit: (size_of_val(idt) - 1) as u16,
        base: VirtAddr::new(idt.as_ptr().addr() as u64),
    };
    // SAFETY: The IDT is valid to load because:
    //  - It lives for `'static`.
    //  - It contains correct entries at correct indexes: all handlers are defined in `trap.S` with
    //    correct handler signatures.
    unsafe { lidt(&idtr) };
}

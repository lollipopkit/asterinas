// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::{
        CpuException, FXSAVE_AREA_SIZE, FpuContext, PageFaultErrorCode, UserContext,
    },
    mm::VmIo,
    user::UserContextApi,
};

use crate::{
    prelude::*,
    process::signal::{SignalContext, sig_num::SigNum, signals::fault::FaultSignal},
    thread::exception::ToFaultSignal,
};

impl SignalContext for UserContext {
    fn set_arguments(&mut self, sig_num: SigNum, siginfo_addr: usize, ucontext_addr: usize) {
        self.set_rdi(sig_num.as_u8() as usize);
        self.set_rsi(siginfo_addr);
        self.set_rdx(ucontext_addr);
    }
}

impl ToFaultSignal for CpuException {
    fn to_fault_signal(&self, user_ctx: &UserContext) -> Option<FaultSignal> {
        use crate::process::signal::constants::*;

        let rip = user_ctx.instruction_pointer() as u64;

        let (num, code, addr) = match self {
            CpuException::DivisionError => (SIGFPE, FPE_INTDIV, Some(rip)),
            CpuException::Debug => {
                // TODO: Derive the code from the debug status.
                (SIGTRAP, TRAP_TRACE, Some(rip))
            }
            CpuException::BreakPoint => {
                // Linux uses `SI_KERNEL` without an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L998>
                (SIGTRAP, SI_KERNEL, None)
            }
            CpuException::Overflow => {
                // Linux uses `SI_KERNEL` without an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L387>
                (SIGSEGV, SI_KERNEL, None)
            }
            CpuException::BoundRangeExceeded => {
                // Linux uses `SI_KERNEL` without an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/traps.c#L718-L731>
                (SIGSEGV, SI_KERNEL, None)
            }
            CpuException::InvalidOpcode => (SIGILL, ILL_ILLOPN, Some(rip)),
            CpuException::CoprocessorSegmentOverrun => {
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/traps.c#L500-L504>
                (SIGFPE, SI_KERNEL, None)
            }
            CpuException::InvalidTss(..) => {
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/traps.c#L506-L510>
                (SIGSEGV, SI_KERNEL, None)
            }
            CpuException::SegmentNotPresent(..) => {
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/traps.c#L512-L516>
                (SIGBUS, SI_KERNEL, None)
            }
            CpuException::StackSegmentFault(..) => {
                // Linux uses `SI_KERNEL` without an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L519-L520>
                (SIGBUS, SI_KERNEL, None)
            }
            CpuException::GeneralProtectionFault(..) => {
                // Linux uses `SI_KERNEL` without an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L904-L911>
                (SIGSEGV, SI_KERNEL, None)
            }
            CpuException::PageFault(raw_page_fault_info) => {
                // FIXME: The code should depend on whether the faulting address is covered by a
                // mapping, not just on the `PRESENT` bit.
                let code = if raw_page_fault_info
                    .error_code
                    .contains(PageFaultErrorCode::PRESENT)
                {
                    SEGV_ACCERR
                } else {
                    SEGV_MAPERR
                };
                let addr = Some(raw_page_fault_info.addr as u64);
                (SIGSEGV, code, addr)
            }
            CpuException::X87FloatingPointException | CpuException::SIMDFloatingPointException => {
                // TODO: Derive the code from the floating-point status.
                (SIGFPE, FPE_FLTDIV, Some(rip))
            }
            CpuException::AlignmentCheck => {
                // Linux does not provide an address.
                //
                // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L538-L539>
                (SIGBUS, BUS_ADRALN, None)
            }
            CpuException::ControlProtectionException => {
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/cet.c#L48-L81>
                (SIGSEGV, SEGV_CPERR, Some(0))
            }

            _ => return None,
        };

        Some(FaultSignal::new(num, code, addr))
    }
}

/// The software-reserved bytes at the end of the FXSAVE area in a signal frame.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/include/uapi/asm/sigcontext.h#L40-L72>
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct FpxSwBytes {
    magic1: u32,
    extended_size: u32,
    xfeatures: u64,
    xstate_size: u32,
    padding: [u32; 7],
}

const FP_XSTATE_MAGIC1: u32 = 0x46505853;
const FP_XSTATE_MAGIC2: u32 = 0x46505845;
const FPX_SW_BYTES_OFFSET: usize = FXSAVE_AREA_SIZE - size_of::<FpxSwBytes>();
const XSTATE_BV_OFFSET: usize = FXSAVE_AREA_SIZE;
const XSAVE_HEADER_SIZE: usize = 64;
/// X87 | SSE
const XFEATURE_MASK_FPSSE: u64 = 0b11;

/// Returns the image of the FPU context to save in a signal frame.
///
/// The image carries the software-reserved bytes and, in the XSAVE format, the trailing
/// `FP_XSTATE_MAGIC2`, so that user space can find out the layout.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/fpu/signal.c#L105-L148>
pub(crate) fn fpu_sigframe_image(fpu_context: &FpuContext) -> Vec<u8> {
    let mut image = fpu_context.as_bytes().to_vec();
    let size = image.len();

    let sw_bytes = FpxSwBytes {
        magic1: FP_XSTATE_MAGIC1,
        extended_size: (size + size_of::<u32>()) as u32,
        xfeatures: FpuContext::user_features(),
        xstate_size: size as u32,
        padding: [0; 7],
    };
    image[FPX_SW_BYTES_OFFSET..FXSAVE_AREA_SIZE].copy_from_slice(sw_bytes.as_bytes());

    if size > FXSAVE_AREA_SIZE {
        // Always mark the x87 and SSE states as present, so that changes made by legacy programs
        // that do not touch `XSTATE_BV` are restored.
        let bv_bytes = &mut image[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + size_of::<u64>()];
        let xstate_bv = u64::from_ne_bytes(bv_bytes.try_into().unwrap()) | XFEATURE_MASK_FPSSE;
        bv_bytes.copy_from_slice(&xstate_bv.to_ne_bytes());

        image.extend_from_slice(&FP_XSTATE_MAGIC2.to_ne_bytes());
    }

    image
}

/// Reads the FPU context saved in a signal frame at `addr`.
///
/// A null address yields the initial FPU context. Without valid software-reserved bytes and
/// `FP_XSTATE_MAGIC2`, only the legacy x87 and SSE states are restored, and the other states are
/// initialized.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/fpu/signal.c#L27-L64>,
// <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/fpu/signal.c#L327-L352>,
// <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/fpu/signal.c#L449-L460>
pub(crate) fn read_fpu_sigframe(user_space: &CurrentUserSpace, addr: Vaddr) -> Result<FpuContext> {
    if addr == 0 {
        return Ok(FpuContext::new());
    }

    let mut fxsave_image = [0u8; FXSAVE_AREA_SIZE];
    user_space.read_bytes(addr, &mut fxsave_image[..])?;

    let size = FpuContext::size();
    if size > FXSAVE_AREA_SIZE {
        let sw_bytes = FpxSwBytes::from_bytes(&fxsave_image[FPX_SW_BYTES_OFFSET..]);
        let xstate_size = sw_bytes.xstate_size as usize;
        if sw_bytes.magic1 == FP_XSTATE_MAGIC1
            && xstate_size >= FXSAVE_AREA_SIZE + XSAVE_HEADER_SIZE
            && xstate_size <= size
            && sw_bytes.xstate_size <= sw_bytes.extended_size
            && user_space.read_val::<u32>(addr + xstate_size)? == FP_XSTATE_MAGIC2
        {
            let mut image = vec![0u8; size];
            user_space.read_bytes(addr, &mut image[..])?;
            return FpuContext::try_from_xsave_image(&image, sw_bytes.xfeatures)
                .map_err(|_| Error::with_message(Errno::EINVAL, "the XSAVE image is invalid"));
        }
    }

    FpuContext::try_from_fxsave_image(&fxsave_image)
        .map_err(|_| Error::with_message(Errno::EINVAL, "the FXSAVE image is invalid"))
}

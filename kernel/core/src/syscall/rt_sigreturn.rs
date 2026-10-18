// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::{FpuContext, UserContext},
    mm::VmIo,
    user::UserContextApi,
};

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{
        posix_thread::ContextPthreadAdminApi,
        signal::{
            c_types::{stack_t, ucontext_t},
            constants::SIGSEGV,
            force_signal,
            signals::fault::FaultSignal,
        },
    },
    syscall::sigaltstack::set_new_stack,
};

pub(super) fn sys_rt_sigreturn(ctx: &Context, user_ctx: &mut UserContext) -> Result<SyscallReturn> {
    // Always make any pending restarted syscalls return `EINTR`.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal_64.c#L56-L57>
    ctx.thread_local.set_restart_block(None);

    if let Err(e) = restore_sigframe(ctx, user_ctx) {
        // An invalid frame raises `SIGSEGV`, keeping the state restored before the failure.
        //
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal_64.c#L276-L278>,
        // <https://elixir.bootlin.com/linux/v7.2.10/source/arch/riscv/kernel/signal.c#L341-L350>,
        // <https://elixir.bootlin.com/linux/v7.2.10/source/arch/loongarch/kernel/signal.c#L930-L932>,
        // <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/signal.c#L1166-L1168>
        debug!("sys_rt_sigreturn: bad signal frame: {:?}", e);
        force_signal(ctx, bad_frame_signal(ctx, user_ctx));
        return Ok(SyscallReturn::Return(0));
    }

    Ok(SyscallReturn::NoReturn)
}

/// Restores the user context from the signal frame on the user stack.
///
/// The steps are taken in the Linux order, so that the same state is restored if a later step
/// fails.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal_64.c#L246-L279>,
// <https://elixir.bootlin.com/linux/v7.2.10/source/arch/riscv/kernel/signal.c#L310-L351>,
// <https://elixir.bootlin.com/linux/v7.2.10/source/arch/loongarch/kernel/signal.c#L902-L933>,
// <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/signal.c#L1019-L1078>
fn restore_sigframe(ctx: &Context, user_ctx: &mut UserContext) -> Result<()> {
    let sig_context_addr = user_ctx.stack_pointer() as Vaddr;
    debug!(
        "sys_rt_sigreturn: sig_context_addr = {:#x}",
        sig_context_addr
    );

    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/signal.c#L1141-L1146>
    #[cfg(target_arch = "aarch64")]
    if !sig_context_addr.is_multiple_of(16) {
        return_errno_with_message!(Errno::EFAULT, "the signal frame is misaligned");
    }

    let ucontext = ctx.user_space().read_val::<ucontext_t>(sig_context_addr)?;

    // Restore the signal mask.
    ctx.set_sig_mask(ucontext.uc_sigmask.into());

    // On x86-64, the signal stack is restored before the registers, so it is checked against the
    // stack pointer of the signal frame.
    #[cfg(target_arch = "x86_64")]
    restore_sig_stack(ctx, ucontext.uc_stack, sig_context_addr);

    // Restore general-purpose registers.
    ucontext.uc_mcontext.copy_user_regs_to(user_ctx);

    // Restore the FPU context.
    let fpu = ctx.thread_local.supp_user_context().fpu();
    let fpu_context = cfg_select! {
        target_arch = "x86_64" => {{
            // A bad FPU context resets the FPU context and fails.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/fpu/signal.c#L449-L492>
            let res = crate::arch::signal::read_fpu_sigframe(
                &ctx.user_space(),
                ucontext.uc_mcontext.fpu_context_addr(),
            );
            if res.is_err() {
                fpu.set(FpuContext::new());
            }
            res?
        }}
        target_arch = "aarch64" => {{
            let mut fpu_context = FpuContext::new();
            let record = ucontext.uc_mcontext.fpsimd_record(fpu_context.as_bytes().len())?;
            fpu_context.as_bytes_mut().copy_from_slice(record);
            fpu_context
        }}
        any(target_arch = "riscv64", target_arch = "loongarch64") => {{
            // In RISC-V/LoongArch64, the FPU context is placed directly after `ucontext_t` on the
            // signal stack.
            let mut fpu_context = FpuContext::new();
            ctx.user_space().read_bytes(
                sig_context_addr + size_of::<ucontext_t>(),
                fpu_context.as_bytes_mut(),
            )?;
            fpu_context
        }}
        _ => compile_error!("unsupported target"),
    };
    fpu.set(fpu_context);

    #[cfg(not(target_arch = "x86_64"))]
    restore_sig_stack(ctx, ucontext.uc_stack, user_ctx.stack_pointer());

    Ok(())
}

fn restore_sig_stack(ctx: &Context, stack: stack_t, sp: Vaddr) {
    // If the stack setting is invalid, we silently ignore the error, following Linux's behavior.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4541-L4550>
    let _ = set_new_stack(stack, ctx, sp);
}

/// Returns the `SIGSEGV` to force for an invalid signal frame.
fn bad_frame_signal(ctx: &Context, user_ctx: &UserContext) -> FaultSignal {
    cfg_select! {
        target_arch = "aarch64" => {
            use crate::process::signal::constants::{SEGV_ACCERR, SEGV_MAPERR};

            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/traps.c#L441-L453>
            let sp = user_ctx.stack_pointer();
            let has_vma = ctx
                .user_space()
                .vmar()
                .query(sp..usize::MAX)
                .iter()
                .next()
                .is_some();
            let code = if has_vma { SEGV_ACCERR } else { SEGV_MAPERR };
            FaultSignal::new(SIGSEGV, code, Some(sp as u64))
        }
        _ => {
            use crate::process::signal::constants::SI_KERNEL;

            let _ = (ctx, user_ctx);
            FaultSignal::new(SIGSEGV, SI_KERNEL, None)
        }
    }
}

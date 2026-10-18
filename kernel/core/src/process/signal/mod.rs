// SPDX-License-Identifier: MPL-2.0

pub(crate) mod c_types;
pub(crate) mod constants;
mod pause;
mod pending;
mod poll;
pub(crate) mod sig_action;
pub(crate) mod sig_disposition;
pub(crate) mod sig_mask;
pub(crate) mod sig_num;
pub(crate) mod sig_queues;
mod sig_stack;
pub(crate) mod signals;

use align_ext::AlignExt;
use c_types::{siginfo_t, ucontext_t};
use constants::{SI_KERNEL, SIGPIPE, SIGSEGV};
use ostd::{
    arch::cpu::context::{FpuContext, UserContext},
    mm::VmIo,
    user::UserContextApi,
};
pub use pause::pause_on_until;
pub(crate) use pause::{Pause, PauseReason, with_sigmask_changed};
pub(crate) use pending::{DequeuedSignal, HandlePendingSignal};
pub(crate) use poll::{PollAdaptor, Pollee, Poller};
pub use poll::{PollHandle, Pollable};
use sig_action::{SigAction, SigActionFlags, SigDefaultAction, SigHandler};
use sig_mask::SigMask;
use sig_num::SigNum;
pub(crate) use sig_stack::{SigStack, SigStackFlags, SigStackStatus};

use super::posix_thread::ThreadLocal;
use crate::{
    cpu::LinuxAbi,
    prelude::*,
    process::{
        TermStatus,
        posix_thread::{
            AsPosixThread, ContextPthreadAdminApi, do_exit_group, ptrace::PtraceStopResult,
        },
        signal::{
            c_types::stack_t,
            constants::SIGKILL,
            signals::{
                Signal,
                fault::FaultSignal,
                user::{UserSignal, UserSignalKind},
            },
        },
    },
};

pub(crate) trait SignalContext {
    /// Sets signal handler arguments.
    fn set_arguments(&mut self, sig_num: SigNum, siginfo_addr: usize, ucontext_addr: usize);
}

/// Sends `SIGPIPE` to the current thread, which writes to a pipe or a stream socket that is
/// broken.
///
/// Like Linux's `send_sig(SIGPIPE, current, 0)`, the signal is directed to the current thread and
/// carries `SI_USER` with the PID and the real UID of the current process.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L1133-L1145>
pub(crate) fn send_sigpipe_to_current() {
    let current = current_thread!();
    let Some(posix_thread) = current.as_posix_thread() else {
        return;
    };

    posix_thread.enqueue_signal(Box::new(UserSignal::new(
        SIGPIPE,
        UserSignalKind::Kill,
        posix_thread.process().pid(),
        posix_thread.credentials().ruid(),
    )));
}

/// Restarts the interrupted syscall, if any, because no user signal handler runs.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal.c#L343-L359>
pub(crate) fn restart_interrupted_syscall(user_ctx: &mut UserContext, ctx: &Context) {
    let Some((errno, orig_syscall_ret)) = syscall_to_restart(user_ctx, ctx) else {
        return;
    };

    restart_syscall(user_ctx, ctx, orig_syscall_ret);
    if errno == Errno::ERESTART_RESTARTBLOCK {
        user_ctx.set_syscall_num(crate::syscall::SYS_RESTART_SYSCALL as usize);
    }
}

/// Returns the restart errno and the original syscall return value (i.e., the syscall number on
/// x86-64 and the first argument on other architectures) if the current syscall is interrupted
/// and may be restarted.
//
// The check is done after ptrace-stops, so that the tracer can see or change the return value.
fn syscall_to_restart(user_ctx: &UserContext, ctx: &Context) -> Option<(Errno, usize)> {
    const RESTART_ERRNOS: [Errno; 4] = [
        Errno::ERESTARTSYS,
        Errno::ERESTARTNOINTR,
        Errno::ERESTARTNOHAND,
        Errno::ERESTART_RESTARTBLOCK,
    ];

    let orig_syscall_ret = ctx.thread_local.orig_syscall_ret()?;
    let syscall_ret = user_ctx.syscall_ret();
    RESTART_ERRNOS
        .into_iter()
        .find(|errno| syscall_ret == -(*errno as i32) as usize)
        .map(|errno| (errno, orig_syscall_ret))
}

fn restart_syscall(user_ctx: &mut UserContext, ctx: &Context, orig_syscall_ret: usize) {
    #[cfg(target_arch = "x86_64")]
    const SYSCALL_INSTR_LEN: usize = 2; // syscall
    #[cfg(target_arch = "riscv64")]
    const SYSCALL_INSTR_LEN: usize = 4; // ecall
    #[cfg(target_arch = "loongarch64")]
    const SYSCALL_INSTR_LEN: usize = 4; // syscall
    #[cfg(target_arch = "aarch64")]
    const SYSCALL_INSTR_LEN: usize = 4; // svc

    user_ctx.set_syscall_ret(orig_syscall_ret);
    user_ctx.set_instruction_pointer(user_ctx.instruction_pointer() - SYSCALL_INSTR_LEN);

    // The restored first argument may look like a restart errno. Forget the syscall so that it
    // is not restarted again. On x86-64, the restored value is the syscall number, which cannot.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/riscv/kernel/signal.c#L512-L513>
    #[cfg(not(target_arch = "x86_64"))]
    ctx.thread_local.set_orig_syscall_ret(None);
    #[cfg(target_arch = "x86_64")]
    let _ = ctx;
}

/// Handles pending signals (and pending ptrace traps) for the current process.
///
/// Like Linux, ignored signals are skipped until a signal is taken, a stop is initiated, or no
/// signal is pending.
///
/// Returns whether a user signal handler is set up (or the thread is exiting), in which case the
/// interrupted syscall has been handled. Otherwise, the caller should call
/// [`restart_interrupted_syscall`] once no more signals are to be handled (e.g., after the
/// thread is continued from a stop).
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3002-L3050>
pub(crate) fn handle_pending_signal(user_ctx: &mut UserContext, ctx: &Context) -> bool {
    let mut restore_sig_mask = ctx
        .thread_local
        .sig_mask_saved()
        .take()
        .map(|mask| RestoreSigMaskGuard { ctx, mask });

    loop {
        // Ptrace traps are taken before dequeuing signals.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2969-L2981>
        while ctx.posix_thread.ptrace_do_jobctl_trap(ctx, user_ctx) {}

        // A thread participates in the group stop in progress before dequeuing more signals,
        // unless it has been killed. The caller makes the thread participate and calls this
        // function again.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2954-L2971>
        if ctx.process.is_stopped() && !ctx.posix_thread.is_traced() && !ctx.has_pending_sigkill() {
            return false;
        }

        let (dequeued, sig_action) = if let Some(dequeued_signal) = dequeue_pending_signal(ctx) {
            dequeued_signal
        } else {
            // Fast path: There is no signal mask to restore.
            if restore_sig_mask.is_none() {
                return false;
            }
            // Restore the signal mask first.
            let _ = restore_sig_mask.take();

            // Try again with the new signal mask.
            if let Some(dequeued_signal) = dequeue_pending_signal(ctx) {
                dequeued_signal
            } else {
                return false;
            }
        };

        let (signal, sig_action) = if dequeued.num() != SIGKILL {
            match ctx.posix_thread.ptrace_stop(dequeued, ctx, user_ctx) {
                PtraceStopResult::Continued(Some(dequeued)) => {
                    // Note that this `dequeued` object outputted by `ptrace_stop`
                    // might be different from the input `dequeued` object
                    // because of tracer manipulation.
                    // But we name both `dequeued` anyway.

                    let sig_num = dequeued.num();
                    if ctx.posix_thread.sig_mask().contains(sig_num) {
                        // Requeue the injected signal to the same signal queue as the
                        // dequeued stop signal (thread queue or process queue).
                        //
                        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/signal.c#L2770>
                        requeue_signal(ctx, dequeued);
                        continue;
                    }

                    (dequeued.unwrap(), get_sig_action(ctx, sig_num))
                }
                PtraceStopResult::Continued(None) => continue,
                PtraceStopResult::Interrupted => {
                    match dequeue_pending_signal(ctx) {
                        Some((dequeued, action)) if dequeued.num() == SIGKILL => {
                            (dequeued.unwrap(), action)
                        }
                        // SIGKILL was consumed by a sibling thread; this thread will be
                        // terminated as part of the process-wide exit.
                        _ => return true,
                    }
                }
                PtraceStopResult::NotTraced(dequeued) => (dequeued.unwrap().unwrap(), sig_action),
            }
        } else {
            (dequeued.unwrap(), sig_action)
        };

        let sig_num = signal.num();
        let SigAction {
            handler,
            flags,
            restorer_addr,
            mask,
        } = sig_action;
        match handler {
            SigHandler::Ign => {
                debug!("Ignore signal {:?}", sig_num);
            }
            SigHandler::User(handler_addr) => {
                if flags.contains(SigActionFlags::SA_RESETHAND) {
                    // In Linux, SA_RESETHAND corresponds to SA_ONESHOT,
                    // which means the user handler will be executed only once and then reset to the default.
                    // Only the handler is reset, so the flags and the mask are kept.
                    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3026-L3027>
                    let sig_dispositions = ctx.process.sig_dispositions().lock();
                    let mut sig_dispositions = sig_dispositions.lock();
                    sig_dispositions.reset_handler(sig_num);
                }

                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal.c#L263-L283>
                if let Some((errno, orig_syscall_ret)) = syscall_to_restart(user_ctx, ctx) {
                    let should_restart = match errno {
                        Errno::ERESTARTNOINTR => true,
                        Errno::ERESTARTSYS => flags.contains(SigActionFlags::SA_RESTART),
                        _ => false,
                    };
                    if should_restart {
                        restart_syscall(user_ctx, ctx, orig_syscall_ret);
                    } else {
                        user_ctx.set_syscall_ret(-(Errno::EINTR as i32) as usize);
                    }
                }

                let mask_to_restore = restore_sig_mask.as_ref().map(|guard| guard.mask);
                if let Err(e) = handle_user_signal(
                    ctx,
                    sig_num,
                    handler_addr,
                    flags,
                    restorer_addr,
                    mask,
                    mask_to_restore,
                    user_ctx,
                    signal.to_info(),
                ) {
                    debug!("Failed to set up the signal frame: {:?}", e);
                    // The signal mask to restore must be kept so that the frame of the forced
                    // `SIGSEGV` saves it.
                    if let Some(guard) = restore_sig_mask {
                        ctx.thread_local
                            .sig_mask_saved()
                            .set(Some(guard.into_mask()));
                    }
                    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3166-L3172>
                    force_sigsegv(ctx, sig_num);
                    // Deliver the forced `SIGSEGV` before returning to user space, as Linux does by
                    // looping in `exit_to_user_mode_loop`.
                    let _ = handle_pending_signal(user_ctx, ctx);
                } else if let Some(guard) = restore_sig_mask {
                    // The signal mask to restore is saved in the signal frame.
                    let _ = guard.into_mask();
                }
                return true;
            }
            SigHandler::Dfl if ctx.process.is_init_process() && !signal.is_forced() => {
                // From Linux man pages "kill(2)":
                // "The only signals that can be sent to process ID 1, the init process, are those for
                // which init has explicitly installed signal handlers."
                //
                // Forced signals are exceptions. Otherwise, init would fault again forever.
                // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/signal.c#L1314-L1319>
            }
            SigHandler::Dfl => {
                let sig_default_action = SigDefaultAction::from_signum(sig_num);
                debug!("sig_default_action = {:?}", sig_default_action);

                match sig_default_action {
                    SigDefaultAction::Core | SigDefaultAction::Term => {
                        warn!(
                            "PID {}: terminating on signal {}",
                            ctx.process.pid(),
                            sig_num.sig_name()
                        );
                        // The signal terminates the current process. Therefore, we should exit here.
                        do_exit_group(TermStatus::Killed(sig_num), ctx, user_ctx);
                        return true;
                    }
                    SigDefaultAction::Ign => {}
                    SigDefaultAction::Stop => {
                        // The caller participates in the stop and calls this function again.
                        ctx.process.stop(sig_num);
                        return false;
                    }
                    // The process has been continued when `SIGCONT` was generated.
                    SigDefaultAction::Cont => {}
                }
            }
        }
    }
}

/// A guard that restores the signal mask on drop.
struct RestoreSigMaskGuard<'a> {
    ctx: &'a Context<'a>,
    mask: SigMask,
}

impl RestoreSigMaskGuard<'_> {
    /// Forgets the guard and returns the signal mask to restore.
    fn into_mask(self) -> SigMask {
        let mask = self.mask;
        // Assert that it's a `Copy` type. So we won't leak resources.
        let _ = self.mask;

        core::mem::forget(self);

        mask
    }
}

impl Drop for RestoreSigMaskGuard<'_> {
    fn drop(&mut self) {
        self.ctx.set_sig_mask(self.mask);
    }
}

fn dequeue_pending_signal(ctx: &Context) -> Option<(DequeuedSignal, SigAction)> {
    let posix_thread = ctx.posix_thread;

    let sig_dispositions = ctx.process.sig_dispositions().lock();
    let sig_dispositions = sig_dispositions.lock();

    let sig_mask = posix_thread.sig_mask();
    let (signal, sig_num, sig_action) = loop {
        let signal = ctx.dequeue_signal(&sig_mask)?;
        let sig_num = signal.num();
        let sig_action = sig_dispositions.get(sig_num);
        if sig_action.will_ignore(sig_num) && !posix_thread.is_traced() {
            continue;
        }

        break (signal, sig_num, sig_action);
    };

    debug!(
        "sig_num = {:?}, sig_name = {}, sig_action = {:#x?}",
        sig_num,
        sig_num.sig_name(),
        sig_action
    );

    Some((signal, sig_action))
}

/// Re-queue the ptrace-captured signal.
///
/// This appends to the tail of the origin queue,
/// which (a) loses same-number RT-signal send-order FIFO and
/// (b) allows newer lower-numbered standard signals queued
/// during the ptrace stop to preempt this signal.
/// This is intentionally consistent with Linux's behaviors.
fn requeue_signal(ctx: &Context, signal: DequeuedSignal) {
    match signal {
        DequeuedSignal::FromProcess(signal) => ctx.process.enqueue_signal(signal),
        DequeuedSignal::FromThread(signal) => ctx.posix_thread.enqueue_signal(signal),
    }
}

/// Forces a signal on the current thread.
///
/// If the signal is blocked or ignored, it is unblocked and its handler is reset to `SIG_DFL`.
/// A forced signal with the default disposition also terminates the init process.
pub(crate) fn force_signal(ctx: &Context, signal: FaultSignal) {
    force_signal_with(ctx, signal, false);
}

/// Forces `SIGSEGV` on the current thread after failing to set up the frame of `failed_sig`.
///
/// If `failed_sig` is `SIGSEGV` itself, its handler is reset to `SIG_DFL` so that the forced
/// `SIGSEGV` terminates the process instead of failing again.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L1735-L1741>
fn force_sigsegv(ctx: &Context, failed_sig: SigNum) {
    let signal = FaultSignal::new(SIGSEGV, SI_KERNEL, None);
    force_signal_with(ctx, signal, failed_sig == SIGSEGV);
}

// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L1339-L1372>
fn force_signal_with(ctx: &Context, signal: FaultSignal, reset_handler: bool) {
    let sig_num = signal.num();

    let sig_dispositions = ctx.process.sig_dispositions().lock();
    let mut sig_dispositions = sig_dispositions.lock();

    let is_blocked = ctx.posix_thread.has_signal_blocked(sig_num);
    if is_blocked || reset_handler || sig_dispositions.get(sig_num).handler == SigHandler::Ign {
        sig_dispositions.reset_handler(sig_num);
    }
    if is_blocked {
        ctx.set_sig_mask(ctx.posix_thread.sig_mask() - sig_num);
    }

    ctx.posix_thread.enqueue_signal(Box::new(signal));
}

fn get_sig_action(ctx: &Context, sig_num: SigNum) -> SigAction {
    let sig_dispositions = ctx.process.sig_dispositions().lock();
    let sig_dispositions = sig_dispositions.lock();
    sig_dispositions.get(sig_num)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn handle_user_signal(
    ctx: &Context,
    sig_num: SigNum,
    handler_addr: Vaddr,
    flags: SigActionFlags,
    restorer_addr: Vaddr,
    mut mask: SigMask,
    mask_to_restore: Option<SigMask>,
    user_ctx: &mut UserContext,
    sig_info: siginfo_t,
) -> Result<()> {
    debug!("sig_num = {:?}, signame = {}", sig_num, sig_num.sig_name());
    debug!("handler_addr = 0x{:x}", handler_addr);
    debug!("flags = {:?}", flags);
    debug!("restorer_addr = 0x{:x}", restorer_addr);
    debug!("mask = {:?}, mask_to_restore = {:?}", mask, mask_to_restore);

    if !flags.contains(SigActionFlags::SA_NODEFER) {
        // Add the current signal to `mask`.
        mask += sig_num;
    }

    let old_mask = ctx.posix_thread.sig_mask();
    let mask_to_restore = mask_to_restore.unwrap_or(old_mask);

    // Set up the signal stack.
    let mut stack_pointer = if let Some(sp) =
        use_alternate_signal_stack(flags, ctx.thread_local, user_ctx.stack_pointer())
    {
        sp as u64
    } else {
        // Just use the user stack.
        let sp = user_ctx.stack_pointer() as u64;

        // Prevent corruption of the current stack. Architectures like as x86-64 have red zones
        // that can be accessed below the SP. Signal handlers must not write to these zones.
        // FIXME: This may not be necessary for all architectures.
        sp.wrapping_sub(128)
    };

    let user_space = ctx.user_space();

    // 1. Write `siginfo_t`.
    stack_pointer = alloc_aligned_in_user_stack(
        stack_pointer,
        size_of::<siginfo_t>(),
        align_of::<siginfo_t>(),
    );
    user_space.write_val(stack_pointer as _, &sig_info)?;
    let siginfo_addr = stack_pointer;

    // 2. Write `ucontext_t`.

    // Save the current signal stack information.
    let uc_stack = stack_t::from(&*ctx.thread_local.sig_stack().borrow());

    let mut ucontext = ucontext_t {
        uc_stack,
        uc_sigmask: mask_to_restore.into(),
        ..Default::default()
    };

    // Save general-purpose registers.
    ucontext.uc_mcontext.copy_user_regs_from(user_ctx);

    // Clone the FPU context.
    let supp = ctx.thread_local.supp_user_context();
    let fpu_context = supp.fpu().get();
    #[cfg(not(target_arch = "x86_64"))]
    let fpu_context_bytes = fpu_context.as_bytes();

    cfg_select! {
        target_arch = "x86_64" => {
            let fpu_image = crate::arch::signal::fpu_sigframe_image(&fpu_context);
            // Align the FPU context address to the 64-byte boundary so that the
            // user program can use the XSAVE/XRSTOR instructions at that address,
            // if necessary.
            let fpu_context_addr =
                alloc_aligned_in_user_stack(stack_pointer, fpu_image.len(), 64);
            let ucontext_addr = alloc_aligned_in_user_stack(
                fpu_context_addr,
                size_of::<ucontext_t>(),
                align_of::<ucontext_t>(),
            );
            ucontext
                .uc_mcontext
                .set_fpu_context_addr(fpu_context_addr as _);

            const UC_FP_XSTATE: u64 = 1 << 0;
            ucontext.uc_flags = UC_FP_XSTATE;
        }
        target_arch = "riscv64" => {
            // Reference:
            // <https://elixir.bootlin.com/linux/v6.17.5/source/arch/riscv/include/uapi/asm/ptrace.h#L94-L98>,
            // <https://elixir.bootlin.com/linux/v6.17.5/source/arch/riscv/include/uapi/asm/ptrace.h#L69-L77>.
            const FP_STATE_SIZE: usize =
                size_of::<ostd::arch::cpu::context::QFpuContext>() + 3 * size_of::<u32>();

            let ucontext_addr = alloc_aligned_in_user_stack(
                stack_pointer,
                size_of::<ucontext_t>() + FP_STATE_SIZE,
                align_of::<ucontext_t>(),
            );
            let fpu_context_addr = (ucontext_addr as usize) + size_of::<ucontext_t>();
        }
        target_arch = "aarch64" => {
            // The FP/SIMD state is a record in the reserved area of `uc_mcontext`.
            ucontext.uc_mcontext.set_fpsimd_record(fpu_context_bytes);
            let ucontext_addr = alloc_aligned_in_user_stack(
                stack_pointer,
                size_of::<ucontext_t>(),
                align_of::<ucontext_t>(),
            );
        }
        target_arch = "loongarch64" => {
            // FIXME: Allocate the FPU context.
            // Example: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/loongarch/kernel/signal.c#L848>
            let ucontext_addr = alloc_aligned_in_user_stack(
                stack_pointer,
                size_of::<ucontext_t>() + fpu_context_bytes.len(),
                align_of::<ucontext_t>(),
            );
            // FIXME: Set the FPU flags
            // Example: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/loongarch/kernel/signal.c#L805>
            let fpu_context_addr = (ucontext_addr as usize) + size_of::<ucontext_t>();
        }
        _ => {
            compile_error!("unsupported target");
        }
    }

    #[cfg(target_arch = "x86_64")]
    user_space.write_bytes(fpu_context_addr as _, &fpu_image[..])?;
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    user_space.write_bytes(fpu_context_addr as _, fpu_context_bytes)?;
    user_space.write_val(ucontext_addr as _, &ucontext)?;

    // Align the SP to the 16-byte boundary. This is required by the x86-64 ABI before calling any
    // function.
    stack_pointer = ucontext_addr.align_down(16);

    // 3. Write the address of the restorer code.
    let retaddr = if flags.contains(SigActionFlags::SA_RESTORER) {
        restorer_addr
    } else {
        cfg_select! {
            any(target_arch = "riscv64", target_arch = "aarch64") => {
                ctx.user_space().vmar().process_vm().vdso_base()
                    + crate::vdso::__VDSO_RT_SIGRETURN_OFFSET
            }
            _ => {
                // Note that this should already be rejected at the `rt_sigaction` system call.
                return_errno_with_message!(
                    Errno::EINVAL,
                    "this architecture currently requires SA_RESTORER"
                )
            }
        }
    };
    cfg_select! {
        target_arch = "x86_64" => {
            stack_pointer = write_u64_to_user_stack(stack_pointer, retaddr as u64)?;
        }
        any(target_arch = "riscv64", target_arch = "loongarch64") => {
            user_ctx.set_ra(retaddr);
        }
        target_arch = "aarch64" => {
            user_ctx.set_x30(retaddr);
        }
        _ => {
            compile_error!("unsupported target");
        }
    }

    debug!(
        "Before calling to signal handler: stack_pointer = 0x{:x}",
        stack_pointer
    );

    // The signal frame is set up. Commit the state changes, which must not happen if the setup
    // fails.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3146-L3164>

    // Block signals in `mask` while running the signal handler.
    ctx.set_sig_mask(old_mask + mask);
    {
        let mut sig_stack = ctx.thread_local.sig_stack().borrow_mut();
        if sig_stack.flags().contains(SigStackFlags::SS_AUTODISARM) {
            sig_stack.reset();
        }
    }
    // Reset the FPU context.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal.c#L293-L312>
    supp.fpu().set(FpuContext::new());

    // 4. Set correct register values.
    user_ctx.set_instruction_pointer(handler_addr as _);
    user_ctx.set_stack_pointer(stack_pointer as usize);
    // Set parameters of the signal handler.
    if flags.contains(SigActionFlags::SA_SIGINFO) {
        user_ctx.set_arguments(sig_num, siginfo_addr as usize, ucontext_addr as usize);
    } else {
        user_ctx.set_arguments(sig_num, 0, 0);
    }
    // Perform CPU architecture-dependent logic.
    cfg_select! {
        target_arch = "x86_64" => {
            // Clear the DF flag to conform to x86-64 calling conventions. Also clear the TF and
            // RF flags so that the handler does not start with single-stepping enabled.
            //
            // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/arch/x86/kernel/signal.c#L306>
            const X86_RFLAGS_TF: usize = 1 << 8;
            const X86_RFLAGS_DF: usize = 1 << 10;
            const X86_RFLAGS_RF: usize = 1 << 16;
            user_ctx.set_rflags(
                user_ctx.rflags() & !(X86_RFLAGS_TF | X86_RFLAGS_DF | X86_RFLAGS_RF),
            );
        }
        _ => {},
    }

    Ok(())
}

/// Uses the alternate signal stack configured via `sigaltstack`.
///
/// If the current stack pointer `sp` is already within the alternate signal stack
/// or if the stack is disabled, this function returns `None`.
/// Otherwise, it returns the starting stack pointer of the alternate signal stack.
fn use_alternate_signal_stack(
    flags: SigActionFlags,
    thread_local: &ThreadLocal,
    sp: usize,
) -> Option<usize> {
    if !flags.contains(SigActionFlags::SA_ONSTACK) {
        return None;
    }

    let sig_stack = thread_local.sig_stack().borrow();

    if sig_stack.active_status(sp) != SigStackStatus::Inactive {
        return None;
    }

    // Overflow checks are done in the `sigaltstack` system call.
    Some(sig_stack.base() + sig_stack.size())
}

/// Writes a `u64` integer to the user's stack.
#[cfg(target_arch = "x86_64")]
fn write_u64_to_user_stack(sp: u64, value: u64) -> Result<u64> {
    use crate::context::current_userspace;

    let sp = sp.wrapping_sub(size_of::<u64>() as u64);
    current_userspace!().write_val(sp as _, &value)?;
    Ok(sp)
}

/// Allocates `size` bytes on the user's stack.
///
/// The allocation will be aligned to `align`, which must be a power of two.
fn alloc_aligned_in_user_stack(sp: u64, size: usize, align: usize) -> u64 {
    sp.wrapping_sub(size as u64).align_down(align as u64)
}

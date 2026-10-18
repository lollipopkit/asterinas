// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::UserContext,
    irq::DisabledLocalIrqGuard,
    mm::VmIo,
    sync::Waiter,
    task::{Task, TaskOptions},
    user::{ReturnReason, UserContextApi, UserMode, UserModeHooks},
};

use super::{Thread, oops};
use crate::{
    context::current_userspace,
    cpu::LinuxAbi,
    prelude::*,
    process::{
        posix_thread::{AsPosixThread, FIRST_POSIX_TID, ThreadLocal, ptrace::PtraceStopResult},
        signal::{
            HandlePendingSignal, PauseReason, handle_pending_signal, restart_interrupted_syscall,
        },
    },
    syscall::handle_syscall,
    thread::{AsThread, exception::handle_exception},
    vm::vmar::is_userspace_vaddr,
};

/// create new task with userspace and parent process
pub(crate) fn create_new_user_task(
    user_ctx: Box<UserContext>,
    thread_ref: Arc<Thread>,
    thread_local: ThreadLocal,
) -> Task {
    let user_task_entry = move |user_ctx: UserContext| {
        let current_task = Task::current().unwrap();
        let current_thread = current_task.as_thread().unwrap();
        let current_posix_thread = current_thread.as_posix_thread().unwrap();
        let current_thread_local = current_task.as_thread_local().unwrap();
        let current_process = current_posix_thread.process();
        let (stop_waiter, _) = Waiter::new_pair();

        let mut user_mode = UserMode::new(user_ctx);
        debug!(
            "task entry: rip = {:#x}, rsp = {:#x}, rax = {:#x}",
            user_mode.context().instruction_pointer(),
            user_mode.context().stack_pointer(),
            user_mode.context().syscall_ret(),
        );

        // The `clone` syscall may require the child process to write its thread TID to the
        // specified address. Make sure that the store operation completes before we return control
        // to user space in the child process.
        let child_tid_ptr = current_thread_local.set_child_tid().get();
        if is_userspace_vaddr(child_tid_ptr) {
            // At this point, we can do almost nothing if the address is not valid and the store
            // operation fails. So we ignore the error here.
            let _ = current_userspace!().write_val(child_tid_ptr, &current_posix_thread.tid());
        }

        let ctx = Context {
            process: current_process,
            thread_local: current_thread_local,
            posix_thread: current_posix_thread,
            thread: current_thread.as_ref(),
            task: &current_task,
        };

        // The startup method is only executed when the first user thread starts up.
        if ctx.posix_thread.tid() == FIRST_POSIX_TID {
            crate::init::on_first_process_startup(&ctx);
        }

        // A traced thread does not stop for a group-stop. Instead, it traps into the group-stop
        // (in `handle_pending_signal`) and runs again once the tracer resumes it.
        let is_group_stopped = || ctx.process.is_stopped() && !ctx.posix_thread.is_traced();

        let handle_signals = |user_ctx: &mut UserContext| {
            let mut is_handled = false;

            loop {
                // As in Linux, a thread participates in the group stop before handling signals.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2698-L2732>
                if !ctx.posix_thread.ptrace_has_pending_trap() && is_group_stopped() {
                    if let Some(sig_num) = ctx.process.participate_group_stop(ctx.posix_thread) {
                        ctx.process.notify_parent_of_group_stop(sig_num);
                    }
                    let _ = stop_waiter.pause_until_by(
                        || (!is_group_stopped()).then_some(()),
                        PauseReason::StopBySignal,
                    );
                    // As `TASK_STOPPED` in Linux, a stopped thread handles no signals other than
                    // `SIGKILL` until it is continued. A fatal signal that a thread can take kills
                    // the whole group with `SIGKILL` when it is generated (see
                    // `Process::complete_signal`), and other signals stay pending.
                    if is_group_stopped() && !ctx.has_pending_sigkill() {
                        continue;
                    }
                }

                // The trap is taken in `handle_pending_signal`.
                let has_handler = handle_pending_signal(user_ctx, &ctx);
                is_handled |= has_handler;

                if current_thread.is_exited() {
                    break;
                }
                // As Linux, signal frames are set up until no signal with a handler is pending.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/entry/common.c#L49-L66>
                if has_handler {
                    continue;
                }
                if !ctx.posix_thread.ptrace_has_pending_trap() && !is_group_stopped() {
                    break;
                }
            }

            // The restart decision is deferred until the thread is continued, so that a user
            // signal handler that runs after a stop can still interrupt the syscall, as in Linux.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/x86/kernel/signal.c#L333-L359>
            if !is_handled {
                restart_interrupted_syscall(user_ctx, &ctx);
            }
        };

        // Handle the signals that are pending before the thread enters the user space for the
        // first time (e.g., the `SIGSTOP` of an auto-attached tracee), as Linux does when
        // returning from `fork`.
        handle_signals(user_mode.context_mut());

        while !current_thread.is_exited() {
            // Execute the user code
            let return_reason = user_mode.execute(&ctx);

            // Handle user events
            let user_ctx = user_mode.context_mut();
            match return_reason {
                ReturnReason::UserException => {
                    let exception = user_ctx.take_exception().unwrap();
                    ctx.thread_local.set_orig_syscall_ret(None);
                    handle_exception(&ctx, user_ctx, exception)
                }
                ReturnReason::UserSyscall => {
                    ctx.thread_local
                        .set_orig_syscall_ret(Some(user_ctx.syscall_ret()));

                    let res = ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    if !matches!(res, PtraceStopResult::Interrupted) {
                        handle_syscall(&ctx, user_ctx);

                        ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    }
                }
                ReturnReason::KernelEvent => {
                    ctx.thread_local.set_orig_syscall_ret(None);
                }
            };

            // Exit if the thread terminates
            if current_thread.is_exited() {
                break;
            }

            // Handle signals
            handle_signals(user_ctx);
        }
    };

    let user_task_func = move || user_task_entry(*user_ctx);

    TaskOptions::new(move || {
        // TODO: If a kernel "oops" is caught, we should kill the entire
        // process rather than just ending the thread.
        let _ = oops::catch_panics_as_oops(user_task_func);
    })
    .data(thread_ref)
    .local_data(thread_local)
    .build()
    .expect("spawn task failed")
}

impl UserModeHooks for Context<'_> {
    fn has_kernel_event(&self) -> bool {
        self.has_pending()
    }

    fn pre_user_run(&self, guard: &DisabledLocalIrqGuard) {
        self.thread_local
            .supp_user_context()
            .before_user_exec(guard);
    }
}

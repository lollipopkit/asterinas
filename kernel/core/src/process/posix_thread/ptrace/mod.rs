// SPDX-License-Identifier: MPL-2.0

//! Ptrace implementation for POSIX threads.

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
use ostd::arch::cpu::context::{FsBase, GsBase};
use ostd::{arch::cpu::context::UserContext, sync::Waiter};

use super::{AsPosixThread, PosixThread};
#[cfg(target_arch = "x86_64")]
use crate::arch::ptrace as arch_ptrace;
use crate::{
    prelude::*,
    process::{
        CloneArgs, CloneFlags, Process, Uid, WaitOptions,
        exit::send_child_death_signal,
        sigchld::{self, ChildSource},
        signal::{
            DequeuedSignal, HandlePendingSignal, PauseReason,
            c_types::siginfo_t,
            constants::{CLD_STOPPED, CLD_TRAPPED, SIGCHLD, SIGKILL, SIGSTOP, SIGTRAP},
            sig_num::SigNum,
            signals::{
                kernel::KernelSignal,
                raw::RawSignal,
                user::{UserSignal, UserSignalKind},
            },
        },
    },
    thread::{Thread, Tid},
};

mod util;

pub(in crate::process) use util::PtraceEvent;
use util::{JobCtl, StopDeliverySignal, parse_resume_signal};
pub(crate) use util::{
    PtraceAttachMode, PtraceContRequest, PtraceOptions, PtraceStopResult, PtraceWaitStatus,
};

impl PosixThread {
    /// Returns whether this thread is being traced.
    pub(crate) fn is_traced(&self) -> bool {
        self.tracer().is_some()
    }

    /// Returns the tracer of this thread if it is being traced.
    pub(crate) fn tracer(&self) -> Option<Arc<Thread>> {
        self.tracee_status.get().and_then(|status| status.tracer())
    }

    /// Sets the tracer of this thread with the given ptrace options.
    ///
    /// # Errors
    ///
    /// Returns `EPERM` if this thread is already being traced.
    fn set_tracer(
        &self,
        tracer: Weak<Thread>,
        options: PtraceOptions,
        is_seized: bool,
    ) -> Result<()> {
        let status = self.tracee_status.call_once(TraceeStatus::new);
        status.set_tracer(tracer, options, is_seized)
    }

    /// Detaches the tracer of this thread.
    ///
    /// Returns whether the exit notification to the real parent has been deferred
    /// until the detach. If so, the caller should notify the real parent.
    pub(in crate::process) fn detach_tracer(&self) -> bool {
        self.detach_tracer_with(|_| {})
    }

    /// Detaches the tracer of this thread with a callback.
    ///
    /// Returns the same value as [`Self::detach_tracer`].
    fn detach_tracer_with<F>(&self, detach_callback: F) -> bool
    where
        F: FnOnce(&TraceeState),
    {
        let Some(status) = self.tracee_status.get() else {
            return false;
        };
        let is_exit_notify_deferred = status.detach_tracer_with(detach_callback);
        self.wake_signalled_waker();
        is_exit_notify_deferred
    }

    /// Notifies the tracer of the exit of this thread's process
    /// if the tracer is not in the `real_parent` process.
    ///
    /// Returns whether the exit notification to the real parent is deferred.
    /// If so, the real parent will be notified when the tracer reaps or detaches the tracee.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L763-L766>
    pub(in crate::process) fn ptrace_defer_exit_notify(&self, real_parent: &Arc<Process>) -> bool {
        let Some(tracer) = self
            .tracee_status
            .get()
            .and_then(|status| status.defer_exit_notify(real_parent))
        else {
            return false;
        };

        let process = self.process();
        sigchld::notify_parent_of_death(
            ChildSource::Process(&process),
            process.status().exit_code(),
            &tracer.as_posix_thread().unwrap().process(),
            Some(SIGCHLD),
            true,
        );

        true
    }

    /// Stops this thread by ptrace with the given signal if it is currently traced.
    ///
    /// Returns a [`PtraceStopResult`] indicating why this ptrace-stop ended.
    pub(in crate::process) fn ptrace_stop(
        &self,
        signal: DequeuedSignal,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> PtraceStopResult {
        if let Some(status) = self.tracee_status.get() {
            status.ptrace_stop(signal, ctx, user_ctx)
        } else {
            PtraceStopResult::NotTraced(Some(signal))
        }
    }

    /// Stops this thread by ptrace on the `event` if it is currently traced,
    /// and the corresponding option is enabled.
    ///
    /// May block in the event-stop until the tracer continues the stop,
    /// or until a `SIGKILL` interrupts it.
    pub(in crate::process) fn ptrace_may_stop_on(
        &self,
        event: PtraceEvent,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) {
        if let Some(status) = self.tracee_status.get() {
            status.ptrace_may_stop_on(event, ctx, user_ctx)
        }
    }

    /// Stops this thread at a syscall-stop if requested by the tracer.
    ///
    /// Returns a [`PtraceStopResult`] indicating why this ptrace-stop ended.
    pub(crate) fn ptrace_may_stop_on_syscall(
        &self,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> PtraceStopResult {
        if let Some(status) = self.tracee_status.get() {
            status.ptrace_may_stop_on_syscall(ctx, user_ctx)
        } else {
            PtraceStopResult::NotTraced(None)
        }
    }

    /// Attaches the new child thread to the tracer of this thread if required by `clone_args`.
    ///
    /// Returns the clone-family ptrace event that this thread should report
    /// (via [`Self::ptrace_may_stop_on`]) after the child starts running.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/fork.c#L2735-L2750>,
    /// <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/ptrace.h#L201-L220>
    pub(in crate::process) fn ptrace_init_child(
        &self,
        clone_args: &CloneArgs,
        child_thread: &Arc<Thread>,
    ) -> Option<PtraceEvent> {
        let child = child_thread.as_posix_thread().unwrap();
        let (tracer_thread, options, is_seized, event) = self
            .tracee_status
            .get()?
            .clone_trace(clone_args, child.tid())?;

        let tracer = tracer_thread.as_posix_thread().unwrap();
        // The child is newly created, so it cannot have been traced.
        let is_attached = tracer
            .link_tracee(&tracer_thread, child_thread.clone(), options, is_seized)
            .unwrap();
        if !is_attached {
            return event;
        }

        let child_status = child.tracee_status.get().unwrap();
        if is_seized {
            child_status.set_trap_stop_for_new_child(&child.process());
        } else {
            // Linux adds `SIGSTOP` to the private pending set without a `siginfo`,
            // which is then reported as a `SI_USER` signal from PID 0 and UID 0.
            child.enqueue_signal(Box::new(UserSignal::new(
                SIGSTOP,
                UserSignalKind::Kill,
                0,
                Uid::new_root(),
            )));
        }

        event
    }

    /// Returns the ptrace-stop status changes for the `wait` syscall.
    pub(in crate::process) fn wait_ptrace_stopped(
        &self,
        options: WaitOptions,
    ) -> Option<PtraceWaitStatus> {
        self.tracee_status
            .get()
            .and_then(|status| status.wait(options))
    }

    /// Continues this thread from a ptrace-stop with the signal in `data`.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped,
    /// or `EIO` if `data` is not a valid signal number.
    pub(crate) fn ptrace_continue(
        &self,
        request: PtraceContRequest,
        data: usize,
        ctx: &Context,
    ) -> Result<()> {
        let status = self.get_tracee_status()?;

        status.resume(request, data, ctx)?;
        self.wake_signalled_waker();

        Ok(())
    }

    /// Makes this seized thread trap with `PTRACE_EVENT_STOP` (`PTRACE_INTERRUPT`).
    ///
    /// # Errors
    ///
    /// Returns `EIO` if this thread is not seized.
    pub(crate) fn ptrace_interrupt(&self) -> Result<()> {
        let status = self.get_tracee_status()?;

        status.interrupt(self)?;
        self.wake_signalled_waker();

        Ok(())
    }

    /// Makes this seized thread listen for events in a `PTRACE_EVENT_STOP` (`PTRACE_LISTEN`).
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped,
    /// or `EIO` if this thread is not seized or not in a `PTRACE_EVENT_STOP`.
    pub(crate) fn ptrace_listen(&self) -> Result<()> {
        let status = self.get_tracee_status()?;

        status.listen()?;
        self.wake_signalled_waker();

        Ok(())
    }

    /// Returns whether this thread has a pending ptrace trap.
    ///
    /// A pending trap interrupts blocking syscalls like a pending signal.
    pub(crate) fn ptrace_has_pending_trap(&self) -> bool {
        self.tracee_status
            .get()
            .is_some_and(|status| status.has_pending_trap())
    }

    /// Takes the pending ptrace trap of this thread, if any.
    ///
    /// Returns whether a trap is taken and ended by the tracer.
    pub(in crate::process) fn ptrace_do_jobctl_trap(
        &self,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> bool {
        self.tracee_status
            .get()
            .is_some_and(|status| status.do_jobctl_trap(ctx, user_ctx))
    }

    /// Notifies this thread, if traced, that a group-stop with `sig_num` is initiated.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2680-L2693>
    pub(in crate::process) fn ptrace_notify_group_stop(&self, sig_num: SigNum) {
        let Some(status) = self.tracee_status.get() else {
            return;
        };
        if status.notify_group_stop(self, sig_num) {
            self.wake_signalled_waker();
        }
    }

    /// Notifies this thread, if traced, that `SIGCONT` is generated for its process.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L922-L931>
    pub(in crate::process) fn ptrace_notify_group_continue(&self) {
        let Some(status) = self.tracee_status.get() else {
            return;
        };
        if status.notify_group_continue(self) {
            self.wake_signalled_waker();
        }
    }

    /// Gets the general-purpose registers of this thread for ptrace.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn ptrace_get_regs(&self) -> Result<arch_ptrace::CUserRegsStruct> {
        let status = self.get_tracee_status()?;
        status.get_regs()
    }

    /// Sets the general-purpose registers of this thread for ptrace.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn ptrace_set_regs(&self, regs: arch_ptrace::CUserRegsStruct) -> Result<()> {
        let status = self.get_tracee_status()?;
        status.set_regs(regs)
    }

    /// Reads one word in the tracee's USER area.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn ptrace_peek_user(&self, offset: usize) -> Result<usize> {
        let status = self.get_tracee_status()?;
        status.peek_user(offset)
    }

    /// Writes one word in the tracee's USER area.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn ptrace_poke_user(&self, offset: usize, value: usize) -> Result<()> {
        let status = self.get_tracee_status()?;
        status.poke_user(offset, value)
    }

    /// Reads one word from the tracee's memory.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    pub(crate) fn ptrace_peek_data(&self, addr: usize) -> Result<usize> {
        let status = self.get_tracee_status()?;
        status.peek_data(self.weak_process(), addr)
    }

    /// Writes one word to the tracee's memory.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    pub(crate) fn ptrace_poke_data(&self, addr: usize, value: usize) -> Result<()> {
        let status = self.get_tracee_status()?;
        status.poke_data(self.weak_process(), addr, value)
    }

    /// Sets ptrace options for this thread.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    pub(crate) fn ptrace_set_options(&self, options: PtraceOptions) -> Result<()> {
        let status = self.get_tracee_status()?;
        status.set_options(options)
    }

    /// Gets the event of the last ptrace-stop,
    /// if it is a ptrace-event-stop.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    pub(crate) fn ptrace_get_event(&self) -> Result<Option<PtraceEvent>> {
        let status = self.get_tracee_status()?;
        status.get_event()
    }

    /// Gets the signal info of this thread for ptrace.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread is not ptrace-stopped.
    ///
    /// Returns `EINVAL` if the ptrace-stop has no signal info
    /// (i.e., it is a group-stop of a tracee that is not seized).
    pub(crate) fn ptrace_get_siginfo(&self) -> Result<siginfo_t> {
        let status = self.get_tracee_status()?;
        status.get_siginfo()
    }

    /// Returns the tracee status of this thread if it has ever been traced.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if this thread has never been traced.
    fn get_tracee_status(&self) -> Result<&TraceeStatus> {
        self.tracee_status
            .get()
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "the thread has never been traced"))
    }
}

impl PosixThread {
    /// Attaches this tracer to the given tracee.
    ///
    /// With [`PtraceAttachMode::Attach`], a `SIGSTOP` is sent to the tracee. Unless with
    /// [`PtraceAttachMode::TraceMe`], a tracee in a group-stop re-traps into the group-stop
    /// so that the tracer can observe it, and this method waits for the transition.
    ///
    /// # Errors
    ///
    /// Returns `EPERM` if the tracee is already being traced or has exited.
    ///
    /// # Panics
    ///
    /// Panics if `tracer_thread` and `self` do not point to the same thread,
    /// or if `tracee_thread` is not a POSIX thread.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L403-L504>
    pub(crate) fn attach_to(
        &self,
        tracer_thread: &Arc<Thread>,
        tracee_thread: Arc<Thread>,
        mode: PtraceAttachMode,
    ) -> Result<()> {
        let (options, is_seized) = match mode {
            PtraceAttachMode::TraceMe | PtraceAttachMode::Attach => (PtraceOptions::empty(), false),
            PtraceAttachMode::Seize(options) => (options, true),
        };
        if !self.link_tracee(tracer_thread, tracee_thread.clone(), options, is_seized)? {
            return Ok(());
        }

        let tracee = tracee_thread.as_posix_thread().unwrap();
        if matches!(mode, PtraceAttachMode::TraceMe) {
            return Ok(());
        }
        if matches!(mode, PtraceAttachMode::Attach) {
            tracee.enqueue_signal(Box::new(KernelSignal::new(SIGSTOP)));
        }

        let tracee_status = tracee.tracee_status.get().unwrap();
        if !tracee_status.set_trap_stop_if_group_stopped(&tracee.process()) {
            return Ok(());
        }
        tracee.wake_signalled_waker();

        // Wait for the tracee to enter the trap, so the tracer can wait for it immediately.
        // Like Linux, an interruption is not reported, and the trap still happens later.
        let _ = self.process().children_wait_queue().pause_until(|| {
            (!tracee_status.is_trapping() || tracee_thread.is_exited()).then_some(())
        });

        Ok(())
    }

    /// Links the given tracee to this tracer with the given ptrace options.
    ///
    /// Returns whether the tracee is linked. The tracee is not linked
    /// if this tracer has already exited.
    ///
    /// # Errors
    ///
    /// Returns `EPERM` if the tracee is already being traced or has exited.
    ///
    /// # Panics
    ///
    /// Panics if `tracer_thread` and `self` do not point to the same thread,
    /// or if `tracee_thread` is not a POSIX thread.
    fn link_tracee(
        &self,
        tracer_thread: &Arc<Thread>,
        tracee_thread: Arc<Thread>,
        options: PtraceOptions,
        is_seized: bool,
    ) -> Result<bool> {
        debug_assert!(core::ptr::eq(
            tracer_thread.as_posix_thread().unwrap(),
            self
        ));

        let tracees = self.tracees.call_once(|| Mutex::new(BTreeMap::new()));

        // Lock order: tracer.tracees -> tracee.tracee_status
        let mut tracees = tracees.lock();
        if tracer_thread.is_exited() {
            // Pretend that the tracer immediately detaches the tracee,
            // if the tracer has already exited.
            // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/ptrace.c#L496-L498>
            return Ok(false);
        }
        if tracee_thread.is_exited() {
            return_errno_with_message!(Errno::EPERM, "the thread has exited");
        }

        let tracee = tracee_thread.as_posix_thread().unwrap();
        tracee.set_tracer(Arc::downgrade(tracer_thread), options, is_seized)?;
        tracees.insert(tracee.tid(), tracee_thread);

        Ok(true)
    }

    /// Detaches the tracee with `tid` from this tracer and resumes it with the signal in `data`.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if there is no such tracee or it is not ptrace-stopped,
    /// or `EIO` if `data` is not a valid signal number.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L589-L614>
    pub(crate) fn ptrace_detach(&self, tid: Tid, data: usize, ctx: &Context) -> Result<()> {
        let tracees = self
            .tracees()
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "no such tracee"))?;

        // Lock order: tracer.tracees -> tracee.tracee_status
        let mut tracees = tracees.lock();
        let tracee_thread = tracees
            .get(&tid)
            .cloned()
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "no such tracee"))?;
        let tracee = tracee_thread.as_posix_thread().unwrap();

        // The tracee is ptrace-stopped, so it is not a zombie and has no deferred exit
        // notification.
        let is_exit_notify_deferred = tracee
            .tracee_status
            .get()
            .unwrap()
            .detach_stopped(data, ctx)?;
        debug_assert!(!is_exit_notify_deferred);
        tracees.remove(&tid);
        drop(tracees);

        tracee.wake_signalled_waker();

        Ok(())
    }

    /// Silently unlinks this exited thread from its tracer and wakes up the tracer.
    ///
    /// This is used when the thread is released without its exit being reported,
    /// so that the tracer does not keep waiting for it.
    pub(in crate::process) fn ptrace_release_exited(&self) {
        let Some(tracer_thread) = self.tracer() else {
            return;
        };
        let tracer = tracer_thread.as_posix_thread().unwrap();

        // Lock order: tracer.tracees -> tracee.tracee_status
        let mut tracees = tracer.tracees().unwrap().lock();
        if tracees
            .get(&self.tid())
            .is_some_and(|tracee| core::ptr::eq(tracee.as_posix_thread().unwrap(), self))
        {
            tracees.remove(&self.tid());
        }
        // The exit notification is deferred only by `send_child_death_signal` when the whole
        // process becomes a zombie, which is final. A thread released while its process is
        // still alive (e.g., in `execve`) therefore never has a deferred notification.
        let is_exit_notify_deferred = self.detach_tracer();
        assert!(!is_exit_notify_deferred);
        drop(tracees);

        tracer.process().children_wait_queue().wake_all();
    }

    /// Returns the tracee map of this thread if it is a tracer.
    pub(in crate::process) fn tracees(&self) -> Option<&Mutex<BTreeMap<Tid, Arc<Thread>>>> {
        self.tracees.get()
    }

    /// Returns the tracee with the given tid, if it is being traced by this thread.
    ///
    /// # Errors
    ///
    /// Returns `ESRCH` if there is no tracee with the given tid.
    pub(crate) fn get_tracee(&self, tid: Tid) -> Result<Arc<Thread>> {
        self.tracees()
            .and_then(|tracees| tracees.lock().get(&tid).cloned())
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "no such tracee"))
    }

    /// Clears all tracees of this tracer on exit.
    pub(in crate::process) fn clear_tracees(&self) {
        let Some(tracees) = self.tracees() else {
            return;
        };

        let mut tracees_to_kill = Vec::new();
        let mut tracees_to_notify = Vec::new();

        // Lock order: tracer.tracees -> tracee.tracee_status
        let tracees = tracees.lock();
        for tracee_thread in tracees.values() {
            let tracee = tracee_thread.as_posix_thread().unwrap();
            let mut needs_kill = false;
            let is_exit_notify_deferred = tracee.detach_tracer_with(|state| {
                if state.options.contains(PtraceOptions::PTRACE_O_EXITKILL) {
                    needs_kill = true;
                }
            });
            if needs_kill {
                tracees_to_kill.push(tracee_thread.clone());
            }
            if is_exit_notify_deferred {
                tracees_to_notify.push(tracee.process());
            }
        }

        drop(tracees);

        for tracee in tracees_to_kill {
            let tracee = tracee.as_posix_thread().unwrap();
            tracee.enqueue_signal(Box::new(KernelSignal::new(SIGKILL)));
        }

        // Cascade the exit notifications of zombie tracees to their real parents.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L563-L587>
        for tracee_process in tracees_to_notify {
            send_child_death_signal(&tracee_process);
        }
    }
}

pub(super) struct TraceeStatus {
    is_stopped: AtomicBool,
    /// Whether [`TraceeState::jobctl`] contains any of [`JobCtl::PENDING_MASK`].
    has_pending_trap: AtomicBool,
    state: Mutex<TraceeState>,
}

impl TraceeStatus {
    pub(super) fn new() -> Self {
        Self {
            is_stopped: AtomicBool::new(false),
            has_pending_trap: AtomicBool::new(false),
            state: Mutex::new(TraceeState::new()),
        }
    }

    fn tracer(&self) -> Option<Arc<Thread>> {
        self.state.lock().tracer()
    }

    fn set_tracer(
        &self,
        tracer: Weak<Thread>,
        options: PtraceOptions,
        is_seized: bool,
    ) -> Result<()> {
        let mut state = self.state.lock();
        if state.tracer().is_some() {
            return_errno_with_message!(Errno::EPERM, "the thread is already being traced");
        }
        state.tracer = tracer;
        state.options = options;
        state.is_seized = is_seized;
        self.set_jobctl(&mut state, JobCtl::empty());

        Ok(())
    }

    fn detach_tracer_with<F>(&self, detach_callback: F) -> bool
    where
        F: FnOnce(&TraceeState),
    {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();
        self.do_detach_tracer(&mut state, detach_callback)
    }

    /// Detaches the tracer and resumes the tracee, as `__ptrace_unlink` does.
    ///
    /// Pending traps are cleared. If a group-stop is in effect, the tracee will
    /// participate in it after resuming.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L135-L179>
    fn do_detach_tracer<F>(
        &self,
        state: &mut MutexGuard<'_, TraceeState>,
        detach_callback: F,
    ) -> bool
    where
        F: FnOnce(&TraceeState),
    {
        state.tracer = Weak::new();
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(user_context) = state.user_context.as_mut() {
                arch_ptrace::disable_single_step(user_context);
            }
        }
        state.is_tracing_syscall = false;
        detach_callback(state);
        state.is_seized = false;
        self.set_jobctl(state, JobCtl::empty());
        self.is_stopped.store(false, Ordering::Relaxed);

        core::mem::take(&mut state.is_exit_notify_deferred)
    }

    /// Detaches the tracer from this ptrace-stopped tracee with the signal in `data`.
    fn detach_stopped(&self, data: usize, ctx: &Context) -> Result<bool> {
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        Self::set_resume_signal(&mut state, data, ctx)?;

        Ok(self.do_detach_tracer(&mut state, |_| {}))
    }

    /// Updates the job control states and whether a trap is pending.
    fn set_jobctl(&self, state: &mut TraceeState, jobctl: JobCtl) {
        state.jobctl = jobctl;
        self.has_pending_trap
            .store(jobctl.intersects(JobCtl::PENDING_MASK), Ordering::Release);
    }

    fn has_pending_trap(&self) -> bool {
        self.has_pending_trap.load(Ordering::Acquire)
    }

    fn is_trapping(&self) -> bool {
        self.state.lock().jobctl.contains(JobCtl::TRAPPING)
    }

    /// Ends the current `PTRACE_LISTEN`, if any, so that the tracee re-traps.
    fn end_listening(&self, state: &TraceeState) -> bool {
        if state.jobctl.contains(JobCtl::LISTENING) && self.is_ptrace_stopped() {
            self.is_stopped.store(false, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Schedules a trap for a newly attached tracee if its process is in a group-stop.
    ///
    /// Returns whether the tracer should wait for the tracee to enter the trap.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L403-L432>
    fn set_trap_stop_if_group_stopped(&self, process: &Process) -> bool {
        let mut state = self.state.lock();

        let Some(stop_signal) = process.stop_signal() else {
            return false;
        };
        if state.tracer().is_none() {
            return false;
        }

        state.stop_signal = stop_signal;
        let jobctl = state.jobctl | JobCtl::TRAP_STOP | JobCtl::TRAPPING;
        self.set_jobctl(&mut state, jobctl);

        true
    }

    /// Schedules the initial `PTRACE_EVENT_STOP` of a new child of a seized tracee.
    ///
    /// The child also joins the group-stop that is in effect.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L387-L399>
    fn set_trap_stop_for_new_child(&self, process: &Process) {
        let mut state = self.state.lock();

        let mut jobctl = state.jobctl | JobCtl::TRAP_STOP;
        if let Some(stop_signal) = process.stop_signal() {
            state.stop_signal = stop_signal;
            jobctl |= JobCtl::STOP_PENDING;
        }
        self.set_jobctl(&mut state, jobctl);
    }

    /// Records a new group-stop with `sig_num`.
    ///
    /// Returns whether the tracee should be woken up.
    fn notify_group_stop(&self, tracee: &PosixThread, sig_num: SigNum) -> bool {
        let mut state = self.state.lock();
        if state.tracer().is_none() || tracee.has_pending_sigkill() {
            return false;
        }

        state.stop_signal = sig_num;
        let mut jobctl = state.jobctl | JobCtl::STOP_PENDING;
        if state.is_seized {
            jobctl |= JobCtl::TRAP_NOTIFY;
            self.end_listening(&state);
        }
        self.set_jobctl(&mut state, jobctl);

        true
    }

    /// Cancels the pending group-stop and notifies a seized tracee.
    ///
    /// Returns whether the tracee should be woken up.
    fn notify_group_continue(&self, tracee: &PosixThread) -> bool {
        let mut state = self.state.lock();
        if state.tracer().is_none() {
            return false;
        }

        let mut jobctl = state.jobctl - JobCtl::STOP_PENDING;
        if state.is_seized && !tracee.has_pending_sigkill() {
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L876-L883>
            jobctl |= JobCtl::TRAP_NOTIFY;
            self.end_listening(&state);
        }
        self.set_jobctl(&mut state, jobctl);

        state.is_seized
    }

    fn interrupt(&self, tracee: &PosixThread) -> Result<()> {
        let mut state = self.state.lock();
        if !state.is_seized {
            return_errno_with_message!(Errno::EIO, "the thread is not seized");
        }
        // Like Linux, the request succeeds without effects if the tracee is dying.
        if tracee.has_pending_sigkill() {
            return Ok(());
        }

        // A trap that has been reported is not disturbed, except for `PTRACE_LISTEN`.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L1257-L1282>
        let jobctl = state.jobctl | JobCtl::TRAP_STOP;
        self.end_listening(&state);
        self.set_jobctl(&mut state, jobctl);

        Ok(())
    }

    fn listen(&self) -> Result<()> {
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;
        if !state.is_seized || !state.is_event_stop {
            return_errno_with_message!(Errno::EIO, "the thread is not in a `PTRACE_EVENT_STOP`");
        }

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L1284-L1308>
        let jobctl = state.jobctl | JobCtl::LISTENING;
        self.set_jobctl(&mut state, jobctl);
        if jobctl.contains(JobCtl::TRAP_NOTIFY) {
            // An event has happened since this trap started, so re-trap now.
            self.end_listening(&state);
        }

        Ok(())
    }

    /// Takes the pending trap (`do_jobctl_trap` in Linux).
    ///
    /// A seized tracee reports a `PTRACE_EVENT_STOP` with the stop signal if a group-stop is
    /// in effect, or `SIGTRAP` otherwise. A tracee that is not seized reports the stop
    /// signal of the group-stop without a `siginfo`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2756-L2782>
    fn do_jobctl_trap(&self, ctx: &Context, user_ctx: &mut UserContext) -> bool {
        if !self.has_pending_trap() {
            return false;
        }

        let mut state = self.state.lock();
        let mut jobctl = state.jobctl;
        if !jobctl.intersects(JobCtl::PENDING_MASK) {
            return false;
        }

        let tracer = state.tracer();
        if tracer.is_none() || ctx.posix_thread.has_pending_sigkill() {
            // A fatal signal cancels all traps.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2464-L2465>
            self.set_jobctl(&mut state, jobctl - JobCtl::PENDING_MASK - JobCtl::TRAPPING);
            drop(state);
            if let Some(tracer) = tracer {
                let tracer_process = tracer.as_posix_thread().unwrap().process();
                tracer_process.children_wait_queue().wake_all();
            }
            return false;
        }
        let tracer = tracer.unwrap();

        let (signal, wait_status) = if state.is_seized {
            let sig_num = if ctx.process.is_stopped() {
                state.stop_signal
            } else {
                SIGTRAP
            };
            let wait_status = PtraceWaitStatus::from_event_stop(sig_num);
            let mut siginfo = siginfo_t::new(sig_num, wait_status.to_si_code());
            siginfo.set_pid_uid_by(ctx);
            let signal = DequeuedSignal::FromThread(Box::new(RawSignal::new(siginfo)));
            (Some(signal), wait_status)
        } else {
            (None, PtraceWaitStatus::from_signal(state.stop_signal))
        };

        // Any trap clears `TRAP_STOP` and participates in the pending group-stop. A
        // `PTRACE_EVENT_STOP` also clears `TRAP_NOTIFY`. Entering a trap clears `TRAPPING`.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2495-L2510>
        jobctl -= JobCtl::STOP_PENDING | JobCtl::TRAP_STOP | JobCtl::TRAPPING;
        if state.is_seized {
            jobctl -= JobCtl::TRAP_NOTIFY;
        }
        self.set_jobctl(&mut state, jobctl);
        state.is_event_stop = state.is_seized;

        let result = self.do_ptrace_stop(
            state,
            tracer,
            signal,
            wait_status,
            None,
            CLD_STOPPED,
            ctx,
            user_ctx,
        );
        // The signal to resume with is ignored after a trap.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2756-L2772>
        !matches!(result, PtraceStopResult::Interrupted)
    }

    fn defer_exit_notify(&self, real_parent: &Arc<Process>) -> Option<Arc<Thread>> {
        // Hold the lock first to avoid race conditions with `detach_tracer_with`.
        let mut state = self.state.lock();

        let tracer = state.tracer()?;
        if Arc::ptr_eq(&tracer.as_posix_thread().unwrap().process(), real_parent) {
            return None;
        }
        state.is_exit_notify_deferred = true;

        Some(tracer)
    }

    fn ptrace_stop(
        &self,
        signal: DequeuedSignal,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> PtraceStopResult {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = user_ctx;

        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();

        let Some(tracer) = state.tracer() else {
            return PtraceStopResult::NotTraced(Some(signal));
        };

        let wait_status = PtraceWaitStatus::from_signal(signal.signal().num());

        self.do_ptrace_stop(
            state,
            tracer,
            Some(signal),
            wait_status,
            None,
            CLD_TRAPPED,
            ctx,
            user_ctx,
        )
    }

    fn ptrace_may_stop_on(&self, event: PtraceEvent, ctx: &Context, user_ctx: &mut UserContext) {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();

        let Some(tracer) = state.tracer() else {
            return;
        };

        if !state.options.contains(event.option()) {
            // If the PTRACE_O_TRACEEXEC option is not in effect, all successful
            // calls to execve(2) by the traced process will cause it to be sent
            // a SIGTRAP signal, giving the parent a chance to gain control
            // before the new program begins execution.
            //
            // Reference: <https://man7.org/linux/man-pages/man2/ptrace.2.html>
            if matches!(&event, PtraceEvent::Exec(_)) {
                ctx.posix_thread
                    .enqueue_signal(Box::new(UserSignal::new_kill(SIGTRAP, ctx)));
            }
            return;
        }

        let siginfo = event.siginfo(ctx);
        let signal = Box::new(RawSignal::new(siginfo));
        let signal = DequeuedSignal::FromThread(signal);
        let wait_status = PtraceWaitStatus::from_event(&event);

        self.do_ptrace_stop(
            state,
            tracer,
            Some(signal),
            wait_status,
            Some(event),
            CLD_TRAPPED,
            ctx,
            user_ctx,
        );
    }

    fn ptrace_may_stop_on_syscall(
        &self,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> PtraceStopResult {
        let state = self.state.lock();

        let Some(tracer) = state.tracer() else {
            return PtraceStopResult::NotTraced(None);
        };
        if !state.is_tracing_syscall {
            return PtraceStopResult::NotTraced(None);
        }

        let siginfo = util::syscall_stop_siginfo(&state.options, ctx);
        let signal = Box::new(RawSignal::new(siginfo));
        let signal = DequeuedSignal::FromThread(signal);
        let wait_status = PtraceWaitStatus::from_syscall(&state.options);

        self.do_ptrace_stop(
            state,
            tracer,
            Some(signal),
            wait_status,
            None,
            CLD_TRAPPED,
            ctx,
            user_ctx,
        )
    }

    /// Enters a ptrace-stop and notifies the tracer with `SIGCHLD` of `code`
    /// (`CLD_TRAPPED` or `CLD_STOPPED`).
    #[expect(clippy::too_many_arguments)]
    fn do_ptrace_stop(
        &self,
        mut state: MutexGuard<'_, TraceeState>,
        tracer: Arc<Thread>,
        signal: Option<DequeuedSignal>,
        wait_status: PtraceWaitStatus,
        event: Option<PtraceEvent>,
        code: i32,
        ctx: &Context,
        user_ctx: &mut UserContext,
    ) -> PtraceStopResult {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = user_ctx;

        debug_assert!(!self.is_ptrace_stopped());

        state.signal.stop(signal, wait_status);
        state.event = event;
        #[cfg(target_arch = "x86_64")]
        {
            let supp = ctx.thread_local.supp_user_context();
            state.fs_base = Some(supp.fs_base().get());
            state.gs_base = Some(supp.gs_base().get());
            state.user_context = Some(user_ctx.clone());
            state.set_orig_syscall_ret(ctx.thread_local.orig_syscall_ret());
        }
        self.is_stopped.store(true, Ordering::Relaxed);
        drop(state);

        sigchld::notify_parent_of_stop(
            ChildSource::Thread(ctx.posix_thread),
            &tracer.as_posix_thread().unwrap().process(),
            code,
            wait_status.to_sigchld_si_status(),
        );

        let waiter = Waiter::new_pair().0;
        if waiter
            .pause_until_by(
                || (!self.is_ptrace_stopped()).then_some(()),
                PauseReason::StopByPtrace,
            )
            .is_err()
        {
            // A `SIGKILL` interrupts this ptrace-stop.
            let mut state = self.state.lock();
            state.signal.clear();
            state.event = None;
            state.is_event_stop = false;
            let jobctl = state.jobctl - JobCtl::LISTENING;
            self.set_jobctl(&mut state, jobctl);
            #[cfg(target_arch = "x86_64")]
            {
                state.user_context = None;
                state.fs_base = None;
                state.gs_base = None;
                state.clear_orig_syscall_ret();
            }
            state.is_tracing_syscall = false;
            self.is_stopped.store(false, Ordering::Relaxed);
            return PtraceStopResult::Interrupted;
        };

        let mut state = self.state.lock();
        let signal = state.signal.clear();
        state.event = None;
        // `PTRACE_LISTEN` can only be used during this ptrace-stop.
        state.is_event_stop = false;
        let jobctl = state.jobctl - JobCtl::LISTENING;
        self.set_jobctl(&mut state, jobctl);

        #[cfg(target_arch = "x86_64")]
        {
            *user_ctx = state.user_context.take().unwrap();
            let supp = ctx.thread_local.supp_user_context();
            supp.fs_base().set(state.fs_base.take().unwrap());
            supp.gs_base().set(state.gs_base.take().unwrap());
            ctx.thread_local
                .set_orig_syscall_ret(state.take_orig_syscall_ret());
        }

        PtraceStopResult::Continued(signal)
    }

    /// Returns the tracer, the ptrace options, whether the tracer has used `PTRACE_SEIZE`,
    /// and the clone-family event (if enabled) if the new child `child_tid` created with
    /// `clone_args` should be traced.
    fn clone_trace(
        &self,
        clone_args: &CloneArgs,
        child_tid: Tid,
    ) -> Option<(Arc<Thread>, PtraceOptions, bool, Option<PtraceEvent>)> {
        let state = self.state.lock();
        let tracer = state.tracer()?;
        let options = state.options;

        // `CLONE_UNTRACED` only suppresses the event. `CLONE_PTRACE` still traces the child.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/fork.c#L2495>
        let flags = clone_args.flags;
        let event = if flags.contains(CloneFlags::CLONE_UNTRACED) {
            None
        } else if flags.contains(CloneFlags::CLONE_VFORK) {
            Some(PtraceEvent::Vfork(child_tid))
        } else if clone_args.exit_signal != Some(SIGCHLD) {
            Some(PtraceEvent::Clone(child_tid))
        } else {
            Some(PtraceEvent::Fork(child_tid))
        };
        let event = event.filter(|event| options.contains(event.option()));

        if event.is_none() && !flags.contains(CloneFlags::CLONE_PTRACE) {
            return None;
        }

        Some((tracer, options, state.is_seized, event))
    }

    fn is_ptrace_stopped(&self) -> bool {
        self.is_stopped.load(Ordering::Relaxed)
    }

    /// Checks that the tracee is ptrace-stopped and not listening (`ptrace_freeze_traced`).
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L202-L219>
    fn check_ptrace_stopped(&self, state: &TraceeState) -> Result<()> {
        if self.is_ptrace_stopped() && !state.jobctl.contains(JobCtl::LISTENING) {
            Ok(())
        } else {
            return_errno_with_message!(Errno::ESRCH, "the thread is not ptrace-stopped");
        }
    }

    fn wait(&self, options: WaitOptions) -> Option<PtraceWaitStatus> {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();

        // Avoid the race with `detach_tracer` or `resume` in between.
        // A listening tracee is not reported.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1311-L1321>
        if !self.is_ptrace_stopped() || state.jobctl.contains(JobCtl::LISTENING) {
            return None;
        }

        state.signal.wait(options)
    }

    /// Sets the signal that the tracee delivers after resuming from the ptrace-stop.
    fn set_resume_signal(state: &mut TraceeState, data: usize, ctx: &Context) -> Result<()> {
        if let Some(sig_num) = parse_resume_signal(data)? {
            let signal = Box::new(UserSignal::new_kill(sig_num, ctx));
            state.signal.inject(signal);
        } else {
            state.signal.clear();
        }

        Ok(())
    }

    fn resume(&self, request: PtraceContRequest, data: usize, ctx: &Context) -> Result<()> {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        Self::set_resume_signal(&mut state, data, ctx)?;

        #[cfg(target_arch = "x86_64")]
        {
            let user_context = state.user_context.as_mut().unwrap();
            if request == PtraceContRequest::SingleStep {
                arch_ptrace::enable_single_step(user_context);
            } else {
                arch_ptrace::disable_single_step(user_context);
            }
        }

        state.is_tracing_syscall = request == PtraceContRequest::Syscall;

        self.is_stopped.store(false, Ordering::Relaxed);

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_regs(&self) -> Result<arch_ptrace::CUserRegsStruct> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        let user_context = state.user_context.as_ref().unwrap();
        let fs_base = state.fs_base.unwrap();
        let gs_base = state.gs_base.unwrap();
        let mut regs = arch_ptrace::CUserRegsStruct::from_regs(user_context, fs_base, gs_base);
        regs.orig_rax = state.orig_syscall_ret;
        Ok(regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_regs(&self, regs: arch_ptrace::CUserRegsStruct) -> Result<()> {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        let TraceeState {
            user_context,
            fs_base,
            gs_base,
            ..
        } = &mut *state;
        regs.apply_to(
            user_context.as_mut().unwrap(),
            fs_base.as_mut().unwrap(),
            gs_base.as_mut().unwrap(),
        )?;
        state.orig_syscall_ret = regs.orig_rax;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn peek_user(&self, offset: usize) -> Result<usize> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;
        let user_context = state.user_context.as_ref().unwrap();
        let fs_base = state.fs_base.unwrap();
        let gs_base = state.gs_base.unwrap();
        arch_ptrace::read_user_word(
            user_context,
            fs_base,
            gs_base,
            state.orig_syscall_ret,
            offset,
        )
    }

    #[cfg(target_arch = "x86_64")]
    fn poke_user(&self, offset: usize, value: usize) -> Result<()> {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;
        let mut orig_syscall_ret = state.orig_syscall_ret;
        let TraceeState {
            user_context,
            fs_base,
            gs_base,
            ..
        } = &mut *state;
        arch_ptrace::write_user_word(
            user_context.as_mut().unwrap(),
            fs_base.as_mut().unwrap(),
            gs_base.as_mut().unwrap(),
            &mut orig_syscall_ret,
            offset,
            value,
        )?;
        state.orig_syscall_ret = orig_syscall_ret;
        Ok(())
    }

    fn peek_data(&self, process: &Weak<Process>, addr: usize) -> Result<usize> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        let process = process.upgrade().unwrap();
        let vmar_guard = process.lock_vmar();
        let Some(vmar) = vmar_guard.as_ref() else {
            return_errno_with_message!(Errno::EIO, "the process has exited");
        };

        let mut value = [0u8; size_of::<usize>()];
        let mut writer = VmWriter::from(value.as_mut_slice()).to_fallible();
        match vmar.read_alien(addr, &mut writer) {
            Ok(bytes) if bytes == value.len() => Ok(usize::from_ne_bytes(value)),
            _ => return_errno_with_message!(Errno::EIO, "failed to read tracee memory"),
        }
    }

    fn poke_data(&self, process: &Weak<Process>, addr: usize, value: usize) -> Result<()> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        let process = process.upgrade().unwrap();
        let vmar_guard = process.lock_vmar();
        let Some(vmar) = vmar_guard.as_ref() else {
            return_errno_with_message!(Errno::EIO, "the process has exited");
        };

        let value = value.to_ne_bytes();
        let mut reader = VmReader::from(value.as_slice()).to_fallible();
        match vmar.write_alien(addr, &mut reader) {
            Ok(bytes) if bytes == value.len() => Ok(()),
            _ => return_errno_with_message!(Errno::EIO, "failed to write tracee memory"),
        }
    }

    fn set_options(&self, options: PtraceOptions) -> Result<()> {
        // Hold the lock first to avoid race conditions.
        let mut state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        state.options = options;
        Ok(())
    }

    fn get_event(&self) -> Result<Option<PtraceEvent>> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        Ok(state.event.clone())
    }

    fn get_siginfo(&self) -> Result<siginfo_t> {
        // Hold the lock first to avoid race conditions.
        let state = self.state.lock();
        self.check_ptrace_stopped(&state)?;

        state
            .signal
            .get()
            .map(|signal| signal.to_info())
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "the ptrace-stop has no signal info"))
    }
}

struct TraceeState {
    tracer: Weak<Thread>,
    /// Whether the tracer has used `PTRACE_SEIZE` (`PT_SEIZED`).
    is_seized: bool,
    /// The job control states.
    jobctl: JobCtl,
    /// The stop signal of the latest group-stop (`JOBCTL_STOP_SIGMASK`).
    stop_signal: SigNum,
    /// Whether the current ptrace-stop is a `PTRACE_EVENT_STOP`.
    is_event_stop: bool,
    /// The signal associated with the current ptrace-stop and later signal delivery.
    signal: StopDeliverySignal,
    /// The event associated with the current ptrace-event-stop.
    event: Option<PtraceEvent>,
    /// The configured ptrace options.
    options: PtraceOptions,
    /// Whether the tracee should stop at the next syscall enter or exit.
    is_tracing_syscall: bool,
    /// Whether the exit notification of the tracee's process to its real parent
    /// is deferred until the tracer reaps or detaches the tracee.
    is_exit_notify_deferred: bool,
    /// The user register context of the tracee at the time of ptrace-stop.
    #[cfg(target_arch = "x86_64")]
    user_context: Option<UserContext>,
    /// The FS base of the tracee at the time of ptrace-stop.
    #[cfg(target_arch = "x86_64")]
    fs_base: Option<FsBase>,
    /// The GS base of the tracee at the time of ptrace-stop.
    #[cfg(target_arch = "x86_64")]
    gs_base: Option<GsBase>,
    /// The value of `ThreadLocal::orig_syscall_ret` at the time of ptrace-stop,
    /// or [`Self::NOT_A_SYSCALL`] for non-syscall stops.
    #[cfg(target_arch = "x86_64")]
    orig_syscall_ret: usize,
}

impl TraceeState {
    fn new() -> Self {
        Self {
            tracer: Weak::new(),
            is_seized: false,
            jobctl: JobCtl::empty(),
            stop_signal: SIGSTOP,
            is_event_stop: false,
            signal: StopDeliverySignal::default(),
            event: None,
            options: PtraceOptions::empty(),
            is_tracing_syscall: false,
            is_exit_notify_deferred: false,
            #[cfg(target_arch = "x86_64")]
            user_context: None,
            #[cfg(target_arch = "x86_64")]
            fs_base: None,
            #[cfg(target_arch = "x86_64")]
            gs_base: None,
            #[cfg(target_arch = "x86_64")]
            orig_syscall_ret: Self::NOT_A_SYSCALL,
        }
    }

    fn tracer(&self) -> Option<Arc<Thread>> {
        self.tracer.upgrade()
    }
}

#[cfg(target_arch = "x86_64")]
impl TraceeState {
    const NOT_A_SYSCALL: usize = usize::MAX;

    fn set_orig_syscall_ret(&mut self, value: Option<usize>) {
        self.orig_syscall_ret = value.unwrap_or(Self::NOT_A_SYSCALL);
    }

    fn take_orig_syscall_ret(&mut self) -> Option<usize> {
        let value = self.orig_syscall_ret;
        self.clear_orig_syscall_ret();
        (value != Self::NOT_A_SYSCALL).then_some(value)
    }

    fn clear_orig_syscall_ret(&mut self) {
        self.orig_syscall_ret = Self::NOT_A_SYSCALL;
    }
}

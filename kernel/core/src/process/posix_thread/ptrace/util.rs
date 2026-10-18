// SPDX-License-Identifier: MPL-2.0

//! Ptrace utilities for POSIX threads.

use crate::{
    prelude::*,
    process::{
        ExitCode, WaitOptions,
        signal::{
            DequeuedSignal, c_types::siginfo_t, constants::SIGTRAP, sig_num::SigNum,
            signals::Signal,
        },
    },
    thread::Tid,
};

/// The requests that can continue a stopped tracee.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtraceContRequest {
    Continue,
    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    SingleStep,
    Syscall,
}

/// The ways to start tracing a thread.
#[derive(Clone, Copy)]
pub(crate) enum PtraceAttachMode {
    /// `PTRACE_TRACEME`.
    TraceMe,
    /// `PTRACE_ATTACH`.
    Attach,
    /// `PTRACE_SEIZE` with the given options.
    Seize(PtraceOptions),
}

/// Parses the signal that a tracer delivers when resuming or detaching a tracee.
///
/// # Errors
///
/// Returns `EIO` if `data` is not a valid signal number.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L852-L853>
pub(super) fn parse_resume_signal(data: usize) -> Result<Option<SigNum>> {
    SigNum::try_from_raw(data as u64)
        .map_err(|_| Error::with_message(Errno::EIO, "invalid signal number"))
}

/// The result of a ptrace-stop.
pub(crate) enum PtraceStopResult {
    /// The ptrace-stop is continued by the tracer,
    /// or ends because the tracer exits or detaches.
    Continued(Option<DequeuedSignal>),
    /// The ptrace-stop is interrupted by `SIGKILL`.
    Interrupted,
    /// The thread is not traced, or the stop condition is not met
    /// (e.g., the tracee is not being traced for syscall-stops).
    /// Returning the stop signal back, if it is a signal-delivery-stop.
    NotTraced(Option<DequeuedSignal>),
}

/// The signal associated with a ptrace-stop and its later signal delivery.
///
/// A group-stop of a tracee that is not seized has no signal (i.e., no `siginfo`).
#[derive(Default)]
pub(super) enum StopDeliverySignal {
    /// The signal that has not yet been reported through `wait`.
    Pending(Option<DequeuedSignal>, PtraceWaitStatus),
    /// The signal that has been reported through `wait`.
    Consumed(Option<DequeuedSignal>),
    /// The signal that is injected by the tracer.
    Injected(DequeuedSignal),
    /// No ptrace-stop signal is recorded.
    #[default]
    Empty,
}

impl StopDeliverySignal {
    /// Records the signal associated with a ptrace-stop.
    pub(super) fn stop(&mut self, signal: Option<DequeuedSignal>, wait_status: PtraceWaitStatus) {
        *self = Self::Pending(signal, wait_status);
    }

    /// Clears and returns the signal associated with a ptrace-stop,
    /// unless it has already been consumed by `wait`.
    pub(super) fn clear(&mut self) -> Option<DequeuedSignal> {
        let this = core::mem::replace(self, Self::Empty);

        match this {
            Self::Pending(signal, _) => signal,
            Self::Injected(signal) => Some(signal),
            Self::Consumed(_) | Self::Empty => None,
        }
    }

    /// Returns the wait status of the signal associated with a ptrace-stop,
    /// if it has not yet been reported through `wait`.
    pub(super) fn wait(&mut self, options: WaitOptions) -> Option<PtraceWaitStatus> {
        let this = core::mem::replace(self, Self::Empty);

        match this {
            Self::Pending(signal, wait_status) => {
                if !options.contains(WaitOptions::WNOWAIT) {
                    *self = Self::Consumed(signal);
                } else {
                    *self = Self::Pending(signal, wait_status);
                }
                Some(wait_status)
            }
            Self::Consumed(signal) => {
                *self = Self::Consumed(signal);
                None
            }
            Self::Injected(_) => unreachable!(),
            Self::Empty => None,
        }
    }

    /// Injects a signal by the tracer.
    ///
    /// The signal is discarded if the ptrace-stop has no signal.
    pub(super) fn inject(&mut self, new_signal: Box<dyn Signal>) {
        let this = core::mem::replace(self, Self::Empty);

        let signal = match this {
            Self::Pending(signal, _) | Self::Consumed(signal) => signal,
            Self::Injected(_) | Self::Empty => unreachable!(),
        };

        if let Some(mut signal) = signal {
            signal.set_signal(new_signal);
            *self = Self::Injected(signal);
        }
    }

    /// Returns the signal associated with a ptrace-stop,
    /// but does not change the state.
    pub(super) fn get(&self) -> Option<&dyn Signal> {
        match self {
            Self::Pending(Some(signal), _)
            | Self::Consumed(Some(signal))
            | Self::Injected(signal) => Some(signal.signal()),
            Self::Pending(None, _) | Self::Consumed(None) | Self::Empty => None,
        }
    }
}

bitflags! {
    /// The job control states of a tracee.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/sched/jobctl.h>
    pub(super) struct JobCtl: u8 {
        /// A group-stop is pending (`JOBCTL_STOP_PENDING`).
        const STOP_PENDING = 1 << 0;
        /// A trap for `PTRACE_INTERRUPT` or group-stops is pending (`JOBCTL_TRAP_STOP`).
        const TRAP_STOP = 1 << 1;
        /// A trap for notifying the tracer of job control changes is pending
        /// (`JOBCTL_TRAP_NOTIFY`).
        const TRAP_NOTIFY = 1 << 2;
        /// The tracer is waiting for the tracee to enter a trap (`JOBCTL_TRAPPING`).
        const TRAPPING = 1 << 3;
        /// The tracer is listening for events in a `PTRACE_EVENT_STOP` (`JOBCTL_LISTENING`).
        const LISTENING = 1 << 4;
    }
}

impl JobCtl {
    /// The states that make the tracee trap.
    pub(super) const PENDING_MASK: Self = Self::STOP_PENDING
        .union(Self::TRAP_STOP)
        .union(Self::TRAP_NOTIFY);
}

bitflags! {
    /// Options accepted by `PTRACE_SETOPTIONS`.
    pub(crate) struct PtraceOptions: usize {
        /// Marks syscall stops with signal number set to `SIGTRAP | 0x80`.
        const PTRACE_O_TRACESYSGOOD = 1;
        /// Stops the tracee at `fork` and automatically traces the new thread.
        const PTRACE_O_TRACEFORK = 1 << PtraceEvent::Fork(0).code();
        /// Stops the tracee at `vfork` and automatically traces the new thread.
        const PTRACE_O_TRACEVFORK = 1 << PtraceEvent::Vfork(0).code();
        /// Stops the tracee at `clone` and automatically traces the new thread.
        const PTRACE_O_TRACECLONE = 1 << PtraceEvent::Clone(0).code();
        /// Stops the tracee at `execve`.
        const PTRACE_O_TRACEEXEC = 1 << PtraceEvent::Exec(0).code();
        /// Stops the tracee at the completion of `vfork`.
        const PTRACE_O_TRACEVFORKDONE = 1 << PtraceEvent::VforkDone(0).code();
        /// Stops the tracee at `exit`.
        const PTRACE_O_TRACEEXIT = 1 << PtraceEvent::Exit(0).code();
        /// Stops the tracee when a seccomp `SECCOMP_RET_TRACE` rule is triggered.
        ///
        /// This option is accepted but has no effect because seccomp is not supported.
        const PTRACE_O_TRACESECCOMP = 1 << 7;
        /// Send a `SIGKILL` signal to the tracee if the tracer exits.
        const PTRACE_O_EXITKILL = 1 << 20;
    }
}

/// The events of ptrace-event-stops.
#[derive(Debug, Clone)]
pub(crate) enum PtraceEvent {
    /// A `fork` event with the new child thread ID.
    Fork(Tid),
    /// A `vfork` event with the new child thread ID.
    Vfork(Tid),
    /// A `clone` event with the new child thread ID.
    Clone(Tid),
    /// An `execve` event with the former thread ID.
    Exec(Tid),
    /// A done `vfork` event with the child thread ID.
    VforkDone(Tid),
    /// An `exit` event with the tracee's exit code.
    Exit(ExitCode),
}

impl PtraceEvent {
    /// Returns the Linux `PTRACE_EVENT_*` code of this event.
    const fn code(&self) -> u32 {
        match self {
            Self::Fork(_) => 1,
            Self::Vfork(_) => 2,
            Self::Clone(_) => 3,
            Self::Exec(_) => 4,
            Self::VforkDone(_) => 5,
            Self::Exit(_) => 6,
        }
    }

    /// Returns the `PtraceOptions` corresponding to this event.
    pub(super) const fn option(&self) -> PtraceOptions {
        PtraceOptions::from_bits(1 << self.code()).unwrap()
    }

    /// Returns the message of this event.
    pub(crate) const fn message(&self) -> usize {
        match self {
            Self::Fork(tid)
            | Self::Vfork(tid)
            | Self::Clone(tid)
            | Self::Exec(tid)
            | Self::VforkDone(tid) => *tid as usize,
            Self::Exit(exit_code) => *exit_code as usize,
        }
    }

    /// Creates a `siginfo_t` for the ptrace-stop triggered by this event.
    pub(super) fn siginfo(&self, ctx: &Context) -> siginfo_t {
        let code = PtraceWaitStatus::from_event(self).to_si_code();
        let mut siginfo = siginfo_t::new(SIGTRAP, code);
        siginfo.set_pid_uid_by(ctx);
        siginfo
    }
}

/// The event code of `PTRACE_EVENT_STOP`.
const PTRACE_EVENT_STOP: i32 = 128;

/// The `si_status` code of a ptrace-stop for `wait` syscalls.
#[derive(Copy, Clone)]
pub(crate) struct PtraceWaitStatus(i32);

impl PtraceWaitStatus {
    pub(super) fn from_event(event: &PtraceEvent) -> Self {
        Self(SIGTRAP.as_u8() as i32 | ((event.code() as i32) << 8))
    }

    pub(super) fn from_signal(sig: SigNum) -> Self {
        Self(sig.as_u8() as i32)
    }

    /// Creates the wait status of a `PTRACE_EVENT_STOP` with the given signal.
    pub(super) fn from_event_stop(sig: SigNum) -> Self {
        Self(sig.as_u8() as i32 | (PTRACE_EVENT_STOP << 8))
    }

    /// Returns the `si_code` of the `siginfo_t` reported by `PTRACE_GETSIGINFO`.
    pub(super) fn to_si_code(self) -> i32 {
        self.0
    }

    pub(super) fn from_syscall(options: &PtraceOptions) -> Self {
        let mut sig = SIGTRAP.as_u8() as i32;
        if options.contains(PtraceOptions::PTRACE_O_TRACESYSGOOD) {
            sig |= 0x80;
        }
        Self(sig)
    }

    pub(crate) fn to_wait4_status(self) -> u32 {
        ((self.0 as u32) << 8) | 0x7f
    }

    pub(crate) fn to_waitid_si_status(self) -> i32 {
        self.0
    }

    /// Returns the `si_status` of the `SIGCHLD` sent to the tracer.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2406-L2408>
    pub(in crate::process) fn to_sigchld_si_status(self) -> i32 {
        self.0 & 0x7f
    }
}

/// Creates a `siginfo_t` for a syscall-stop.
pub(super) fn syscall_stop_siginfo(options: &PtraceOptions, ctx: &Context) -> siginfo_t {
    let code = PtraceWaitStatus::from_syscall(options).to_si_code();
    let mut siginfo = siginfo_t::new(SIGTRAP, code);
    siginfo.set_pid_uid_by(ctx);
    siginfo
}

// SPDX-License-Identifier: MPL-2.0

//! Notifications of child state changes sent to parents and tracers.

use super::{
    ExitCode, Pid, Process, Uid,
    posix_thread::{AsPosixThread, PosixThread},
    signal::{
        c_types::siginfo_t,
        constants::{CLD_DUMPED, CLD_EXITED, CLD_KILLED, SIGCHLD},
        sig_action::{SigAction, SigActionFlags},
        sig_num::SigNum,
        signals::raw::RawSignal,
    },
};
use crate::{
    prelude::*,
    time::{clocks::ProfClock, duration_to_clock_t},
};

/// The process or thread whose state change is reported.
#[derive(Clone, Copy)]
pub(crate) enum ChildSource<'a> {
    Process(&'a Process),
    Thread(&'a PosixThread),
}

impl<'a> ChildSource<'a> {
    pub(crate) fn pid(self) -> Pid {
        match self {
            Self::Process(process) => process.pid(),
            Self::Thread(thread) => thread.tid(),
        }
    }

    pub(crate) fn uid(self) -> Uid {
        match self {
            Self::Process(process) => process
                .main_thread()
                .as_posix_thread()
                .unwrap()
                .credentials()
                .ruid(),
            Self::Thread(thread) => thread.credentials().ruid(),
        }
    }

    pub(crate) fn prof_clock(self) -> &'a Arc<ProfClock> {
        match self {
            Self::Process(process) => process.prof_clock(),
            Self::Thread(thread) => thread.prof_clock(),
        }
    }

    /// Creates the `siginfo_t` of a `SIGCHLD`-like signal that reports the state change.
    fn siginfo(self, sig: SigNum, code: i32, status: i32) -> siginfo_t {
        let mut siginfo = siginfo_t::new(sig, code);
        siginfo.set_pid_uid(self.pid(), self.uid());
        siginfo.set_status(status);

        let prof_clock = self.prof_clock();
        siginfo.set_utime_stime(
            duration_to_clock_t(prof_clock.user_clock().read_time()),
            duration_to_clock_t(prof_clock.kernel_clock().read_time()),
        );

        siginfo
    }
}

/// Decodes the exit code of a dead child into the `si_code` and `si_status` of `siginfo_t`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2304-L2312>
pub(crate) fn decode_exit_code(exit_code: ExitCode) -> (i32, i32) {
    let status = (exit_code & 0x7f) as i32;

    if exit_code & 0x80 != 0 {
        (CLD_DUMPED, status)
    } else if status != 0 {
        (CLD_KILLED, status)
    } else {
        (CLD_EXITED, (exit_code >> 8) as i32)
    }
}

/// Notifies `parent` of the death of `child` by sending `sig`.
///
/// Returns whether `child` should be reaped automatically because `parent` does not care about
/// its exit status.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2252-L2353>
pub(super) fn notify_parent_of_death(
    child: ChildSource,
    exit_code: ExitCode,
    parent: &Process,
    mut sig: Option<SigNum>,
    is_traced: bool,
) -> bool {
    let mut autoreap = false;
    if !is_traced && sig == Some(SIGCHLD) {
        // FIXME: `SA_NOCLDWAIT` is lost if it is set along with `SIG_DFL`, since `SigAction`
        // does not keep the flags of `SIG_DFL` and `SIG_IGN`.
        match sigchld_action(parent) {
            SigAction::Ign => {
                autoreap = true;
                sig = None;
            }
            SigAction::User { flags, .. } if flags.contains(SigActionFlags::SA_NOCLDWAIT) => {
                autoreap = true;
            }
            _ => {}
        }
    }

    if let Some(sig) = sig {
        let (code, status) = decode_exit_code(exit_code);
        let siginfo = child.siginfo(sig, code, status);
        parent.enqueue_signal(Box::new(RawSignal::new(siginfo)));
    }
    // Wake up the waiters even if no signal is sent, since they may now fail with `ECHILD`.
    parent.children_wait_queue().wake_all();

    autoreap
}

/// Notifies `parent` of a stop, continuation, or ptrace-stop of `child`.
///
/// `code` should be one of `CLD_STOPPED`, `CLD_CONTINUED`, and `CLD_TRAPPED`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2367-L2422>
pub(super) fn notify_parent_of_stop(child: ChildSource, parent: &Process, code: i32, status: i32) {
    // FIXME: `SA_NOCLDSTOP` is lost if it is set along with `SIG_DFL`, since `SigAction` does not
    // keep the flags of `SIG_DFL`.
    let should_send = match sigchld_action(parent) {
        SigAction::Ign => false,
        SigAction::User { flags, .. } => !flags.contains(SigActionFlags::SA_NOCLDSTOP),
        SigAction::Dfl => true,
    };

    if should_send {
        let siginfo = child.siginfo(SIGCHLD, code, status);
        parent.enqueue_signal(Box::new(RawSignal::new(siginfo)));
    }
    // Wake up the waiters even if no signal is sent.
    parent.children_wait_queue().wake_all();
}

fn sigchld_action(parent: &Process) -> SigAction {
    let sig_dispositions = parent.sig_dispositions().lock();
    let sig_dispositions = sig_dispositions.lock();
    sig_dispositions.get(SIGCHLD)
}

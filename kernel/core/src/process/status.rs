// SPDX-License-Identifier: MPL-2.0

//! The process status.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use ostd::sync::SpinLock;

use super::ExitCode;
use crate::process::{WaitOptions, posix_thread::PosixThread, signal::sig_num::SigNum};

/// The status of a process.
///
/// This maintains:
/// 1. Whether the process is a zombie (i.e., all its threads have exited);
/// 2. Whether the process is the vfork child, which shares the user-space virtual memory
///    with its parent process;
/// 3. The exit code of the process;
/// 4. Whether the process is stopped by a signal.
#[derive(Debug)]
pub(crate) struct ProcessStatus {
    is_zombie: AtomicBool,
    is_vfork_child: AtomicBool,
    exit_code: AtomicU32,
    stop_status: StopStatus,
}

impl Default for ProcessStatus {
    fn default() -> Self {
        Self {
            is_zombie: AtomicBool::new(false),
            is_vfork_child: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
            stop_status: StopStatus::new(),
        }
    }
}

impl ProcessStatus {
    /// Returns whether the process is a zombie process.
    pub(crate) fn is_zombie(&self) -> bool {
        // Use the `Acquire` memory order to make the exit code visible.
        self.is_zombie.load(Ordering::Acquire)
    }

    /// Sets the process to be a zombie process.
    ///
    /// This method should be called when the process completes its exit. The current thread must
    /// be the last thread in the process, so that no threads belonging to the process can run
    /// after it.
    pub(super) fn set_zombie(&self) {
        // Use the `Release` memory order to make the exit code visible.
        self.is_zombie.store(true, Ordering::Release);
    }
}

impl ProcessStatus {
    /// Returns whether the process is the vfork child.
    pub(crate) fn is_vfork_child(&self) -> bool {
        self.is_vfork_child.load(Ordering::Acquire)
    }

    /// Sets whether the process is the vfork child.
    pub(crate) fn set_vfork_child(&self, is_vfork_child: bool) {
        self.is_vfork_child.store(is_vfork_child, Ordering::Release);
    }
}

impl ProcessStatus {
    /// Returns the exit code.
    pub(crate) fn exit_code(&self) -> ExitCode {
        self.exit_code.load(Ordering::Relaxed)
    }

    /// Sets the exit code.
    pub(super) fn set_exit_code(&self, exit_code: ExitCode) {
        self.exit_code.store(exit_code, Ordering::Relaxed);
    }
}

impl ProcessStatus {
    pub(super) fn stop_status(&self) -> &StopStatus {
        &self.stop_status
    }
}

/// The group stop status of a process.
///
/// This combines the process-wide job control states that Linux keeps in `signal_struct`.
#[derive(Debug)]
pub(super) struct StopStatus {
    /// Whether a group stop is in effect, i.e., whether [`GroupStop::signal`] is `Some(_)`.
    ///
    /// This is used for checks that need no lock.
    is_stopped: AtomicBool,
    group_stop: SpinLock<GroupStop>,
}

#[derive(Debug)]
struct GroupStop {
    /// The signal of the group stop in effect (`JOBCTL_STOP_SIGMASK`).
    signal: Option<SigNum>,
    /// The number of threads that have yet to participate in the group stop
    /// (`group_stop_count`).
    count: usize,
    /// Whether the group stop has completed (`SIGNAL_STOP_STOPPED`).
    is_completed: bool,
    /// Whether the process has been continued and the continuation has not yet been waited
    /// for (`SIGNAL_STOP_CONTINUED`).
    is_continued: bool,
    /// The stop signal for the real parent to wait for, or `None` if it has been waited for
    /// (`group_exit_code`).
    exit_code: Option<SigNum>,
}

/// A notification of a group stop or continuation to the real parent.
pub(super) enum StopNotification {
    /// `CLD_STOPPED` with the stop signal.
    Stopped(SigNum),
    /// `CLD_CONTINUED`.
    Continued,
}

impl StopStatus {
    pub(self) const fn new() -> Self {
        Self {
            is_stopped: AtomicBool::new(false),
            group_stop: SpinLock::new(GroupStop {
                signal: None,
                count: 0,
                is_completed: false,
                is_continued: false,
                exit_code: None,
            }),
        }
    }

    /// Initiates a group stop with `sig_num`.
    ///
    /// Each thread in `threads` is paired with whether it should participate in the group stop.
    /// The group stop completes when all the participating threads have called
    /// [`Self::participate`].
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2643-L2696>
    pub(super) fn stop<'a>(
        &self,
        sig_num: SigNum,
        threads: impl Iterator<Item = (&'a PosixThread, bool)>,
    ) {
        let mut group_stop = self.group_stop.lock();

        // A traced thread may initiate a new group stop when the previous one has completed. Do
        // not report the new one to the real parent in such case.
        if !group_stop.is_completed {
            group_stop.exit_code = Some(sig_num);
        }
        group_stop.signal = Some(sig_num);
        self.is_stopped.store(true, Ordering::Relaxed);

        group_stop.count = 0;
        for (thread, participates) in threads {
            thread
                .group_stop_pending()
                .store(participates, Ordering::Relaxed);
            if participates {
                group_stop.count += 1;
            }
        }
    }

    /// Makes `thread` participate in the group stop in progress, if it has yet to.
    ///
    /// Returns the stop signal if the group stop completes, in which case the real parent should
    /// be notified.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L361-L385>
    pub(super) fn participate(&self, thread: &PosixThread) -> Option<SigNum> {
        let mut group_stop = self.group_stop.lock();

        if !thread.group_stop_pending().swap(false, Ordering::Relaxed) {
            return None;
        }

        // The count may be reset to zero by `execve`.
        group_stop.count = group_stop.count.saturating_sub(1);
        if group_stop.count != 0 || group_stop.is_completed {
            return None;
        }
        group_stop.is_completed = true;
        group_stop.is_continued = false;

        group_stop.exit_code.or(group_stop.signal)
    }

    /// Makes the new `thread` join the group stop in progress, if any.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L387-L399>
    pub(super) fn join(&self, thread: &PosixThread) {
        let mut group_stop = self.group_stop.lock();

        if group_stop.count > 0 {
            group_stop.count += 1;
            thread.group_stop_pending().store(true, Ordering::Relaxed);
        }
    }

    /// Ends the group stop in effect because `SIGCONT` is generated.
    ///
    /// Returns the notification to the real parent, if any. If the group stop has not completed,
    /// it is reported as completed (since `SIGCHLD` does not queue, the following continuation
    /// is not reported).
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L918-L957>
    pub(super) fn resume<'a>(
        &self,
        threads: impl Iterator<Item = &'a PosixThread>,
    ) -> Option<StopNotification> {
        let mut group_stop = self.group_stop.lock();

        for thread in threads {
            thread.group_stop_pending().store(false, Ordering::Relaxed);
        }

        let notification = if group_stop.is_completed {
            Some(StopNotification::Continued)
        } else if group_stop.count > 0 {
            group_stop
                .exit_code
                .or(group_stop.signal)
                .map(StopNotification::Stopped)
        } else {
            None
        };
        if notification.is_some() {
            group_stop.is_completed = false;
            group_stop.is_continued = true;
            group_stop.count = 0;
            group_stop.exit_code = None;
        }

        group_stop.signal = None;
        self.is_stopped.store(false, Ordering::Relaxed);

        notification
    }

    /// Makes `threads` no longer participate in the group stop in progress, because the process
    /// is executing a new program.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L1381-L1389>
    pub(super) fn cancel_participation<'a>(&self, threads: impl Iterator<Item = &'a PosixThread>) {
        let mut group_stop = self.group_stop.lock();

        group_stop.count = 0;
        for thread in threads {
            thread.group_stop_pending().store(false, Ordering::Relaxed);
        }
    }

    /// Clears the group stop states because the process is exiting as a group.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L1039-L1045>
    pub(super) fn clear_for_group_exit<'a>(&self, threads: impl Iterator<Item = &'a PosixThread>) {
        let mut group_stop = self.group_stop.lock();

        for thread in threads {
            thread.group_stop_pending().store(false, Ordering::Relaxed);
        }
        group_stop.signal = None;
        group_stop.count = 0;
        group_stop.is_completed = false;
        group_stop.is_continued = false;
        group_stop.exit_code = None;
        self.is_stopped.store(false, Ordering::Relaxed);
    }

    /// Returns whether a group stop is in effect.
    pub(super) fn is_stopped(&self) -> bool {
        self.is_stopped.load(Ordering::Relaxed)
    }

    /// Returns the signal of the group stop in effect, if any.
    pub(super) fn stop_signal(&self) -> Option<SigNum> {
        self.group_stop.lock().signal
    }

    /// Returns the stop signal of the completed group stop for the `wait` syscall,
    /// and consumes it unless `options` contains `WNOWAIT`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1311-L1373>
    pub(super) fn wait_stopped(&self, options: WaitOptions) -> Option<SigNum> {
        let mut group_stop = self.group_stop.lock();

        if !group_stop.is_completed {
            return None;
        }
        let exit_code = group_stop.exit_code?;
        if !options.contains(WaitOptions::WNOWAIT) {
            group_stop.exit_code = None;
        }

        Some(exit_code)
    }

    /// Returns whether the process has been continued for the `wait` syscall,
    /// and consumes the continuation unless `options` contains `WNOWAIT`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1413-L1433>
    pub(super) fn wait_continued(&self, options: WaitOptions) -> bool {
        let mut group_stop = self.group_stop.lock();

        if !group_stop.is_continued {
            return false;
        }
        if !options.contains(WaitOptions::WNOWAIT) {
            group_stop.is_continued = false;
        }

        true
    }
}

// SPDX-License-Identifier: MPL-2.0

use super::{
    ExitCode, Pid, Process,
    exit::send_child_death_signal,
    process_filter::ProcessFilter,
    signal::{constants::SIGCHLD, with_sigmask_changed},
};
use crate::{
    prelude::*,
    process::{
        ReapedChildrenStats, Uid, pid_table,
        posix_thread::{AsPosixThread, PosixThread, ptrace::PtraceWaitStatus},
        sigchld::ChildSource,
        signal::sig_num::SigNum,
    },
    thread::{AsThread, Thread, Tid},
    time::clocks::ProfClock,
};

// The definition of WaitOptions is from Occlum
bitflags! {
    pub(crate) struct WaitOptions: u32 {
        const WNOHANG = 0x1;
        const WSTOPPED = 0x2; // Same as WUNTRACED
        const WEXITED = 0x4;
        const WCONTINUED = 0x8;
        const WNOWAIT = 0x01000000;
        const WNOTHREAD = 0x20000000;
        const WALL = 0x40000000;
        const WCLONE = 0x80000000;
    }
}

pub(crate) fn do_wait(
    child_filter: ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> Result<Option<WaitStatus>> {
    let is_nonblocking = if let ProcessFilter::WithPidfd(pid_file) = &child_filter {
        pid_file.is_nonblocking()
    } else {
        false
    };

    let zombie_child = with_sigmask_changed(
        ctx,
        |sigmask| sigmask + SIGCHLD,
        || {
            ctx.process.children_wait_queue().pause_until(|| {
                let has_unready_tracee = match try_wait_tracees(&child_filter, wait_options, ctx) {
                    WaitResult::Found(status) => return Some(Ok(Some(status))),
                    WaitResult::MatchedButUnready => true,
                    WaitResult::NoMatch => false,
                };

                let has_unready_child = match try_wait_children(&child_filter, wait_options, ctx) {
                    WaitResult::Found(status) => return Some(Ok(Some(status))),
                    WaitResult::MatchedButUnready => true,
                    WaitResult::NoMatch => false,
                };

                if !has_unready_tracee && !has_unready_child {
                    return Some(Err(Error::with_message(
                        Errno::ECHILD,
                        "the process has no child to wait",
                    )));
                }

                if wait_options.contains(WaitOptions::WNOHANG) {
                    return Some(Ok(None));
                }

                if is_nonblocking {
                    return Some(Err(Error::with_message(
                        Errno::EAGAIN,
                        "the PID file is nonblocking and the child has not terminated",
                    )));
                }

                // wait
                None
            })
        },
    )??;

    Ok(zombie_child)
}

fn wait_filter(child_pid: Pid, child: &Arc<Process>, child_filter: &ProcessFilter) -> bool {
    match &child_filter {
        ProcessFilter::Any => true,
        ProcessFilter::WithPid(pid) => child_pid == *pid,
        ProcessFilter::WithPgid(pgid) => child.pgid() == *pgid,
        ProcessFilter::WithPidfd(pid_file) => match pid_file.process_opt() {
            Some(process) => Arc::ptr_eq(&process, child),
            None => false,
        },
    }
}

pub(crate) enum WaitStatus {
    Zombie(Arc<Process>),
    Stop(Arc<Process>, SigNum),
    Continue(Arc<Process>),
    TraceeExit(Arc<Thread>, ExitCode),
    TraceeStop(Arc<Thread>, PtraceWaitStatus),
    TraceeContinue(Arc<Thread>),
}

impl WaitStatus {
    pub(crate) fn pid(&self) -> Pid {
        self.source().pid()
    }

    pub(crate) fn uid(&self) -> Uid {
        self.source().uid()
    }

    pub(crate) fn prof_clock(&self) -> &Arc<ProfClock> {
        self.source().prof_clock()
    }

    fn source(&self) -> ChildSource<'_> {
        match self {
            WaitStatus::Zombie(process)
            | WaitStatus::Stop(process, _)
            | WaitStatus::Continue(process) => ChildSource::Process(process.as_ref()),
            WaitStatus::TraceeExit(thread, _)
            | WaitStatus::TraceeStop(thread, _)
            | WaitStatus::TraceeContinue(thread) => {
                ChildSource::Thread(thread.as_posix_thread().unwrap())
            }
        }
    }
}

/// The result of trying to wait for a child/tracee state change.
enum WaitResult {
    /// A waitable status is found.
    Found(WaitStatus),
    /// At least one target matches, but none is waitable yet.
    MatchedButUnready,
    /// No target matches the wait filter.
    NoMatch,
}

/// Checks tracees for exited, ptrace-stopped, or continued threads.
///
/// The tracees of all threads in the current process are checked, or only those of the current
/// thread with `__WNOTHREAD`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1697-L1710>
fn try_wait_tracees(
    child_filter: &ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> WaitResult {
    if wait_options.contains(WaitOptions::WNOTHREAD) {
        return try_wait_tracees_of(ctx.posix_thread, child_filter, None, wait_options, ctx);
    }

    // Do not hold the lock of tasks while checking tracees to avoid deadlocks
    // when two processes trace the threads of each other.
    let tasks = ctx.process.tasks().lock().as_slice().to_vec();

    let mut fallback_result = WaitResult::NoMatch;
    for task in tasks {
        let tracer = task.as_posix_thread().unwrap();
        match try_wait_tracees_of(tracer, child_filter, None, wait_options, ctx) {
            WaitResult::Found(status) => return WaitResult::Found(status),
            WaitResult::MatchedButUnready => fallback_result = WaitResult::MatchedButUnready,
            WaitResult::NoMatch => {}
        }
    }

    fallback_result
}

/// Checks the tracees of `tracer` for exited, ptrace-stopped, or continued threads.
///
/// If `only_tid` is `Some(_)`, only the tracee with the thread ID is checked.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1465-L1566>
fn try_wait_tracees_of(
    tracer: &PosixThread,
    child_filter: &ProcessFilter,
    only_tid: Option<Tid>,
    wait_options: WaitOptions,
    ctx: &Context,
) -> WaitResult {
    // Lock order: tracer.tracees -> tracee.tracee_status
    let Some(tracees) = tracer.tracees() else {
        return WaitResult::NoMatch;
    };
    let tracees = tracees.lock();

    let mut fallback_result = WaitResult::NoMatch;

    for thread in tracees.values() {
        let tracee = thread.as_posix_thread().unwrap();
        if only_tid.is_some_and(|tid| tid != tracee.tid()) {
            continue;
        }
        let Some(process) = tracee.weak_process().upgrade() else {
            continue;
        };
        if !wait_filter(tracee.tid(), &process, child_filter) {
            continue;
        }

        // Exit/death by signal is reported first to the tracer, then,
        // when the tracer consumes the waitpid(2) result, to the real
        // parent (to the real parent only when the whole multithreaded
        // process exits). If the tracer and the real parent are the same
        // process, the report is sent only once.
        //
        // Reference: <https://man7.org/linux/man-pages/man2/ptrace.2.html>
        if thread.is_exited() {
            // Lock order: tracer.tracees -> tracee_process.tasks
            if Arc::ptr_eq(&process.main_thread(), thread) && !process.status().is_zombie() {
                // Delay reporting `TraceeExit` for a process's main-thread tracee until the
                // process becomes zombie.
                //
                // This avoids a race when the main thread is the last thread to exit and its
                // tracer is also its parent: the thread has called `Thread::exit()` but
                // `ProcessStatus::set_zombie()` has not run yet, so an early wait could
                // report the same exit twice, first as `WaitStatus::TraceeExit` and
                // later as `WaitStatus::Zombie`.
                //
                // Also matches Linux behavior:
                // <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/exit.c#L1486-L1487>.
                //
                // The ptrace-stop state of an exited tracee cannot change, so only an exit
                // or a continuation remains to be waited for.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1536-L1543>
                if wait_options.intersects(WaitOptions::WEXITED | WaitOptions::WCONTINUED) {
                    fallback_result = WaitResult::MatchedButUnready;
                }
                if wait_options.contains(WaitOptions::WCONTINUED)
                    && process.wait_continued(wait_options)
                {
                    return WaitResult::Found(WaitStatus::TraceeContinue(thread.clone()));
                }
                continue;
            }

            // Without `WEXITED`, a reapable exited tracee is skipped as if it did not match.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1192-L1193>
            if !wait_options.contains(WaitOptions::WEXITED) {
                continue;
            }

            // The exit of a main thread is reported with the exit code of its process,
            // which may be a group exit code set by another thread.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1275-L1276>
            let exit_code = if Arc::ptr_eq(&process.main_thread(), thread) {
                process.status().exit_code()
            } else {
                tracee.exit_code()
            };

            let thread = thread.clone();
            if !wait_options.contains(WaitOptions::WNOWAIT) {
                cleanup_exited_tracee(&process, &thread, tracees, ctx);
            }
            return WaitResult::Found(WaitStatus::TraceeExit(thread, exit_code));
        }

        // We have found at least one live tracee matching `child_filter`.
        fallback_result = WaitResult::MatchedButUnready;

        // Waiting for ptrace-stops does not require `WaitOptions::WSTOPPED`.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1349-L1353>
        if let Some(status) = tracee.wait_ptrace_stopped(wait_options) {
            return WaitResult::Found(WaitStatus::TraceeStop(thread.clone(), status));
        }

        // The continuation is per-process and can be consumed by either the tracer or the real
        // parent, whichever waits for it first.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1560-L1565>
        if wait_options.contains(WaitOptions::WCONTINUED) && process.wait_continued(wait_options) {
            return WaitResult::Found(WaitStatus::TraceeContinue(thread.clone()));
        }
    }

    fallback_result
}

fn cleanup_exited_tracee(
    process: &Arc<Process>,
    thread: &Arc<Thread>,
    mut tracees: MutexGuard<BTreeMap<Tid, Arc<Thread>>>,
    ctx: &Context,
) {
    let tracee = thread.as_posix_thread().unwrap();
    tracees.remove(&tracee.tid());
    let is_exit_notify_deferred = tracee.detach_tracer();
    drop(tracees);

    if is_exit_notify_deferred {
        // Cascade the exit notification to the real parent.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1279-L1290>
        send_child_death_signal(process);
        return;
    }

    if !process.status().is_zombie() {
        return;
    }
    if !Arc::ptr_eq(&process.main_thread(), thread) {
        return;
    }
    let tracee_parent = process.parent().lock().process().clone();
    let is_our_child = core::ptr::eq(Weak::as_ptr(&tracee_parent), Arc::as_ptr(&ctx.process));
    if !is_our_child {
        return;
    }

    reap_zombie_child(
        process.pid(),
        ctx.process.children().lock().as_mut().unwrap(),
        ctx.process.reaped_children_stats(),
    );
}

/// Checks children for zombie, stopped, or continued processes.
///
/// The children of all threads in the current process are checked, or only those of the current
/// thread with `__WNOTHREAD`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1465-L1566>
fn try_wait_children(
    child_filter: &ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> WaitResult {
    let is_wnothread = wait_options.contains(WaitOptions::WNOTHREAD);
    // This is checked before locking the children to keep the lock order.
    let is_first_alive_thread = is_wnothread && is_first_alive_thread(ctx);

    // Acquire the children lock at first to prevent race conditions.
    // We want to ensure that multiple waiting threads
    // do not return the same waited process status.
    let mut children_lock = ctx.process.children().lock();
    let children_mut = children_lock.as_mut().unwrap();

    let mut fallback_result = WaitResult::NoMatch;
    // The tracers in the current process whose tracees are children of the current thread.
    let mut tracers_of_children = Vec::new();

    for child in children_mut.values() {
        if !wait_filter(child.pid(), child, child_filter) || !is_eligible_child(child, wait_options)
        {
            continue;
        }
        if is_wnothread && !is_child_of_current_thread(child, is_first_alive_thread, ctx) {
            continue;
        }

        let main_thread = child.main_thread();
        let main_posix_thread = main_thread.as_posix_thread().unwrap();
        let tracer = main_posix_thread.tracer();

        if let Some(tracer) = tracer.as_ref()
            && core::ptr::eq(
                Weak::as_ptr(tracer.as_posix_thread().unwrap().weak_process()),
                Arc::as_ptr(&ctx.process),
            )
        {
            // A child traced by a thread in the current process is handled as a tracee. This
            // also hides the group stop from the real parent, so that a stop is not reported
            // twice.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1494-L1507>
            if is_wnothread && !core::ptr::eq(tracer.as_ref(), ctx.thread) {
                tracers_of_children.push((tracer.clone(), main_posix_thread.tid()));
            }
            continue;
        }

        if child.status().is_zombie() {
            // A zombie child traced by another process is reaped after the tracer reaps or
            // detaches it.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1509-L1519>
            if tracer.is_none() {
                // Without `WEXITED`, a zombie child is skipped as if it did not match.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1192-L1193>
                if !wait_options.contains(WaitOptions::WEXITED) {
                    continue;
                }

                let child = child.clone();
                if !wait_options.contains(WaitOptions::WNOWAIT) {
                    reap_zombie_child(
                        child.pid(),
                        children_mut,
                        ctx.process.reaped_children_stats(),
                    );
                }
                return WaitResult::Found(WaitStatus::Zombie(child));
            }
        }

        // We have found at least one child matching `child_filter`, whose state may change.
        fallback_result = WaitResult::MatchedButUnready;

        // The real parent waits for group stops even if the child is traced by another process.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1311-L1321>
        if wait_options.contains(WaitOptions::WSTOPPED)
            && let Some(sig_num) = child.wait_group_stopped(wait_options)
        {
            return WaitResult::Found(WaitStatus::Stop(child.clone(), sig_num));
        }
        if wait_options.contains(WaitOptions::WCONTINUED) && child.wait_continued(wait_options) {
            return WaitResult::Found(WaitStatus::Continue(child.clone()));
        }
    }

    drop(children_lock);

    // With `__WNOTHREAD`, a child of the current thread traced by another thread in the current
    // process is not checked in `try_wait_tracees`.
    for (tracer, tid) in tracers_of_children {
        let tracer = tracer.as_posix_thread().unwrap();
        match try_wait_tracees_of(tracer, child_filter, Some(tid), wait_options, ctx) {
            WaitResult::Found(status) => return WaitResult::Found(status),
            WaitResult::MatchedButUnready => fallback_result = WaitResult::MatchedButUnready,
            WaitResult::NoMatch => {}
        }
    }

    fallback_result
}

/// Returns whether `child` matches `__WALL` and `__WCLONE` in `wait_options`.
///
/// A "clone" child is one that sends no `SIGCHLD` to its parent on exit. It is waited for only
/// with `__WCLONE`, and otherwise only the other children are waited for, unless with `__WALL`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1152-L1177>
fn is_eligible_child(child: &Process, wait_options: WaitOptions) -> bool {
    if wait_options.contains(WaitOptions::WALL) {
        return true;
    }

    let is_clone_child = child.exit_signal() != Some(SIGCHLD);
    is_clone_child == wait_options.contains(WaitOptions::WCLONE)
}

/// Returns whether the current thread is the first alive thread in the current process, which
/// inherits the children of the exited threads.
fn is_first_alive_thread(ctx: &Context) -> bool {
    let tasks = ctx.process.tasks().lock();
    tasks
        .as_slice()
        .iter()
        .map(|task| task.as_thread().unwrap())
        .find(|thread| !thread.is_exited())
        .is_some_and(|thread| core::ptr::eq(thread.as_ref(), ctx.thread))
}

/// Returns whether `child` is a child of the current thread.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1635-L1643>
fn is_child_of_current_thread(child: &Process, is_first_alive_thread: bool, ctx: &Context) -> bool {
    // Lock order: children of process -> parent of process
    let parent_thread = child.parent().lock().thread().upgrade();
    match parent_thread {
        Some(thread) if !thread.is_exited() => core::ptr::eq(thread.as_ref(), ctx.thread),
        _ => is_first_alive_thread,
    }
}

/// Free zombie child with `child_pid`, returns the exit code of child process.
fn reap_zombie_child(
    child_pid: Pid,
    children_lock: &mut BTreeMap<Pid, Arc<Process>>,
    reaped_children_stats: &Mutex<ReapedChildrenStats>,
) -> ExitCode {
    let child_process = release_zombie_child(child_pid, children_lock);

    let (mut user_time, mut kernel_time) = child_process.reaped_children_stats().lock().get();
    user_time += child_process.prof_clock().user_clock().read_time();
    kernel_time += child_process.prof_clock().kernel_clock().read_time();
    reaped_children_stats.lock().add(user_time, kernel_time);

    child_process.status().exit_code()
}

/// Removes zombie child with `child_pid` from the process tree.
///
/// Unlike [`reap_zombie_child`], this does not account the resource usage of the child to the
/// parent, which is the case when the child is reaped automatically.
pub(super) fn release_zombie_child(
    child_pid: Pid,
    children_lock: &mut BTreeMap<Pid, Arc<Process>>,
) -> Arc<Process> {
    let child_process = children_lock.remove(&child_pid).unwrap();
    assert!(child_process.status().is_zombie());

    let mut pid_table = pid_table::pid_table_mut();

    // Lock order: children of process -> PID table -> tasks of process
    debug_assert_eq!(child_process.tasks().lock().as_slice().len(), 1);
    debug_assert_eq!(
        child_process.tasks().lock().as_slice()[0]
            .as_posix_thread()
            .unwrap()
            .tid(),
        child_pid
    );

    // Lock order: children of process -> PID table
    // -> group of process -> group inner -> session inner

    // Remove the process from the global table
    pid_table.remove_process(child_process.pid());

    // Remove the process group and the session from global table, if necessary
    let mut child_group_mut = child_process.process_group.lock();
    child_process.clear_old_group_and_session(&mut child_group_mut, &mut pid_table);
    drop(child_group_mut);

    child_process
}

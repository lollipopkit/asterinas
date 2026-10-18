// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use super::{
    INIT_PROCESS_PID, Pid, Process, pid_table,
    sigchld::{self, ChildSource},
    signal::{constants::SIGCHLD, sig_num::SigNum},
    wait::release_zombie_child,
};
use crate::{
    events::IoEvents,
    fs::cgroupfs::CgroupMembership,
    prelude::*,
    process::{
        kill::check_signal_perm, posix_thread::AsPosixThread, signal::signals::user::UserSignal,
    },
    security::audit,
    thread::AsThread,
};

/// Exits the current POSIX process.
///
/// This is for internal use. Do NOT call this directly. When the last thread in the process exits,
/// [`do_exit`] or [`do_exit_group`] will invoke this method automatically.
///
/// [`do_exit`]: crate::process::posix_thread::do_exit
/// [`do_exit_group`]: crate::process::posix_thread::do_exit_group
pub(super) fn exit_process(ctx: &Context) {
    let current_process = ctx.process.as_ref();
    current_process.complete_vfork_done();

    // Drop fields in `Process`.
    drop_after!(current_process.lock_vmar().set_vmar(None));

    // Move the children to the reaper process and send them signals. The children should see a new
    // parent when they receive the signal.
    let children = move_children_to_reaper_process(current_process);
    for child in children.values() {
        send_parent_death_signal(child, ctx);
    }
    drop(children);

    // This must happen before the process can be reaped, so that audit hooks see the exit
    // before a waiter does.
    audit::on_exit(current_process);

    // Mark the current process as a zombie. After this point, it may be reaped concurrently and
    // removed from the process tree. For example, the process may no longer have a live parent if
    // the parent exits after reaping the process.
    //
    // This must happen after `move_children_to_reaper_process`. See the comments in
    // `find_reaper_process` for details.
    //
    // This must also happen while the children of the parent are locked, so that the parent
    // cannot reap the process before we decide whether it should be reaped automatically.
    with_parent_children(current_process, |parent_and_siblings| {
        current_process.status().set_zombie();

        current_process.pidfile_pollee.notify(IoEvents::IN);

        if let Some((parent, siblings)) = parent_and_siblings {
            notify_parent_of_death(current_process, parent, siblings);
        }
    });

    // Remove the process from the cgroup.
    let mut cgroup_guard = CgroupMembership::write_lock();
    cgroup_guard.move_process_to_root(current_process);
    drop(cgroup_guard);
}

/// Drops a value after releasing the lock or borrow guard.
///
/// For example, [`ThreadLocal::vmar`] needs to be borrowed during a context switch. This means that
/// the kernel may panic if we borrow it as mutable and tries to acquire a mutex while dropping the
/// last [`VmarHandle`]. This utility macro ensures that the value is dropped only after the borrow
/// guard has been released, preventing all these issues.
///
/// [`ThreadLocal::vmar`]: super::posix_thread::ThreadLocal::vmar
/// [`VmarHandle`]: crate::vm::vmar::VmarHandle
macro_rules! drop_after {
    ($expr:expr) => {
        let val = $expr;
        drop(val);
    };
}

pub(super) use drop_after;

/// Moves the children to a reaper process.
///
/// Returns the moved children. Note that no new processes can become this process's children after
/// this point, so the returned children reliably represent the set of children at the time the
/// process exits.
fn move_children_to_reaper_process(current_process: &Process) -> BTreeMap<Pid, Arc<Process>> {
    if current_process.is_init_process() {
        return BTreeMap::new();
    }

    while let Some(reaper_process) = find_reaper_process(current_process) {
        if let Ok(children) = move_process_children(current_process, &reaper_process) {
            reaper_process.children_wait_queue().wake_all();
            return children;
        }
    }

    let init_process = pid_table::pid_table_mut()
        .get_process(INIT_PROCESS_PID)
        .unwrap();
    let children = move_process_children(current_process, &init_process).unwrap();
    init_process.children_wait_queue().wake_all();

    children
}

/// Finds a reaper process for `current_process`.
///
/// If there is no reaper process for `current_process`, returns `None`.
fn find_reaper_process(current_process: &Process) -> Option<Arc<Process>> {
    // The current process is not yet zombie (see `exit_process`), so it cannot have been reaped,
    // and it is still present in its parent's children map. An exiting parent will move the
    // current process to a new reaper (updating this `Weak` reference) before becoming zombie
    // itself. Therefore, the parent is always alive and `upgrade` cannot fail.
    let mut parent = current_process.parent().lock().process().upgrade().unwrap();

    loop {
        if parent.is_init_process() {
            return Some(parent);
        }

        if !parent.has_child_subreaper.load(Ordering::Acquire) {
            return None;
        }

        let is_reaper = parent.is_child_subreaper();
        let is_zombie = parent.status().is_zombie();
        if is_reaper && !is_zombie {
            return Some(parent);
        }

        let grandparent = parent.parent().lock().process().upgrade();
        if let Some(grandparent) = grandparent {
            parent = grandparent;
        } else {
            // The grandparent was concurrently reaped and dropped, so we lost the path up the
            // ancestor chain. Retry from the current process's parent to pick up the latest reaper
            // assignment. This `upgrade` won't fail for the same reason explained above.
            parent = current_process.parent().lock().process().upgrade().unwrap();
        }
    }
}

/// Moves the children of `current_process` to be the children of `reaper_process`.
///
/// Returns the moved children on success. Otherwise, if the `reaper_process` is zombie, returns
/// `Err(())`.
fn move_process_children(
    current_process: &Process,
    reaper_process: &Arc<Process>,
) -> Result<BTreeMap<Pid, Arc<Process>>, ()> {
    // Lock order: children of process -> parent of process
    let mut reaper_process_children = reaper_process.children().lock();
    let Some(reaper_process_children) = reaper_process_children.as_mut() else {
        // The reaper process has exited, and it is not the init process
        // (since we never clear the init process's children).
        return Err(());
    };

    // We hold the lock of children while updating the children's parents.
    // This ensures when dealing with CLONE_PARENT,
    // the retrial will see an up-to-date real parent.
    let mut current_children = current_process.children().lock();
    let children = current_children.take().unwrap();

    for child_process in children.values() {
        let mut parent = child_process.parent.lock();
        reaper_process_children.insert(child_process.pid(), child_process.clone());
        parent.set_process(reaper_process);
        drop(parent);

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L689-L702>
        child_process.set_exit_signal(SIGCHLD);
        if child_process.status().is_zombie()
            && child_process
                .main_thread()
                .as_posix_thread()
                .unwrap()
                .tracer()
                .is_none()
        {
            notify_and_maybe_reap(
                child_process,
                reaper_process,
                reaper_process_children,
                false,
            );
        }
    }

    Ok(children)
}

/// Sends the parent-death signals to the children of the current thread, which is exiting but is
/// not the last thread in the current process.
///
/// The children are implicitly reparented to the first alive thread in the current process (see
/// [`ParentProcessGuard::thread`]). `was_first_alive` tells whether the current thread was the
/// first alive thread before it exited.
///
/// [`ParentProcessGuard::thread`]: super::process::ParentProcessGuard::thread
pub(super) fn send_parent_death_signals_on_thread_exit(was_first_alive: bool, ctx: &Context) {
    let children = {
        let children = ctx.process.children().lock();
        let Some(children) = children.as_ref() else {
            return;
        };

        // Lock order: children of process -> parent of process
        children
            .values()
            .filter(|child| match child.parent().lock().thread().upgrade() {
                Some(thread) if core::ptr::eq(thread.as_ref(), ctx.thread) => true,
                Some(thread) if !thread.is_exited() => false,
                _ => was_first_alive,
            })
            .cloned()
            .collect::<Vec<_>>()
    };

    for child in children.iter() {
        send_parent_death_signal(child, ctx);
    }
}

/// Sends the parent-death signals of the threads in `child` to `child`, as the current thread
/// (the parent thread of `child`) exits.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L726-L733>
fn send_parent_death_signal(child: &Process, ctx: &Context) {
    let signals = child
        .tasks()
        .lock()
        .as_slice()
        .iter()
        .filter(|task| !task.as_thread().unwrap().is_exited())
        .filter_map(|task| {
            let thread = task.as_posix_thread().unwrap();
            let sig_num = thread.parent_death_signal()?;
            check_signal_perm(thread, ctx, Some(sig_num)).ok()?;
            Some(sig_num)
        })
        .collect::<Vec<_>>();

    for sig_num in signals {
        child.enqueue_signal(Box::new(UserSignal::new_kill(sig_num, ctx)));
    }
}

/// Sends a child-death signal to the parent.
///
/// If the process is traced by a tracer in another process, the tracer is notified instead,
/// and the parent will be notified when the tracer reaps or detaches the process.
pub(super) fn send_child_death_signal(process: &Process) {
    with_parent_children(process, |parent_and_siblings| {
        if let Some((parent, siblings)) = parent_and_siblings {
            notify_parent_of_death(process, parent, siblings);
        }
    });
}

/// Runs `f` with the parent of `process` and the locked children of the parent.
///
/// While `f` runs, the parent of `process` cannot change. If `process` has no parent (i.e., it is
/// the init process), `f` gets `None`.
fn with_parent_children(
    process: &Process,
    f: impl FnOnce(Option<(&Arc<Process>, &mut BTreeMap<Pid, Arc<Process>>)>),
) {
    loop {
        let Some(parent) = process.parent().lock().process().upgrade() else {
            return f(None);
        };

        // Lock order: children of process -> parent of process
        let mut siblings = parent.children().lock();
        if !core::ptr::eq(
            process.parent().lock().process().as_ptr(),
            Arc::as_ptr(&parent),
        ) {
            // The parent has exited and moved `process` to a reaper concurrently.
            continue;
        }

        // The parent clears its children only after moving them to a reaper, which updates the
        // parent of `process`. So the children must still be present.
        return f(Some((&parent, siblings.as_mut().unwrap())));
    }
}

/// Notifies the parent of the death of `process`, which is a zombie child of `parent`.
fn notify_parent_of_death(
    process: &Process,
    parent: &Arc<Process>,
    siblings: &mut BTreeMap<Pid, Arc<Process>>,
) {
    if !siblings
        .get(&process.pid())
        .is_some_and(|child| core::ptr::eq(child.as_ref(), process))
    {
        // The process has been reaped concurrently.
        return;
    }

    let main_thread = process.main_thread();
    let main_posix_thread = main_thread.as_posix_thread().unwrap();
    if main_posix_thread.ptrace_defer_exit_notify(parent) {
        return;
    }

    let is_traced = main_posix_thread.tracer().is_some();
    notify_and_maybe_reap(process, parent, siblings, is_traced);
}

/// Notifies `parent` of the death of `process` and reaps it if `parent` does not care.
fn notify_and_maybe_reap(
    process: &Process,
    parent: &Arc<Process>,
    siblings: &mut BTreeMap<Pid, Arc<Process>>,
    is_traced: bool,
) {
    let autoreap = sigchld::notify_parent_of_death(
        ChildSource::Process(process),
        process.status().exit_code(),
        parent,
        child_death_signal(process, parent),
        is_traced,
    );

    if autoreap {
        release_zombie_child(process.pid(), siblings);
    }
}

/// Returns the signal that notifies `parent` of the death of `process`.
fn child_death_signal(process: &Process, parent: &Process) -> Option<SigNum> {
    let sig = process.exit_signal();

    // If the parent has executed a new program, it may not expect a custom exit signal.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2271-L2278>
    if sig != Some(SIGCHLD) && process.parent_exec_id() != parent.self_exec_id() {
        return Some(SIGCHLD);
    }

    sig
}

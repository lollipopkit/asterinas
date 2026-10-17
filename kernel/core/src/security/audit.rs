// SPDX-License-Identifier: MPL-2.0

//! Auditing the effects of processes.
//!
//! A component can attach an audit context to a process with
//! [`Process::set_audit_context`] and register [`AuditHooks`] to be told about the effects
//! of that process. A process keeps its audit context for its lifetime, and its children
//! inherit it on fork. Processes without an audit context are not audited.
//!
//! The hooks can also deny some events of audited processes before they happen, see
//! [`AuditHooks::check_event`].

use spin::Once;

use crate::{prelude::*, process::Process};

/// An effect of a process that is reported to the [`AuditHooks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditEvent {
    /// A file is opened for reading.
    FileRead,
    /// A file is opened for writing, created, removed, renamed, or changed in metadata.
    FileWritten,
    /// A program is executed.
    Exec,
    /// The entries of a directory are listed.
    DirListed,
    /// A path is looked up but does not exist.
    LookupMissed,
    /// A socket connects or sends a message to an address.
    Connect,
}

/// The identity of a file, which is stable across renames and links (`st_dev` and `st_ino`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileId {
    /// The ID of the device that contains the file.
    pub dev: u64,
    /// The inode number of the file.
    pub ino: u64,
}

/// The hooks that are called for processes with an audit context.
pub trait AuditHooks: Sync {
    /// Called after `child` is forked from `parent` and has inherited its audit context,
    /// before `child` starts running.
    fn on_fork(&self, parent: &Process, child: &Process);

    /// Called when `process` exits, before it can be reaped.
    fn on_exit(&self, process: &Process);

    /// Called when `process` causes `event`.
    ///
    /// `target` is the absolute path in the mount namespace for file events, and a
    /// printable address for [`AuditEvent::Connect`].
    fn on_event(&self, process: &Process, event: AuditEvent, target: &str);

    /// Called after [`Self::on_event`] when `process` opens the file `file` at `target` for
    /// reading ([`AuditEvent::FileRead`]) or writing ([`AuditEvent::FileWritten`]).
    fn on_file_opened(&self, _process: &Process, _event: AuditEvent, _target: &str, _file: FileId) {
    }

    /// Called before `process` causes `event`, which is only done for
    /// [`AuditEvent::Connect`].
    ///
    /// Returning an error prevents the event, and the error is returned to the process.
    fn check_event(&self, _process: &Process, _event: AuditEvent, _target: &str) -> Result<()> {
        Ok(())
    }
}

static HOOKS: Once<&'static dyn AuditHooks> = Once::new();

/// Registers the audit hooks.
///
/// Returns `EBUSY` if hooks have already been registered.
pub fn register_hooks(hooks: &'static dyn AuditHooks) -> Result<()> {
    let mut is_registered = false;
    HOOKS.call_once(|| {
        is_registered = true;
        hooks
    });
    if !is_registered {
        return_errno_with_message!(Errno::EBUSY, "audit hooks have already been registered");
    }
    Ok(())
}

/// Returns whether the current process is audited.
///
/// This lets callers prepare the target of an event that is only reported after the
/// operation succeeds.
pub(crate) fn is_audited() -> bool {
    HOOKS.get().is_some()
        && Process::current().is_some_and(|process| process.audit_context().is_some())
}

/// Reports an event of the current process, if it is audited.
///
/// `target` is only called if the event is reported. The event is not reported if `target`
/// returns `None`.
pub(crate) fn audit(event: AuditEvent, target: impl FnOnce() -> Option<String>) {
    let Some(hooks) = HOOKS.get() else {
        return;
    };
    let Some(process) = Process::current() else {
        return;
    };
    if process.audit_context().is_none() {
        return;
    }
    if let Some(target) = target() {
        hooks.on_event(&process, event, &target);
    }
}

/// Reports that the current process opens a file, if it is audited.
///
/// `target` and `file` are only called if the event is reported. The event is not reported if
/// `target` returns `None`.
pub(crate) fn audit_open(
    event: AuditEvent,
    target: impl FnOnce() -> Option<String>,
    file: impl FnOnce() -> Option<FileId>,
) {
    let Some(hooks) = HOOKS.get() else {
        return;
    };
    let Some(process) = Process::current() else {
        return;
    };
    if process.audit_context().is_none() {
        return;
    }
    let Some(target) = target() else {
        return;
    };
    hooks.on_event(&process, event, &target);
    if let Some(file) = file() {
        hooks.on_file_opened(&process, event, &target, file);
    }
}

/// Checks whether the current process may cause an event, if it is audited.
///
/// `target` is only called if the event is checked, and the event is allowed if it returns
/// `None`.
pub(crate) fn check(event: AuditEvent, target: impl FnOnce() -> Option<String>) -> Result<()> {
    let Some(hooks) = HOOKS.get() else {
        return Ok(());
    };
    let Some(process) = Process::current() else {
        return Ok(());
    };
    if process.audit_context().is_none() {
        return Ok(());
    }
    match target() {
        Some(target) => hooks.check_event(&process, event, &target),
        None => Ok(()),
    }
}

/// Lets a newly forked child inherit the audit context of its parent.
///
/// This must be called before the child starts running.
pub(crate) fn on_fork(parent: &Process, child: &Process) {
    let Some(context) = parent.audit_context() else {
        return;
    };
    // The child is not running yet, so nothing else can set its audit context.
    child.set_audit_context(context.clone()).unwrap();
    if let Some(hooks) = HOOKS.get() {
        hooks.on_fork(parent, child);
    }
}

/// Reports that an audited process exits.
pub(crate) fn on_exit(process: &Process) {
    if process.audit_context().is_none() {
        return;
    }
    if let Some(hooks) = HOOKS.get() {
        hooks.on_exit(process);
    }
}

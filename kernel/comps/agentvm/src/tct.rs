// SPDX-License-Identifier: MPL-2.0

//! Tool-call transactions (TCTs).
//!
//! A TCT groups the processes that run one agent tool call. A process joins a TCT with
//! [`Tct::begin`] and stays in it for its lifetime: the TCT is the audit context of the
//! process, so it is inherited on fork and kept across exec, and a process cannot leave it
//! or join another one. Ending a TCT does not move its processes out, so processes that
//! outlive the tool call (e.g., daemons) remain attributable to it.
//!
//! The [`Effect`]s of the processes in a TCT are recorded through the audit hooks. A TCT and
//! its effects stay available after it ends, until it is released with [`Tct::release`].
//!
//! The data of ended TCTs becomes durable through [`Tct::commit`]. A commit only happens when
//! no TCT is running, and no TCT begins until it finishes, so the durable state never
//! contains part of a tool call. A TCT is running if it has not ended and some of its
//! processes have not exited; a TCT whose processes have all exited cannot write any more,
//! even if its controller never ends it. One commit covers every TCT that is not running.
//!
//! Each commit creates a new epoch: the durable state that contains the TCTs that it covers.
//! The caller of a commit can hold the commit gate after the data is durable, so that no TCT
//! begins until the host has taken a snapshot of the epoch.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use aster_core::{
    fs::vfs::{sync_all_file_systems, sync_policy::SyncPolicy},
    prelude::*,
    process::{Process, signal::pause_on_until},
    security::audit::{AuditEvent, AuditHooks},
};
use ostd::sync::{Mutex, SpinLock, WaitQueue};

/// A tool-call transaction.
#[derive(Debug)]
pub(crate) struct Tct {
    id: u64,
    flags: TctFlags,
    nr_live_processes: AtomicUsize,
    has_ended: AtomicBool,
    /// The epoch of the commit that has made the data of the TCT durable, or zero if the TCT
    /// has not been committed.
    commit_epoch: AtomicU64,
    effects: Mutex<Effects>,
}

bitflags::bitflags! {
    /// The flags that a TCT is created with.
    pub(crate) struct TctFlags: u32 {
        /// Defers the sync requests of the processes in the TCT until it is committed, when
        /// all the file systems (in every mount namespace) are written back and flushed at
        /// once.
        ///
        /// This is only safe if the storage is rolled back to the state of the last commit
        /// after a crash, because data synced inside the TCT is not durable until then.
        const DEFER_SYNC = 1 << 0;
    }
}

/// The TCTs that have begun but not been released, indexed by ID.
static TCTS: Mutex<BTreeMap<u64, Arc<Tct>>> = Mutex::new(BTreeMap::new());

/// The commit state shared by all TCTs.
#[derive(Debug, Default)]
struct CommitState {
    /// The number of running TCTs, i.e., TCTs that have begun but not ended, and have
    /// processes that have not exited.
    nr_running: usize,
    /// Whether the commit gate is closed, i.e., a commit is in progress or its caller holds
    /// the gate.
    is_committing: bool,
    /// The epoch of the last commit, which starts from one.
    last_epoch: u64,
}

static COMMIT_STATE: SpinLock<CommitState> = SpinLock::new(CommitState {
    nr_running: 0,
    is_committing: false,
    last_epoch: 0,
});

/// The wait queue for changes of [`COMMIT_STATE`].
static COMMIT_WAIT_QUEUE: WaitQueue = WaitQueue::new();

/// A kind of effect that a TCT has.
///
/// The value is the tag of the effect in [`Tct::export_effects`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Effect {
    /// A file opened for reading.
    Read = b'r',
    /// A file opened for writing, created, removed, renamed, or changed in metadata.
    Write = b'w',
    /// A program executed.
    Exec = b'x',
    /// A directory whose entries were listed.
    List = b'l',
    /// A path that was looked up but did not exist.
    Missing = b'm',
    /// A socket address connected or sent to.
    Connect = b'c',
}

impl From<AuditEvent> for Effect {
    fn from(event: AuditEvent) -> Self {
        match event {
            AuditEvent::FileRead => Self::Read,
            AuditEvent::FileWritten => Self::Write,
            AuditEvent::Exec => Self::Exec,
            AuditEvent::DirListed => Self::List,
            AuditEvent::LookupMissed => Self::Missing,
            AuditEvent::Connect => Self::Connect,
        }
    }
}

/// The maximum number of distinct effects recorded for a TCT.
///
/// Further effects mark the record as incomplete, so a tool cannot exhaust kernel memory.
const MAX_NR_EFFECTS: usize = 65536;

/// The tag in [`Tct::export_effects`] that marks an incomplete record.
const INCOMPLETE_TAG: u8 = b'!';

#[derive(Debug, Default)]
struct Effects {
    set: BTreeSet<(Effect, String)>,
    is_incomplete: bool,
}

impl Tct {
    /// Creates a new TCT, which begins when a process is put into it with [`Self::begin`].
    pub(crate) fn new(flags: TctFlags) -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        Arc::new(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            flags,
            nr_live_processes: AtomicUsize::new(1),
            has_ended: AtomicBool::new(false),
            commit_epoch: AtomicU64::new(0),
            effects: Mutex::new(Effects::default()),
        })
    }

    /// Begins the TCT by putting `process`, which must be the current process, into it.
    ///
    /// Waits for any commit in progress to finish first.
    ///
    /// Returns `EPERM` if `process` is already in a TCT or has another audit context, or
    /// `EINTR` if a signal interrupts the wait.
    pub(crate) fn begin(self: &Arc<Self>, process: &Process) -> Result<()> {
        pause_on_until(&COMMIT_WAIT_QUEUE, || {
            let mut state = COMMIT_STATE.lock();
            if state.is_committing {
                return None;
            }
            state.nr_running += 1;
            Some(())
        })?;
        if let Err(err) = process.set_audit_context(self.clone()) {
            COMMIT_STATE.lock().nr_running -= 1;
            COMMIT_WAIT_QUEUE.wake_all();
            return Err(err);
        }
        // The TCT keeps running until it is inserted, because `process` is the current process,
        // which cannot exit before this returns, and the TCT cannot be ended before it can be
        // found by its ID. So no commit can start in between.
        TCTS.lock().insert(self.id, self.clone());
        Ok(())
    }

    /// Returns the TCT that `process` is in.
    pub(crate) fn of(process: &Process) -> Option<&Self> {
        process.audit_context()?.downcast_ref::<Self>()
    }

    /// Returns the TCT with the given ID, if it has not been released.
    pub(crate) fn get(id: u64) -> Result<Arc<Self>> {
        TCTS.lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "the TCT does not exist"))
    }

    /// Ends the TCT.
    ///
    /// Processes that outlive the TCT have their sync requests served directly from then on.
    /// The data of the TCT becomes durable once it is committed with [`Self::commit`], which
    /// the agent shim can do while the model handles the result of the tool call.
    ///
    /// Returns `EINVAL` if the TCT has already ended.
    pub(crate) fn end(&self) -> Result<()> {
        let mut state = COMMIT_STATE.lock();
        if self.has_ended.swap(true, Ordering::AcqRel) {
            return_errno_with_message!(Errno::EINVAL, "the TCT has already ended");
        }
        if self.nr_live_processes.load(Ordering::Relaxed) > 0 {
            state.nr_running -= 1;
            COMMIT_WAIT_QUEUE.wake_all();
        }
        Ok(())
    }

    /// Commits the data of the TCT, writing back and flushing all the file systems, so that
    /// the data is durable on return.
    ///
    /// The commit waits until no TCT is running, so the caller must end the other running
    /// TCTs that it controls first. It covers every TCT that is not running. If another commit
    /// has covered this TCT, this waits until the commit gate opens and returns without
    /// committing again, so a TCT is reported as committed only after any snapshot of its
    /// epoch has finished.
    ///
    /// If `should_hold` is true and this commit covers the TCT, the commit gate stays closed
    /// on return until [`Self::open_commit_gate`] is called.
    ///
    /// A failed commit can be retried. Returns `EINVAL` if the TCT has not ended, or `EINTR`
    /// if a signal interrupts the wait.
    pub(crate) fn commit(&self, should_hold: bool) -> Result<CommitOutcome> {
        if !self.has_ended.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::EINVAL, "the TCT has not ended");
        }

        let committed_epoch = pause_on_until(&COMMIT_WAIT_QUEUE, || {
            let mut state = COMMIT_STATE.lock();
            if state.is_committing {
                return None;
            }
            let epoch = self.commit_epoch.load(Ordering::Acquire);
            if epoch != 0 {
                return Some(Some(epoch));
            }
            if state.nr_running > 0 {
                return None;
            }
            state.is_committing = true;
            Some(None)
        })?;
        if let Some(epoch) = committed_epoch {
            return Ok(CommitOutcome {
                epoch,
                holds_gate: false,
            });
        }

        // No TCT can begin until the commit finishes, so these are all the TCTs, and none of
        // them is running. Each of them ended, or had all of its processes exit, before the
        // commit starts, so the commit covers all the sync requests that it deferred.
        let tcts: Vec<_> = TCTS
            .lock()
            .values()
            .filter(|tct| tct.commit_epoch.load(Ordering::Relaxed) == 0)
            .cloned()
            .collect();
        if let Err(err) = sync_all_file_systems() {
            Self::open_commit_gate();
            return Err(err);
        }

        let epoch = {
            let mut state = COMMIT_STATE.lock();
            state.last_epoch += 1;
            state.last_epoch
        };
        for tct in tcts {
            tct.commit_epoch.store(epoch, Ordering::Release);
        }
        if !should_hold {
            Self::open_commit_gate();
        }
        Ok(CommitOutcome {
            epoch,
            holds_gate: should_hold,
        })
    }

    /// Opens the commit gate that a commit has closed, so that TCTs can begin.
    pub(crate) fn open_commit_gate() {
        COMMIT_STATE.lock().is_committing = false;
        COMMIT_WAIT_QUEUE.wake_all();
    }

    /// Releases the TCT with the given ID, after which it can no longer be found by its ID.
    ///
    /// Returns `EBUSY` if the TCT has not ended, or if it deferred sync requests and has not
    /// been committed.
    pub(crate) fn release(id: u64) -> Result<()> {
        let mut tcts = TCTS.lock();
        let Some(tct) = tcts.get(&id) else {
            return_errno_with_message!(Errno::EINVAL, "the TCT does not exist");
        };
        if !tct.has_ended.load(Ordering::Relaxed)
            || (tct.flags.contains(TctFlags::DEFER_SYNC)
                && tct.commit_epoch.load(Ordering::Acquire) == 0)
        {
            return_errno_with_message!(Errno::EBUSY, "the TCT has not ended or been committed");
        }
        tcts.remove(&id);
        Ok(())
    }

    /// Returns the ID of the TCT.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Returns the number of processes in the TCT that have not exited.
    pub(crate) fn nr_live_processes(&self) -> usize {
        self.nr_live_processes.load(Ordering::Relaxed)
    }

    /// Exports the recorded effects.
    ///
    /// Each effect is encoded as its tag, followed by its target and a NUL byte. If some
    /// effects were not recorded, the output starts with an entry tagged `!` with an empty
    /// target.
    pub(crate) fn export_effects(&self) -> Vec<u8> {
        let effects = self.effects.lock();
        let mut buf = Vec::new();
        if effects.is_incomplete {
            buf.extend_from_slice(&[INCOMPLETE_TAG, 0]);
        }
        for (effect, target) in effects.set.iter() {
            buf.push(*effect as u8);
            buf.extend_from_slice(target.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn record(&self, effect: Effect, target: &str) {
        let entry = (effect, String::from(target));
        let mut effects = self.effects.lock();
        if effects.set.len() >= MAX_NR_EFFECTS && !effects.set.contains(&entry) {
            effects.is_incomplete = true;
            return;
        }
        effects.set.insert(entry);
    }
}

/// The outcome of [`Tct::commit`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct CommitOutcome {
    /// The epoch of the commit that covers the TCT.
    pub(crate) epoch: u64,
    /// Whether the caller holds the commit gate.
    pub(crate) holds_gate: bool,
}

/// The sync policy that defers the sync requests in TCTs with [`TctFlags::DEFER_SYNC`].
pub(crate) struct TctSyncPolicy;

impl SyncPolicy for TctSyncPolicy {
    /// A request may still be deferred after [`Tct::end`] starts, if it saw the TCT before
    /// it ended. That is safe: the request only covers data written before it, which is
    /// written back by the commit, because the commit starts after the TCT is marked ended.
    fn defers_sync(&self, process: &Process) -> bool {
        Tct::of(process).is_some_and(|tct| {
            tct.flags.contains(TctFlags::DEFER_SYNC) && !tct.has_ended.load(Ordering::Acquire)
        })
    }
}

/// The audit hooks that maintain TCTs.
pub(crate) struct TctAuditHooks;

impl AuditHooks for TctAuditHooks {
    fn on_fork(&self, _parent: &Process, child: &Process) {
        if let Some(tct) = Tct::of(child) {
            tct.nr_live_processes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_exit(&self, process: &Process) {
        let Some(tct) = Tct::of(process) else {
            return;
        };
        // A fork only adds a process to a TCT with a live process, so the TCT only stops
        // running here or in `Tct::end`, which serialize on the commit state.
        let mut state = COMMIT_STATE.lock();
        if tct.nr_live_processes.fetch_sub(1, Ordering::Relaxed) == 1
            && !tct.has_ended.load(Ordering::Acquire)
        {
            state.nr_running -= 1;
            COMMIT_WAIT_QUEUE.wake_all();
        }
    }

    fn on_event(&self, process: &Process, event: AuditEvent, target: &str) {
        if let Some(tct) = Tct::of(process) {
            tct.record(event.into(), target);
        }
    }
}

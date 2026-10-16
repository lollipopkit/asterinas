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
    process::Process,
    security::audit::{AuditEvent, AuditHooks},
};
use ostd::sync::Mutex;

/// A tool-call transaction.
#[derive(Debug)]
pub(crate) struct Tct {
    id: u64,
    flags: TctFlags,
    nr_live_processes: AtomicUsize,
    has_ended: AtomicBool,
    /// Whether the data of the TCT is durable, which is only false for a TCT with
    /// [`TctFlags::DEFER_SYNC`] that has not been committed by [`Tct::end`].
    is_committed: AtomicBool,
    effects: Mutex<Effects>,
}

bitflags::bitflags! {
    /// The flags that a TCT is created with.
    pub(crate) struct TctFlags: u32 {
        /// Defers the sync requests of the processes in the TCT until it ends, when all the
        /// file systems (in every mount namespace) are written back and flushed at once.
        ///
        /// This is only safe if the storage is rolled back to the state of the previous TCT
        /// after a crash, because data synced inside the TCT is not durable until it ends.
        const DEFER_SYNC = 1 << 0;
    }
}

/// The TCTs that have begun but not been released, indexed by ID.
static TCTS: Mutex<BTreeMap<u64, Arc<Tct>>> = Mutex::new(BTreeMap::new());

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
            is_committed: AtomicBool::new(!flags.contains(TctFlags::DEFER_SYNC)),
            effects: Mutex::new(Effects::default()),
        })
    }

    /// Begins the TCT by putting `process` into it.
    ///
    /// Returns `EPERM` if `process` is already in a TCT or has another audit context.
    pub(crate) fn begin(self: &Arc<Self>, process: &Process) -> Result<()> {
        process.set_audit_context(self.clone())?;
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
    /// Returns `EINVAL` if the TCT has already ended and been committed.
    ///
    /// With [`TctFlags::DEFER_SYNC`], all the file systems are written back and flushed, so
    /// the data of the TCT is durable on return. Processes that outlive the TCT have their
    /// sync requests served directly from then on. If committing the data fails, the TCT
    /// stays ended but uncommitted, and ending it again retries the commit.
    pub(crate) fn end(&self) -> Result<()> {
        // Stop deferring sync requests first, so that data synced by the processes that outlive
        // the TCT is not left out of the commit.
        let has_ended = self.has_ended.swap(true, Ordering::Relaxed);
        if self.is_committed.load(Ordering::Acquire) {
            if has_ended {
                return_errno_with_message!(Errno::EINVAL, "the TCT has already ended");
            }
            return Ok(());
        }
        sync_all_file_systems()?;
        self.is_committed.store(true, Ordering::Release);
        Ok(())
    }

    /// Releases the TCT with the given ID, after which it can no longer be found by its ID.
    ///
    /// Returns `EBUSY` if the TCT has not ended, or its data has not been committed.
    pub(crate) fn release(id: u64) -> Result<()> {
        let mut tcts = TCTS.lock();
        let Some(tct) = tcts.get(&id) else {
            return_errno_with_message!(Errno::EINVAL, "the TCT does not exist");
        };
        if !tct.has_ended.load(Ordering::Relaxed) || !tct.is_committed.load(Ordering::Acquire) {
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

/// The sync policy that defers the sync requests in TCTs with [`TctFlags::DEFER_SYNC`].
pub(crate) struct TctSyncPolicy;

impl SyncPolicy for TctSyncPolicy {
    fn defers_sync(&self, process: &Process) -> bool {
        Tct::of(process).is_some_and(|tct| {
            tct.flags.contains(TctFlags::DEFER_SYNC) && !tct.has_ended.load(Ordering::Relaxed)
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
        if let Some(tct) = Tct::of(process) {
            tct.nr_live_processes.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn on_event(&self, process: &Process, event: AuditEvent, target: &str) {
        if let Some(tct) = Tct::of(process) {
            tct.record(event.into(), target);
        }
    }
}

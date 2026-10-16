// SPDX-License-Identifier: MPL-2.0

//! Tool-call transactions (TCTs).
//!
//! A TCT groups the processes that run one agent tool call. A process joins a TCT with
//! [`Tct::begin`] and stays in it for its lifetime: the TCT is inherited on fork and kept
//! across exec, and a process cannot leave it or join another one. Ending a TCT does not
//! move its processes out, so processes that outlive the tool call (e.g., daemons) remain
//! attributable to it.
//!
//! The kernel records the [`Effect`]s of the processes in a TCT. A TCT and its effects stay
//! available after it ends, until it is released with [`Tct::release`].

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::Process;
use crate::prelude::*;

/// A tool-call transaction.
#[derive(Debug)]
pub(crate) struct Tct {
    id: u64,
    nr_live_processes: AtomicUsize,
    has_ended: AtomicBool,
    effects: Mutex<Effects>,
}

/// The TCTs that have begun but not been released, indexed by ID.
static TCTS: Mutex<BTreeMap<u64, Arc<Tct>>> = Mutex::new(BTreeMap::new());

/// A kind of effect that a TCT has.
///
/// The value is the tag of the effect in [`Tct::export_effects`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Effect {
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
    /// Begins a new TCT and puts `process` into it.
    ///
    /// Returns `EPERM` if `process` is already in a TCT.
    pub(crate) fn begin(process: &Process) -> Result<Arc<Self>> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        if process.tct().is_some() {
            return_errno_with_message!(Errno::EPERM, "the process is already in a TCT");
        }

        let tct = Arc::new(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            nr_live_processes: AtomicUsize::new(0),
            has_ended: AtomicBool::new(false),
            effects: Mutex::new(Effects::default()),
        });
        // Another thread of the process may join a TCT concurrently.
        if !Arc::ptr_eq(process.tct_once().call_once(|| tct.clone()), &tct) {
            return_errno_with_message!(Errno::EPERM, "the process is already in a TCT");
        }
        tct.nr_live_processes.fetch_add(1, Ordering::Relaxed);
        TCTS.lock().insert(tct.id, tct.clone());

        Ok(tct)
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
    /// Returns `EINVAL` if the TCT has already ended.
    pub(crate) fn end(&self) -> Result<()> {
        if self.has_ended.swap(true, Ordering::Relaxed) {
            return_errno_with_message!(Errno::EINVAL, "the TCT has already ended");
        }
        Ok(())
    }

    /// Releases the TCT with the given ID, after which it can no longer be found by its ID.
    ///
    /// Returns `EBUSY` if the TCT has not ended.
    pub(crate) fn release(id: u64) -> Result<()> {
        let mut tcts = TCTS.lock();
        let Some(tct) = tcts.get(&id) else {
            return_errno_with_message!(Errno::EINVAL, "the TCT does not exist");
        };
        if !tct.has_ended.load(Ordering::Relaxed) {
            return_errno_with_message!(Errno::EBUSY, "the TCT has not ended");
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

    /// Records an effect of the current process, if it is in a TCT.
    ///
    /// `target` is only called if the current process is in a TCT. The effect is not
    /// recorded if `target` returns `None`.
    pub(crate) fn record_current(effect: Effect, target: impl FnOnce() -> Option<String>) {
        let Some(process) = Process::current() else {
            return;
        };
        let Some(tct) = process.tct() else {
            return;
        };
        let Some(target) = target() else {
            return;
        };

        let mut effects = tct.effects.lock();
        let entry = (effect, target);
        if effects.set.len() >= MAX_NR_EFFECTS && !effects.set.contains(&entry) {
            effects.is_incomplete = true;
            return;
        }
        effects.set.insert(entry);
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

    /// Puts a newly forked child into the TCT of its parent, if any.
    ///
    /// This must be called before the child starts running.
    pub(super) fn inherit(parent: &Process, child: &Process) {
        let Some(tct) = parent.tct() else {
            return;
        };
        tct.nr_live_processes.fetch_add(1, Ordering::Relaxed);
        child.tct_once().call_once(|| tct.clone());
    }

    /// Records that a process in the TCT has exited.
    pub(super) fn on_process_exit(process: &Process) {
        if let Some(tct) = process.tct() {
            tct.nr_live_processes.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

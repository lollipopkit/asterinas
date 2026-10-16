// SPDX-License-Identifier: MPL-2.0

//! Tool-call transactions (TCTs).
//!
//! A TCT groups the processes that run one agent tool call. A process joins a TCT with
//! [`Tct::begin`] and stays in it for its lifetime: the TCT is inherited on fork and kept
//! across exec, and a process cannot leave it or join another one. Ending a TCT does not
//! move its processes out, so processes that outlive the tool call (e.g., daemons) remain
//! attributable to it.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::Process;
use crate::prelude::*;

/// A tool-call transaction.
#[derive(Debug)]
pub(crate) struct Tct {
    id: u64,
    nr_live_processes: AtomicUsize,
}

/// The TCTs that have begun but not ended, indexed by ID.
static OPEN_TCTS: Mutex<BTreeMap<u64, Arc<Tct>>> = Mutex::new(BTreeMap::new());

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
        });
        // Another thread of the process may join a TCT concurrently.
        if !Arc::ptr_eq(process.tct_once().call_once(|| tct.clone()), &tct) {
            return_errno_with_message!(Errno::EPERM, "the process is already in a TCT");
        }
        tct.nr_live_processes.fetch_add(1, Ordering::Relaxed);
        OPEN_TCTS.lock().insert(tct.id, tct.clone());

        Ok(tct)
    }

    /// Ends the TCT with the given ID and returns it.
    ///
    /// Returns `EINVAL` if no such TCT has begun, or if it has already ended.
    pub(crate) fn end(id: u64) -> Result<Arc<Self>> {
        let Some(tct) = OPEN_TCTS.lock().remove(&id) else {
            return_errno_with_message!(Errno::EINVAL, "the TCT does not exist or has ended");
        };

        Ok(tct)
    }

    /// Returns the ID of the TCT.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Returns the number of processes in the TCT that have not exited.
    pub(crate) fn nr_live_processes(&self) -> usize {
        self.nr_live_processes.load(Ordering::Relaxed)
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

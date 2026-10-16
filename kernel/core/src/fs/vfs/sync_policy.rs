// SPDX-License-Identifier: MPL-2.0

//! Deferring the sync requests of processes.
//!
//! A component can register a [`SyncPolicy`] that defers the sync requests of some
//! processes (`fsync`, `fdatasync`, `sync`, `syncfs`, `msync`, and writes to `O_SYNC` or
//! `O_DSYNC` files). A deferred request returns without writing anything back, so the policy
//! must make the data durable later, and must only defer requests whose data can be lost on
//! a crash (e.g., because the storage is rolled back to an earlier snapshot after a crash).

use spin::Once;

use crate::{prelude::*, process::Process};

/// A policy that decides whether the sync requests of a process are deferred.
pub trait SyncPolicy: Sync {
    /// Returns whether the sync requests of `process` are deferred.
    fn defers_sync(&self, process: &Process) -> bool;
}

static POLICY: Once<&'static dyn SyncPolicy> = Once::new();

/// Registers the sync policy.
///
/// Returns `EBUSY` if a policy has already been registered.
pub fn register_policy(policy: &'static dyn SyncPolicy) -> Result<()> {
    let mut is_registered = false;
    POLICY.call_once(|| {
        is_registered = true;
        policy
    });
    if !is_registered {
        return_errno_with_message!(Errno::EBUSY, "a sync policy has already been registered");
    }
    Ok(())
}

/// Returns whether the sync requests of the current process are deferred.
pub(crate) fn defers_current_sync() -> bool {
    let Some(policy) = POLICY.get() else {
        return false;
    };
    Process::current().is_some_and(|process| policy.defers_sync(&process))
}

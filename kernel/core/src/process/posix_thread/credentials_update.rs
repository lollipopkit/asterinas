// SPDX-License-Identifier: MPL-2.0

use core::{
    ops::Deref,
    sync::atomic::{Ordering, fence},
};

use aster_rights::ReadWriteOp;

use super::PosixThread;
use crate::{
    prelude::*,
    process::{
        Credentials, Dumpable, Gid, Process, SUID_DUMPABLE, Uid, credentials::capabilities::CapSet,
    },
};

/// The read-write credentials of the current thread.
///
/// Like `commit_creds` in Linux, an update that changes the effective or filesystem IDs or
/// gains permitted capabilities makes the process non-dumpable and clears the parent death
/// signal of the thread when this is dropped.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/cred.c#L383-L401>
pub(crate) struct CredentialsUpdate<'a> {
    credentials: Credentials<ReadWriteOp>,
    thread: &'a PosixThread,
    process: &'a Process,
    old_ids: DumpabilityIds,
    old_dumpable: Dumpable,
    _guard: MutexGuard<'a, ()>,
}

/// The parts of the credentials whose changes affect the dumpability.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DumpabilityIds {
    euid: Uid,
    egid: Gid,
    fsuid: Uid,
    fsgid: Gid,
    permitted: CapSet,
}

impl DumpabilityIds {
    fn of(credentials: &Credentials<ReadWriteOp>) -> Self {
        Self {
            euid: credentials.euid(),
            egid: credentials.egid(),
            fsuid: credentials.fsuid(),
            fsgid: credentials.fsgid(),
            permitted: credentials.permitted_capset(),
        }
    }

    fn changes_dumpability_to(&self, new: &Self) -> bool {
        self.euid != new.euid
            || self.egid != new.egid
            || self.fsuid != new.fsuid
            || self.fsgid != new.fsgid
            || !self.permitted.contains(new.permitted)
    }
}

impl<'a> CredentialsUpdate<'a> {
    pub(super) fn new(
        credentials: Credentials<ReadWriteOp>,
        thread: &'a PosixThread,
        process: &'a Process,
    ) -> Self {
        let guard = process.credentials_update_lock().lock();
        let old_ids = DumpabilityIds::of(&credentials);
        // The credentials are updated in place, so the process becomes non-dumpable before any
        // change is visible. Otherwise, an alien access check that races with dropping privileges
        // could see the new credentials with the old dumpability.
        let old_dumpable = process.swap_dumpable_locked(SUID_DUMPABLE);
        // Pairs with the fence in `check_dumpable_access`.
        fence(Ordering::Release);

        Self {
            credentials,
            thread,
            process,
            old_ids,
            old_dumpable,
            _guard: guard,
        }
    }
}

impl Deref for CredentialsUpdate<'_> {
    type Target = Credentials<ReadWriteOp>;

    fn deref(&self) -> &Self::Target {
        &self.credentials
    }
}

impl Drop for CredentialsUpdate<'_> {
    fn drop(&mut self) {
        if self
            .old_ids
            .changes_dumpability_to(&DumpabilityIds::of(&self.credentials))
        {
            self.thread.clear_parent_death_signal();
        } else {
            self.process.swap_dumpable_locked(self.old_dumpable);
        }
    }
}

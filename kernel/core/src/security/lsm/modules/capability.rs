// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{Ordering, fence};

use super::super::{
    LsmFlags, LsmModule,
    hooks::{AlienAccessContext, CapableContext, LsmAlienAccessHook, LsmCapabilityHook},
};
use crate::{
    prelude::*,
    process::{
        Dumpable, credentials::capabilities::CapSet, posix_thread::alien_access::CredsSource,
    },
};

pub(super) static CAPABILITY_LSM: CapabilityLsm = CapabilityLsm;

/// Capability-based authorization checks for built-in kernel operations.
pub(super) struct CapabilityLsm;

impl LsmModule for CapabilityLsm {
    fn name(&self) -> &'static str {
        "capability"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::empty()
    }
}

impl LsmCapabilityHook for CapabilityLsm {
    fn on_capable(&self, context: &CapableContext) -> Result<()> {
        // Since creating new user namespaces is not supported at the moment,
        // there is effectively only one user namespace in the entire system.
        // Therefore, the thread has a single set of capabilities used for permission checks.
        // FIXME: Once support for creating new user namespaces is added,
        // we should verify the thread's capabilities within the relevant user namespace.
        if context
            .posix_thread()
            .credentials()
            .effective_capset()
            .contains(context.required_cap())
        {
            return Ok(());
        }

        return_errno_with_message!(
            Errno::EPERM,
            "the thread does not have the required capability"
        );
    }
}

impl LsmAlienAccessHook for CapabilityLsm {
    fn on_alien_access(&self, context: &AlienAccessContext) -> Result<()> {
        let accessor_cred = context.accessor().credentials();
        let target_cred = context.target().credentials();
        let target_process = context.target().process();
        let has_ptrace_capability = || {
            let target_user_ns = target_process.user_ns().lock();
            self.on_capable(&CapableContext::new(
                target_user_ns.as_ref(),
                context.accessor(),
                CapSet::SYS_PTRACE,
            ))
            .is_ok()
        };

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/ptrace.c#L305-L371>
        let (caller_uid, caller_gid, caller_caps) = match context.mode().creds() {
            CredsSource::FsCreds => (
                accessor_cred.fsuid(),
                accessor_cred.fsgid(),
                accessor_cred.effective_capset(),
            ),
            CredsSource::RealCreds => (
                accessor_cred.ruid(),
                accessor_cred.rgid(),
                accessor_cred.permitted_capset(),
            ),
        };
        let caller_is_same = caller_uid == target_cred.euid()
            && caller_uid == target_cred.suid()
            && caller_uid == target_cred.ruid()
            && caller_gid == target_cred.egid()
            && caller_gid == target_cred.sgid()
            && caller_gid == target_cred.rgid();
        if !caller_is_same && !has_ptrace_capability() {
            return_errno_with_message!(
                Errno::EPERM,
                "the calling process does not have the required permissions"
            );
        }

        // Read the dumpability after the credentials. This pairs with the fence that follows
        // making the process non-dumpable before its credentials change.
        fence(Ordering::Acquire);
        if target_process.dumpable() != Dumpable::Owner && !has_ptrace_capability() {
            return_errno_with_message!(Errno::EPERM, "the target process is not dumpable");
        }

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/security/commoncap.c#L164-L186>
        if !caller_caps.contains(target_cred.permitted_capset()) && !has_ptrace_capability() {
            return_errno_with_message!(
                Errno::EPERM,
                "the target process has capabilities that the calling process does not have"
            );
        }

        Ok(())
    }
}

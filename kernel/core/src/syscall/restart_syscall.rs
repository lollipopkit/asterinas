// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

/// The continuation of a syscall interrupted with `ERESTART_RESTARTBLOCK`.
///
/// If no user signal handler runs, the interrupted syscall is replaced with `restart_syscall`,
/// which runs the continuation instead of the original syscall. This allows the syscall to
/// resume with updated arguments (e.g., the remaining time instead of the original timeout).
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/restart_block.h#L23-L57>
pub(crate) struct RestartBlock(Box<RestartFn>);

type RestartFn = dyn FnOnce(&Context) -> Result<isize> + Send;

impl RestartBlock {
    /// Stores `restart_fn` as the restart block of the current thread and returns the
    /// `ERESTART_RESTARTBLOCK` error to be returned by the interrupted syscall.
    //
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/thread_info.h#L83-L89>
    pub(super) fn set<F>(ctx: &Context, restart_fn: F) -> Error
    where
        F: FnOnce(&Context) -> Result<isize> + Send + 'static,
    {
        ctx.thread_local
            .set_restart_block(Some(RestartBlock(Box::new(restart_fn))));
        Error::new(Errno::ERESTART_RESTARTBLOCK)
    }
}

impl Debug for RestartBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RestartBlock").finish_non_exhaustive()
    }
}

pub(super) fn sys_restart_syscall(ctx: &Context) -> Result<SyscallReturn> {
    // Without a restart block, Linux runs `do_no_restart_syscall`, which returns `EINTR`.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3256-L3265>
    let Some(RestartBlock(restart_fn)) = ctx.thread_local.set_restart_block(None) else {
        return_errno_with_message!(Errno::EINTR, "there is no syscall to restart");
    };

    restart_fn(ctx).map(SyscallReturn::Return)
}

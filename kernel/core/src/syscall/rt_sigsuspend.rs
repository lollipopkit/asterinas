// SPDX-License-Identifier: MPL-2.0

use ostd::sync::Waiter;

use super::{
    SyscallReturn,
    rt_sigprocmask::{RequireFullSize, UserSigSetPtr},
};
use crate::{prelude::*, process::posix_thread::ContextPthreadAdminApi};

pub(super) fn sys_rt_sigsuspend(
    sigmask_addr: Vaddr,
    sigmask_size: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "sigmask_addr = 0x{:x}, sigmask_size = {}",
        sigmask_addr, sigmask_size
    );

    let user_space = ctx.user_space();
    let sigmask_ptr = {
        let size_policy = RequireFullSize::new(sigmask_size)?;
        UserSigSetPtr::new(&user_space, sigmask_addr, size_policy)
    };
    let sigmask = sigmask_ptr.read_val()?;
    ctx.save_and_set_sig_mask(sigmask);

    // Wait until receiving any signal. The error must be `EINTR`.
    let waiter = Waiter::new_pair().0;
    let _ = waiter.pause_until(|| None::<()>);

    // Restart the syscall unless a user signal handler runs. The saved signal mask is restored
    // after the signal is handled.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4913-L4925>
    return_errno_with_message!(
        Errno::ERESTARTNOHAND,
        "rt_sigsuspend is interrupted by a signal"
    );
}

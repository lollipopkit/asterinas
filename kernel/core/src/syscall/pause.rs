// SPDX-License-Identifier: MPL-2.0

use ostd::sync::Waiter;

use super::SyscallReturn;
use crate::prelude::*;

pub(super) fn sys_pause(_ctx: &Context) -> Result<SyscallReturn> {
    let waiter = Waiter::new_pair().0;

    // Wait until receiving any signal. The error must be `EINTR`.
    let _ = waiter.pause_until(|| None::<()>);

    // Restart the syscall unless a user signal handler runs.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4903-L4910>
    return_errno_with_message!(Errno::ERESTARTNOHAND, "pause is interrupted by a signal");
}

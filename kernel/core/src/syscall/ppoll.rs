// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmIo;

use super::{
    SyscallReturn,
    poll::{do_sys_poll, poll_select_end_time, poll_select_finish},
    rt_sigprocmask::{RequireFullSize, UserSigSetPtr},
};
use crate::{prelude::*, process::posix_thread::ContextPthreadAdminApi, time::timespec_t};

pub(super) fn sys_ppoll(
    fds: Vaddr,
    nfds: u32,
    timespec_addr: Vaddr,
    sigmask_addr: Vaddr,
    sigmask_size: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let user_space = ctx.user_space();

    let end_time = if timespec_addr != 0 {
        let time_spec = user_space.read_val::<timespec_t>(timespec_addr)?;
        poll_select_end_time(Some(Duration::try_from(time_spec)?))
    } else {
        None
    };

    if sigmask_addr != 0 {
        let sigmask_ptr = {
            let size_policy = RequireFullSize::new(sigmask_size)?;
            UserSigSetPtr::new(&user_space, sigmask_addr, size_policy)
        };
        let sigmask = sigmask_ptr.read_val()?;
        ctx.save_and_set_sig_mask(sigmask);
    }

    let res = do_sys_poll(fds, nfds, end_time, ctx);

    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/select.c#L1092-L1114>
    let write_remaining =
        |remaining: Duration| user_space.write_val(timespec_addr, &timespec_t::from(remaining));
    let num_revents = poll_select_finish(end_time, write_remaining, res, ctx)?;
    Ok(SyscallReturn::Return(num_revents as _))
}

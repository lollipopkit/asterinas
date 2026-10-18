// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmIo;

use super::{
    SyscallReturn,
    poll::{poll_select_end_time, poll_select_finish},
    rt_sigprocmask::{RequireFullSize, UserSigSetPtr},
    select::do_sys_select,
};
use crate::{
    fs::file::file_table::RawFileDesc,
    prelude::*,
    process::{posix_thread::ContextPthreadAdminApi, signal::sig_mask::SigMask},
    time::timespec_t,
};

pub(super) fn sys_pselect6(
    nfds: RawFileDesc,
    readfds_addr: Vaddr,
    writefds_addr: Vaddr,
    exceptfds_addr: Vaddr,
    timespec_addr: Vaddr,
    sigmask_addr: Vaddr,
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
        let sigmask_with_size = user_space.read_val::<SigMaskWithSize>(sigmask_addr)?;
        if sigmask_with_size.addr != 0 {
            let sigmask_ptr = {
                let size_policy = RequireFullSize::new(sigmask_with_size.size)?;
                UserSigSetPtr::new(&user_space, sigmask_with_size.addr, size_policy)
            };
            let sigmask: SigMask = sigmask_ptr.read_val()?;
            ctx.save_and_set_sig_mask(sigmask);
        }
    }

    let res = do_sys_select(
        nfds,
        readfds_addr,
        writefds_addr,
        exceptfds_addr,
        end_time,
        ctx,
    );

    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/select.c#L739-L772>
    let write_remaining =
        |remaining: Duration| user_space.write_val(timespec_addr, &timespec_t::from(remaining));
    let num_revents = poll_select_finish(end_time, write_remaining, res, ctx)?;
    Ok(SyscallReturn::Return(num_revents as _))
}

// Reference: <https://elixir.bootlin.com/linux/v6.19.8/source/fs/select.c#L763-L772>
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SigMaskWithSize {
    addr: Vaddr,
    size: usize,
}

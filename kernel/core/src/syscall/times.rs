// SPDX-License-Identifier: MPL-2.0

use ostd::{mm::VmIo, timer::Jiffies};

use super::SyscallReturn;
use crate::{
    prelude::*,
    time::{clock_t, duration_to_clock_t},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct Tms {
    tms_utime: clock_t,
    tms_stime: clock_t,
    tms_cutime: clock_t,
    tms_cstime: clock_t,
}

// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/sys.c#L1051-L1075>
pub(super) fn sys_times(tbuf: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    if tbuf != 0 {
        let process = ctx.process.as_ref();
        let prof_clock = process.prof_clock();
        let (cutime, cstime) = process.reaped_children_stats().lock().get();
        let tms = Tms {
            tms_utime: duration_to_clock_t(prof_clock.user_clock().read_time()),
            tms_stime: duration_to_clock_t(prof_clock.kernel_clock().read_time()),
            tms_cutime: duration_to_clock_t(cutime),
            tms_cstime: duration_to_clock_t(cstime),
        };
        ctx.user_space().write_val(tbuf, &tms)?;
    }

    // Linux starts its jiffies at `INITIAL_JIFFIES` to catch wrap-around bugs, so user space can
    // only rely on differences between the returned values.
    let ticks = duration_to_clock_t(Jiffies::elapsed().as_duration());
    Ok(SyscallReturn::Return(ticks as _))
}

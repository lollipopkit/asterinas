// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::{mm::VmIo, sync::Waiter};

use super::{ClockId, SyscallReturn, clock_gettime::read_clock, restart_syscall::RestartBlock};
use crate::{
    prelude::*,
    time::{
        TIMER_ABSTIME, TimerManager, clockid_t,
        clocks::{BootTimeClock, MonotonicClock, RealTimeClock},
        timer::Timeout,
        timespec_t,
        wait::ManagedTimeout,
    },
};

pub(super) fn sys_nanosleep(
    request_timespec_addr: Vaddr,
    remain_timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let clockid = ClockId::CLOCK_MONOTONIC;

    do_clock_nanosleep(
        clockid as clockid_t,
        false,
        request_timespec_addr,
        remain_timespec_addr,
        ctx,
    )
}

pub(super) fn sys_clock_nanosleep(
    clockid: clockid_t,
    flags: i32,
    request_timespec_addr: Vaddr,
    remain_timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let is_abs_time = (flags & TIMER_ABSTIME) != 0;

    do_clock_nanosleep(
        clockid,
        is_abs_time,
        request_timespec_addr,
        remain_timespec_addr,
        ctx,
    )
}

fn do_clock_nanosleep(
    clockid: clockid_t,
    is_abs_time: bool,
    request_timespec_addr: Vaddr,
    remain_timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    // Check the clock first.
    timer_manager_of(clockid, ctx)?;

    let request_time = {
        let timespec = ctx
            .user_space()
            .read_val::<timespec_t>(request_timespec_addr)?;
        Duration::try_from(timespec)?
    };

    debug!(
        "clockid = {:?}, is_abs_time = {}, request_time = {:?}, remain_timespec_addr = 0x{:x}",
        clockid, is_abs_time, request_time, remain_timespec_addr
    );

    if is_abs_time {
        if sleep_until(clockid, request_time, ctx)? {
            return Ok(SyscallReturn::Return(0));
        }

        // Absolute sleeps do not update the remaining time and restart with the original
        // arguments.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/hrtimer.c#L2458-L2461>
        return_errno_with_message!(Errno::ERESTARTNOHAND, "sleep was interrupted");
    }

    // Relative `CLOCK_REALTIME` sleeps are not affected by clock modifications.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/hrtimer.c#L1893-L1899>
    let clockid = if clockid == ClockId::CLOCK_REALTIME as clockid_t {
        ClockId::CLOCK_MONOTONIC as clockid_t
    } else {
        clockid
    };
    let expiry = read_clock(clockid, ctx)? + request_time;

    nanosleep_until(clockid, expiry, remain_timespec_addr, ctx).map(SyscallReturn::Return)
}

/// Sleeps until `expiry` for relative sleeps and their restarts.
///
/// If the sleep is interrupted, the remaining time is written to `remain_timespec_addr` (if not
/// null) and the syscall continues to sleep until `expiry` via `restart_syscall` unless a user
/// signal handler runs.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/hrtimer.c#L2399-L2443>
fn nanosleep_until(
    clockid: clockid_t,
    expiry: Duration,
    remain_timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<isize> {
    if sleep_until(clockid, expiry, ctx)? {
        return Ok(0);
    }

    if remain_timespec_addr != 0 {
        let now = read_clock(clockid, ctx)?;
        if now >= expiry {
            return Ok(0);
        }

        let remaining_timespec = timespec_t::from(expiry - now);
        ctx.user_space()
            .write_val(remain_timespec_addr, &remaining_timespec)?;
    }

    Err(RestartBlock::set(ctx, move |ctx| {
        nanosleep_until(clockid, expiry, remain_timespec_addr, ctx)
    }))
}

/// Sleeps until the clock reaches `expiry`.
///
/// Returns `true` if the sleep completes, or `false` if it is interrupted by a signal.
fn sleep_until(clockid: clockid_t, expiry: Duration, ctx: &Context) -> Result<bool> {
    let timer_manager = timer_manager_of(clockid, ctx)?;

    let waiter = Waiter::new_pair().0;
    let res = waiter.pause_until_or_timeout(
        || None::<()>,
        ManagedTimeout::new_with_manager(Timeout::When(expiry), timer_manager),
    );

    match res {
        Err(e) if e.error() == Errno::ETIME => Ok(true),
        Err(e) if e.error() == Errno::EINTR => Ok(read_clock(clockid, ctx)? >= expiry),
        Ok(()) | Err(_) => unreachable!(),
    }
}

fn timer_manager_of<'a>(clockid: clockid_t, ctx: &'a Context) -> Result<&'a Arc<TimerManager>> {
    let timer_manager = match ClockId::try_from(clockid)? {
        ClockId::CLOCK_BOOTTIME => BootTimeClock::timer_manager(),
        ClockId::CLOCK_MONOTONIC => MonotonicClock::timer_manager(),
        ClockId::CLOCK_REALTIME => RealTimeClock::timer_manager(),
        // FIXME: We should better not expose this prof timer manager.
        ClockId::CLOCK_PROCESS_CPUTIME_ID => {
            ctx.process.timer_manager().prof_timer().timer_manager()
        }
        // Linux returns `EOPNOTSUPP` for `CLOCK_THREAD_CPUTIME_ID`,
        // `CLOCK_MONOTONIC_RAW`, and the low-resolution coarse clocks.
        ClockId::CLOCK_THREAD_CPUTIME_ID
        | ClockId::CLOCK_MONOTONIC_RAW
        | ClockId::CLOCK_REALTIME_COARSE
        | ClockId::CLOCK_MONOTONIC_COARSE => {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "unsupported clockid for clock_nanosleep"
            );
        }
    };

    Ok(timer_manager)
}

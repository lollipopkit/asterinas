// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmIo;

use crate::{
    prelude::*,
    process::posix_thread::futex::{
        FUTEX_BITSET_MATCH_ANY, FutexFlags, FutexOp, FutexVisibility, futex_op_and_flags_from_u32,
        futex_requeue, futex_wait_bitset, futex_wake, futex_wake_bitset, futex_wake_op,
    },
    syscall::{SyscallReturn, restart_syscall::RestartBlock},
    time::{
        clocks::{MonotonicClock, RealTimeClock},
        timer::Timeout,
        timespec_t,
        wait::ManagedTimeout,
    },
};

pub(super) fn sys_futex(
    futex_addr: Vaddr,
    futex_op: i32,
    futex_val: u32,
    utime_addr: Vaddr,
    futex_new_addr: Vaddr,
    bitset: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let (futex_op, futex_flags) = futex_op_and_flags_from_u32(futex_op as _)?;
    debug!(
        "futex_op = {:?}, futex_flags = {:?}, futex_addr = 0x{:x}, futex_val = 0x{:x}",
        futex_op, futex_flags, futex_addr, futex_val
    );

    let get_futex_deadline = |timeout_addr: Vaddr| -> Result<Option<FutexDeadline>> {
        if timeout_addr == 0 {
            return Ok(None);
        }

        let timeout = {
            let time_spec: timespec_t = ctx.user_space().read_val(timeout_addr)?;
            Duration::try_from(time_spec)?
        };

        let is_real_time = futex_flags.contains(FutexFlags::FUTEX_CLOCK_REALTIME);
        if is_real_time && futex_op == FutexOp::FUTEX_WAIT {
            // Reference:
            // <https://github.com/torvalds/linux/commit/4fbf5d6837bf81fd7a27d771358f4ee6c4f243f8>
            return_errno_with_message!(Errno::ENOSYS, "FUTEX_WAIT cannot use CLOCK_REALTIME");
        }

        // For `FUTEX_WAIT`, `timeout` is interpreted as a relative value. This differs from
        // other futex operations, where `timeout` is interpreted as an absolute value.
        // Reference: <https://www.man7.org/linux/man-pages/man2/FUTEX_WAIT.2const.html>
        let expiry = if futex_op == FutexOp::FUTEX_WAIT {
            MonotonicClock::get().read_time().saturating_add(timeout)
        } else {
            timeout
        };
        debug!(
            "futex expiry = {:?}, is_real_time = {}",
            expiry, is_real_time
        );

        Ok(Some(FutexDeadline {
            expiry,
            is_real_time,
        }))
    };

    let visibility = FutexVisibility::from(futex_flags);
    let res = match futex_op {
        FutexOp::FUTEX_WAIT | FutexOp::FUTEX_WAIT_BITSET => {
            let bitset = if futex_op == FutexOp::FUTEX_WAIT {
                FUTEX_BITSET_MATCH_ANY
            } else {
                bitset
            };
            let deadline = get_futex_deadline(utime_addr)?;
            let res = do_futex_wait(futex_addr, futex_val, deadline, bitset, visibility, ctx);
            return res.map(SyscallReturn::Return);
        }
        FutexOp::FUTEX_WAKE => {
            let max_count = futex_val_to_max_count(futex_val);
            futex_wake(futex_addr as _, max_count, visibility)
        }
        FutexOp::FUTEX_WAKE_BITSET => {
            let max_count = futex_val_to_max_count(futex_val);
            futex_wake_bitset(futex_addr as _, max_count, bitset as _, visibility)
        }
        FutexOp::FUTEX_REQUEUE => {
            let max_nwakes = futex_val_to_max_count(futex_val);
            // `utime_addr` is used as the maximum number of requeues in this case.
            // When `utime_addr` is 0 or negative, it means no requeues.
            let max_nrequeues = (utime_addr as i32).max(0) as usize;
            futex_requeue(
                futex_addr as _,
                max_nwakes,
                max_nrequeues,
                futex_new_addr as _,
                ctx,
                visibility,
            )
        }
        FutexOp::FUTEX_WAKE_OP => {
            let futex_val_2 = utime_addr as u32;
            futex_wake_op(
                futex_addr,
                futex_new_addr,
                futex_val_to_max_count(futex_val),
                futex_val_to_max_count(futex_val_2),
                bitset,
                ctx,
                visibility,
            )
        }
        _ => {
            warn!("futex op = {:?}", futex_op);
            return_errno_with_message!(Errno::ENOSYS, "unsupported futex op");
        }
    }
    .map_err(|err| match err.error() {
        Errno::ETIME => Error::new(Errno::ETIMEDOUT),
        Errno::EINTR => Error::new(Errno::ERESTARTSYS),
        _ => err,
    })?;

    debug!("futex returns, tid = {}", ctx.posix_thread.tid());
    Ok(SyscallReturn::Return(res as _))
}

/// The absolute timeout of a futex wait.
#[derive(Clone, Copy, Debug)]
struct FutexDeadline {
    expiry: Duration,
    is_real_time: bool,
}

/// Waits on the futex until `deadline`.
///
/// If interrupted, a wait with a timeout continues via `restart_syscall` with the same deadline
/// unless a user signal handler runs, and a wait without a timeout restarts with `ERESTARTSYS`.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/futex/waitwake.c#L741-L785>
fn do_futex_wait(
    futex_addr: Vaddr,
    futex_val: u32,
    deadline: Option<FutexDeadline>,
    bitset: u32,
    visibility: FutexVisibility,
    ctx: &Context,
) -> Result<isize> {
    let timeout = deadline.map(|deadline| {
        let timer_manager = if deadline.is_real_time {
            RealTimeClock::timer_manager()
        } else {
            MonotonicClock::timer_manager()
        };
        ManagedTimeout::new_with_manager(Timeout::When(deadline.expiry), timer_manager)
    });

    let Err(err) = futex_wait_bitset(futex_addr, futex_val as _, timeout, bitset, ctx, visibility)
    else {
        return Ok(0);
    };

    match err.error() {
        Errno::ETIME => Err(Error::new(Errno::ETIMEDOUT)),
        Errno::EINTR if deadline.is_some() => Err(RestartBlock::set(ctx, move |ctx| {
            do_futex_wait(futex_addr, futex_val, deadline, bitset, visibility, ctx)
        })),
        Errno::EINTR => Err(Error::new(Errno::ERESTARTSYS)),
        _ => Err(err),
    }
}

fn futex_val_to_max_count(futex_val: u32) -> usize {
    // Linux wakes one waiter even if `futex_val` is 0 or negative. To be
    // consistent with Linux, we set `max_count` to 1 if it is 0 or negative.
    // Reference: <https://elixir.bootlin.com/linux/v7.2/source/kernel/futex/waitwake.c#L219>
    (futex_val as i32).max(1) as usize
}

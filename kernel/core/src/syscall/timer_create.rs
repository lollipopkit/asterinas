// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::{
    SyscallReturn,
    clock_gettime::{CpuClockOwner, DynamicClockIdInfo, DynamicClockType},
};
use crate::{
    prelude::*,
    process::{
        Process, pid_table,
        posix_thread::AsPosixThread,
        signal::{
            c_types::{SigNotify, sigevent_t, siginfo_t, sigval_t},
            constants::{SI_TIMER, SIGALRM},
            sig_num::SigNum,
            signals::raw::RawSignal,
        },
    },
    syscall::ClockId,
    thread::{
        Thread,
        work_queue::{submit_work_item, work_item::WorkItem},
    },
    time::{
        Timer, clockid_t,
        clocks::{BootTimeClock, MonotonicClock, RealTimeClock},
        timer::TimerGuard,
        timer_t,
    },
};

pub(super) fn sys_timer_create(
    clockid: clockid_t,
    sigevent_addr: Vaddr,
    timer_id_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let notify = if sigevent_addr == 0 {
        // If `sigevent_addr` is NULL, send `SIGALRM` to the current process with the timer ID as
        // `sival_int`.
        TimerNotify::Signal {
            target: SignalTarget::Process(ctx.process.clone()),
            num: SIGALRM,
            value: None,
        }
    } else {
        let sig_event = ctx.user_space().read_val::<sigevent_t>(sigevent_addr)?;
        let sigev_notify = SigNotify::try_from(sig_event.sigev_notify)?;
        let target = match sigev_notify {
            // Do nothing when the timer is expired.
            SigNotify::SIGEV_NONE => None,
            // Send a signal to the current process when the timer is expired.
            //
            // `SIGEV_THREAD` is implemented by the C library, so the kernel treats it like
            // `SIGEV_SIGNAL`.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/posix-timers.c#L411-L415>
            SigNotify::SIGEV_SIGNAL | SigNotify::SIGEV_THREAD => {
                Some(SignalTarget::Process(ctx.process.clone()))
            }
            // Send a signal to the specified thread when the timer is expired.
            SigNotify::SIGEV_THREAD_ID => {
                let tid = sig_event.sigev_un.read_tid() as u32;
                let thread = pid_table::pid_table_mut().get_thread(tid).ok_or_else(|| {
                    Error::with_message(Errno::EINVAL, "the target thread does not exist")
                })?;
                let posix_thread = thread.as_posix_thread().unwrap();
                if posix_thread.process().pid() != ctx.process.pid() {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "the target thread does not belong to the current process"
                    );
                }
                Some(SignalTarget::Thread(thread))
            }
        };
        match target {
            Some(target) => {
                let num = u8::try_from(sig_event.sigev_signo)
                    .map_err(|_| Error::with_message(Errno::EINVAL, "invalid signal number"))
                    .and_then(SigNum::try_from)?;
                TimerNotify::Signal {
                    target,
                    num,
                    value: Some(sig_event.sigev_value),
                }
            }
            None => TimerNotify::None,
        }
    };

    let timer_id = ctx.process.timer_manager().add_posix_timer(|timer_id| {
        let sent_signal = notify.into_callback(timer_id);
        let work_item = WorkItem::new(sent_signal);
        let func = move |_guard: TimerGuard| {
            submit_work_item(
                work_item.clone(),
                crate::thread::work_queue::WorkPriority::High,
            );
        };

        create_timer(clockid, func, ctx)
    })?;
    if let Err(error) = ctx.user_space().write_val(timer_id_addr, &timer_id) {
        let _ = ctx.process.timer_manager().remove_posix_timer(timer_id);
        return Err(error.into());
    }
    Ok(SyscallReturn::Return(0))
}

/// The notification method of a POSIX timer.
enum TimerNotify {
    None,
    Signal {
        target: SignalTarget,
        num: SigNum,
        /// The `sigev_value`, or `None` to use the timer ID as `sival_int`.
        value: Option<sigval_t>,
    },
}

enum SignalTarget {
    Process(Arc<Process>),
    Thread(Arc<Thread>),
}

impl TimerNotify {
    /// Converts the notification method into a callback that will be invoked when the timer
    /// with `timer_id` expires.
    fn into_callback(self, timer_id: timer_t) -> Box<dyn Fn() + Send + Sync + 'static> {
        let Self::Signal { target, num, value } = self else {
            return Box::new(|| {});
        };

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/time/posix-timers.c#L508-L531>
        //
        // TODO: Set `si_overrun` to the number of the timer overruns.
        let signal = {
            let mut info = siginfo_t::new(num, SI_TIMER);
            info.set_timer(timer_id, 0);
            info.set_value(value.unwrap_or_else(|| sigval_t::new_sigval_int(timer_id)));
            RawSignal::new(info)
        };

        match target {
            SignalTarget::Process(process) => Box::new(move || {
                process.enqueue_signal(Box::new(signal));
            }),
            SignalTarget::Thread(thread) => Box::new(move || {
                if let Some(posix_thread) = thread.as_posix_thread() {
                    posix_thread.enqueue_signal(Box::new(signal));
                }
            }),
        }
    }
}

pub(super) fn sys_timer_delete(timer_id: timer_t, ctx: &Context) -> Result<SyscallReturn> {
    let Some(timer) = ctx.process.timer_manager().remove_posix_timer(timer_id) else {
        return_errno_with_message!(Errno::EINVAL, "invalid timer ID");
    };

    timer.lock().cancel();
    Ok(SyscallReturn::Return(0))
}

/// Creates a timer associated with the specified fixed or dynamic clock ID.
///
/// This timer will invoke the given callback function (`func`) when it expires.
fn create_timer<F>(clockid: clockid_t, func: F, ctx: &Context) -> Result<Arc<Timer>>
where
    F: Fn(TimerGuard) + Send + Sync + 'static,
{
    let timer = if clockid >= 0 {
        return create_timer_for_clock(ClockId::try_from(clockid)?, func, ctx);
    } else {
        let clockid_info = DynamicClockIdInfo::try_from(clockid)?;
        let clock_type = clockid_info.clock_type();
        match clockid_info.owner(ctx, false)? {
            CpuClockOwner::Process(process) => {
                let process_timer_manager = process.timer_manager();
                match clock_type {
                    DynamicClockType::Profiling | DynamicClockType::Scheduling => {
                        process_timer_manager.create_prof_timer(func)
                    }
                    DynamicClockType::Virtual => process_timer_manager.create_virtual_timer(func),
                }
            }
            CpuClockOwner::Thread(thread) => {
                let posix_thread = thread.as_posix_thread().unwrap();
                match clock_type {
                    DynamicClockType::Profiling | DynamicClockType::Scheduling => {
                        posix_thread.create_prof_timer(func)
                    }
                    DynamicClockType::Virtual => posix_thread.create_virtual_timer(func),
                }
            }
        }
    };
    Ok(timer)
}

/// Creates a timer associated with the specified clock ID.
///
/// This timer will invoke the given callback function (`func`) when it expires.
pub(crate) fn create_timer_for_clock<F>(
    clock_id: ClockId,
    func: F,
    ctx: &Context,
) -> Result<Arc<Timer>>
where
    F: Fn(TimerGuard) + Send + Sync + 'static,
{
    let process_timer_manager = ctx.process.timer_manager();
    let timer = match clock_id {
        ClockId::CLOCK_PROCESS_CPUTIME_ID => process_timer_manager.create_prof_timer(func),
        ClockId::CLOCK_THREAD_CPUTIME_ID => ctx.posix_thread.create_prof_timer(func),
        ClockId::CLOCK_REALTIME => RealTimeClock::timer_manager().create_timer(func),
        ClockId::CLOCK_MONOTONIC => MonotonicClock::timer_manager().create_timer(func),
        ClockId::CLOCK_BOOTTIME => BootTimeClock::timer_manager().create_timer(func),
        _ => return_errno_with_message!(Errno::EINVAL, "invalid clock ID"),
    };
    Ok(timer)
}

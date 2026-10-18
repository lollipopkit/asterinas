// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{
        Pid, kill,
        signal::{
            c_types::siginfo_t,
            constants::SI_TKILL,
            sig_num::SigNum,
            signals::{Signal, raw::RawSignal},
        },
        tgkill,
    },
    thread::Tid,
};

/// Sends a signal with the user-provided `siginfo_t` to a process.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4273-L4300>
pub(super) fn sys_rt_sigqueueinfo(
    pid: i32,
    sig: i32,
    info_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let info = siginfo_t::read_from_user(info_addr, Some(sig), ctx)?;
    debug!("pid = {}, sig = {}, si_code = {}", pid, sig, info.si_code);

    check_si_code(&info, pid, ctx)?;
    if pid <= 0 {
        return_errno_with_message!(Errno::ESRCH, "the target process does not exist");
    }

    kill(pid as Pid, to_signal(sig, info)?, ctx)?;
    Ok(SyscallReturn::Return(0))
}

/// Sends a signal with the user-provided `siginfo_t` to a thread.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4316-L4340>
pub(super) fn sys_rt_tgsigqueueinfo(
    tgid: i32,
    tid: i32,
    sig: i32,
    info_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let info = siginfo_t::read_from_user(info_addr, Some(sig), ctx)?;
    debug!(
        "tgid = {}, tid = {}, sig = {}, si_code = {}",
        tgid, tid, sig, info.si_code
    );

    if tgid <= 0 || tid <= 0 {
        return_errno_with_message!(Errno::EINVAL, "non-positive TGIDs or TIDs are not valid");
    }
    check_si_code(&info, tid, ctx)?;

    tgkill(tid as Tid, Some(tgid as Pid), to_signal(sig, info)?, ctx)?;
    Ok(SyscallReturn::Return(0))
}

/// Checks that the user does not pretend to send signals from the kernel, `kill()`, or
/// `tgkill()`, unless the signal is sent to the current thread.
fn check_si_code(info: &siginfo_t, target_tid: i32, ctx: &Context) -> Result<()> {
    if (info.si_code >= 0 || info.si_code == SI_TKILL)
        && ctx.posix_thread.tid() != target_tid as Tid
    {
        return_errno_with_message!(
            Errno::EPERM,
            "signals with this code can only be sent to the current thread"
        );
    }
    Ok(())
}

fn to_signal(sig: i32, info: siginfo_t) -> Result<Option<Box<dyn Signal>>> {
    if sig == 0 {
        return Ok(None);
    }

    u8::try_from(sig)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid signal number"))
        .and_then(SigNum::try_from)?;
    Ok(Some(Box::new(RawSignal::new(info))))
}

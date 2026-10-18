// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::{SyscallReturn, wait4::calculate_rusage};
use crate::{
    prelude::*,
    process::{
        ProcessFilter, WaitOptions, WaitStatus, decode_exit_code, do_wait,
        signal::constants::{CLD_CONTINUED, CLD_STOPPED, CLD_TRAPPED, SIGCHLD, SIGCONT},
    },
};

pub(super) fn sys_waitid(
    which: u64,
    upid: u64,
    infoq_addr: u64,
    options: u64,
    rusage_addr: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let process_filter = ProcessFilter::from_which_and_id(which, upid as _, ctx)?;
    // The upper bits are ignored since `options` is an `int`.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1825-L1826>
    let wait_options = WaitOptions::from_bits(options as u32)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid options"))?;

    // Check for waitid options
    if !wait_options
        .intersects(WaitOptions::WSTOPPED | WaitOptions::WCONTINUED | WaitOptions::WEXITED)
    {
        return_errno_with_message!(
            Errno::EINVAL,
            "at least one of WSTOPPED, WCONTINUED, or WEXITED should be specified"
        );
    }

    let wait_status =
        do_wait(process_filter, wait_options, ctx).map_err(|err| match err.error() {
            Errno::EINTR => Error::new(Errno::ERESTARTSYS),
            _ => err,
        })?;

    if let Some(wait_status) = wait_status.as_ref()
        && rusage_addr != 0
    {
        ctx.user_space()
            .write_val(rusage_addr as usize, &calculate_rusage(wait_status))?;
    }

    if infoq_addr != 0 {
        // Like Linux, only the following fields of `siginfo_t` are written, which are zeros if
        // no child is waited for (with `WNOHANG`).
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/exit.c#L1839-L1851>
        let (si_signo, (si_code, si_status), pid, uid) = match wait_status.as_ref() {
            Some(wait_status) => (
                SIGCHLD.as_u8() as i32,
                calculate_si_code_and_si_status(wait_status),
                wait_status.pid(),
                wait_status.uid().into(),
            ),
            None => (0, (0, 0), 0, 0),
        };

        // The `si_signo`, `si_errno`, and `si_code` fields.
        let header: [i32; 3] = [si_signo, 0, si_code];
        ctx.user_space().write_val(infoq_addr as usize, &header)?;
        // The `si_pid`, `si_uid`, and `si_status` fields.
        let sigchld: [u32; 3] = [pid, uid, si_status as u32];
        ctx.user_space()
            .write_val(infoq_addr as usize + SIGCHLD_FIELDS_OFFSET, &sigchld)?;
    }

    Ok(SyscallReturn::Return(0))
}

/// The offset of the `_sigchld` fields in `siginfo_t`.
const SIGCHLD_FIELDS_OFFSET: usize = 16;

fn calculate_si_code_and_si_status(wait_status: &WaitStatus) -> (i32, i32) {
    match wait_status {
        WaitStatus::Zombie(process) => decode_exit_code(process.status().exit_code()),
        WaitStatus::Stop(_process, signum) => (CLD_STOPPED, signum.as_u8() as i32),
        WaitStatus::Continue(_) | WaitStatus::TraceeContinue(_) => {
            (CLD_CONTINUED, SIGCONT.as_u8() as i32)
        }
        WaitStatus::TraceeExit(_, exit_code) => decode_exit_code(*exit_code),
        WaitStatus::TraceeStop(_, status) => (CLD_TRAPPED, status.to_waitid_si_status()),
    }
}

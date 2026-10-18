// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{
        ProcessFilter, kill, kill_all, kill_group,
        signal::{
            sig_num::SigNum,
            signals::{Signal, user::UserSignal},
        },
    },
};

pub(super) fn sys_kill(process_filter: i32, sig_num: i32, ctx: &Context) -> Result<SyscallReturn> {
    let process_filter = ProcessFilter::from_id(process_filter)?;
    debug!(
        "process_filter = {:?}, sig_num = {}",
        process_filter, sig_num
    );
    do_sys_kill(process_filter, SigNum::try_from_raw(sig_num as u64), ctx)?;
    Ok(SyscallReturn::Return(0))
}

fn do_sys_kill(
    filter: ProcessFilter,
    sig_num: Result<Option<SigNum>>,
    ctx: &Context,
) -> Result<()> {
    let signal = sig_num.map(|sig_num| sig_num.map(|sig_num| UserSignal::new_kill(sig_num, ctx)));

    match filter {
        ProcessFilter::Any => kill_all(signal, ctx)?,
        ProcessFilter::WithPid(pid) => kill(
            pid,
            signal.map(|signal| signal.map(|s| Box::new(s) as Box<dyn Signal>)),
            ctx,
        )?,
        ProcessFilter::WithPgid(pgid) => kill_group(pgid, signal, ctx)?,
        ProcessFilter::WithPidfd(_) => unreachable!(),
    }
    Ok(())
}

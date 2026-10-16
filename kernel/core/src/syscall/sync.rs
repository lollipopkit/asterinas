// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::{
        file::{
            StatusFlags,
            file_table::{RawFileDesc, get_file_fast},
        },
        vfs::{file_system, sync_policy},
    },
    prelude::*,
};

/// Writes back all the file systems. Like Linux, this syncs the file systems in every mount
/// namespace and ignores errors.
///
/// Reference: Linux `ksys_sync()`.
pub(super) fn sys_sync(_ctx: &Context) -> Result<SyscallReturn> {
    if !sync_policy::defers_current_sync() {
        let _ = file_system::sync_all_file_systems();
    }
    Ok(SyscallReturn::Return(0))
}

pub(super) fn sys_syncfs(raw_fd: RawFileDesc, ctx: &Context) -> Result<SyscallReturn> {
    debug!("raw_fd = {}", raw_fd);

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, raw_fd.try_into()?);
    if file.status_flags().contains(StatusFlags::O_PATH) {
        return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
    }
    if !sync_policy::defers_current_sync() {
        file.path().fs().sync()?;
    }
    Ok(SyscallReturn::Return(0))
}

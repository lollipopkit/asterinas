// SPDX-License-Identifier: MPL-2.0

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcSym, ProcSymOps},
        vfs::inode::{Inode, SymbolicLink},
    },
    prelude::*,
    process::posix_thread::{AsPosixThread, alien_access::AlienAccessMode},
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/cwd` or `/proc/[pid]/task/[tid]/root` (and
/// also `/proc/[pid]/cwd` or `/proc/[pid]/root`).
pub(super) struct FsLinkSymOps {
    dir: TidDirOps,
    is_root: bool,
}

impl FsLinkSymOps {
    pub(super) fn new_cwd_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        Self::new_inode(dir, parent, false)
    }

    pub(super) fn new_root_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        Self::new_inode(dir, parent, true)
    }

    fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>, is_root: bool) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/base.c#L3671-L3672>
        // <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/base.c#L175-L176>
        let ops = Self {
            dir: dir.clone(),
            is_root,
        };
        ProcSym::new(ops, parent, mkmod!(a+rwx))
    }
}

impl ProcSymOps for FsLinkSymOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.dir.thread()
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        let Some(thread) = self.dir.thread() else {
            return_errno_with_message!(Errno::ESRCH, "the thread does not exist");
        };
        let posix_thread = thread.as_posix_thread().unwrap();
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/base.c#L1776-L1798>
        posix_thread
            .check_alien_access_from(
                current_thread!().as_posix_thread().unwrap(),
                AlienAccessMode::READ_WITH_FS_CREDS,
            )
            .map_err(|_| Error::with_message(Errno::EACCES, "alien access is denied"))?;

        // Linux drops the FS information of a task when it exits. Reference:
        // <https://elixir.bootlin.com/linux/v7.2.10/source/fs/proc/base.c#L222-L234>
        if thread.is_exited() {
            return_errno_with_message!(Errno::ENOENT, "the thread has exited");
        }

        let fs = posix_thread.read_fs();
        let resolver = fs.resolver().read();
        let path = if self.is_root {
            resolver.root()
        } else {
            resolver.cwd()
        };

        Ok(SymbolicLink::Path(path.clone()))
    }
}

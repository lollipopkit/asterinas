// SPDX-License-Identifier: MPL-2.0

//! Opened Inode-backed File Handle

use core::fmt::Display;

use super::{
    AccessMode, CreationFlags, FileCommon, FileLike, InodeType, MappableObject,
    SettableStatusFlags, StatusFlags, SyncMode, file_table::FdFlags, flock::FlockItem,
};
use crate::{
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        utils::DirentVisitor,
        vfs::{
            file_system::{FsFlags, FsWriteGuard},
            inode::{FallocMode, FileOps},
            inode_ext::InodeExt,
            path::{Path, WriteAccess},
            range_lock::{RangeLockItem, RangeLockOwner, RangeLockType},
            sync_policy,
            xattr::clear_file_priv,
        },
    },
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::{audit::AuditEvent, lsm::hooks as lsm_hooks},
    util::ioctl::RawIoctl,
    vm::vmar::FileMmapRequest,
};

pub(crate) struct InodeHandle {
    /// `open_file` is similar to the `file_private` field in Linux's `file` structure. If
    /// `open_file` is `Some(_)`, typical file operations including `read`, `write`, `poll`,
    /// and `ioctl` will be provided by the per-open file object instead of `path`.
    open_file: Option<Box<dyn PerOpenFileOps>>,
    offset: Mutex<usize>,
    /// Write access held while the file is open for writing (Linux `FMODE_WRITER`).
    _write_access: Option<WriteAccess>,
    /// Path and common states of the handle.
    //
    // This field is placed last so that its `Path` keeps the corresponding filesystem alive
    // while `open_file` is dropped, because releasing `open_file` may access that filesystem.
    //
    // Struct fields are dropped in declaration order.
    // Reference: <https://doc.rust-lang.org/reference/destructors.html>.
    common: FileCommon,
}

impl InodeHandle {
    pub(crate) fn new(
        path: Path,
        access_mode: AccessMode,
        status_flags: StatusFlags,
    ) -> Result<Self> {
        let inode = path.inode();
        if !status_flags.contains(StatusFlags::O_PATH) {
            // "Opening a file or directory with the O_PATH flag requires no permissions on the
            // object itself".
            // Reference: <https://man7.org/linux/man-pages/man2/openat.2.html>
            inode.check_permission(access_mode.into())?;
        }

        Self::new_unchecked_access(path, access_mode, status_flags)
    }

    pub(crate) fn new_unchecked_access(
        path: Path,
        mut access_mode: AccessMode,
        status_flags: StatusFlags,
    ) -> Result<Self> {
        let inode = path.inode();
        // Writing to a device, FIFO or socket does not write to its file system.
        let write_access = if access_mode.is_writable()
            && !status_flags.contains(StatusFlags::O_PATH)
            && !inode.type_().is_special_file()
            && inode.type_() != InodeType::Dir
        {
            Some(path.get_write_access()?)
        } else {
            None
        };
        let open_file = if status_flags.contains(StatusFlags::O_PATH) {
            // The file is opened with `O_PATH`. We follow Linux to report `O_RDONLY` here (e.g.,
            // in `/proc/[pid]/fdinfo/[n]`).
            access_mode = AccessMode::O_RDONLY;
            None
        } else if inode.type_() == InodeType::Dir && access_mode.is_writable() {
            return_errno_with_message!(Errno::EISDIR, "a directory cannot be opened writable");
        } else {
            inode
                .open(path.dentry(), access_mode, status_flags)
                .transpose()?
        };

        // Listing a directory is recorded by `readdir`.
        if !status_flags.contains(StatusFlags::O_PATH) && inode.type_() != InodeType::Dir {
            if access_mode.is_readable() {
                path.audit(AuditEvent::FileRead);
            }
            if access_mode.is_writable() {
                path.audit(AuditEvent::FileWritten);
            }
        }

        Ok(Self {
            open_file,
            offset: Mutex::new(0),
            _write_access: write_access,
            common: FileCommon::new(path, access_mode, status_flags),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.common.path()
    }

    pub(crate) fn access_mode(&self) -> AccessMode {
        self.common.access_mode()
    }

    pub(crate) fn status_flags(&self) -> StatusFlags {
        self.common.status_flags()
    }

    /// Handles the ioctl commands that act on the whole file system.
    fn fs_ioctl(&self, raw_ioctl: RawIoctl) -> Option<Result<()>> {
        use ioctl_defs::*;

        let check_sys_admin = || {
            let current = current_thread!();
            let posix_thread = current.as_posix_thread().unwrap();
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                UserNamespace::get_init_singleton().as_ref(),
                posix_thread,
                CapSet::SYS_ADMIN,
            ))
        };

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ Freeze => {
                Some(check_sys_admin().and_then(|()| self.path().fs().freeze()))
            }
            _cmd @ Thaw => {
                Some(check_sys_admin().and_then(|()| self.path().fs().thaw()))
            }
            _ => None,
        })
    }

    /// Starts a write through this file, which waits while its file system is frozen.
    ///
    /// Like Linux `file_start_write()`, it only applies to regular files.
    fn start_write(&self) -> Option<FsWriteGuard> {
        let path = self.path();
        path.type_()
            .is_regular_file()
            .then(|| path.fs().start_write())
    }

    /// Updates the access time after the inode was read.
    ///
    /// Reads served by per-open operations (devices, pipes) do not count, nor do files
    /// opened with `O_NOATIME`.
    ///
    /// Reference: Linux `file_accessed()`.
    fn file_accessed(&self) {
        if self.open_file.is_none() && !self.status_flags().contains(StatusFlags::O_NOATIME) {
            self.path().touch_atime();
        }
    }

    pub(crate) fn offset(&self) -> usize {
        let offset = self.offset.lock();
        *offset
    }

    fn file_ops_and_is_offset_aware(&self) -> (&dyn FileOps, bool) {
        if let Some(ref open_file) = self.open_file {
            let is_offset_aware = open_file.is_offset_aware();
            return (open_file.as_ref(), is_offset_aware);
        }

        let inode = self.path().inode();
        let is_offset_aware = inode.type_().is_seekable();
        (inode.as_ref(), is_offset_aware)
    }

    /// Returns the `FileOps` for positional I/O, rejecting files
    /// that do not support `pread`/`pwrite`.
    fn file_ops_for_positional_io(&self) -> Result<&dyn FileOps> {
        if let Some(ref open_file) = self.open_file {
            open_file.check_positional_io()?;
            return Ok(open_file.as_ref());
        }

        let inode = self.path().inode();
        if !inode.type_().is_seekable() {
            return_errno_with_message!(
                Errno::ESPIPE,
                "the inode cannot be read or written at a specific offset"
            );
        }
        Ok(inode.as_ref())
    }

    /// Makes the written data durable if the file is opened with `O_SYNC` or `O_DSYNC`, or
    /// its file system is mounted with `sync`.
    ///
    /// Reference: Linux `iocb_flags()` and `generic_write_sync()`.
    fn sync_written(&self, len: usize) -> Result<()> {
        if len == 0 || self.open_file.is_some() {
            return Ok(());
        }
        let status_flags = self.status_flags();
        if !status_flags.contains(StatusFlags::O_DSYNC)
            && !self.path().fs().flags().contains(FsFlags::SYNCHRONOUS)
        {
            return Ok(());
        }
        let mode = if status_flags.contains(StatusFlags::O_SYNC) {
            SyncMode::Full
        } else {
            SyncMode::Data
        };
        if sync_policy::defers_current_sync() {
            return Ok(());
        }
        self.path().sync(mode)
    }

    pub(crate) fn readdir(&self, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_readable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened readable");
        }

        let file_ops: &dyn FileOps = if let Some(ref open_file) = self.open_file {
            open_file.as_ref()
        } else {
            self.path().inode().as_ref()
        };
        let mut offset = self.offset.lock();
        let read_cnt = file_ops.readdir_at(*offset, visitor)?;
        *offset += read_cnt;
        self.file_accessed();
        self.path().audit(AuditEvent::DirListed);
        Ok(read_cnt)
    }

    pub(crate) fn test_range_lock(&self, mut lock: RangeLockItem) -> Result<RangeLockItem> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        let Some(range_lock_list) = self
            .path()
            .inode()
            .fs_lock_context()
            .map(|c| c.range_lock_list())
        else {
            // The lock list is not present. So nothing is locked.
            lock.set_type(RangeLockType::Unlock);
            return Ok(lock);
        };

        let req_lock = range_lock_list.test_lock(lock);
        Ok(req_lock)
    }

    pub(crate) fn set_range_lock(&self, lock: &RangeLockItem, is_nonblocking: bool) -> Result<()> {
        match lock.type_() {
            RangeLockType::ReadLock => {
                if self.status_flags().contains(StatusFlags::O_PATH)
                    || !self.access_mode().is_readable()
                {
                    return_errno_with_message!(Errno::EBADF, "the file is not opened readable");
                }
            }
            RangeLockType::WriteLock => {
                if self.status_flags().contains(StatusFlags::O_PATH)
                    || !self.access_mode().is_writable()
                {
                    return_errno_with_message!(Errno::EBADF, "the file is not opened writable");
                }
            }
            RangeLockType::Unlock => {
                if self.status_flags().contains(StatusFlags::O_PATH) {
                    return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
                }
            }
        }

        if RangeLockType::Unlock == lock.type_() {
            self.unlock_range_lock(lock);
            return Ok(());
        }

        let range_lock_list = self
            .path()
            .inode()
            .fs_lock_context_or_init()
            .range_lock_list();
        range_lock_list.set_lock(lock, is_nonblocking)
    }

    pub(crate) fn release_range_locks(&self, owner: RangeLockOwner) {
        if let Some(range_lock_list) = self
            .path()
            .inode()
            .fs_lock_context()
            .map(|context| context.range_lock_list())
        {
            range_lock_list.unlock_all(owner);
        }
    }

    fn unlock_range_lock(&self, lock: &RangeLockItem) {
        if let Some(range_lock_list) = self
            .path()
            .inode()
            .fs_lock_context()
            .map(|c| c.range_lock_list())
        {
            range_lock_list.unlock(lock);
        }
    }

    pub(crate) fn set_flock(&self, lock: FlockItem, is_nonblocking: bool) -> Result<()> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        let flock_list = self.path().inode().fs_lock_context_or_init().flock_list();
        flock_list.set_lock(lock, is_nonblocking)
    }

    pub(crate) fn unlock_flock(&self) -> Result<()> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        if let Some(flock_list) = self
            .path()
            .inode()
            .fs_lock_context()
            .map(|c| c.flock_list())
        {
            flock_list.unlock(self);
        }

        Ok(())
    }

    pub(crate) fn downcast_open_file<T: 'static>(&self) -> Result<Option<&T>> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        let Some(open_file) = self.open_file.as_ref() else {
            return Ok(None);
        };

        Ok((open_file.as_ref() as &dyn Any).downcast_ref::<T>())
    }
}

impl Pollable for InodeHandle {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        if let Some(ref open_file) = self.open_file {
            return open_file.poll(mask, poller);
        }

        if self.status_flags().contains(StatusFlags::O_PATH) {
            IoEvents::NVAL
        } else {
            let events = IoEvents::IN | IoEvents::OUT;
            events & mask
        }
    }
}

impl FileLike for InodeHandle {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_readable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened readable");
        }

        let (file_ops, is_offset_aware) = self.file_ops_and_is_offset_aware();
        let status_flags = self.status_flags();

        if !is_offset_aware {
            return file_ops.read_at(0, writer, status_flags);
        }

        let mut offset = self.offset.lock();

        let requested = writer.avail();
        let len = file_ops.read_at(*offset, writer, status_flags)?;
        *offset += len;
        // Like Linux `filemap_read()`, an empty request does not access the file.
        if requested > 0 {
            self.file_accessed();
        }

        Ok(len)
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_writable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened writable");
        }
        let _write = self.start_write();
        if reader.remain() > 0 {
            clear_file_priv(self.path().dentry())?;
        }

        let (file_ops, is_offset_aware) = self.file_ops_and_is_offset_aware();
        let status_flags = self.status_flags();

        if !is_offset_aware {
            return file_ops.write_at(0, reader, status_flags);
        }

        let mut offset = self.offset.lock();

        // FIXME: How can we deal with the `O_APPEND` flag if `open_file` is set?
        if status_flags.contains(StatusFlags::O_APPEND) && self.open_file.is_none() {
            // FIXME: `O_APPEND` should ensure that new content is appended even if another process
            // is writing to the file concurrently.
            *offset = self.path().size();
        }

        let len = file_ops.write_at(*offset, reader, status_flags)?;
        *offset += len;
        self.sync_written(len)?;

        Ok(len)
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let file_ops = self.file_ops_for_positional_io()?;
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_readable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened readable");
        }

        let status_flags = self.status_flags();

        let requested = writer.avail();
        let len = file_ops.read_at(offset, writer, status_flags)?;
        // Like Linux `filemap_read()`, an empty request does not access the file.
        if requested > 0 {
            self.file_accessed();
        }
        Ok(len)
    }

    fn write_at(&self, mut offset: usize, reader: &mut VmReader) -> Result<usize> {
        let file_ops = self.file_ops_for_positional_io()?;
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_writable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened writable");
        }
        let _write = self.start_write();
        if reader.remain() > 0 {
            clear_file_priv(self.path().dentry())?;
        }

        let status_flags = self.status_flags();

        // FIXME: How can we deal with the `O_APPEND` flag if `open_file` is set?
        if status_flags.contains(StatusFlags::O_APPEND) && self.open_file.is_none() {
            // If the file has the `O_APPEND` flag, the offset is ignored.
            // FIXME: `O_APPEND` should ensure that new content is appended even if another process
            // is writing to the file concurrently.
            offset = self.path().size();
        }

        let len = file_ops.write_at(offset, reader, status_flags)?;
        self.sync_written(len)?;
        Ok(len)
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        // Like Linux `do_vfs_ioctl()`, these apply to every file of the file system.
        if let Some(res) = self.fs_ioctl(raw_ioctl) {
            return res.map(|()| 0);
        }

        if let Some(ref open_file) = self.open_file {
            return open_file.ioctl(self.common.path(), raw_ioctl);
        }

        return_errno_with_message!(Errno::ENOTTY, "ioctl is not supported");
    }

    fn mappable(&self, request: FileMmapRequest) -> Result<MappableObject<'_>> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        if let Some(ref open_file) = self.open_file {
            // If the file is a special file (e.g., device file), we should
            // return the file-specific mappable object.
            return open_file.mappable(request);
        }

        let inode = self.path().inode();
        if let Some(page_cache) = inode.page_cache() {
            // Otherwise, if the inode has a page cache, it is a file-backed
            // mapping and we return the VMO as the mappable object.
            // Mapping a file counts as accessing it (Linux `generic_file_mmap()`).
            self.file_accessed();
            Ok(MappableObject::Vmo(page_cache))
        } else {
            return_errno_with_message!(Errno::ENODEV, "the file is not mappable");
        }
    }

    fn resize(&self, new_size: usize) -> Result<()> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }
        if !self.access_mode().is_writable() {
            return_errno_with_message!(Errno::EINVAL, "the file is not opened writable");
        }

        if self.status_flags().contains(StatusFlags::O_APPEND) {
            // FIXME: It's allowed to `ftruncate` an append-only file on Linux.
            return_errno_with_message!(Errno::EPERM, "can not resize append-only file");
        }
        // `ftruncate` uses the descriptor's write mode and must not recheck current inode
        // permissions. See <https://man7.org/linux/man-pages/man2/truncate.2.html>.
        let _write = self.start_write();
        self.path().resize_unchecked_access(new_size)
    }

    fn settable_status_flags(&self) -> SettableStatusFlags {
        if let Some(ref open_file) = self.open_file {
            return open_file.settable_status_flags();
        }

        if self.path().inode().type_().is_regular_file() {
            // FIXME: This operation should depend on whether the underlying filesystem supports `O_DIRECT`.
            SettableStatusFlags::minimal().with_o_direct()
        } else {
            SettableStatusFlags::minimal()
        }
    }

    fn seek(&self, pos: SeekFrom) -> Result<usize> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        if let Some(ref open_file) = self.open_file {
            open_file.check_seekable()?;
            if open_file.is_offset_aware() {
                return do_seek_util(&self.offset, pos, open_file.seek_end()?);
            } else {
                return Ok(0);
            }
        }

        let inode = self.path().inode();
        if !inode.type_().is_seekable() {
            return_errno_with_message!(Errno::ESPIPE, "seek is not supported");
        }
        do_seek_util(&self.offset, pos, inode.seek_end())
    }

    fn fallocate(&self, mode: FallocMode, offset: usize, len: usize) -> Result<()> {
        if self.status_flags().contains(StatusFlags::O_PATH) || !self.access_mode().is_writable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened writable");
        }
        let _write = self.start_write();

        let dentry = self.path().dentry();
        let inode = dentry.inode().as_ref();
        let inode_type = inode.type_();

        // TODO: `fallocate` on pipe files also fails with `ESPIPE`.
        if inode_type == InodeType::NamedPipe {
            return_errno_with_message!(Errno::ESPIPE, "the inode is a FIFO file");
        }
        if !(inode_type == InodeType::File || inode_type == InodeType::Dir) {
            return_errno_with_message!(
                Errno::ENODEV,
                "the inode is not a regular file or a directory"
            );
        }

        let status_flags = self.status_flags();
        if status_flags.contains(StatusFlags::O_APPEND)
            && (mode == FallocMode::PunchHoleKeepSize
                || mode == FallocMode::CollapseRange
                || mode == FallocMode::InsertRange)
        {
            return_errno_with_message!(
                Errno::EPERM,
                "the flags do not work on the append-only file"
            );
        }
        if status_flags.contains(StatusFlags::O_DIRECT)
            || status_flags.contains(StatusFlags::O_PATH)
        {
            return_errno_with_message!(
                Errno::EBADF,
                "currently fallocate file with O_DIRECT or O_PATH is not supported"
            );
        }

        clear_file_priv(dentry)?;
        inode.fallocate(mode, offset, len)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<InodeHandle>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut flags = self.inner.status_flags().bits() | self.inner.access_mode() as u32;
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= CreationFlags::O_CLOEXEC.bits();
                }

                writeln!(f, "pos:\t{}", self.inner.offset())?;
                writeln!(f, "flags:\t0{:o}", flags)?;
                writeln!(f, "mnt_id:\t{}", self.inner.path().mount_node().id())?;
                writeln!(f, "ino:\t{}", self.inner.path().inode().ino())
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }

    fn sync(&self, mode: SyncMode) -> Result<()> {
        if self.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the file is opened as a path");
        }

        if let Some(ref open_file) = self.open_file {
            return open_file.sync(mode);
        }

        self.path().sync(mode)
    }
}

impl Drop for InodeHandle {
    fn drop(&mut self) {
        let _ = self.unlock_flock();
    }
}

impl Debug for InodeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("InodeHandle")
            .field("path", &self.path())
            .field("offset", &self.offset())
            .field("status_flags", &self.status_flags())
            .finish_non_exhaustive()
    }
}

/// Describes the position to seek from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeekFrom {
    Start(usize),
    End(isize),
    Current(isize),
}

/// File operations for one opened file description.
///
/// A per-open file object can hold file-description-specific state and override
/// operations that are not purely inode-backed, such as state and operations for
/// devices, pipes, namespace files, and procfs files.
pub trait PerOpenFileOps: Pollable + FileOps + Any + Send + Sync + 'static {
    /// Checks whether the `seek()` operation should fail.
    fn check_seekable(&self) -> Result<()>;

    /// Returns whether the `read()`/`write()` operation should use and advance the offset.
    ///
    /// If [`PerOpenFileOps::check_seekable`] succeeds but this method returns `false`,
    /// the offset in the `seek()` operation will be ignored.
    /// In that case, the `seek()` operation will do nothing but succeed.
    fn is_offset_aware(&self) -> bool;

    /// Checks whether positional I/O (`pread`/`pwrite`) is supported.
    ///
    /// The default delegates to [`check_seekable`], which is correct for
    /// most files. Override this for files that support positional I/O
    /// but not seeking (e.g., nsfs).
    ///
    /// [`check_seekable`]: PerOpenFileOps::check_seekable
    fn check_positional_io(&self) -> Result<()> {
        self.check_seekable()
    }

    /// Returns the end position for [`SeekFrom::End`].
    ///
    /// This is intentionally separate from `Inode::seek_end`. Both `Inode`
    /// and [`PerOpenFileOps`] need `SEEK_END` support, but `Inode::seek_end`
    /// has an inode-specific default implementation, so the two cannot be
    /// cleanly unified under [`FileOps`].
    fn seek_end(&self) -> Result<Option<usize>> {
        Ok(None)
    }

    // See `FileLike::mappable`.
    fn mappable(&self, _request: FileMmapRequest) -> Result<MappableObject<'_>> {
        return_errno_with_message!(Errno::EINVAL, "the file is not mappable");
    }

    fn ioctl(&self, _path: &Path, _raw_ioctl: RawIoctl) -> Result<i32> {
        return_errno_with_message!(Errno::ENOTTY, "ioctl is not supported");
    }

    /// Returns the status flags that can be set for this opened file.
    fn settable_status_flags(&self) -> SettableStatusFlags {
        // `O_ASYNC` and `O_DIRECT` can only be set on file descriptions that explicitly
        // support them.
        SettableStatusFlags::minimal()
    }

    /// Synchronizes the file according to `mode`.
    ///
    /// Per-open file operations do not support synchronization by default.
    /// Implementations that support synchronization must override this method.
    fn sync(&self, _mode: SyncMode) -> Result<()> {
        return_errno_with_message!(Errno::EINVAL, "the file does not support synchronization")
    }
}

fn do_seek_util(offset: &Mutex<usize>, pos: SeekFrom, end: Option<usize>) -> Result<usize> {
    let mut offset = offset.lock();

    let new_offset = match pos {
        SeekFrom::Start(off) => off,
        SeekFrom::End(diff) => {
            if let Some(end) = end {
                end.wrapping_add_signed(diff)
            } else {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "seeking the file from the end is not supported"
                );
            }
        }
        SeekFrom::Current(diff) => offset.wrapping_add_signed(diff),
    };

    // Invariant: `*offset <= isize::MAX as usize`.
    // TODO: Investigate whether `read`/`write` can break this invariant.
    if new_offset.cast_signed() < 0 {
        return_errno_with_message!(Errno::EINVAL, "the file offset cannot be negative");
    }

    *offset = new_offset;
    Ok(new_offset)
}

mod ioctl_defs {
    use crate::{ioc, util::ioctl::InOutData};

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/fs.h>

    pub(super) type Freeze = ioc!(FIFREEZE, b'X', 119, InOutData<i32>);
    pub(super) type Thaw   = ioc!(FITHAW,   b'X', 120, InOutData<i32>);
}

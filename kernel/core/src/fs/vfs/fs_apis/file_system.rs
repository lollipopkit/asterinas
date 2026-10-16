// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};

use atomic_integer_wrapper::define_atomic_version_of_integer_like_type;
use device_id::DeviceId;

use super::inode::Inode;
use crate::prelude::*;

/// Common interface implemented by each concrete file system instance.
pub(crate) trait FileSystem: Any + Sync + Send {
    /// Gets the name of this FS type such as `"ext4"` or `"sysfs"`.
    fn name(&self) -> &'static str;

    /// Gets the source of this file system, e.g., the device name or user-provided source string.
    fn source(&self) -> Option<&str> {
        None
    }

    /// Syncs the file system.
    fn sync(&self) -> Result<()>;

    /// Returns the root inode of this file system.
    ///
    /// For each mount, the VFS invokes this method only once and eagerly when
    /// it creates the mount root. It never defers the lookup to a later path
    /// walk. For mounts created by `mount()`, the call happens in the thread
    /// context that performs the syscall.
    fn root_inode(&self) -> Arc<dyn Inode>;

    /// Returns the super block of this file system.
    fn sb(&self) -> SuperBlock;

    /// Returns the flags of this file system.
    fn flags(&self) -> FsFlags {
        // TODO: Currently we do not support any flags for filesystems.
        // Remove the default empty implementation in the future.
        FsFlags::empty()
    }

    /// Sets the flags of this file system.
    fn set_fs_flags(&self, _flags: FsFlags, _data: Option<&str>, _ctx: &Context) -> Result<()> {
        // TODO: Remove the default empty implementation in the future.
        warn!("setting file system flags is not implemented");
        Ok(())
    }

    /// Returns the FS event subscriber stats of this file system.
    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats;

    /// Returns the write state of this file system, shared by all of its mounts.
    fn write_state(&self) -> &FsWriteState;

    /// Shuts down this file system when the last mount referencing it is dropped.
    ///
    /// The file system is still alive during the call, so it can sync and write its final
    /// on-disk state (Linux `generic_shutdown_super()`). It is not called when another
    /// holder outlives the last mount, which leaves such a file system as not cleanly
    /// unmounted.
    fn shutdown(&self) {}
}

impl dyn FileSystem {
    /// Sets the flags of this file system, refusing to make it read-only while it has writers.
    ///
    /// Reference: Linux `reconfigure_super()` calling `sb_prepare_remount_readonly()`.
    pub(crate) fn reconfigure(
        &self,
        flags: FsFlags,
        data: Option<&str>,
        ctx: &Context,
    ) -> Result<()> {
        if flags.contains(FsFlags::RDONLY) && !self.flags().contains(FsFlags::RDONLY) {
            self.write_state()
                .writers()
                .make_read_only(|| self.set_fs_flags(flags, data, ctx))
        } else {
            self.set_fs_flags(flags, data, ctx)
        }
    }

    pub(crate) fn downcast_ref<T: FileSystem>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref::<T>()
    }
}

impl Debug for dyn FileSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("FileSystem")
            .field("super_block", &self.sb())
            .field("flags", &self.flags())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SuperBlock {
    pub magic: u64,
    pub bsize: usize,
    pub blocks: usize,
    pub bfree: usize,
    pub bavail: usize,
    pub files: usize,
    pub ffree: usize,
    pub fsid: u64,
    pub namelen: usize,
    pub frsize: usize,
    pub flags: u64,
    pub container_dev_id: DeviceId,
}

impl SuperBlock {
    pub(crate) fn new(
        magic: u64,
        block_size: usize,
        name_max_len: usize,
        dev_id: DeviceId,
    ) -> Self {
        Self {
            magic,
            bsize: block_size,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: 0,
            namelen: name_max_len,
            frsize: block_size,
            flags: 0,
            container_dev_id: dev_id,
        }
    }
}

bitflags! {
    /// Flags for per file system.
    pub(crate) struct FsFlags: u32 {
        /// The filesystem is mounted read-only.
        const RDONLY        =   1 << 0;
        /// Writes are synced at once.
        const SYNCHRONOUS   =   1 << 4;
        /// Allow mandatory locks on an FS.
        const MANDLOCK      =   1 << 6;
        /// Directory modifications are synchronous.
        const DIRSYNC       =   1 << 7;
        /// Suppress certain messages in kernel log.
        const SILENT        =   1 << 15;
        /// Update the on-disk [acm]times lazily.
        const LAZYTIME      =   1 << 25;
    }
}

impl core::fmt::Display for FsFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.contains(FsFlags::RDONLY) {
            write!(f, "ro")?;
        } else {
            write!(f, "rw")?;
        }
        if self.contains(FsFlags::SYNCHRONOUS) {
            write!(f, ",sync")?;
        }
        if self.contains(FsFlags::MANDLOCK) {
            write!(f, ",mandlock")?;
        }
        if self.contains(FsFlags::DIRSYNC) {
            write!(f, ",dirsync")?;
        }
        if self.contains(FsFlags::SILENT) {
            write!(f, ",silent")?;
        }
        if self.contains(FsFlags::LAZYTIME) {
            write!(f, ",lazytime")?;
        }
        Ok(())
    }
}

impl From<u32> for FsFlags {
    fn from(value: u32) -> Self {
        Self::from_bits_truncate(value)
    }
}

impl From<FsFlags> for u32 {
    fn from(value: FsFlags) -> Self {
        value.bits()
    }
}

define_atomic_version_of_integer_like_type!(FsFlags, {
    /// An atomic version of `FsFlags`.
    #[derive(Debug)]
    pub(crate) struct AtomicFsFlags(AtomicU32);
});

/// Write state of a file system, shared by all of its mounts.
#[derive(Debug)]
pub(crate) struct FsWriteState {
    writers: WriterCount,
}

impl FsWriteState {
    pub(crate) fn new() -> Self {
        Self {
            writers: WriterCount::new(),
        }
    }

    /// Returns the writers across all mounts.
    pub(crate) fn writers(&self) -> &WriterCount {
        &self.writers
    }
}

/// Counts the writers of a mount or a file system so that it becomes read-only only
/// when it has none.
///
/// A writer is an operation that writes, held for its duration, or a file opened for
/// writing, held until the file is closed.
///
/// Reference: Linux `mnt_get_write_access()` and `mnt_make_readonly()`.
#[derive(Debug)]
pub(crate) struct WriterCount {
    /// Taken shared to add a writer and exclusively to switch to read-only.
    transition: RwMutex<()>,
    writers: AtomicUsize,
}

impl WriterCount {
    pub(crate) fn new() -> Self {
        Self {
            transition: RwMutex::new(()),
            writers: AtomicUsize::new(0),
        }
    }

    /// Adds a writer unless `is_read_only` reports that the object is read-only.
    pub(crate) fn add(&self, is_read_only: impl FnOnce() -> bool) -> Result<()> {
        let _transition = self.transition.read();
        if is_read_only() {
            return_errno_with_message!(Errno::EROFS, "the mount or filesystem is read-only");
        }
        self.writers.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Removes a writer added by [`Self::add`].
    pub(crate) fn remove(&self) {
        let writers = self.writers.fetch_sub(1, Ordering::Release);
        debug_assert!(writers > 0);
    }

    /// Runs `make_read_only` unless there are writers, which fails with `EBUSY`.
    ///
    /// No writer can be added while `make_read_only` runs.
    pub(crate) fn make_read_only<T>(
        &self,
        make_read_only: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _transition = self.transition.write();
        if self.writers.load(Ordering::Acquire) > 0 {
            return_errno_with_message!(Errno::EBUSY, "the mount or filesystem has writers");
        }
        make_read_only()
    }
}

#[derive(Debug)]
pub(crate) struct FsEventSubscriberStats {
    // The number of subscribers to this file system.
    num_subscribers: AtomicI64,
}

impl FsEventSubscriberStats {
    pub(crate) fn new() -> Self {
        Self {
            num_subscribers: AtomicI64::new(0),
        }
    }

    pub(crate) fn add_subscriber(&self) {
        self.num_subscribers.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn remove_subscriber(&self) {
        let subscribers = self.num_subscribers.fetch_sub(1, Ordering::Release);
        debug_assert!(
            subscribers >= 0,
            "the number of subscribers is negative: {} (removed one)",
            subscribers
        );
    }

    pub(crate) fn remove_subscribers(&self, num_subscribers: usize) {
        let subscribers = self
            .num_subscribers
            .fetch_sub(num_subscribers as i64, Ordering::Release);
        debug_assert!(
            subscribers >= 0,
            "the number of subscribers is negative: {} (removed {})",
            subscribers,
            num_subscribers
        );
    }

    pub(crate) fn has_any_subscribers(&self) -> bool {
        self.num_subscribers.load(Ordering::Acquire) > 0
    }
}

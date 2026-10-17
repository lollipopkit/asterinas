// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};

use atomic_integer_wrapper::define_atomic_version_of_integer_like_type;
use device_id::DeviceId;
use ostd::sync::{RwMutexWriteGuard, WaitQueue};

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

    /// Returns whether reading a file or directory updates its access time.
    ///
    /// The VFS then updates it according to the mount's atime policy (Linux
    /// `file_accessed()` in `generic_file_read_iter()` and `iterate_dir()`). File systems
    /// whose reads are not page-cache reads of stored data, or whose server owns the
    /// access time (Linux FUSE sets `S_NOATIME`), keep the default.
    fn updates_atime(&self) -> bool {
        false
    }

    /// Returns whether this file system can be frozen with [`Self::freeze_fs`].
    fn supports_freeze(&self) -> bool {
        false
    }

    /// Makes the synced, writer-free file system consistent on disk before it is frozen
    /// (Linux `freeze_fs`).
    fn freeze_fs(&self) -> Result<()> {
        Ok(())
    }

    /// Undoes [`Self::freeze_fs`] before writes resume (Linux `unfreeze_fs`).
    fn unfreeze_fs(&self) -> Result<()> {
        Ok(())
    }

    /// Shuts down this file system when the last mount referencing it is dropped.
    ///
    /// The file system is still alive during the call, so it can sync and write its final
    /// on-disk state (Linux `generic_shutdown_super()`). It is not called when another
    /// holder outlives the last mount, which leaves such a file system as not cleanly
    /// unmounted.
    fn shutdown(&self) {}
}

/// The file systems that have been mounted and are still alive, like Linux `super_blocks`.
static FILE_SYSTEMS: Mutex<Vec<Weak<dyn FileSystem>>> = Mutex::new(Vec::new());

/// Records a mounted file system, so that [`sync_all_file_systems`] syncs it.
pub(in crate::fs) fn register_file_system(fs: &Arc<dyn FileSystem>) {
    let fs = Arc::downgrade(fs);
    let mut file_systems = FILE_SYSTEMS.lock();
    file_systems.retain(|weak| weak.strong_count() > 0);
    if !file_systems.iter().any(|weak| weak.ptr_eq(&fs)) {
        file_systems.push(fs);
    }
}

/// Writes back all the file systems and flushes their devices.
///
/// Unlike `sync(2)`, which ignores errors, this returns the first error after trying all the
/// file systems.
///
/// Reference: Linux `ksys_sync()`.
pub fn sync_all_file_systems() -> Result<()> {
    let file_systems: Vec<Arc<dyn FileSystem>> = FILE_SYSTEMS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .collect();

    let mut res = Ok(());
    for fs in file_systems {
        if let Err(err) = fs.sync() {
            res = res.and(Err(err));
        }
    }
    res
}

impl dyn FileSystem {
    /// Starts a write, waiting while this file system is frozen (Linux `sb_start_write()`).
    pub(crate) fn start_write(self: Arc<Self>) -> FsWriteGuard {
        self.write_state().freeze().enter();
        FsWriteGuard { fs: self }
    }

    /// Blocks new writes, waits for the running ones, syncs, and freezes this file system.
    ///
    /// Reference: Linux `freeze_super()`.
    pub(crate) fn freeze(&self) -> Result<()> {
        if !self.supports_freeze() {
            return_errno_with_message!(Errno::EOPNOTSUPP, "the file system cannot be frozen");
        }
        // A read-only file system has nothing to write back. The flags are read under the
        // freeze transition lock, which also serializes `reconfigure`.
        let is_read_only = || self.flags().contains(FsFlags::RDONLY);
        self.write_state().freeze().freeze(
            || if is_read_only() { Ok(()) } else { self.sync() },
            || {
                if is_read_only() {
                    Ok(())
                } else {
                    self.freeze_fs()
                }
            },
        )
    }

    /// Thaws this file system and lets blocked writes continue.
    ///
    /// Reference: Linux `thaw_super()`.
    pub(crate) fn thaw(&self) -> Result<()> {
        self.write_state().freeze().thaw(|| {
            if self.flags().contains(FsFlags::RDONLY) {
                return Ok(());
            }
            self.unfreeze_fs()
        })
    }

    /// Sets the flags of this file system, refusing to make it read-only while it has writers.
    ///
    /// Reference: Linux `reconfigure_super()` calling `sb_prepare_remount_readonly()`.
    pub(crate) fn reconfigure(
        &self,
        flags: FsFlags,
        data: Option<&str>,
        ctx: &Context,
    ) -> Result<()> {
        let _unfrozen = self.write_state().freeze().lock_unfrozen()?;
        let read_only_state = self.write_state().writers().lock_read_only_state();
        if flags.contains(FsFlags::RDONLY) && !self.flags().contains(FsFlags::RDONLY) {
            read_only_state.check_no_writers()?;
        }
        self.set_fs_flags(flags, data, ctx)
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
    freeze: FreezeGate,
}

impl FsWriteState {
    pub(crate) fn new() -> Self {
        Self {
            writers: WriterCount::new(),
            freeze: FreezeGate::new(),
        }
    }

    /// Returns the writers across all mounts.
    pub(crate) fn writers(&self) -> &WriterCount {
        &self.writers
    }

    /// Returns the gate that writes pass through while the file system is not frozen.
    pub(crate) fn freeze(&self) -> &FreezeGate {
        &self.freeze
    }
}

/// How far a file system is frozen (Linux `sb->s_writers.frozen`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreezeLevel {
    Unfrozen,
    /// New writes wait, and the freezer waits for the running ones to end.
    Freezing,
    Frozen,
}

#[derive(Debug)]
struct FreezeGateState {
    level: FreezeLevel,
    running_writes: usize,
}

/// Lets writes to a file system run only while it is not frozen.
///
/// Every write (an operation that modifies the file system, a write through a file, or a
/// write fault on a shared file mapping) runs inside `<dyn FileSystem>::start_write`,
/// which waits while the file system is frozen.
///
/// Reference: Linux `sb_start_write()`, `freeze_super()` and `thaw_super()`.
pub(crate) struct FreezeGate {
    state: SpinLock<FreezeGateState>,
    /// Woken when writes may resume or the last running write ends.
    wait_queue: WaitQueue,
    /// Taken shared by syncs and exclusively while the file system becomes frozen, so that
    /// no sync started before the freeze writes after it.
    sync_lock: RwMutex<()>,
    /// Serializes freezing and thawing.
    transition: Mutex<()>,
}

impl Debug for FreezeGate {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("FreezeGate")
            .field("state", &*self.state.lock())
            .finish_non_exhaustive()
    }
}

impl FreezeGate {
    fn new() -> Self {
        Self {
            state: SpinLock::new(FreezeGateState {
                level: FreezeLevel::Unfrozen,
                running_writes: 0,
            }),
            wait_queue: WaitQueue::new(),
            sync_lock: RwMutex::new(()),
            transition: Mutex::new(()),
        }
    }

    /// Starts a write, waiting while the file system is frozen or being frozen.
    ///
    /// The write ends with [`Self::exit`]. A write must not start another write before it
    /// ends, which would wait for a freeze that waits for this write.
    pub(crate) fn enter(&self) {
        self.wait_queue.wait_until(|| {
            let mut state = self.state.lock();
            (state.level == FreezeLevel::Unfrozen).then(|| state.running_writes += 1)
        });
    }

    /// Starts a write like [`Self::enter`] if the file system is not frozen, without waiting.
    pub(crate) fn try_enter(&self) -> bool {
        let mut state = self.state.lock();
        if state.level != FreezeLevel::Unfrozen {
            return false;
        }
        state.running_writes += 1;
        true
    }

    /// Ends a write started by [`Self::enter`] or [`Self::try_enter`].
    pub(crate) fn exit(&self) {
        let mut state = self.state.lock();
        state.running_writes -= 1;
        let wake_freezer = state.running_writes == 0 && state.level == FreezeLevel::Freezing;
        drop(state);
        if wake_freezer {
            self.wait_queue.wake_all();
        }
    }

    /// Keeps the file system from being frozen until the guard is dropped, which fails with
    /// `EBUSY` if it is frozen already.
    pub(crate) fn lock_unfrozen(&self) -> Result<MutexGuard<'_, ()>> {
        let transition = self.transition.lock();
        if self.state.lock().level != FreezeLevel::Unfrozen {
            return_errno_with_message!(Errno::EBUSY, "the file system is frozen");
        }
        Ok(transition)
    }

    /// Returns whether the file system is completely frozen.
    pub(crate) fn is_frozen(&self) -> bool {
        self.state.lock().level == FreezeLevel::Frozen
    }

    fn set_level(&self, level: FreezeLevel) {
        self.state.lock().level = level;
        self.wait_queue.wake_all();
    }

    /// Runs `sync` unless the file system is frozen, in which case there is nothing to sync.
    ///
    /// A file system's sync must run inside this, or it could undo what freezing wrote.
    pub(crate) fn sync_unless_frozen(&self, sync: impl FnOnce() -> Result<()>) -> Result<()> {
        let _sync = self.sync_lock.read();
        if self.is_frozen() {
            return Ok(());
        }
        sync()
    }

    fn freeze(
        &self,
        sync: impl FnOnce() -> Result<()>,
        freeze_fs: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let _transition = self.transition.lock();
        {
            let mut state = self.state.lock();
            if state.level != FreezeLevel::Unfrozen {
                return_errno_with_message!(Errno::EBUSY, "the file system is already frozen");
            }
            state.level = FreezeLevel::Freezing;
        }
        self.wait_queue
            .wait_until(|| (self.state.lock().running_writes == 0).then_some(()));

        let result = sync().and_then(|()| {
            let _sync = self.sync_lock.write();
            freeze_fs()?;
            self.set_level(FreezeLevel::Frozen);
            Ok(())
        });
        if result.is_err() {
            self.set_level(FreezeLevel::Unfrozen);
        }
        result
    }

    fn thaw(&self, unfreeze: impl FnOnce() -> Result<()>) -> Result<()> {
        let _transition = self.transition.lock();
        if self.state.lock().level != FreezeLevel::Frozen {
            return_errno_with_message!(Errno::EINVAL, "the file system is not frozen");
        }
        // Like Linux, a file system that fails to thaw stays frozen.
        unfreeze()?;
        self.set_level(FreezeLevel::Unfrozen);
        Ok(())
    }
}

/// A running write to a file system, started by `<dyn FileSystem>::start_write`.
pub(crate) struct FsWriteGuard {
    fs: Arc<dyn FileSystem>,
}

impl Drop for FsWriteGuard {
    fn drop(&mut self) {
        self.fs.write_state().freeze().exit();
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
    /// Taken shared to add a writer and exclusively to change the read-only state.
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

    /// Locks the read-only state for a change, during which no writer can be added.
    ///
    /// Every change of the read-only state must happen under this lock, so that changes
    /// are serialized with each other and with adding writers.
    pub(crate) fn lock_read_only_state(&self) -> ReadOnlyStateGuard<'_> {
        ReadOnlyStateGuard {
            _transition: self.transition.write(),
            writers: &self.writers,
        }
    }
}

/// A locked read-only state, returned by [`WriterCount::lock_read_only_state`].
pub(crate) struct ReadOnlyStateGuard<'a> {
    _transition: RwMutexWriteGuard<'a, ()>,
    writers: &'a AtomicUsize,
}

impl ReadOnlyStateGuard<'_> {
    /// Checks that the object may become read-only, which fails with `EBUSY` while it
    /// has writers.
    pub(crate) fn check_no_writers(&self) -> Result<()> {
        if self.writers.load(Ordering::Acquire) > 0 {
            return_errno_with_message!(Errno::EBUSY, "the mount or filesystem has writers");
        }
        Ok(())
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

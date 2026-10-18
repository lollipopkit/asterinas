// SPDX-License-Identifier: MPL-2.0

use core::{
    borrow::Borrow,
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
};

use atomic_integer_wrapper::define_atomic_version_of_integer_like_type;
use ostd::{
    impl_untyped_frame_meta_for,
    mm::{Frame, FrameAllocOptions, HasPaddr, UserMappingObserver},
    sync::WaitQueue,
};

use crate::{
    prelude::*,
    vm::stat::{MemStat, mod_mem_stat},
};

/// The state of a page in the page cache.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(crate) enum PageState {
    /// `Uninit` indicates a new allocated page which content has not been initialized.
    /// The page is available to write, not available to read or map.
    Uninit = 0,
    /// `UpToDate` indicates a page which content is consistent with corresponding disk content.
    /// The page is available to read and map, not available to write.
    UpToDate = 1,
    /// `Dirty` indicates a page which content has been updated and not written back to underlying disk.
    /// The page is available to read, write, and map.
    Dirty = 2,
    /// `Evicted` indicates an evicted page which content has been initialized.
    /// The page is available to read, not available to write and map.
    Evicted = 3,
}

impl From<PageState> for u8 {
    fn from(value: PageState) -> Self {
        value as u8
    }
}

define_atomic_version_of_integer_like_type!(PageState, try_from = true, {
    #[derive(Debug)]
    struct AtomicPageState(AtomicU8);
});

impl PageState {
    /// Checks if the page is uninitialized.
    pub(super) fn is_uninit(self) -> bool {
        matches!(self, Self::Uninit)
    }

    /// Checks if the page is up-to-date.
    pub(super) fn is_up_to_date(self) -> bool {
        matches!(self, Self::UpToDate)
    }

    /// Checks if the page is dirty.
    pub(super) fn is_dirty(self) -> bool {
        matches!(self, Self::Dirty)
    }

    /// Checks if the page is evicted.
    pub(super) fn is_evicted(self) -> bool {
        matches!(self, Self::Evicted)
    }
}

/// The kind of a page in the page cache, which decides how the page is
/// accounted in the memory statistics.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    /// Kernel memory that is not accounted as page cache or anonymous memory
    /// (e.g., the vDSO data).
    Kernel,
    /// File data cached from a backend.
    File,
    /// Block device metadata cached by a file system, i.e., Linux's buffers.
    Buffer,
    /// Memory of tmpfs or memfd files, or shared anonymous memory created
    /// with `MAP_NORESERVE`.
    ///
    /// Each page is charged to the committed memory when it is allocated,
    /// like Linux's shmem objects with `VM_NORESERVE`.
    Shmem,
    /// Shared anonymous memory whose whole size has been charged to the
    /// committed memory when the memory is created.
    ShmemReserved,
    /// Memory of ramfs files, which can never be reclaimed.
    Ramfs,
    /// Anonymous memory of private mappings (e.g., the initial stack).
    Anon,
}

impl PageKind {
    /// Returns the counter of the pages of this kind.
    ///
    /// Each page of a counted kind is counted from its allocation to its
    /// free. Pages charged to the committed memory one by one are counted as
    /// [`MemStat::Shmem`], like Linux's shmem objects with `VM_NORESERVE`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/mm/shmem.c#L169-L219>
    fn stat(self) -> Option<MemStat> {
        match self {
            Self::File => Some(MemStat::File),
            Self::Buffer => Some(MemStat::Buffer),
            Self::Shmem => Some(MemStat::Shmem),
            Self::ShmemReserved => Some(MemStat::ShmemReserved),
            Self::Ramfs => Some(MemStat::Ramfs),
            Self::Kernel | Self::Anon => None,
        }
    }

    /// Returns whether dirty pages are counted as `NR_FILE_DIRTY`.
    ///
    /// Like Linux, only pages that can be written back to storage count.
    fn counts_dirty(self) -> bool {
        matches!(self, Self::File | Self::Buffer)
    }

    /// Adds `delta` pages of this kind to the memory statistics.
    fn account(self, delta: isize) {
        if let Some(stat) = self.stat() {
            mod_mem_stat(stat, delta);
        }
    }

    /// Returns the counter of the pages of this kind that are mapped to user
    /// space.
    fn mapped_stat(self) -> Option<MemStat> {
        match self {
            Self::File | Self::Buffer | Self::Shmem | Self::ShmemReserved | Self::Ramfs => {
                Some(MemStat::FileMapped)
            }
            Self::Anon => Some(MemStat::AnonMapped),
            Self::Kernel => None,
        }
    }
}

/// A page in the page cache.
pub(crate) type CachePage = Frame<CachePageMeta>;

/// Metadata for a page in the page cache.
#[derive(Debug)]
pub(crate) struct CachePageMeta {
    /// The current state of the page (uninit, up-to-date, or dirty).
    state: AtomicPageState,
    /// This bit acts as a mutex for the corresponding page.
    ///
    /// When this bit is set, the holder has the exclusive right to perform critical
    /// state transitions (e.g., preparing for I/O).
    lock: AtomicBool,
    /// This bit indicates that the page's contents are "in-flight" to storage.
    ///
    /// This bit works like `PG_writeback` in Linux, it helps the page cache
    /// avoid holding the page lock for an extended period during writeback to the backend.
    ///
    /// This bit is set and normally checked while holding the page lock. It is
    /// cleared without the page lock only from the BIO completion callback after
    /// the VMO writeback path has handed off the writeback state.
    is_writing_back: AtomicBool,
    /// The kind of the page.
    kind: PageKind,
    /// The number of user page table entries that map the page.
    nr_user_mappings: AtomicU32,
    // TODO: Add a reverse mapping from the page to VMO for eviction.
}

impl CachePageMeta {
    /// Creates the metadata of a new page and accounts the page.
    ///
    /// The page is unaccounted when the metadata is dropped.
    pub(super) fn new(kind: PageKind, state: PageState) -> Self {
        debug_assert!(!state.is_dirty());
        kind.account(1);
        Self {
            state: AtomicPageState::new(state),
            lock: AtomicBool::new(false),
            is_writing_back: AtomicBool::new(false),
            kind,
            nr_user_mappings: AtomicU32::new(0),
        }
    }

    /// Sets the state of the page and accounts dirty pages.
    fn set_state(&self, new_state: PageState) {
        let old_state = self.state.swap(new_state, Ordering::AcqRel);
        if self.kind.counts_dirty() && old_state.is_dirty() != new_state.is_dirty() {
            mod_mem_stat(
                MemStat::FileDirty,
                if new_state.is_dirty() { 1 } else { -1 },
            );
        }
    }
}

impl Drop for CachePageMeta {
    fn drop(&mut self) {
        // Truncation may discard dirty pages without writing them back.
        if self.kind.counts_dirty() && self.state.load(Ordering::Relaxed).is_dirty() {
            mod_mem_stat(MemStat::FileDirty, -1);
        }
        debug_assert!(!self.is_writing_back.load(Ordering::Relaxed));
        debug_assert_eq!(self.nr_user_mappings.load(Ordering::Relaxed), 0);
        self.kind.account(-1);
    }
}

impl_untyped_frame_meta_for!(CachePageMeta, user_mappings);

impl UserMappingObserver for CachePageMeta {
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/mm/rmap.c#L1334-L1354>
    fn on_map_to_user(&self) {
        if self.nr_user_mappings.fetch_add(1, Ordering::Relaxed) == 0
            && let Some(stat) = self.kind.mapped_stat()
        {
            mod_mem_stat(stat, 1);
        }
    }

    fn on_unmap_from_user(&self) {
        if self.nr_user_mappings.fetch_sub(1, Ordering::Relaxed) == 1
            && let Some(stat) = self.kind.mapped_stat()
        {
            mod_mem_stat(stat, -1);
        }
    }
}

/// Convenience operations on a [`CachePage`] handle.
///
/// Implemented for every [`CachePage`], this gives access to the page lock,
/// the per-page wait queue, and lifecycle helpers used during page commit.
pub(crate) trait CachePageExt: Sized {
    /// Gets the metadata associated with the cache page.
    fn metadata(&self) -> &CachePageMeta;

    /// Gets the wait queue associated with the cache page.
    fn wait_queue(&self) -> &'static WaitQueue;

    /// Tries to lock the cache page.
    fn try_lock(self) -> Option<LockedCachePage>;

    /// Tries to lock the cache page by reference.
    fn try_lock_guard(&self) -> Option<LockedCachePageGuard<'_>>;

    /// Locks the cache page, blocking until the lock is acquired.
    ///
    /// This method may block. It must not be called while holding a spinlock or
    /// with interrupts disabled.
    fn lock(self) -> LockedCachePage;

    /// Locks the cache page by reference, blocking until the lock is acquired.
    ///
    /// This method may block. It must not be called while holding a spinlock or
    /// with interrupts disabled.
    fn lock_guard(&self) -> LockedCachePageGuard<'_>;

    /// Ensures the page is initialized, calling `init_fn` if necessary.
    ///
    /// This method may block while waiting for another initializer. It must not
    /// be called while holding a spinlock or with interrupts disabled.
    fn ensure_init(&self, init_fn: impl FnOnce(LockedCachePage) -> Result<()>) -> Result<()>;

    /// Clears writeback state for a page whose writeback has completed or was canceled.
    ///
    /// Callers must invoke this method only to finish a writeback operation
    /// previously started with [`LockedCachePage::set_writing_back`], either
    /// from its completion callback or while handling submission failure.
    fn clear_writing_back(&self) {
        if self
            .metadata()
            .is_writing_back
            .swap(false, Ordering::Release)
        {
            mod_mem_stat(MemStat::Writeback, -1);
        }
        self.wait_queue().wake_all();
    }

    /// Allocates a new cache page which content and state are uninitialized.
    fn alloc_uninit(kind: PageKind) -> Result<CachePage> {
        let meta = CachePageMeta::new(kind, PageState::Uninit);
        let page = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_frame_with(meta)?;
        Ok(page)
    }

    /// Allocates a new zeroed cache page with the up-to-date state.
    fn alloc_zero(kind: PageKind) -> Result<CachePage> {
        let meta = CachePageMeta::new(kind, PageState::UpToDate);
        let page = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_frame_with(meta)?;
        Ok(page)
    }

    /// Returns the state of the cache page.
    fn state(&self) -> PageState {
        self.metadata().state.load(Ordering::Acquire)
    }
}

impl CachePageExt for CachePage {
    fn metadata(&self) -> &CachePageMeta {
        self.meta()
    }

    fn wait_queue(&self) -> &'static WaitQueue {
        const PAGE_SHIFT: u32 = PAGE_SIZE.trailing_zeros();
        const PAGE_WAIT_QUEUE_MASK: usize = 0xff;
        const PAGE_WAIT_QUEUE_NUM: usize = PAGE_WAIT_QUEUE_MASK + 1;

        /// Global array of wait queues for page cache operations.
        ///
        /// Each wait queue in this array handles wait/wake operations for a subset of cache pages.
        /// The queue for a specific page is selected using: `PAGE_WAIT_QUEUES[page.paddr() & PAGE_WAIT_QUEUE_MASK]`.
        ///
        /// This approach avoids the overhead of per-page wait queues while still providing
        /// reasonable concurrency through hashing.
        static PAGE_WAIT_QUEUES: [WaitQueue; PAGE_WAIT_QUEUE_NUM] =
            [const { WaitQueue::new() }; PAGE_WAIT_QUEUE_NUM];

        &PAGE_WAIT_QUEUES[(self.paddr() >> PAGE_SHIFT) & PAGE_WAIT_QUEUE_MASK]
    }

    fn try_lock(self) -> Option<LockedCachePage> {
        try_lock_page(&self).map(|wait_queue| LockedCachePage::new(self, wait_queue))
    }

    fn try_lock_guard(&self) -> Option<LockedCachePageGuard<'_>> {
        try_lock_page(self).map(|wait_queue| LockedCachePage::new(self, wait_queue))
    }

    fn lock(self) -> LockedCachePage {
        let wait_queue = lock_page(&self);
        LockedCachePage::new(self, wait_queue)
    }

    fn lock_guard(&self) -> LockedCachePageGuard<'_> {
        if let Some(locked_page) = self.try_lock_guard() {
            return locked_page;
        }

        let wait_queue = lock_page(self);
        LockedCachePage::new(self, wait_queue)
    }

    fn ensure_init(&self, init_fn: impl FnOnce(LockedCachePage) -> Result<()>) -> Result<()> {
        // Fast path: if the page is already initialized, return immediately without waiting.
        if !self.state().is_uninit() {
            return Ok(());
        }

        let locked_page = self.lock_guard();
        // Check again after acquiring the lock to avoid duplicate initialization.
        if !locked_page.state().is_uninit() {
            return Ok(());
        }

        init_fn(locked_page.into_owned())
    }
}

/// A locked cache page that owns its page handle by default.
///
/// The locked page has the exclusive right to perform critical
/// state transitions (e.g., preparing for I/O).
///
/// Use [`LockedCachePageGuard`] when the lock should borrow an existing
/// [`CachePage`] instead of taking ownership of it.
pub(crate) struct LockedCachePage<PageRef: Borrow<CachePage> = CachePage> {
    page: Option<PageRef>,
    wait_queue: &'static WaitQueue,
}

/// A borrowed guard for a locked cache page.
pub(crate) type LockedCachePageGuard<'a> = LockedCachePage<&'a CachePage>;

impl<PageRef: Borrow<CachePage>> Debug for LockedCachePage<PageRef> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("LockedCachePage")
            .field("page", &self.page.as_ref().map(|page| page.borrow()))
            .finish()
    }
}

impl<PageRef: Borrow<CachePage>> LockedCachePage<PageRef> {
    fn new(page: PageRef, wait_queue: &'static WaitQueue) -> Self {
        Self {
            page: Some(page),
            wait_queue,
        }
    }

    fn page(&self) -> &CachePage {
        self.page.as_ref().expect("page already taken").borrow()
    }

    /// Marks the page as up-to-date.
    ///
    /// This indicates that the page's contents are synchronized with disk
    /// and can be safely read.
    pub(crate) fn set_up_to_date(&self) {
        self.page().metadata().set_state(PageState::UpToDate);
    }

    /// Marks the page as dirty.
    ///
    /// This indicates that the page has been modified and needs to be
    /// written back to disk eventually.
    pub(crate) fn set_dirty(&self) {
        self.metadata().set_state(PageState::Dirty);
    }

    /// Marks the page as evicted.
    ///
    /// This indicates that the page has been evicted and is no longer
    /// associated with the page cache.
    pub(super) fn set_evicted(&self) {
        self.metadata().set_state(PageState::Evicted);
    }

    /// Sets the writing back flag of the page, indicating that the page
    /// is in-flight to storage.
    pub(crate) fn set_writing_back(&self) {
        if !self
            .metadata()
            .is_writing_back
            .swap(true, Ordering::Release)
        {
            mod_mem_stat(MemStat::Writeback, 1);
        }
    }

    /// Waits until the page finishes writing back to storage.
    ///
    /// This function will wait on the same wait queue used for locking the page.
    pub(crate) fn wait_until_finish_writing_back(&self) {
        self.wait_queue
            .wait_until(|| (!self.is_writing_back()).then_some(()));
    }

    /// Checks if the page is currently being written back to storage.
    pub(super) fn is_writing_back(&self) -> bool {
        self.metadata().is_writing_back.load(Ordering::Acquire)
    }
}

impl LockedCachePage<CachePage> {
    /// Unlocks the page and returns the underlying cache page.
    pub(crate) fn unlock(mut self) -> CachePage {
        let page = self.page.take().expect("page already taken");
        unlock_page(&page, self.wait_queue);
        page
    }

    /// Transfers ownership of the locked page to a new guard.
    ///
    /// This method leaves this guard inert so it will not unlock the page when dropped.
    pub(super) fn detach(&mut self) -> LockedCachePage {
        let page = self.page.take().expect("page already detached");
        LockedCachePage::new(page, self.wait_queue)
    }
}

impl LockedCachePage<&CachePage> {
    /// Converts a borrowed locked page into an owned locked page.
    pub(super) fn into_owned(mut self) -> LockedCachePage {
        let page = self.page.take().expect("page already taken").clone();
        LockedCachePage::new(page, self.wait_queue)
    }
}

impl<PageRef: Borrow<CachePage>> Deref for LockedCachePage<PageRef> {
    type Target = CachePage;

    fn deref(&self) -> &Self::Target {
        self.page()
    }
}

impl<PageRef: Borrow<CachePage>> Drop for LockedCachePage<PageRef> {
    fn drop(&mut self) {
        if let Some(page) = &self.page {
            unlock_page(page.borrow(), self.wait_queue);
        }
    }
}

fn unlock_page(page: &CachePage, wait_queue: &'static WaitQueue) {
    page.metadata().lock.store(false, Ordering::Release);
    wait_queue.wake_all();
}

fn try_lock_page(page: &CachePage) -> Option<&'static WaitQueue> {
    let wait_queue = page.wait_queue();
    page.metadata()
        .lock
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
        .then_some(wait_queue)
}

fn lock_page(page: &CachePage) -> &'static WaitQueue {
    let wait_queue = page.wait_queue();
    wait_queue.wait_until(|| {
        page.metadata()
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
    });
    wait_queue
}

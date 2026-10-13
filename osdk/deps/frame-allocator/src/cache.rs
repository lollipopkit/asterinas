// SPDX-License-Identifier: MPL-2.0

//! A fixed-size local cache for frame allocation.

use core::alloc::Layout;

use ostd::{
    cpu::CpuId,
    cpu_local,
    irq::DisabledLocalIrqGuard,
    mm::{PAGE_SIZE, Paddr},
    sync::{LocalIrqDisabled, SpinLock},
};

// The lock of a cache must be acquired before that of any pool.
cpu_local! {
    static CACHE: SpinLock<CacheOfSizes, LocalIrqDisabled> = SpinLock::new(CacheOfSizes::new());
}

struct CacheOfSizes {
    cache1: CacheArray<1, 12>,
    cache2: CacheArray<2, 6>,
    cache3: CacheArray<3, 6>,
    cache4: CacheArray<4, 6>,
}

/// A fixed-size local cache for frame allocation.
///
/// Each cache array contains at most `COUNT` segments. Each segment contains
/// `NR_CONT_FRAMES` contiguous frames.
struct CacheArray<const NR_CONT_FRAMES: usize, const COUNT: usize> {
    inner: [Option<Paddr>; COUNT],
    size: usize,
}

impl<const NR_CONT_FRAMES: usize, const COUNT: usize> CacheArray<NR_CONT_FRAMES, COUNT> {
    const fn new() -> Self {
        Self {
            inner: [const { None }; COUNT],
            size: 0,
        }
    }

    /// The size of the segments that this cache manages.
    const fn segment_size() -> usize {
        NR_CONT_FRAMES * PAGE_SIZE
    }

    /// Allocates a segment of frames.
    ///
    /// It may allocate directly from this cache. If the cache is empty, it
    /// will fill the cache.
    fn alloc(&mut self, guard: &DisabledLocalIrqGuard) -> Option<Paddr> {
        if let Some(frame) = self.pop_front() {
            return Some(frame);
        }

        let nr_to_alloc = COUNT * 2 / 3;
        if let Some(allocated) = super::pools::alloc(
            guard,
            Layout::from_size_align(nr_to_alloc * Self::segment_size(), PAGE_SIZE).unwrap(),
        ) {
            for i in 1..nr_to_alloc {
                self.push_front(allocated + i * Self::segment_size());
            }

            return Some(allocated);
        }

        // The pools may still have chunks that are large enough for one
        // segment but not for a batch of segments.
        super::pools::alloc(
            guard,
            Layout::from_size_align(Self::segment_size(), PAGE_SIZE).unwrap(),
        )
    }

    /// Deallocates a segment of frames.
    ///
    /// It may deallocate directly to this cache. If the cache is full, it will
    /// deallocate to the global pool.
    fn dealloc(&mut self, guard: &DisabledLocalIrqGuard, addr: Paddr) {
        if self.push_front(addr).is_none() {
            let nr_to_dealloc = COUNT * 2 / 3 + 1;

            let segments = (0..nr_to_dealloc).map(|i| {
                if i == 0 {
                    (addr, Self::segment_size())
                } else {
                    (self.pop_front().unwrap(), Self::segment_size())
                }
            });

            super::pools::dealloc(guard, segments);
        };
    }

    fn push_front(&mut self, frame: Paddr) -> Option<()> {
        if self.size == COUNT {
            return None;
        }

        self.inner[self.size] = Some(frame);
        self.size += 1;
        Some(())
    }

    fn pop_front(&mut self) -> Option<Paddr> {
        if self.size == 0 {
            return None;
        }

        let frame = self.inner[self.size - 1].take().unwrap();
        self.size -= 1;
        Some(frame)
    }
}

impl CacheOfSizes {
    const fn new() -> Self {
        Self {
            cache1: CacheArray::new(),
            cache2: CacheArray::new(),
            cache3: CacheArray::new(),
            cache4: CacheArray::new(),
        }
    }

    /// Removes all cached segments.
    ///
    /// Returns the address and the size of each removed segment.
    fn take_all(&mut self) -> impl Iterator<Item = (Paddr, usize)> + use<> {
        fn take<const N: usize, const C: usize>(
            cache: &mut CacheArray<N, C>,
        ) -> impl Iterator<Item = (Paddr, usize)> + use<N, C> {
            let mut segments = [None; C];
            for segment in segments.iter_mut() {
                *segment = cache.pop_front();
            }
            segments
                .into_iter()
                .flatten()
                .map(|addr| (addr, CacheArray::<N, C>::segment_size()))
        }

        take(&mut self.cache1)
            .chain(take(&mut self.cache2))
            .chain(take(&mut self.cache3))
            .chain(take(&mut self.cache4))
    }
}

pub(super) fn alloc(guard: &DisabledLocalIrqGuard, layout: Layout) -> Option<Paddr> {
    let nr_frames = layout.size() / PAGE_SIZE;
    if layout.align() > layout.size() {
        return super::pools::alloc(guard, layout);
    }

    let mut cache = CACHE.get_with(guard).deref_target().lock();

    match nr_frames {
        1 => cache.cache1.alloc(guard),
        2 => cache.cache2.alloc(guard),
        3 => cache.cache3.alloc(guard),
        4 => cache.cache4.alloc(guard),
        _ => super::pools::alloc(guard, layout),
    }
}

pub(super) fn dealloc(guard: &DisabledLocalIrqGuard, addr: Paddr, size: usize) {
    let nr_frames = size / PAGE_SIZE;
    if nr_frames > 4 {
        super::pools::dealloc(guard, [(addr, size)].into_iter());
        return;
    }

    let mut cache = CACHE.get_with(guard).deref_target().lock();

    match nr_frames {
        1 => cache.cache1.dealloc(guard, addr),
        2 => cache.cache2.dealloc(guard, addr),
        3 => cache.cache3.dealloc(guard, addr),
        4 => cache.cache4.dealloc(guard, addr),
        _ => super::pools::dealloc(guard, [(addr, size)].into_iter()),
    }
}

/// Moves all segments in the cache of the given CPU to the global pool.
///
/// The caller must not hold the lock of any cache or pool.
pub(super) fn reclaim_from(cpu: CpuId) {
    let segments = CACHE.get_on_cpu(cpu).lock().take_all();
    super::pools::dealloc_to_global(segments);
}

#[cfg(ktest)]
mod test {
    use ostd::{
        cpu::PinCurrentCpu,
        irq,
        mm::{FrameAllocOptions, HasPaddr, UniqueFrame},
        prelude::ktest,
    };

    use super::*;

    #[ktest]
    fn reclaim_from_empties_cache() {
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let addr = frame.paddr();
        UniqueFrame::try_from(frame).unwrap().reset_as_unused();

        let guard = irq::disable_local();
        // Give the frame back as free memory, bypassing the deallocation path.
        crate::TOTAL_FREE_SIZE.add(guard.current_cpu(), PAGE_SIZE);
        let pushed = CACHE.get_with(&guard).lock().cache1.push_front(addr);
        if pushed.is_none() {
            // The cache is full, which is also fine for this test.
            crate::pools::dealloc_to_global([(addr, PAGE_SIZE)].into_iter());
        }

        reclaim_from(guard.current_cpu());
        assert_eq!(CACHE.get_with(&guard).lock().take_all().count(), 0);
    }
}

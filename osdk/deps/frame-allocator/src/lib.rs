// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]

//! An implementation of the global physical memory frame allocator for
//! [OSTD](https://crates.io/crates/ostd) based kernels.
//!
//! # Background
//!
//! `OSTD` has provided a page allocator interface, namely [`GlobalFrameAllocator`]
//! and [`global_frame_allocator`] procedure macro, allowing users to plug in
//! their own frame allocator into the kernel safely. You can refer to the
//! [`ostd::mm::frame::allocator`] module for detailed introduction.
//!
//! # Introduction
//!
//! This crate is an implementation of a scalable and efficient global frame
//! allocator based on the buddy system. It is by default shipped with OSDK
//! for users that don't have special requirements on the frame allocator.
//!
//! [`GlobalFrameAllocator`]: ostd::mm::frame::GlobalFrameAllocator
//! [`global_frame_allocator`]: ostd::global_frame_allocator

// The heap allocator usually depends on frame allocation. If we depend on heap
// allocation then there will be a cyclic dependency. We only use the heap in
// unit tests.
#[cfg(ktest)]
extern crate alloc;

use core::alloc::Layout;

use ostd::{
    cpu::{PinCurrentCpu, all_cpus},
    irq,
    mm::{Paddr, frame::GlobalFrameAllocator},
};

mod cache;
mod chunk;
mod pools;
mod set;
mod smp_counter;

#[cfg(ktest)]
mod test;

fast_smp_counter! {
    /// The total size of free memory.
    pub static TOTAL_FREE_SIZE: usize;
}

/// Loads the total size (in bytes) of free memory in the allocator.
pub fn load_total_free_size() -> usize {
    TOTAL_FREE_SIZE.get()
}

/// The global frame allocator provided by OSDK.
///
/// It is a singleton that provides frame allocation for the kernel. If
/// multiple instances of this struct are created, all the member functions
/// will eventually access the same allocator.
pub struct FrameAllocator;

impl GlobalFrameAllocator for FrameAllocator {
    fn alloc(&self, layout: Layout) -> Option<Paddr> {
        let guard = irq::disable_local();
        let res = cache::alloc(&guard, layout).or_else(|| {
            reclaim_all();
            cache::alloc(&guard, layout)
        });
        if res.is_some() {
            TOTAL_FREE_SIZE.sub(guard.current_cpu(), layout.size());
        }
        res
    }

    fn dealloc(&self, addr: Paddr, size: usize) {
        let guard = irq::disable_local();
        TOTAL_FREE_SIZE.add(guard.current_cpu(), size);
        cache::dealloc(&guard, addr, size);
    }

    fn add_free_memory(&self, addr: Paddr, size: usize) {
        let guard = irq::disable_local();
        TOTAL_FREE_SIZE.add(guard.current_cpu(), size);
        pools::add_free_memory(&guard, addr, size);
    }
}

/// Moves the free frames held by the caches and the local pools of all CPUs
/// to the global pool.
///
/// Free frames that are held by different CPUs cannot coalesce. So an
/// allocation can fail even if plenty of memory is free. Reclaiming them lets
/// them coalesce in the global pool, so the failed allocation can be retried.
fn reclaim_all() {
    for cpu in all_cpus() {
        cache::reclaim_from(cpu);
        pools::reclaim_from(cpu);
    }
}

// SPDX-License-Identifier: MPL-2.0

//! Controlling the balancing between CPU-local free pools and the global free pool.

use ostd::{cpu::num_cpus, mm::PAGE_SIZE};

use super::{BuddyOrder, BuddySet, MAX_LOCAL_BUDDY_ORDER, OnDemandGlobalLock, lesser_order_of};

use crate::chunk::{size_of_order, split_to_order};

/// Controls the expected size of cache for each CPU-local free pool.
///
/// The expected size will be the size of `GLOBAL_POOL` divided by the number
/// of the CPUs, and then divided by this constant.
const CACHE_EXPECTED_PORTION: usize = 2;

/// Returns the expected size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_expected_size(global_size: usize) -> usize {
    global_size / num_cpus() / CACHE_EXPECTED_PORTION
}

/// Controls the minimal size of cache for each CPU-local free pool.
///
/// The minimal will be the expected size divided by this constant.
const CACHE_MINIMAL_PORTION: usize = 8;

/// Returns the minimal size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_minimal_size(global_size: usize) -> usize {
    cache_expected_size(global_size) / CACHE_MINIMAL_PORTION
}

/// Controls the maximal size of cache for each CPU-local free pool.
///
/// The maximal will be the expected size multiplied by this constant.
const CACHE_MAXIMAL_MULTIPLIER: usize = 2;

/// Returns the maximal size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_maximal_size(global_size: usize) -> usize {
    cache_expected_size(global_size) * CACHE_MAXIMAL_MULTIPLIER
}

/// Balances a local cache and the global free pool.
pub(super) fn balance(
    local: &mut BuddySet<MAX_LOCAL_BUDDY_ORDER>,
    global: &mut OnDemandGlobalLock,
) {
    let global_size = global.get_global_size();

    let minimal_local_size = cache_minimal_size(global_size);
    let expected_local_size = cache_expected_size(global_size);
    let maximal_local_size = cache_maximal_size(global_size);

    let local_size = local.total_size();

    if local_size >= maximal_local_size {
        // Move local frames to the global pool.
        let expected_removal = local_size - expected_local_size;
        if expected_removal < PAGE_SIZE {
            return;
        }

        let lesser_order = lesser_order_of(expected_removal);

        balance_to(local, &mut *global.get(), lesser_order);
    } else if local_size < minimal_local_size {
        // Move global frames to the local pool.
        let expected_allocation = expected_local_size - local_size;
        if global_size == 0 || expected_allocation < PAGE_SIZE {
            return;
        }

        let lesser_order = lesser_order_of(expected_allocation);

        balance_to(&mut *global.get(), local, lesser_order);
    }
}

/// The maximum number of chunks moved by one call to [`balance_to`].
///
/// It bounds the time spent with IRQs disabled when the source is fragmented.
/// Balancing happens on every allocation and deallocation, so the pools still
/// converge over time.
const MAX_CHUNKS_PER_BALANCE: usize = 16;

/// Balances from `a` to `b` by moving chunks of up to `size_of_order(order)`
/// bytes in total.
///
/// If `a` has no chunk of the given order, smaller chunks are moved instead.
fn balance_to<const MAX_ORDER1: BuddyOrder, const MAX_ORDER2: BuddyOrder>(
    a: &mut BuddySet<MAX_ORDER1>,
    b: &mut BuddySet<MAX_ORDER2>,
    order: BuddyOrder,
) {
    let mut remaining = size_of_order(order);

    for _ in 0..MAX_CHUNKS_PER_BALANCE {
        let Some((addr, chunk_order)) = a.alloc_chunk_at_most(lesser_order_of(remaining)) else {
            break;
        };

        if chunk_order >= MAX_ORDER2 {
            let inserted_order = MAX_ORDER2 - 1;
            split_to_order(addr, chunk_order, inserted_order).for_each(|addr| {
                b.insert_chunk(addr, inserted_order);
            });
        } else {
            b.insert_chunk(addr, chunk_order);
        }

        remaining -= size_of_order(chunk_order);
        if remaining == 0 {
            break;
        }
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;
    use crate::test::MockMemoryRegion;

    #[ktest]
    fn balance_to_moves_smaller_chunks() {
        let region = MockMemoryRegion::alloc(size_of_order(2));
        let frame0 = region.paddr();
        let frame2 = frame0 + size_of_order(1);

        // Two single frames that are not buddies cannot coalesce.
        let mut a = BuddySet::<5>::new_empty();
        let mut b = BuddySet::<5>::new_empty();
        a.insert_chunk(frame0, 0);
        a.insert_chunk(frame2, 0);

        balance_to(&mut a, &mut b, 3);
        assert_eq!(a.total_size(), 0);
        assert_eq!(b.total_size(), size_of_order(1));

        assert!(b.alloc_chunk(0).is_some());
        assert!(b.alloc_chunk(0).is_some());
    }
}

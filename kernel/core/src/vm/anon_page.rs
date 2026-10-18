// SPDX-License-Identifier: MPL-2.0

//! Pages of private anonymous memory.

use ostd::{
    impl_untyped_frame_meta_for,
    mm::{Frame, FrameAllocOptions},
};

use crate::{
    prelude::*,
    vm::stat::{MemStat, mod_mem_stat},
};

/// A page of private anonymous memory, which is not in any page cache.
///
/// Such pages are allocated for page faults in private anonymous mappings and
/// for copy-on-write.
pub(crate) type AnonPage = Frame<AnonPageMeta>;

/// The metadata of an [`AnonPage`].
///
/// An anonymous page is allocated right before it is mapped to user space,
/// and it is freed after its last user mapping is removed. So it is counted
/// as mapped anonymous memory during its lifetime, which avoids tracking the
/// number of mappings on the hot paths like `fork`.
#[derive(Debug)]
pub(crate) struct AnonPageMeta {
    _private: (),
}

impl AnonPageMeta {
    fn new() -> Self {
        mod_mem_stat(MemStat::AnonMapped, 1);
        Self { _private: () }
    }
}

impl Drop for AnonPageMeta {
    fn drop(&mut self) {
        mod_mem_stat(MemStat::AnonMapped, -1);
    }
}

impl_untyped_frame_meta_for!(AnonPageMeta);

/// Allocates an anonymous page.
///
/// The content of the page is zeroed if `zeroed` is true. Otherwise, it is
/// uninitialized.
pub(crate) fn alloc_anon_page(zeroed: bool) -> Result<AnonPage> {
    let page = FrameAllocOptions::new()
        .zeroed(zeroed)
        .alloc_frame_with(AnonPageMeta::new())?;
    Ok(page)
}

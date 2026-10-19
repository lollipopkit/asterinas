// SPDX-License-Identifier: MPL-2.0

//! Untyped physical memory management.
//!
//! As detailed in [`crate::mm::frame`], untyped memory can be accessed with
//! relaxed rules but we cannot create references to them. This module provides
//! the declaration of untyped frames and segments, and the implementation of
//! extra functionalities (such as [`VmIo`]) for them.
//!
//! [`VmIo`]: crate::mm::VmIo

use super::{Frame, Segment, meta::AnyFrameMeta};
use crate::mm::{
    HasPaddr, HasSize, Infallible,
    io::{
        VmReader, VmWriter,
        util::{HasVmReaderWriter, VmReaderWriterIdentity},
    },
    paddr_to_vaddr,
};

/// The metadata of untyped frame.
///
/// If a structure `M` implements [`AnyUFrameMeta`], it can be used as the
/// metadata of a type of untyped frames [`Frame<M>`]. All frames of such type
/// will be accessible as untyped memory.
pub trait AnyUFrameMeta: AnyFrameMeta {}

/// A smart pointer to an untyped frame with any metadata.
///
/// The metadata of the frame is not known at compile time but the frame must
/// be an untyped one. An [`UFrame`] as a parameter accepts any type of
/// untyped frame metadata.
///
/// The usage of this frame will not be changed while this object is alive.
pub type UFrame = Frame<dyn AnyUFrameMeta>;

/// Observes the user mappings of untyped frames.
///
/// Metadata types implemented with
/// `impl_untyped_frame_meta_for!(T, user_mappings)` receive the notifications
/// of [`AnyFrameMeta::on_map_to_user`] and
/// [`AnyFrameMeta::on_unmap_from_user`] through this trait.
pub trait UserMappingObserver {
    /// See [`AnyFrameMeta::on_map_to_user`].
    fn on_map_to_user(&self);

    /// See [`AnyFrameMeta::on_unmap_from_user`].
    fn on_unmap_from_user(&self);
}

/// Makes a structure usable as untyped frame metadata.
///
/// If this macro is used for built-in typed frame metadata, it won't compile.
#[macro_export]
macro_rules! impl_untyped_frame_meta_for {
    // Implement with the notifications of user mappings forwarded to the
    // `UserMappingObserver` implementation.
    ($t:ty, user_mappings) => {
        // SAFETY: Untyped frames can be safely read.
        unsafe impl $crate::mm::frame::meta::AnyFrameMeta for $t {
            fn is_untyped(&self) -> bool {
                true
            }

            fn on_map_to_user(&self) {
                <$t as $crate::mm::frame::untyped::UserMappingObserver>::on_map_to_user(self)
            }

            fn on_unmap_from_user(&self) {
                <$t as $crate::mm::frame::untyped::UserMappingObserver>::on_unmap_from_user(self)
            }
        }
        impl $crate::mm::frame::untyped::AnyUFrameMeta for $t {}

        $crate::check_frame_meta_layout!($t);
    };
    // Implement without specifying the drop behavior.
    ($t:ty) => {
        // SAFETY: Untyped frames can be safely read.
        unsafe impl $crate::mm::frame::meta::AnyFrameMeta for $t {
            fn is_untyped(&self) -> bool {
                true
            }
        }
        impl $crate::mm::frame::untyped::AnyUFrameMeta for $t {}

        $crate::check_frame_meta_layout!($t);
    };
    // Implement with a customized drop function.
    ($t:ty, $body:expr) => {
        // SAFETY: Untyped frames can be safely read.
        unsafe impl $crate::mm::frame::meta::AnyFrameMeta for $t {
            fn on_drop(&mut self, reader: &mut $crate::mm::VmReader<$crate::mm::Infallible>) {
                $body
            }

            fn is_untyped(&self) -> bool {
                true
            }
        }
        impl $crate::mm::frame::untyped::AnyUFrameMeta for $t {}

        $crate::check_frame_meta_layout!($t);
    };
}

// A special case of untyped metadata is the unit type.
impl_untyped_frame_meta_for!(());

macro_rules! impl_untyped_for {
    ($t:ident) => {
        impl<UM: AnyUFrameMeta + ?Sized> HasVmReaderWriter for $t<UM> {
            type Types = VmReaderWriterIdentity;

            fn reader(&self) -> VmReader<'_, Infallible> {
                let ptr = paddr_to_vaddr(self.paddr()) as *const u8;
                // SAFETY:
                // - The memory range points to untyped memory.
                // - The frame/segment is alive during the lifetime `'_`.
                // - Using `VmReader` and `VmWriter` is the only way to access the frame/segment.
                unsafe { VmReader::from_kernel_space(ptr, self.size()) }
            }

            fn writer(&self) -> VmWriter<'_, Infallible> {
                let ptr = paddr_to_vaddr(self.paddr()) as *mut u8;
                // SAFETY:
                // - The memory range points to untyped memory.
                // - The frame/segment is alive during the lifetime `'_`.
                // - Using `VmReader` and `VmWriter` is the only way to access the frame/segment.
                unsafe { VmWriter::from_kernel_space(ptr, self.size()) }
            }
        }
    };
}

impl_untyped_for!(Frame);
impl_untyped_for!(Segment);

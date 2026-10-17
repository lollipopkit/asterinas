// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::AtomicU8;

use atomic_integer_wrapper::define_atomic_version_of_integer_like_type;

use crate::prelude::*;

/// The dumpability of a process, which also decides whether processes of the same user can
/// inspect it.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/sched/coredump.h#L10-L14>
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(crate) enum Dumpable {
    /// The process is not dumped, and only privileged processes can inspect it.
    Off = 0,
    /// The process is dumped, and processes of the same user can inspect it.
    Owner = 1,
    /// The process is dumped as root, and only privileged processes can inspect it.
    Root = 2,
}

/// The dumpability of a process that drops or gains privileges (`suid_dumpable` in Linux).
pub(crate) const SUID_DUMPABLE: Dumpable = Dumpable::Off;

impl From<Dumpable> for u8 {
    fn from(value: Dumpable) -> Self {
        value as _
    }
}

define_atomic_version_of_integer_like_type!(Dumpable, try_from = true, {
    #[derive(Debug)]
    pub(super) struct AtomicDumpable(AtomicU8);
});

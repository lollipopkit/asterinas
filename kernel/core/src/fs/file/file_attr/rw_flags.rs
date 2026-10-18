// SPDX-License-Identifier: MPL-2.0

use bitflags::bitflags;

use crate::{fs::file::FileLike, prelude::*};

bitflags! {
    /// The per-I/O flags of `preadv2` and `pwritev2` (`RWF_*` in Linux).
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/linux/fs.h#L427-L457>
    pub struct RwfFlags: u32 {
        /// High priority I/O, which is a hint for polled direct I/O.
        const HIPRI = 0x01;
        /// Per-I/O `O_DSYNC`.
        const DSYNC = 0x02;
        /// Per-I/O `O_SYNC`.
        const SYNC = 0x04;
        /// Per-I/O non-blocking mode.
        const NOWAIT = 0x08;
        /// Per-I/O `O_APPEND`.
        const APPEND = 0x10;
        /// Per-I/O negation of `O_APPEND`.
        const NOAPPEND = 0x20;
        /// Atomic writes.
        const ATOMIC = 0x40;
        /// Uncached buffered I/O.
        const DONTCACHE = 0x80;
        /// Per-I/O `MSG_NOSIGNAL` for pipes and sockets.
        const NOSIGNAL = 0x100;
    }
}

impl RwfFlags {
    /// Parses and checks the raw flags of an I/O operation on `file`.
    ///
    /// Like Linux, this should be called only if the operation has some data to transfer.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/fs.h#L3427-L3472>
    pub(crate) fn from_raw_checked(raw: u32, file: &dyn FileLike) -> Result<Self> {
        if raw == 0 {
            return Ok(Self::empty());
        }

        let Some(flags) = Self::from_bits(raw) else {
            return_errno_with_message!(Errno::EOPNOTSUPP, "the flags are unknown");
        };
        if flags.contains(Self::APPEND | Self::NOAPPEND) {
            return_errno_with_message!(
                Errno::EINVAL,
                "RWF_APPEND and RWF_NOAPPEND cannot be used together"
            );
        }
        if flags.contains(Self::NOWAIT) && !file.supports_nowait() {
            return_errno_with_message!(Errno::EOPNOTSUPP, "the file does not support RWF_NOWAIT");
        }
        // TODO: Support atomic writes (`RWF_ATOMIC`) and uncached I/O (`RWF_DONTCACHE`). Like
        // Linux, they are rejected if the file does not support them (and `RWF_ATOMIC` is always
        // rejected for reads), which is always the case for now.
        if flags.contains(Self::ATOMIC) {
            return_errno_with_message!(Errno::EOPNOTSUPP, "the file does not support RWF_ATOMIC");
        }
        if flags.contains(Self::DONTCACHE) {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "the file does not support RWF_DONTCACHE"
            );
        }

        Ok(flags)
    }
}

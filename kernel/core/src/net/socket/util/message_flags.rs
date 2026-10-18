// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::socket::ReceiveBehavior;
use bitflags::bitflags;

use crate::{prelude::*, process::signal::send_sigpipe_to_current};

bitflags! {
    /// Flags passed to socket send operations.
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct SendFlags: i32 {
        const MSG_OOB       = 0x1;
        const MSG_DONTROUTE = 0x4;
        const MSG_PROBE     = 0x10;
        const MSG_DONTWAIT  = 0x40;
        const MSG_EOR       = 0x80;
        const MSG_FIN       = 0x200;
        const MSG_SYN       = 0x400;
        const MSG_CONFIRM   = 0x800;
        const MSG_RST       = 0x1000;
        const MSG_NOSIGNAL  = 0x4000;
        const MSG_MORE      = 0x8000;
        const MSG_BATCH     = 0x40000;
        const MSG_ZEROCOPY  = 0x4000000;
        const MSG_FASTOPEN  = 0x20000000;

        const SUPPORTED     = SendFlags::MSG_DONTWAIT.bits
            | SendFlags::MSG_CONFIRM.bits
            | SendFlags::MSG_NOSIGNAL.bits;
    }
}

impl SendFlags {
    pub(crate) const fn is_all_supported(self) -> bool {
        Self::SUPPORTED.contains(self)
    }

    /// Sends `SIGPIPE` to the current thread if the send operation fails with `EPIPE`, unless
    /// `MSG_NOSIGNAL` is set.
    ///
    /// Like Linux, only stream sockets do this. Datagram and `SOCK_SEQPACKET` sockets return
    /// `EPIPE` without the signal.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/stream.c#L189-L196>
    pub(crate) fn raise_sigpipe_on_epipe<T>(self, result: Result<T>) -> Result<T> {
        if !self.contains(SendFlags::MSG_NOSIGNAL)
            && result
                .as_ref()
                .is_err_and(|err| err.error() == Errno::EPIPE)
        {
            send_sigpipe_to_current();
        }
        result
    }
}

bitflags! {
    /// Flags passed to or returned from socket receive operations.
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct RecvFlags: i32 {
        const MSG_OOB          = SendFlags::MSG_OOB.bits;
        const MSG_PEEK         = 0x2;
        const MSG_CTRUNC       = 0x8;
        const MSG_TRUNC        = 0x20;
        const MSG_DONTWAIT     = SendFlags::MSG_DONTWAIT.bits;
        const MSG_EOR          = SendFlags::MSG_EOR.bits;
        const MSG_WAITALL      = 0x100;
        const MSG_ERRQUEUE     = 0x2000;
        const MSG_WAITFORONE   = 0x10000;
        const MSG_SOCK_DEVMEM  = 0x2000000;
        const MSG_CMSG_CLOEXEC = 0x40000000;

        const SUPPORTED        = RecvFlags::MSG_PEEK.bits
            | RecvFlags::MSG_TRUNC.bits
            | RecvFlags::MSG_DONTWAIT.bits
            | RecvFlags::MSG_WAITALL.bits;
    }
}

impl RecvFlags {
    pub(crate) const fn is_all_supported(self) -> bool {
        Self::SUPPORTED.contains(self)
    }

    /// Returns whether receive operations should consume or peek data.
    pub(crate) fn receive_behavior(self) -> ReceiveBehavior {
        if self.contains(Self::MSG_PEEK) {
            ReceiveBehavior::Peek
        } else {
            ReceiveBehavior::Recv
        }
    }
}

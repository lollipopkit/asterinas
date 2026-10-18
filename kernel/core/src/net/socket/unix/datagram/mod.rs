// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::AtomicI32;

mod message;
mod socket;

pub(crate) use socket::UnixDatagramSocket;

/// `net.unix.max_dgram_qlen`, which limits the length of the receive queue of a UNIX datagram
/// socket.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L3814>
pub(crate) static MAX_DGRAM_QLEN: AtomicI32 = AtomicI32::new(10);

// SPDX-License-Identifier: MPL-2.0

//! Socket buffer sizes (`SO_SNDBUF` and `SO_RCVBUF`) and their limits.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::prelude::*;

/// The truesize of the smallest buffer charged to a socket.
///
/// This is `TCP_SKB_MIN_TRUESIZE` in Linux, which is `2048 + SKB_DATA_ALIGN(sizeof(struct
/// sk_buff))` on 64-bit platforms.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/net/sock.h#L2627-L2630>
const SKB_MIN_TRUESIZE: u32 = 2048 + 256;

/// The minimum send buffer size.
pub(crate) const SOCK_MIN_SNDBUF: u32 = SKB_MIN_TRUESIZE * 2;
/// The minimum receive buffer size.
pub(crate) const SOCK_MIN_RCVBUF: u32 = SKB_MIN_TRUESIZE;

/// The overhead charged to a socket buffer for each packet or message, in addition to its data.
///
/// This is `SKB_TRUESIZE(0)` in Linux, which includes the sizes of `struct sk_buff` and `struct
/// skb_shared_info` on 64-bit platforms. Charging it makes small packets or messages consume the
/// buffer like in Linux, and bounds the number of queued packets or messages.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/skbuff.h#L273-L275>
pub(crate) const SKB_TRUESIZE_OVERHEAD: usize = 256 + 320;

/// The default buffer size, which is `SK_WMEM_DEFAULT` and `SK_RMEM_DEFAULT` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/net/sock.h#L3082-L3085>
const SK_MEM_DEFAULT: u32 = (SKB_TRUESIZE_OVERHEAD as u32 + 256) * 256;

/// The maximum buffer size that can be set without `CAP_NET_ADMIN`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L285-L290>
const SK_MEM_MAX: u32 = 4 << 20;

/// A sysctl value of socket buffer sizes in `/proc/sys/net/core`.
pub(crate) struct BufferSysctl {
    value: AtomicU32,
    min: u32,
}

impl BufferSysctl {
    const fn new(value: u32, min: u32) -> Self {
        Self {
            value: AtomicU32::new(value),
            min,
        }
    }

    /// Returns the current value.
    pub(crate) fn get(&self) -> u32 {
        self.value.load(Ordering::Relaxed)
    }

    /// Sets a new value, which must not be less than the minimum value.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sysctl_net_core.c#L743-L774>
    pub(crate) fn set(&self, value: i32) -> Result<()> {
        if value < 0 || (value as u32) < self.min {
            return_errno_with_message!(Errno::EINVAL, "the buffer size is too small");
        }
        self.value.store(value as u32, Ordering::Relaxed);
        Ok(())
    }
}

/// `net.core.wmem_max`.
pub(crate) static WMEM_MAX: BufferSysctl = BufferSysctl::new(SK_MEM_MAX, SOCK_MIN_SNDBUF);
/// `net.core.rmem_max`.
pub(crate) static RMEM_MAX: BufferSysctl = BufferSysctl::new(SK_MEM_MAX, SOCK_MIN_RCVBUF);
/// `net.core.wmem_default`.
pub(crate) static WMEM_DEFAULT: BufferSysctl = BufferSysctl::new(SK_MEM_DEFAULT, SOCK_MIN_SNDBUF);
/// `net.core.rmem_default`.
pub(crate) static RMEM_DEFAULT: BufferSysctl = BufferSysctl::new(SK_MEM_DEFAULT, SOCK_MIN_RCVBUF);

/// Computes the send buffer size set by `SO_SNDBUF` (or `SO_SNDBUFFORCE` if `is_force`).
///
/// Like Linux, the value is doubled to account for the bookkeeping overhead, and the result is
/// what `getsockopt` returns. Without `SO_SNDBUFFORCE`, the value is limited by
/// `net.core.wmem_max`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L1337-L1367>
pub(crate) fn send_buf_from_user(value: u32, is_force: bool) -> u32 {
    let value = if is_force {
        (value as i32).max(0) as u32
    } else {
        value.min(WMEM_MAX.get())
    };
    double_buf_size(value, SOCK_MIN_SNDBUF)
}

/// Computes the receive buffer size set by `SO_RCVBUF` (or `SO_RCVBUFFORCE` if `is_force`).
///
/// Like Linux, the value is doubled to account for the bookkeeping overhead, and the result is
/// what `getsockopt` returns. Without `SO_RCVBUFFORCE`, the value is limited by
/// `net.core.rmem_max`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L967-L987>
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L1369-L1388>
pub(crate) fn recv_buf_from_user(value: u32, is_force: bool) -> u32 {
    let value = if is_force {
        (value as i32).max(0) as u32
    } else {
        value.min(RMEM_MAX.get())
    };
    double_buf_size(value, SOCK_MIN_RCVBUF)
}

fn double_buf_size(value: u32, min: u32) -> u32 {
    // The value is non-negative as an `i32` since it does not exceed the sysctl maximum values.
    let value = value.min(i32::MAX as u32 / 2);
    (value * 2).max(min)
}

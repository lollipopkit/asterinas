// SPDX-License-Identifier: MPL-2.0

use alloc::boxed::Box;

use smoltcp::time::Duration;

use super::{
    NeedIfacePoll,
    unbound::{RawTcpSocket, new_tcp_socket},
};

/// A trait defines setting socket options on a raw socket.
pub trait RawTcpSetOption {
    /// Sets the keep alive interval.
    ///
    /// Polling the iface _may_ be required after this method succeeds.
    fn set_keep_alive(&self, interval: Option<Duration>) -> NeedIfacePoll;

    /// Enables or disables Nagle’s Algorithm.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    fn set_nagle_enabled(&self, enabled: bool);
}

/// Socket options on a raw socket.
pub struct RawTcpOption {
    /// The keep alive interval.
    pub keep_alive: Option<Duration>,
    /// Whether Nagle's algorithm is enabled.
    pub is_nagle_enabled: bool,
    /// The length of the receive buffer.
    pub recv_buf_len: usize,
    /// The length of the send buffer.
    pub send_buf_len: usize,
}

impl RawTcpOption {
    /// Creates a raw socket with the options.
    pub(super) fn new_socket(&self) -> Box<RawTcpSocket> {
        let mut socket = new_tcp_socket(self.recv_buf_len, self.send_buf_len);
        socket.set_keep_alive(self.keep_alive);
        socket.set_nagle_enabled(self.is_nagle_enabled);
        socket
    }

    /// Creates a raw socket with the buffer lengths and the options of `from`.
    pub(super) fn new_inherited(from: &RawTcpSocket) -> Box<RawTcpSocket> {
        let mut socket = new_tcp_socket(from.recv_capacity(), from.send_capacity());
        Self::inherit(from, &mut socket);
        socket
    }

    /// Copies the options (but not the buffer lengths) from `from` to `to`.
    pub(super) fn inherit(from: &RawTcpSocket, to: &mut RawTcpSocket) {
        to.set_keep_alive(from.keep_alive());
        to.set_nagle_enabled(from.nagle_enabled());
    }
}

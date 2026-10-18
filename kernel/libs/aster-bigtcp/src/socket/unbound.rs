// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, vec, vec::Vec};

pub(super) type RawTcpSocket = smoltcp::socket::tcp::Socket<'static>;
pub type RawUdpSocket = smoltcp::socket::udp::Socket<'static>;

/// Creates a raw TCP socket with the specified buffer lengths.
///
/// The buffer lengths are limited by [`TCP_MAX_BUF_LEN`].
pub(super) fn new_tcp_socket(recv_buf_len: usize, send_buf_len: usize) -> Box<RawTcpSocket> {
    let raw_tcp_socket = {
        let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![
            0u8;
            recv_buf_len
                .clamp(1, TCP_MAX_BUF_LEN)
        ]);
        let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![
            0u8;
            send_buf_len
                .clamp(1, TCP_MAX_BUF_LEN)
        ]);
        RawTcpSocket::new(rx_buffer, tx_buffer)
    };
    Box::new(raw_tcp_socket)
}

/// Creates a raw UDP socket that only sends datagrams.
///
/// Received datagrams are queued in a [`UdpRecvQueue`] instead.
///
/// [`UdpRecvQueue`]: super::bound::UdpRecvQueue
pub(super) fn new_udp_socket() -> Box<RawUdpSocket> {
    let raw_udp_socket = {
        let metadata = smoltcp::socket::udp::PacketMetadata::EMPTY;
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(Vec::new(), Vec::new());
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![metadata; UDP_METADATA_LEN],
            vec![0u8; UDP_SEND_PAYLOAD_LEN],
        );
        RawUdpSocket::new(rx_buffer, tx_buffer)
    };
    Box::new(raw_udp_socket)
}

// TCP socket buffer sizes:
//
// According to
// <https://github.com/torvalds/linux/blob/9852d85ec9d492ebef56dc5f229416c925758edc/include/net/sock.h#L2798-L2806>
// and
// <https://github.com/torvalds/linux/blob/9852d85ec9d492ebef56dc5f229416c925758edc/net/core/sock.c#L286-L287>,
// it seems that the socket buffer should be 256 packets * 256 bytes/packet = 65536 bytes by
// default. However, the loopback MTU is also 65536 bytes, and having the same size for the socket
// buffer and the MTU will cause the implementation of Nagle's algorithm in smoltcp to behave
// abnormally (see <https://github.com/asterinas/asterinas/pull/1396>). So the socket buffer size
// is increased from 64K to 128K.
pub const TCP_RECV_BUF_LEN: usize = 65536 * 2;
pub const TCP_SEND_BUF_LEN: usize = 65536 * 2;

/// The maximum length of the TCP socket buffers.
///
/// The buffers are allocated when the socket is created, so their lengths are limited. This is
/// twice the default `net.core.rmem_max` and `net.core.wmem_max` in Linux, which is the maximum
/// buffer size that can be set without `CAP_NET_ADMIN`.
const TCP_MAX_BUF_LEN: usize = 8 << 20;

// UDP socket buffer sizes:
const UDP_SEND_PAYLOAD_LEN: usize = 65536;
const UDP_METADATA_LEN: usize = 256;

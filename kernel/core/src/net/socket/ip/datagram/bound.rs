// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::udp::{RecvError, SendError},
    wire::IpEndpoint,
};

use super::unbound::UnboundDatagram;
use crate::{
    events::IoEvents,
    net::{
        iface::{BoundUdpPort, Iface, UdpSocket},
        socket::util::{RecvFlags, RecvOutput, SendFlags, datagram_common},
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

/// The maximum length of a UDP payload, which is limited by the 16-bit length field.
const MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize;

pub(super) struct BoundDatagram {
    bound_socket: UdpSocket,
    remote_endpoint: Option<IpEndpoint>,
    locks: BindLocks,
}

/// Whether the local address and the local port are specified by `bind`.
///
/// These correspond to `SOCK_BINDADDR_LOCK` and `SOCK_BINDPORT_LOCK` in Linux, which decide what
/// is kept after `connect(AF_UNSPEC)`.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BindLocks {
    pub(super) addr: bool,
    pub(super) port: bool,
}

impl BoundDatagram {
    pub(super) fn new(bound_socket: UdpSocket, locks: BindLocks) -> Self {
        Self {
            bound_socket,
            remote_endpoint: None,
            locks,
        }
    }

    /// Dissolves the association with the remote endpoint.
    ///
    /// Like Linux, the port is released unless it is specified by `bind`. If the port is
    /// released, this method returns the unbound socket that this socket becomes, which keeps the
    /// local address only if it is specified by `bind`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L2168-L2193>
    //
    // TODO: Linux keeps the received datagrams after releasing the port, but they are dropped
    // with the bound socket here.
    pub(super) fn disconnect(&mut self) -> Option<UnboundDatagram> {
        self.bound_socket.disconnect();
        self.remote_endpoint = None;

        if self.locks.port {
            return None;
        }
        let local_addr = self
            .locks
            .addr
            .then(|| self.bound_socket.local_endpoint().addr);
        Some(UnboundDatagram::new_disconnected(local_addr))
    }

    pub(super) fn iface(&self) -> &Arc<Iface> {
        self.bound_socket.iface()
    }

    pub(super) fn bound_port(&self) -> &BoundUdpPort {
        self.bound_socket.bound_port()
    }
}

impl datagram_common::Bound for BoundDatagram {
    type Endpoint = IpEndpoint;

    fn local_endpoint(&self) -> Self::Endpoint {
        self.bound_socket.local_endpoint()
    }

    fn remote_endpoint(&self) -> Option<&Self::Endpoint> {
        self.remote_endpoint.as_ref()
    }

    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) {
        self.bound_socket.connect(*endpoint);
        self.remote_endpoint = Some(*endpoint)
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Self::Endpoint)> {
        // User space cannot be accessed while holding spin locks, so the packet is first copied to
        // a kernel buffer. If copying to user space fails later, the packet is dropped like Linux.
        let user_len = writer.sum_lens();
        let result = self
            .bound_socket
            .recv(flags.receive_behavior(), |packet, udp_metadata| {
                let copy_len = packet.len().min(user_len);
                (
                    packet[..copy_len].to_vec(),
                    udp_metadata.endpoint,
                    packet.len(),
                )
            });

        match result {
            Ok((data, endpoint, message_len)) => {
                let copied_len = writer.write(&mut VmReader::from(data.as_slice()))?;
                let output = RecvOutput::new_for_packet(flags, copied_len, message_len);
                Ok((output, endpoint))
            }
            Err(RecvError::Exhausted) => {
                return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty")
            }
            Err(RecvError::Truncated) => {
                unreachable!("`recv` should never fail with `RecvError::Truncated`")
            }
        }
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &Self::Endpoint,
        _flags: SendFlags,
    ) -> Result<usize> {
        let len = reader.sum_lens();
        if len > MAX_UDP_PAYLOAD_LEN {
            return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
        }

        // User space cannot be accessed while holding spin locks, so the data are first copied to
        // a kernel buffer. This also ensures that no packet is sent if the copy fails.
        let mut data = vec![0u8; len];
        reader.read(&mut VmWriter::from(data.as_mut_slice()))?;

        let result = self.bound_socket.send(len, *remote, |socket_buffer| {
            socket_buffer.copy_from_slice(&data)
        });

        match result {
            Ok(()) => Ok(len),
            Err(SendError::TooLarge) => {
                return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
            }
            Err(SendError::Unaddressable) => {
                return_errno_with_message!(Errno::EINVAL, "the destination address is invalid");
            }
            Err(SendError::BufferFull) => {
                return_errno_with_message!(Errno::EAGAIN, "the send buffer is full");
            }
        }
    }

    fn check_io_events(&self) -> IoEvents {
        self.bound_socket.raw_with(|socket| {
            let mut events = IoEvents::empty();

            if socket.can_recv() {
                events |= IoEvents::IN;
            }

            if socket.can_send() {
                events |= IoEvents::OUT;
            }

            events
        })
    }
}

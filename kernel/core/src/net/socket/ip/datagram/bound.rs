// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicBool, Ordering};

use aster_bigtcp::{
    errors::udp::{RecvError, SendError},
    socket::UdpRecvQueue,
    wire::{IpAddress, IpEndpoint},
};

use super::unbound::UnboundDatagram;
use crate::{
    events::IoEvents,
    net::{
        iface::{Iface, UdpSocket},
        route::is_broadcast_endpoint,
        socket::{
            ip::common::{BindLocks, select_source},
            util::{RecvFlags, RecvOutput, SendFlags, datagram_common},
        },
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

/// The maximum length of a UDP payload, which is limited by the 16-bit length field.
const MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize;

/// A bound UDP socket.
///
/// A socket bound at a specified address has one bigtcp socket. A socket bound at the unspecified
/// address has one bigtcp socket on each iface, and all the sockets share the same port number.
/// Like Linux, all the bigtcp sockets share one receive queue, so datagrams are received in their
/// arrival order.
pub(super) struct BoundDatagram {
    // INVARIANT: `bound_sockets` is not empty, and the first socket is bound at the local
    // endpoint.
    bound_sockets: Vec<UdpSocket>,
    recv_queue: Arc<UdpRecvQueue>,
    remote_endpoint: Option<IpEndpoint>,
    /// The source address selected by `connect` if the socket is bound at the unspecified
    /// address.
    connected_source: Option<ConnectedSource>,
    /// Whether the route to the remote endpoint has been checked, like a cached route (i.e.,
    /// `sk_dst_cache`) in Linux.
    ///
    /// Like Linux, a datagram to the remote endpoint is not checked against `SO_BROADCAST` if the
    /// route is cached. The cache is set by a successful `connect` or `send`, and is reset by
    /// every `connect`, even if it fails.
    is_route_cached: AtomicBool,
    locks: BindLocks,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedSource {
    addr: IpAddress,
    /// The index of the bigtcp socket on the iface that owns `addr`.
    socket_index: usize,
}

impl BoundDatagram {
    pub(super) fn new(
        bound_sockets: Vec<UdpSocket>,
        recv_queue: Arc<UdpRecvQueue>,
        locks: BindLocks,
    ) -> Self {
        debug_assert!(!bound_sockets.is_empty());
        Self {
            bound_sockets,
            recv_queue,
            remote_endpoint: None,
            connected_source: None,
            is_route_cached: AtomicBool::new(false),
            locks,
        }
    }

    /// Connects to the remote endpoint.
    ///
    /// Like Linux, connecting to a broadcast address requires `SO_BROADCAST`. If connecting
    /// fails, the socket stays associated with the previous remote endpoint (if any), but the
    /// route must be checked again.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/datagram.c#L36-L63>
    pub(super) fn connect(&mut self, remote: &IpEndpoint, can_broadcast: bool) -> Result<()> {
        *self.is_route_cached.get_mut() = false;

        if !can_broadcast && is_broadcast_endpoint(remote) {
            return_errno_with_message!(
                Errno::EACCES,
                "connecting to a broadcast address without SO_BROADCAST is not allowed"
            );
        }

        datagram_common::Bound::set_remote_endpoint(self, remote)?;
        *self.is_route_cached.get_mut() = true;

        Ok(())
    }

    /// Checks the route to the connected remote endpoint if it is not cached.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L1402-L1432>
    pub(super) fn check_connected_route(&self, can_broadcast: bool) -> Result<()> {
        if self.is_route_cached.load(Ordering::Relaxed) {
            return Ok(());
        }

        if let Some(remote) = self.remote_endpoint.as_ref()
            && !can_broadcast
            && is_broadcast_endpoint(remote)
        {
            return_errno_with_message!(
                Errno::EACCES,
                "sending to a broadcast address without SO_BROADCAST is not allowed"
            );
        }

        self.is_route_cached.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn first_socket(&self) -> &UdpSocket {
        &self.bound_sockets[0]
    }

    /// Dissolves the association with the remote endpoint.
    ///
    /// Like Linux, the port is released unless it is specified by `bind`. If the port is
    /// released, this method returns the unbound socket that this socket becomes, which keeps the
    /// local address only if it is specified by `bind`. A local address selected by `connect` is
    /// always reset.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L2168-L2193>
    pub(super) fn disconnect(&mut self) -> Option<UnboundDatagram> {
        for bound_socket in self.bound_sockets.iter() {
            bound_socket.disconnect();
        }
        self.remote_endpoint = None;
        self.connected_source = None;
        *self.is_route_cached.get_mut() = false;

        if self.locks.port {
            return None;
        }
        let local_addr = self
            .locks
            .addr
            .then(|| self.first_socket().local_endpoint().addr);
        Some(UnboundDatagram::new_disconnected(
            local_addr,
            self.recv_queue.clone(),
        ))
    }

    /// Returns the ifaces of the bigtcp sockets.
    pub(super) fn ifaces(&self) -> impl Iterator<Item = &Arc<Iface>> {
        self.bound_sockets
            .iter()
            .map(|bound_socket| bound_socket.iface())
    }

    pub(super) fn set_can_reuse(&self, can_reuse: bool) {
        for bound_socket in self.bound_sockets.iter() {
            bound_socket.bound_port().set_can_reuse(can_reuse);
        }
    }

    /// Returns the bigtcp socket on `iface`.
    fn socket_on(&self, iface: &Arc<Iface>) -> Result<(usize, &UdpSocket)> {
        self.bound_sockets
            .iter()
            .enumerate()
            .find(|(_, bound_socket)| bound_socket.iface().index() == iface.index())
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the socket is not bound on the route output iface",
                )
            })
    }

    /// Selects the bigtcp socket and the source address for sending datagrams to `remote`.
    ///
    /// If the source address is `None`, the address that the socket is bound at is used.
    fn select_output(&self, remote: &IpEndpoint) -> Result<(&UdpSocket, Option<IpAddress>)> {
        if let Some(source) = self.connected_source {
            return Ok((&self.bound_sockets[source.socket_index], Some(source.addr)));
        }

        let first_socket = self.first_socket();
        if !first_socket.local_endpoint().addr.is_unspecified() {
            return Ok((first_socket, None));
        }

        // Like Linux, the source address is selected for each datagram by routing if the socket is
        // bound at the unspecified address.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L1418-L1439>
        let (iface, source_addr) = select_source(remote.addr)?;
        let (_, bound_socket) = self.socket_on(&iface)?;
        Ok((bound_socket, Some(source_addr)))
    }

    /// Sends a datagram to `remote` and returns the number of bytes sent and the iface to poll.
    pub(super) fn send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &IpEndpoint,
        flags: SendFlags,
    ) -> Result<(usize, &Arc<Iface>)> {
        let len = reader.sum_lens();
        if len > MAX_UDP_PAYLOAD_LEN {
            return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
        }

        let (bound_socket, source_addr) = self.select_output(remote)?;

        // User space cannot be accessed while holding spin locks, so the data are first copied to
        // a kernel buffer. This also ensures that no packet is sent if the copy fails.
        let mut data = vec![0u8; len];
        reader.read(&mut VmWriter::from(data.as_mut_slice()))?;

        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/ip_output.c#L1195-L1196>
        let confirm_neighbor = flags.contains(SendFlags::MSG_CONFIRM);
        let result = bound_socket.send(
            len,
            *remote,
            source_addr,
            confirm_neighbor,
            |socket_buffer| socket_buffer.copy_from_slice(&data),
        );

        match result {
            Ok(()) => Ok((len, bound_socket.iface())),
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
}

impl datagram_common::Bound for BoundDatagram {
    type Endpoint = IpEndpoint;

    fn local_endpoint(&self) -> Self::Endpoint {
        let endpoint = self.first_socket().local_endpoint();
        match self.connected_source {
            Some(source) => IpEndpoint::new(source.addr, endpoint.port),
            None => endpoint,
        }
    }

    fn remote_endpoint(&self) -> Option<&Self::Endpoint> {
        self.remote_endpoint.as_ref()
    }

    /// Connects to the remote endpoint.
    ///
    /// Like Linux, if the socket is bound at the unspecified address, the source address is
    /// selected by routing on the first connection and is kept until the socket is disconnected.
    /// Then the socket only receives datagrams at that address.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/datagram.c#L65-L74>
    //
    // TODO: The port is still bound at the unspecified address on all ifaces, so binding another
    // socket to the same port at a different address still conflicts, which is not the case in
    // Linux.
    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) -> Result<()> {
        if self.connected_source.is_none()
            && self.first_socket().local_endpoint().addr.is_unspecified()
        {
            let (iface, addr) = select_source(endpoint.addr)?;
            let (socket_index, _) = self.socket_on(&iface)?;
            self.connected_source = Some(ConnectedSource { addr, socket_index });
        }

        let local_addr = self.connected_source.map(|source| source.addr);
        for bound_socket in self.bound_sockets.iter() {
            bound_socket.connect(*endpoint, local_addr);
        }
        self.remote_endpoint = Some(*endpoint);

        Ok(())
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Self::Endpoint)> {
        recv_from_queue(&self.recv_queue, writer, flags)
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &Self::Endpoint,
        flags: SendFlags,
    ) -> Result<usize> {
        self.send(reader, remote, flags).map(|(len, _)| len)
    }

    fn check_io_events(&self) -> IoEvents {
        let can_send = self
            .bound_sockets
            .iter()
            .all(|bound_socket| bound_socket.raw_with(|socket| socket.can_send()));

        let mut events = IoEvents::empty();
        if self.recv_queue.can_recv() {
            events |= IoEvents::IN;
        }
        // Datagrams may be sent from any of the sockets.
        if can_send {
            events |= IoEvents::OUT;
        }
        events
    }
}

/// Receives a datagram from the receive queue.
pub(super) fn recv_from_queue(
    recv_queue: &UdpRecvQueue,
    writer: &mut dyn MultiWrite,
    flags: RecvFlags,
) -> Result<(RecvOutput, IpEndpoint)> {
    // User space cannot be accessed while holding spin locks, so the packet is first copied to a
    // kernel buffer. If copying to user space fails later, the packet is dropped like Linux.
    let user_len = writer.sum_lens();
    let result = recv_queue.recv(flags.receive_behavior(), |packet, udp_metadata| {
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

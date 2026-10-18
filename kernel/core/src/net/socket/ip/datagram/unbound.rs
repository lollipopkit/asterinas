// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    socket::{UdpRecvQueue, UdpSocket},
    wire::{IpAddress, IpEndpoint},
};

use super::{
    bound::{BoundDatagram, recv_from_queue},
    observer::DatagramObserver,
};
use crate::{
    events::IoEvents,
    net::socket::{
        ip::{
            addr::UNSPECIFIED_LOCAL_ENDPOINT,
            common::{BindLocks, bind_ports},
        },
        util::{RecvFlags, RecvOutput, datagram_common},
    },
    prelude::*,
    process::signal::Pollee,
    util::MultiWrite,
};

pub(super) struct UnboundDatagram {
    /// The local address specified by `bind`, which is kept after `connect(AF_UNSPEC)` releases
    /// the port.
    local_addr: Option<IpAddress>,
    /// The receive queue, which is created when the socket is bound for the first time.
    ///
    /// Like Linux, the received datagrams are kept after `connect(AF_UNSPEC)` releases the port.
    recv_queue: Option<Arc<UdpRecvQueue>>,
}

impl UnboundDatagram {
    pub(super) fn new() -> Self {
        Self {
            local_addr: None,
            recv_queue: None,
        }
    }

    pub(super) fn new_disconnected(
        local_addr: Option<IpAddress>,
        recv_queue: Arc<UdpRecvQueue>,
    ) -> Self {
        Self {
            local_addr,
            recv_queue: Some(recv_queue),
        }
    }

    fn recv_queue(&mut self) -> Arc<UdpRecvQueue> {
        self.recv_queue
            .get_or_insert_with(UdpRecvQueue::new)
            .clone()
    }

    /// Returns the local endpoint, whose port is always zero.
    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.local_addr
            .map_or(UNSPECIFIED_LOCAL_ENDPOINT, |addr| IpEndpoint::new(addr, 0))
    }
}

pub(super) struct BindOptions {
    pub(super) can_reuse: bool,
}

impl datagram_common::Unbound for UnboundDatagram {
    type Endpoint = IpEndpoint;
    type BindOptions = BindOptions;

    type Bound = BoundDatagram;

    fn bind(
        &mut self,
        endpoint: &Self::Endpoint,
        pollee: &Pollee,
        options: BindOptions,
    ) -> Result<Self::Bound> {
        let locks = BindLocks::from_bind(endpoint);
        new_bound(
            endpoint,
            options.can_reuse,
            locks,
            self.recv_queue(),
            pollee,
        )
    }

    /// Binds the socket to an ephemeral port.
    ///
    /// Like Linux, the socket is bound at the unspecified address unless the local address is
    /// kept after `connect(AF_UNSPEC)`. If the socket is then connected, the local address will be
    /// selected by routing.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/af_inet.c#L181-L196>
    fn bind_ephemeral(
        &mut self,
        _remote_endpoint: &Self::Endpoint,
        pollee: &Pollee,
    ) -> Result<Self::Bound> {
        let locks = BindLocks {
            addr: self.local_addr.is_some(),
            port: false,
        };
        new_bound(
            &self.local_endpoint(),
            false,
            locks,
            self.recv_queue(),
            pollee,
        )
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Self::Endpoint)> {
        match self.recv_queue.as_ref() {
            Some(recv_queue) => recv_from_queue(recv_queue, writer, flags),
            None => return_errno_with_message!(Errno::EAGAIN, "the socket is not bound"),
        }
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::OUT;
        if self
            .recv_queue
            .as_ref()
            .is_some_and(|recv_queue| recv_queue.can_recv())
        {
            events |= IoEvents::IN;
        }
        events
    }
}

fn new_bound(
    endpoint: &IpEndpoint,
    can_reuse: bool,
    locks: BindLocks,
    recv_queue: Arc<UdpRecvQueue>,
    pollee: &Pollee,
) -> Result<BoundDatagram> {
    let bound_ports = bind_ports(endpoint, can_reuse, false, |iface, config| {
        iface.bind_udp(config)
    })?;

    let bound_sockets = bound_ports
        .into_iter()
        .map(|bound_port| {
            match UdpSocket::new_bind(
                bound_port,
                recv_queue.clone(),
                DatagramObserver::new(pollee.clone()),
            ) {
                Ok(bound_socket) => bound_socket,
                Err((_, err)) => {
                    unreachable!("`new_bind` fails with {:?}, which should not happen", err)
                }
            }
        })
        .collect();

    Ok(BoundDatagram::new(bound_sockets, recv_queue, locks))
}

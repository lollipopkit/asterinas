// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    socket::UdpSocket,
    wire::{IpAddress, IpEndpoint},
};

use super::{
    bound::{BindLocks, BoundDatagram},
    observer::DatagramObserver,
};
use crate::{
    events::IoEvents,
    net::{
        iface::BoundUdpPort,
        socket::{
            ip::{
                addr::UNSPECIFIED_LOCAL_ENDPOINT,
                common::{
                    get_ephemeral_endpoint, map_unspecified_to_localhost,
                    resolve_bind_iface_and_config,
                },
            },
            util::datagram_common,
        },
    },
    prelude::*,
    process::signal::Pollee,
};

pub(super) struct UnboundDatagram {
    /// The local address specified by `bind`, which is kept after `connect(AF_UNSPEC)` releases
    /// the port.
    local_addr: Option<IpAddress>,
}

impl UnboundDatagram {
    pub(super) fn new() -> Self {
        Self { local_addr: None }
    }

    pub(super) fn new_disconnected(local_addr: Option<IpAddress>) -> Self {
        Self { local_addr }
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
        let locks = BindLocks {
            addr: !endpoint.addr.is_unspecified(),
            port: endpoint.port != 0,
        };
        new_bound(endpoint, options.can_reuse, locks, pollee)
    }

    fn bind_ephemeral(
        &mut self,
        remote_endpoint: &Self::Endpoint,
        pollee: &Pollee,
    ) -> Result<Self::Bound> {
        let (endpoint, locks) = if let Some(local_addr) = self.local_addr {
            let locks = BindLocks {
                addr: true,
                port: false,
            };
            (IpEndpoint::new(local_addr, 0), locks)
        } else {
            let remote_endpoint = map_unspecified_to_localhost(*remote_endpoint);
            let endpoint = get_ephemeral_endpoint(&remote_endpoint)?;
            (endpoint, BindLocks::default())
        };
        new_bound(&endpoint, false, locks, pollee)
    }

    fn check_io_events(&self) -> IoEvents {
        IoEvents::OUT
    }
}

fn new_bound(
    endpoint: &IpEndpoint,
    can_reuse: bool,
    locks: BindLocks,
    pollee: &Pollee,
) -> Result<BoundDatagram> {
    let bound_port = bind_port(endpoint, can_reuse)?;

    let bound_socket = match UdpSocket::new_bind(bound_port, DatagramObserver::new(pollee.clone()))
    {
        Ok(bound_socket) => bound_socket,
        Err((_, err)) => {
            unreachable!("`new_bind` fails with {:?}, which should not happen", err)
        }
    };

    Ok(BoundDatagram::new(bound_socket, locks))
}

fn bind_port(endpoint: &IpEndpoint, can_reuse: bool) -> Result<BoundUdpPort> {
    let (iface, config) = resolve_bind_iface_and_config(endpoint, can_reuse)?;
    Ok(iface.bind_udp(config)?)
}

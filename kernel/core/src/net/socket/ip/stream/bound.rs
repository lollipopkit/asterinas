// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{iface::BindPortConfig, wire::IpEndpoint};

use crate::{
    net::{
        iface::BoundTcpPort,
        route,
        socket::ip::common::{bind_ports, get_ephemeral_endpoint},
    },
    prelude::*,
};

/// The local ports bound by a TCP socket.
///
/// A socket bound at a specified address has one port. A socket bound at an unspecified address
/// has one port on each iface (and for each address family if the socket is dual-stack), and all
/// the ports share the same port number.
pub(super) struct BoundTcpPorts {
    // INVARIANT: `ports` is not empty, and the first port is bound at the local endpoint.
    ports: Vec<BoundTcpPort>,
}

impl BoundTcpPorts {
    /// Binds the socket to the local endpoint.
    ///
    /// See [`bind_ports`] for the meaning of `is_dual_stack`.
    pub(super) fn bind(
        endpoint: &IpEndpoint,
        can_reuse: bool,
        is_dual_stack: bool,
    ) -> Result<Self> {
        let ports = bind_ports(endpoint, can_reuse, is_dual_stack, |iface, config| {
            iface.bind_tcp(config)
        })?;
        Ok(Self { ports })
    }

    /// Returns the local endpoint, whose address may be unspecified.
    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.ports[0].endpoint()
    }

    pub(super) fn set_can_reuse(&self, can_reuse: bool) {
        for port in self.ports.iter() {
            port.set_can_reuse(can_reuse);
        }
    }

    pub(super) fn into_ports(self) -> Vec<BoundTcpPort> {
        self.ports
    }

    /// Recovers the bound ports from the ports returned by [`Self::into_ports`].
    pub(super) fn from_ports(ports: Vec<BoundTcpPort>) -> Self {
        debug_assert!(!ports.is_empty());
        Self { ports }
    }

    /// Converts the bound ports to a port for connecting to the remote endpoint.
    ///
    /// If the local address is unspecified, the port number is bound at the source address chosen
    /// by routing, and the ports at the unspecified address are released.
    pub(super) fn into_connecting_port(
        self,
        remote_endpoint: &IpEndpoint,
        can_reuse: bool,
    ) -> core::result::Result<BoundTcpPort, (Error, Self)> {
        let local_endpoint = self.local_endpoint();
        if !local_endpoint.addr.is_unspecified() {
            let mut ports = self.ports;
            debug_assert_eq!(ports.len(), 1);
            return Ok(ports.pop().unwrap());
        }

        let source_addr = match get_ephemeral_endpoint(remote_endpoint) {
            Ok(endpoint) => endpoint.addr,
            Err(err) => return Err((err, self)),
        };
        let iface = match route::lookup_local_iface(source_addr) {
            Ok(iface) => iface,
            Err(err) => return Err((err, self)),
        };

        // The port number is owned by this socket, so binding it in the same way as a backlog
        // socket never conflicts with the ports to be released.
        let source_endpoint = IpEndpoint::new(source_addr, local_endpoint.port);
        let port = match iface.bind_tcp(BindPortConfig::new_backlog(source_endpoint)) {
            Ok(port) => port,
            Err(err) => return Err((err.into(), self)),
        };
        port.set_can_reuse(can_reuse);

        Ok(port)
    }
}

impl From<BoundTcpPort> for BoundTcpPorts {
    fn from(port: BoundTcpPort) -> Self {
        Self { ports: vec![port] }
    }
}

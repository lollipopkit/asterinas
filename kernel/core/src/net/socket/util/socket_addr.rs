// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_bigtcp::wire::{Ipv4Address, Ipv6Address, PortNum};

use crate::{
    net::socket::{netlink::NetlinkSocketAddr, unix::UnixSocketAddr, vsock::VsockSocketAddr},
    prelude::*,
    security::audit::{self, AuditEvent},
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SocketAddr {
    Unix(UnixSocketAddr),
    IPv4(Ipv4Address, PortNum),
    IPv6(Ipv6Address, PortNum),
    Netlink(NetlinkSocketAddr),
    Vsock(VsockSocketAddr),
}

impl SocketAddr {
    /// Audits a connection or a message to this address by the current process.
    pub(crate) fn audit_connect(&self) {
        audit::audit(AuditEvent::Connect, || match self {
            Self::IPv4(addr, port) => Some(format!("{addr}:{port}")),
            Self::IPv6(addr, port) => Some(format!("[{addr}]:{port}")),
            Self::Unix(UnixSocketAddr::Path(path)) => {
                Some(format!("unix:{}", path.to_string_lossy()))
            }
            Self::Unix(UnixSocketAddr::Abstract(name)) => {
                Some(format!("unix:@{}", String::from_utf8_lossy(name)))
            }
            Self::Vsock(addr) => Some(format!("vsock:{}:{}", addr.cid, addr.port)),
            // Unnamed Unix sockets and netlink sockets do not reach other parties.
            Self::Unix(UnixSocketAddr::Unnamed) | Self::Netlink(_) => None,
        });
    }
}

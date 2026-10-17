// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_bigtcp::wire::{Ipv4Address, Ipv6Address, PortNum};

use crate::{
    net::socket::{
        Socket, netlink::NetlinkSocketAddr, unix::UnixSocketAddr, vsock::VsockSocketAddr,
    },
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
    /// Returns the target of an [`AuditEvent::Connect`] to this address.
    ///
    /// Returns `None` for addresses that do not reach other parties.
    pub(crate) fn audit_target(&self) -> Option<String> {
        match self {
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
        }
    }

    /// Returns the target to audit if the current process is audited.
    ///
    /// The target is reported with [`audit_connect`] after the operation succeeds.
    pub(crate) fn audit_target_if_audited(addr: Option<&Self>) -> Option<String> {
        if audit::is_audited() {
            addr.and_then(Self::audit_target)
        } else {
            None
        }
    }
}

/// Checks whether the current process may send data to `addr`, or to the peer of `socket` if
/// `addr` is `None`, which is a [`AuditEvent::Connect`] if the process is audited.
pub(crate) fn check_connect(socket: &dyn Socket, addr: Option<&SocketAddr>) -> Result<()> {
    audit::check(AuditEvent::Connect, || match addr {
        Some(addr) => addr.audit_target(),
        None => socket.peer_addr().ok()?.audit_target(),
    })
}

/// Reports an [`AuditEvent::Connect`] to a target from [`SocketAddr::audit_target_if_audited`].
pub(crate) fn audit_connect(target: Option<String>) {
    if let Some(target) = target {
        audit::audit(AuditEvent::Connect, || Some(target));
    }
}

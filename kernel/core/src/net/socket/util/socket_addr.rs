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
    Unspec(UnspecSocketAddr),
}

/// A socket address in the `AF_UNSPEC` family.
///
/// `connect` with such an address dissolves the association of a socket with its peer. IPv4
/// sockets also treat it as an `AF_INET` address in `bind` and `sendmsg`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UnspecSocketAddr {
    /// The IPv4 address and port, if the address is long enough to be read as an `AF_INET` one.
    inet: Option<(Ipv4Address, PortNum)>,
}

impl UnspecSocketAddr {
    pub(crate) const fn new(inet: Option<(Ipv4Address, PortNum)>) -> Self {
        Self { inet }
    }

    /// Returns the IPv4 address and port that the address represents as an `AF_INET` one.
    ///
    /// Fails with `EINVAL` if the address is shorter than an `AF_INET` one.
    pub(crate) fn inet(&self) -> Result<(Ipv4Address, PortNum)> {
        self.inet.ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "the socket address length is too small")
        })
    }
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
            // IPv4 sockets send data to the `AF_INET` address that an `AF_UNSPEC` one represents.
            Self::Unspec(UnspecSocketAddr {
                inet: Some((addr, port)),
            }) => Some(format!("{addr}:{port}")),
            Self::Unspec(UnspecSocketAddr { inet: None }) => None,
            // Unnamed Unix sockets and netlink sockets do not reach other parties.
            Self::Unix(UnixSocketAddr::Unnamed) | Self::Netlink(_) => None,
        }
    }
}

/// Checks whether the current process may connect or send data to `addr`, or to the peer of
/// `socket` if `addr` is `None`, which is an [`AuditEvent::Connect`] if the process is audited.
///
/// Returns the target to report with [`audit_connect`] after the operation succeeds.
pub(crate) fn check_connect(
    socket: &dyn Socket,
    addr: Option<&SocketAddr>,
) -> Result<Option<String>> {
    if !audit::is_audited() {
        return Ok(None);
    }

    let target = match addr {
        Some(addr) => addr.audit_target(),
        None => match socket.peer_addr() {
            Ok(peer) => peer.audit_target(),
            // Nothing can be sent without a destination.
            Err(err) if err.error() == Errno::ENOTCONN => None,
            // The peer cannot be determined, so it is checked as a target that a policy can only
            // allow explicitly.
            Err(_) => Some(String::from("unknown")),
        },
    };
    if let Some(target) = &target {
        audit::check(AuditEvent::Connect, || Some(target.clone()))?;
    }
    Ok(target)
}

/// Reports an [`AuditEvent::Connect`] to a target from [`check_connect`].
pub(crate) fn audit_connect(target: Option<String>) {
    if let Some(target) = target {
        audit::audit(AuditEvent::Connect, || Some(target));
    }
}

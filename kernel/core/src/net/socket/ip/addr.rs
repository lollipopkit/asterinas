// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};

use crate::{net::socket::util::SocketAddr, prelude::*};

impl TryFrom<SocketAddr> for IpEndpoint {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        match value {
            SocketAddr::IPv4(addr, port) => Ok(IpEndpoint::new(addr.into(), port)),
            SocketAddr::IPv6(addr, port) => Ok(IpEndpoint::new(addr.into(), port)),
            _ => return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the address is in an unsupported address family"
            ),
        }
    }
}

impl From<IpEndpoint> for SocketAddr {
    fn from(endpoint: IpEndpoint) -> Self {
        let port = endpoint.port;
        match endpoint.addr {
            IpAddress::Ipv4(addr) => SocketAddr::IPv4(addr, port),
            IpAddress::Ipv6(addr) => SocketAddr::IPv6(addr, port),
        }
    }
}

/// An IPv4 local endpoint, which indicates that the local endpoint is unspecified.
///
/// According to the Linux man pages and the Linux implementation, `getsockname()` will _not_ fail
/// even if the socket is unbound. Instead, it will return an unspecified socket address. This
/// unspecified endpoint helps with that.
pub(super) const UNSPECIFIED_LOCAL_ENDPOINT: IpEndpoint =
    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0);

/// An IPv6 local endpoint, which indicates that the local endpoint is unspecified.
pub(super) const UNSPECIFIED_LOCAL_ENDPOINT_V6: IpEndpoint =
    IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::UNSPECIFIED), 0);

/// Address family for IP sockets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpAddressFamily {
    IPv4,
    IPv6,
}

impl IpAddressFamily {
    /// Returns the unspecified endpoint for this address family.
    pub(super) const fn unspecified_endpoint(&self) -> IpEndpoint {
        match self {
            IpAddressFamily::IPv4 => UNSPECIFIED_LOCAL_ENDPOINT,
            IpAddressFamily::IPv6 => UNSPECIFIED_LOCAL_ENDPOINT_V6,
        }
    }

    /// Converts a socket address to an endpoint of this address family.
    ///
    /// Fails with `EAFNOSUPPORT` if the address is not in this address family.
    pub(super) fn to_endpoint(self, socket_addr: SocketAddr) -> Result<IpEndpoint> {
        let endpoint = IpEndpoint::try_from(socket_addr)?;
        if IpAddressFamily::from(endpoint.addr) != self {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the protocol family does not match the address family"
            );
        }
        Ok(endpoint)
    }

    /// Converts the socket address of `bind` to an endpoint of this address family.
    ///
    /// Like Linux, an IPv4 socket also binds to an `AF_UNSPEC` address as an `AF_INET` one, but
    /// only if the IPv4 address is `INADDR_ANY`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/af_inet.c#L489-L497>
    pub(super) fn to_bind_endpoint(self, socket_addr: SocketAddr) -> Result<IpEndpoint> {
        match (self, socket_addr) {
            (IpAddressFamily::IPv4, SocketAddr::Unspec(addr)) => {
                let (addr, port) = addr.inet()?;
                if !addr.is_unspecified() {
                    return_errno_with_message!(
                        Errno::EAFNOSUPPORT,
                        "an AF_UNSPEC address to bind must be INADDR_ANY"
                    );
                }
                Ok(IpEndpoint::new(addr.into(), port))
            }
            (_, socket_addr) => self.to_endpoint(socket_addr),
        }
    }

    /// Converts the destination socket address of `sendmsg` to an endpoint of this address family.
    ///
    /// Like Linux, an IPv4 socket also sends data to an `AF_UNSPEC` address as an `AF_INET` one.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L1293-L1299>
    pub(super) fn to_send_endpoint(self, socket_addr: SocketAddr) -> Result<IpEndpoint> {
        match (self, socket_addr) {
            (IpAddressFamily::IPv4, SocketAddr::Unspec(addr)) => {
                let (addr, port) = addr.inet()?;
                Ok(IpEndpoint::new(addr.into(), port))
            }
            (_, socket_addr) => self.to_endpoint(socket_addr),
        }
    }

    /// Converts an endpoint to a socket address of this address family.
    ///
    /// For an IPv6 socket, an IPv4 endpoint is converted to an IPv4-mapped IPv6 address. Such an
    /// endpoint comes from IPv4 traffic handled by a dual-stack socket.
    pub(super) fn to_socket_addr(self, endpoint: IpEndpoint) -> SocketAddr {
        match (self, endpoint.addr) {
            (IpAddressFamily::IPv6, IpAddress::Ipv4(addr)) => {
                SocketAddr::IPv6(addr.to_ipv6_mapped(), endpoint.port)
            }
            _ => endpoint.into(),
        }
    }
}

// Note: This does not handle IPv4-mapped IPv6 addresses. When `IPV6_V6ONLY` is set,
// IPv4-mapped addresses are not permitted, so this function cannot be used to determine
// whether such an address is acceptable.
impl From<IpAddress> for IpAddressFamily {
    fn from(addr: IpAddress) -> Self {
        match addr {
            IpAddress::Ipv4(_) => IpAddressFamily::IPv4,
            IpAddress::Ipv6(_) => IpAddressFamily::IPv6,
        }
    }
}

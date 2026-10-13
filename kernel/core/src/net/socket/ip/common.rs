// SPDX-License-Identifier: MPL-2.0

use core::ops::Deref;

use aster_bigtcp::{
    errors::BindError,
    iface::BindPortConfig,
    wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address},
};

use crate::{
    net::{
        iface::{BoundPort, Iface, iter_all_ifaces},
        route,
        socket::util::check_port_privilege,
    },
    prelude::*,
};

pub(super) fn resolve_bind_iface_and_config(
    endpoint: &IpEndpoint,
    can_reuse: bool,
) -> Result<(Arc<Iface>, BindPortConfig)> {
    check_port_privilege(endpoint.port)?;

    let iface = route::lookup_local_iface(endpoint.addr)?;

    let bind_port_config = BindPortConfig::new(*endpoint, can_reuse);

    Ok((iface, bind_port_config))
}

/// Binds a local endpoint to ports on ifaces.
///
/// A specified address is bound on the iface that owns it, which results in one port. An
/// unspecified address is bound on all ifaces with the same port number, so that the socket can
/// receive packets from all of them. If `is_dual_stack` is true, the IPv4 unspecified address is
/// also bound on all ifaces so that an IPv6 socket can receive IPv4 packets.
///
/// The first returned port is always bound at the address of `endpoint`.
//
// TODO: Ifaces that are added after binding are not covered. Currently, all ifaces are created
// during initialization.
pub(super) fn bind_ports<P>(
    endpoint: &IpEndpoint,
    can_reuse: bool,
    is_dual_stack: bool,
    bind: impl Fn(&Arc<Iface>, BindPortConfig) -> core::result::Result<P, BindError>,
) -> Result<Vec<P>>
where
    P: Deref<Target = BoundPort>,
{
    check_port_privilege(endpoint.port)?;

    if !endpoint.addr.is_unspecified() {
        let iface = route::lookup_local_iface(endpoint.addr)?;
        let port = bind(&iface, BindPortConfig::new(*endpoint, can_reuse))?;
        return Ok(vec![port]);
    }

    let mut addrs = vec![endpoint.addr];
    if is_dual_stack {
        debug_assert!(matches!(endpoint.addr, IpAddress::Ipv6(_)));
        addrs.push(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
    }
    let targets: Vec<(&Arc<Iface>, IpAddress)> = addrs
        .iter()
        .flat_map(|addr| iter_all_ifaces().map(|iface| (iface, *addr)))
        .collect();
    let bind_all = |port: u16| {
        targets
            .iter()
            .map(|(iface, addr)| {
                bind(
                    iface,
                    BindPortConfig::new(IpEndpoint::new(*addr, port), can_reuse),
                )
            })
            .collect::<core::result::Result<Vec<_>, _>>()
    };

    if endpoint.port != 0 {
        return Ok(bind_all(endpoint.port)?);
    }

    // Pick an ephemeral port on the first iface, then try to bind the same port on the others.
    // Each try starts after the last picked port, so all ephemeral ports are tried in the end.
    const NUM_EPHEMERAL_PORTS: usize = 60999 - 32768 + 1;
    let (first_iface, first_addr) = targets[0];
    for _ in 0..NUM_EPHEMERAL_PORTS {
        let first = bind(
            first_iface,
            BindPortConfig::new(IpEndpoint::new(first_addr, 0), can_reuse),
        )?;
        let port = first.port();
        // Release the picked port so that `bind_all` can bind it again on the first iface.
        drop(first);

        match bind_all(port) {
            Ok(ports) => return Ok(ports),
            Err(BindError::InUse) => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(BindError::Exhausted.into())
}

impl From<BindError> for Error {
    fn from(value: BindError) -> Self {
        match value {
            BindError::Exhausted => {
                Error::with_message(Errno::EAGAIN, "no ephemeral port is available")
            }
            BindError::InUse => {
                Error::with_message(Errno::EADDRINUSE, "the address is already in use")
            }
        }
    }
}

pub(super) fn get_ephemeral_endpoint(remote_endpoint: &IpEndpoint) -> Result<IpEndpoint> {
    let route_dst = remote_endpoint.addr;
    let iface = route::lookup_iface(route_dst)?;

    let source = match route_dst {
        IpAddress::Ipv4(_) => iface
            .ipv4_cidr()
            .map(|cidr| IpAddress::Ipv4(cidr.address()))
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the route output iface has no IPv4 address",
                )
            })?,
        IpAddress::Ipv6(_) => iface
            .ipv6_cidr()
            .map(|cidr| IpAddress::Ipv6(cidr.address()))
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the route output iface has no IPv6 address",
                )
            })?,
    };

    Ok(IpEndpoint::new(source, 0))
}

/// Maps an unspecified `connect` destination to the loopback address.
///
/// Linux treats `connect` to an unspecified address as connecting to localhost.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/net/ipv4/route.c#L2803-L2812>.
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/net/ipv6/tcp_ipv6.c#L171-L181>.
pub(super) fn map_unspecified_to_localhost(mut endpoint: IpEndpoint) -> IpEndpoint {
    endpoint.addr = match endpoint.addr {
        IpAddress::Ipv4(address) if address.is_unspecified() => Ipv4Address::LOCALHOST.into(),
        IpAddress::Ipv6(address) if address.is_unspecified() => Ipv6Address::LOCALHOST.into(),
        address => address,
    };
    endpoint
}

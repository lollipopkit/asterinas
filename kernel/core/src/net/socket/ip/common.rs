// SPDX-License-Identifier: MPL-2.0

use core::ops::Deref;

use aster_bigtcp::{
    errors::BindError,
    iface::BindPortConfig,
    wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address},
};
use ostd::task::Task;

use crate::{
    net::{
        iface::{BoundPort, Iface, iter_all_ifaces},
        route,
        socket::util::check_port_privilege,
    },
    prelude::*,
    vm::{perms::VmPerms, vmar::PageFaultInfo},
};

/// Checks whether the current thread may bind to `endpoint`.
///
/// Port 0 asks for an ephemeral port, which needs no privilege.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/af_inet.c#L516-L520>
fn check_bind_privilege(endpoint: &IpEndpoint) -> Result<()> {
    if endpoint.port == 0 {
        return Ok(());
    }
    check_port_privilege(endpoint.port)
}

/// Whether the local address and the local port are specified by `bind`.
///
/// These correspond to `SOCK_BINDADDR_LOCK` and `SOCK_BINDPORT_LOCK` in Linux, which decide what
/// is kept after `connect(AF_UNSPEC)`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/af_inet.c#L559-L562>
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BindLocks {
    pub(super) addr: bool,
    pub(super) port: bool,
}

impl BindLocks {
    /// Returns the locks set by binding to `endpoint`.
    pub(super) fn from_bind(endpoint: &IpEndpoint) -> Self {
        Self {
            addr: !endpoint.addr.is_unspecified(),
            port: endpoint.port != 0,
        }
    }
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
    check_bind_privilege(endpoint)?;

    bind_ports_with(
        endpoint,
        is_dual_stack,
        |endpoint| BindPortConfig::new(endpoint, can_reuse),
        bind,
    )
}

/// Binds a port number that the socket still owns at `endpoint` again.
///
/// This works like [`bind_ports`], except that the port number must be specified and owned by
/// the socket (e.g., by its connection that is being reset). So binding never conflicts with the
/// ports that are to be released. The caller should then set whether the new ports are reusable.
pub(super) fn rebind_owned_ports<P>(
    endpoint: &IpEndpoint,
    is_dual_stack: bool,
    bind: impl Fn(&Arc<Iface>, BindPortConfig) -> core::result::Result<P, BindError>,
) -> Result<Vec<P>>
where
    P: Deref<Target = BoundPort>,
{
    debug_assert_ne!(endpoint.port, 0);

    bind_ports_with(endpoint, is_dual_stack, BindPortConfig::new_backlog, bind)
}

fn bind_ports_with<P>(
    endpoint: &IpEndpoint,
    is_dual_stack: bool,
    config: impl Fn(IpEndpoint) -> BindPortConfig,
    bind: impl Fn(&Arc<Iface>, BindPortConfig) -> core::result::Result<P, BindError>,
) -> Result<Vec<P>>
where
    P: Deref<Target = BoundPort>,
{
    if !endpoint.addr.is_unspecified() {
        let iface = route::lookup_local_iface(endpoint.addr)?;
        let port = bind(&iface, config(*endpoint))?;
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
            .map(|(iface, addr)| bind(iface, config(IpEndpoint::new(*addr, port))))
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
        let first = bind(first_iface, config(IpEndpoint::new(first_addr, 0)))?;
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

/// Runs `copy`, which copies data from or to user space while holding spin locks.
///
/// The page fault handler is disabled when running `copy`, because handling page faults may sleep.
/// Returns `None` if `copy` fails due to a page fault. In that case, the caller should release the
/// spin locks, call [`fault_in_user_page`], and retry.
pub(super) fn try_copy_in_atomic_mode<T>(copy: impl FnOnce() -> Result<T>) -> Option<Result<T>> {
    let task = Task::current().unwrap();
    match task.as_thread_local() {
        Some(thread_local) => thread_local.with_page_fault_disabled(copy),
        // Kernel threads do not access user space, so page faults cannot occur.
        None => Some(copy()),
    }
}

/// Handles the page fault at `addr` of the current user space.
///
/// This method must not be called in the atomic mode. It fails with `EFAULT` if the page fault
/// cannot be resolved, e.g., when the address is not mapped.
pub(super) fn fault_in_user_page(addr: Option<Vaddr>, perms: VmPerms) -> Result<()> {
    let Some(addr) = addr else {
        return_errno_with_message!(Errno::EFAULT, "no user buffer can cause the page fault");
    };

    let task = Task::current().unwrap();
    let thread_local = task.as_thread_local().unwrap();
    CurrentUserSpace::new(thread_local)
        .vmar()
        .handle_page_fault(&PageFaultInfo::new(addr, perms))
        .map_err(|_| Error::with_message(Errno::EFAULT, "the user buffer is not accessible"))
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
    let (_, source) = select_source(remote_endpoint.addr)?;
    Ok(IpEndpoint::new(source, 0))
}

/// Selects the output iface and the source address for sending packets to `dst`.
///
/// This is how Linux chooses the source address if the socket is bound at the unspecified
/// address.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/route.c#L2871-L2877>
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/fib_semantics.c#L2253-L2264>
pub(super) fn select_source(dst: IpAddress) -> Result<(Arc<Iface>, IpAddress)> {
    let iface = route::lookup_iface(dst)?;

    let source = match dst {
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

    Ok((iface, source))
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

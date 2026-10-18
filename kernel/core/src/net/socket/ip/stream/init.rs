// SPDX-License-Identifier: MPL-2.0

use core::{
    net::Ipv4Addr,
    sync::atomic::{AtomicI32, Ordering},
};

use aster_bigtcp::{
    socket::RawTcpOption,
    wire::{IpAddress, IpEndpoint, Ipv6Address},
};

use super::{
    bound::BoundTcpPorts, connecting::ConnectingStream, listen::ListenStream,
    observer::StreamObserver,
};
use crate::{
    events::IoEvents,
    net::{
        iface::BoundTcpPort,
        route::is_broadcast_endpoint,
        socket::{
            ip::{
                addr::IpAddressFamily,
                common::{get_ephemeral_endpoint, map_unspecified_to_localhost},
            },
            util::SocketAddr,
        },
    },
    prelude::*,
};

pub(super) struct InitStream {
    bound_ports: Option<BoundTcpPorts>,
    /// The local address specified by `bind`, which is kept after `connect(AF_UNSPEC)` releases
    /// the port.
    local_addr: Option<IpAddress>,
    /// Indicates if the last `connect()` is considered to be done.
    ///
    /// If `connect()` is called but we're still in the `InitStream`, this means that the
    /// connection is refused.
    ///
    ///  * If the connection is refused synchronously, the error code is returned by the
    ///    `connect()` system call, and after that we always consider the `connect()` to be already
    ///    done.
    ///
    ///  * If the connection is refused asynchronously (e.g., non-blocking sockets or interrupted
    ///    `connect()`), the last `connect()` is not considered to have been done until another
    ///    `connect()`, which checks and resets the boolean value and returns an appropriate error
    ///    code.
    is_connect_done: bool,
    /// The pending socket error, or zero if there is none.
    ///
    /// This is set to `ECONNREFUSED` when the connection is refused, or `ECONNRESET` when the
    /// connection is reset by `connect(AF_UNSPEC)`. It is cleared when the error code is reported
    /// via `getsockopt(SOL_SOCKET, SO_ERROR)`, `send()`, `recv()`, or `connect()`.
    error: AtomicI32,
}

impl InitStream {
    pub(super) fn new() -> Self {
        Self {
            bound_ports: None,
            local_addr: None,
            is_connect_done: true,
            error: AtomicI32::new(0),
        }
    }

    pub(super) fn new_bound(bound_ports: BoundTcpPorts) -> Self {
        Self {
            bound_ports: Some(bound_ports),
            ..Self::new()
        }
    }

    pub(super) fn new_refused(bound_port: BoundTcpPort) -> Self {
        Self {
            bound_ports: Some(bound_port.into()),
            is_connect_done: false,
            error: AtomicI32::new(Errno::ECONNREFUSED as i32),
            ..Self::new()
        }
    }

    /// Creates a socket that is disconnected by `connect(AF_UNSPEC)`.
    ///
    /// If `bound_ports` is `None`, the port is released, but `local_addr` (if any) is kept.
    pub(super) fn new_disconnected(
        bound_ports: Option<BoundTcpPorts>,
        local_addr: Option<IpAddress>,
        error: Option<Errno>,
    ) -> Self {
        Self {
            bound_ports,
            local_addr,
            error: AtomicI32::new(error.map_or(0, |errno| errno as i32)),
            ..Self::new()
        }
    }

    pub(super) fn bind(
        &mut self,
        endpoint: &IpEndpoint,
        family: IpAddressFamily,
        can_reuse: bool,
        is_dual_stack: bool,
    ) -> Result<()> {
        if self.bound_ports.is_some() {
            return_errno_with_message!(Errno::EINVAL, "the socket is already bound to an address");
        }

        // When we support `IPV6_V6ONLY` and if it is set, we should also reject IPv4-mapped
        // IPv6 addresses.
        if IpAddressFamily::from(endpoint.addr) != family {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the protocol family does not match the address family"
            );
        }

        self.bound_ports = Some(BoundTcpPorts::bind(endpoint, can_reuse, is_dual_stack)?);
        self.local_addr = None;

        Ok(())
    }

    pub(super) fn bound_ports(&self) -> Option<&BoundTcpPorts> {
        self.bound_ports.as_ref()
    }

    pub(super) fn connect(
        self,
        remote_endpoint: &IpEndpoint,
        family: IpAddressFamily,
        option: &RawTcpOption,
        can_reuse: bool,
        observer: StreamObserver,
    ) -> Result<ConnectingStream, (Error, Self)> {
        debug_assert!(
            self.is_connect_done,
            "`finish_last_connect()` should be called before calling `connect()`"
        );

        // When we support `IPV6_V6ONLY` and if it is set, we should also reject IPv4-mapped
        // IPv6 addresses.
        if IpAddressFamily::from(remote_endpoint.addr) != family {
            return Err((
                Error::with_message(
                    Errno::EAFNOSUPPORT,
                    "the protocol family does not match the address family",
                ),
                self,
            ));
        }

        // FIXME: This is a temporary compatibility workaround for some gVisor test cases.
        // Remove it once IPv4-mapped IPv6 TCP is supported.
        // gVisor expects that connecting to `::ffff:0.0.0.0` returns `ECONNREFUSED`
        // when there's no listener on that address.
        // Linux handles `::ffff:0.0.0.0` via the IPv4 TCP path and routes it to `127.0.0.1`.
        // IPv4-mapped loopback addresses also use the IPv4 TCP path.
        let is_ipv4_mapped_localhost = matches!(
            remote_endpoint.addr,
            IpAddress::Ipv6(address)
                if address
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_unspecified() || address.is_loopback())
        );

        let remote_endpoint = map_unspecified_to_localhost(*remote_endpoint);
        if is_broadcast_endpoint(&remote_endpoint) {
            return Err((
                Error::with_message(
                    Errno::ENETUNREACH,
                    "TCP sockets cannot connect to broadcast addresses",
                ),
                self,
            ));
        }
        let route_endpoint = if is_ipv4_mapped_localhost {
            IpEndpoint::new(Ipv6Address::LOCALHOST.into(), remote_endpoint.port)
        } else {
            remote_endpoint
        };

        let bound_port = if let Some(bound_ports) = self.bound_ports {
            match bound_ports.into_connecting_port(&route_endpoint, can_reuse) {
                Ok(bound_port) => bound_port,
                Err((err, bound_ports)) => return Err((err, Self::new_bound(bound_ports))),
            }
        } else {
            let endpoint = match self.local_addr {
                Some(addr) => IpEndpoint::new(addr, 0),
                None => match get_ephemeral_endpoint(&route_endpoint) {
                    Ok(endpoint) => endpoint,
                    Err(err) => return Err((err, self)),
                },
            };
            match BoundTcpPorts::bind(&endpoint, can_reuse, false) {
                Ok(bound_ports) => bound_ports.into_ports().pop().unwrap(),
                Err(err) => return Err((err, self)),
            }
        };

        if is_ipv4_mapped_localhost {
            return Err((
                Error::with_message(
                    Errno::ECONNREFUSED,
                    "IPv4-mapped IPv6 connections are not supported",
                ),
                InitStream::new_refused(bound_port),
            ));
        }

        ConnectingStream::new(bound_port, remote_endpoint, option, observer).map_err(
            |(err, bound_port)| {
                if err.error() == Errno::ECONNREFUSED {
                    (err, InitStream::new_refused(bound_port))
                } else {
                    (err, InitStream::new_bound(bound_port.into()))
                }
            },
        )
    }

    /// Dissolves the association, which only considers the last `connect()` to be done.
    ///
    /// Like Linux, the socket error (if any) is still reported later.
    pub(super) fn disconnect(&mut self) {
        self.is_connect_done = true;
    }

    pub(super) fn finish_last_connect(&mut self) -> Result<()> {
        if self.is_connect_done {
            return Ok(());
        }

        self.is_connect_done = true;

        if let Some(err) = self.test_and_clear_error() {
            return Err(err);
        }
        return_errno_with_message!(
            Errno::ECONNABORTED,
            "the error code for the connection failure is not available"
        );
    }

    pub(super) fn listen(
        self,
        backlog: usize,
        family: IpAddressFamily,
        option: &RawTcpOption,
        can_reuse: bool,
        is_dual_stack: bool,
        observer: StreamObserver,
    ) -> Result<ListenStream, (Error, Self)> {
        if !self.is_connect_done {
            // See the comments of `is_connect_done`.
            // `listen()` is also not allowed until the second `connect()`.
            return Err((
                Error::with_message(
                    Errno::EINVAL,
                    "the connection is refused, but the connecting phase is not done",
                ),
                self,
            ));
        }

        let bound_ports = if let Some(bound_ports) = self.bound_ports {
            bound_ports
        } else {
            // An unbound socket is bound to the unspecified address (or the address kept by
            // `connect(AF_UNSPEC)`) with an ephemeral port.
            // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/ipv4/inet_connection_sock.c#L1363>.
            let endpoint = self
                .local_addr
                .map_or(family.unspecified_endpoint(), |addr| {
                    IpEndpoint::new(addr, 0)
                });
            match BoundTcpPorts::bind(&endpoint, can_reuse, is_dual_stack) {
                Ok(bound_ports) => bound_ports,
                Err(err) => return Err((err, self)),
            }
        };

        match ListenStream::new(bound_ports, backlog, option, observer) {
            Ok(listen_stream) => Ok(listen_stream),
            Err((bound_ports, error)) => Err((error, Self::new_bound(bound_ports))),
        }
    }

    pub(super) fn try_recv(&self) -> Result<(usize, SocketAddr)> {
        // FIXME: Linux does not return addresses for `recvfrom` on connection-oriented sockets.
        // This is a placeholder that has no Linux equivalent. (Note also that in this case
        // `getpeeraddr` will simply fail with `ENOTCONN`).
        const UNSPECIFIED_SOCKET_ADDR: SocketAddr = SocketAddr::IPv4(Ipv4Addr::UNSPECIFIED, 0);

        // Below are some magic checks to make our behavior identical to Linux.

        if let Some(err) = self.test_and_clear_error() {
            return Err(err);
        }

        // Before the last `connect()` is done, the refused socket is shut down, so EOF is
        // reported. After that, Linux disconnects the socket, which clears the shutdown state.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/tcp.c#L2759-L2776>
        if self.is_connect_done {
            return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
        }

        Ok((0, UNSPECIFIED_SOCKET_ADDR))
    }

    pub(super) fn try_send(&self) -> Result<usize> {
        if let Some(err) = self.test_and_clear_error() {
            return Err(err);
        }

        return_errno_with_message!(Errno::EPIPE, "the socket is not connected");
    }

    pub(super) fn local_endpoint(&self) -> Option<IpEndpoint> {
        if let Some(bound_ports) = self.bound_ports.as_ref() {
            return Some(bound_ports.local_endpoint());
        }
        self.local_addr.map(|addr| IpEndpoint::new(addr, 0))
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        // Linux adds OUT and HUP events for a newly created socket
        let mut events = IoEvents::OUT | IoEvents::HUP;

        if self.error.load(Ordering::Relaxed) != 0 {
            events |= IoEvents::ERR;
        }

        events
    }

    pub(super) fn test_and_clear_error(&self) -> Option<Error> {
        let errno = Errno::try_from(self.error.swap(0, Ordering::Relaxed)).ok()?;
        let message = match errno {
            Errno::ECONNREFUSED => "the connection is refused",
            Errno::ECONNRESET => "the connection is reset",
            _ => "the socket has an error",
        };
        Some(Error::with_message(errno, message))
    }
}

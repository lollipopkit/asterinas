// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::tcp::ListenError,
    socket::{RawTcpOption, RawTcpSetOption},
    wire::IpEndpoint,
};

use super::{bound::BoundTcpPorts, connected::ConnectedStream, observer::StreamObserver};
use crate::{
    events::IoEvents,
    net::iface::{Iface, TcpListener},
    prelude::*,
};

pub(super) struct ListenStream {
    // INVARIANT: `tcp_listeners` is not empty, and the first listener is at the local endpoint.
    tcp_listeners: Vec<TcpListener>,
}

impl ListenStream {
    pub(super) fn new(
        bound_ports: BoundTcpPorts,
        backlog: usize,
        option: &RawTcpOption,
        observer: StreamObserver,
    ) -> Result<Self, (BoundTcpPorts, Error)> {
        const SOMAXCONN: usize = 4096;
        let max_conn = SOMAXCONN.min(backlog);

        match TcpListener::new_listen_all(bound_ports.into_ports(), max_conn, option, observer) {
            Ok(tcp_listeners) => Ok(Self { tcp_listeners }),
            Err((bound_ports, ListenError::AddressInUse)) => Err((
                BoundTcpPorts::from_ports(bound_ports),
                Error::with_message(Errno::EADDRINUSE, "listener key conflicts"),
            )),
            Err((_, err)) => {
                unreachable!(
                    "`new_listen_all` fails with {:?}, which should not happen",
                    err
                )
            }
        }
    }

    pub(super) fn try_accept(&self) -> Result<ConnectedStream> {
        let (new_conn, remote_endpoint) = self
            .tcp_listeners
            .iter()
            .find_map(|tcp_listener| tcp_listener.accept())
            .ok_or_else(|| {
                Error::with_message(Errno::EAGAIN, "no pending connection is available")
            })?;

        Ok(ConnectedStream::new(new_conn, remote_endpoint, false))
    }

    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.tcp_listeners[0].local_endpoint()
    }

    /// Returns the ifaces of the listeners without duplicates.
    pub(super) fn ifaces(&self) -> Vec<Arc<Iface>> {
        let mut ifaces: Vec<Arc<Iface>> = self
            .tcp_listeners
            .iter()
            .map(|tcp_listener| tcp_listener.iface().clone())
            .collect();
        ifaces.sort_by_key(|iface| iface.index());
        ifaces.dedup_by_key(|iface| iface.index());
        ifaces
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        let can_accept = self
            .tcp_listeners
            .iter()
            .any(|tcp_listener| tcp_listener.can_accept());

        // If network packets come in simultaneously, the socket state may change in the middle.
        // However, the current pollee implementation should be able to handle this race condition.
        if can_accept {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    /// Sets the option on all the listeners and returns the result for the first listener.
    pub(super) fn set_raw_option<R>(&self, set_option: impl Fn(&dyn RawTcpSetOption) -> R) -> R {
        let mut results = self
            .tcp_listeners
            .iter()
            .map(|tcp_listener| set_option(tcp_listener));
        let first = results.next().unwrap();
        results.for_each(drop);
        first
    }

    pub(super) fn into_listeners(self) -> Vec<TcpListener> {
        self.tcp_listeners
    }
}

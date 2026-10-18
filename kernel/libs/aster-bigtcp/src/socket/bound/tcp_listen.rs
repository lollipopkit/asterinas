// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::btree_map::BTreeMap, sync::Arc, vec, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    socket::PollAt,
    time::Duration,
    wire::{IpEndpoint, IpListenEndpoint, IpRepr, TcpRepr},
};

use super::{
    common::{Inner, NeedIfacePoll, Socket, SocketBg},
    tcp_conn::{TcpConnection, TcpConnectionBg, TcpConnectionInner, TcpProcessResult},
};
use crate::{
    errors::tcp::ListenError,
    ext::Ext,
    iface::{BindPortConfig, BoundTcpPort, Iface, PacketSlice, PollableIfaceMut},
    socket::{
        option::{RawTcpOption, RawTcpSetOption},
        unbound::{RawTcpSocket, new_tcp_socket},
    },
    socket_table::{ConnectionKey, ListenerKey},
};

pub type TcpListener<E> = Socket<TcpListenerInner<E>, E>;

pub(super) struct TcpBacklog<E: Ext> {
    socket: Box<RawTcpSocket>,
    max_conn: usize,
    pub(super) connecting: BTreeMap<ConnectionKey, TcpConnection<E>>,
    pub(super) connected: Vec<TcpConnection<E>>,
}

/// States needed by [`TcpListenerBg`].
pub struct TcpListenerInner<E: Ext> {
    pub(super) backlog: SpinLock<TcpBacklog<E>, BottomHalfDisabled>,
    listener_key: ListenerKey,
}

impl<E: Ext> TcpListenerInner<E> {
    fn new(backlog: TcpBacklog<E>, listener_key: ListenerKey) -> Self {
        Self {
            backlog: SpinLock::new(backlog),
            listener_key,
        }
    }
}

impl<E: Ext> Inner<E> for TcpListenerInner<E> {
    type BoundPort = BoundTcpPort<E>;
    type Observer = E::TcpEventObserver;

    fn on_drop(this: &Arc<SocketBg<Self, E>>) {
        debug_assert_eq!(
            Arc::strong_count(this),
            1,
            "a listener must be closed before dropping"
        );
    }
}

pub(crate) type TcpListenerBg<E> = SocketBg<TcpListenerInner<E>, E>;

impl<E: Ext> TcpListener<E> {
    /// Listens at a specified endpoint.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn new_listen(
        bound: BoundTcpPort<E>,
        max_conn: usize,
        option: &RawTcpOption,
        observer: E::TcpEventObserver,
    ) -> Result<Self, (BoundTcpPort<E>, ListenError)> {
        match Self::new_listen_all(vec![bound], max_conn, option, observer) {
            Ok(mut listeners) => Ok(listeners.pop().unwrap()),
            Err((mut bound_ports, err)) => Err((bound_ports.pop().unwrap(), err)),
        }
    }

    /// Listens at the endpoints of multiple bound ports.
    ///
    /// Either a listener is created for every bound port, or no listener is created and the bound
    /// ports are returned with the error. An unspecified address in a bound port means listening
    /// at all the addresses of the iface in the same address family.
    ///
    /// Polling the ifaces is _not_ required after this method succeeds.
    pub fn new_listen_all(
        bound_ports: Vec<BoundTcpPort<E>>,
        max_conn: usize,
        option: &RawTcpOption,
        observer: E::TcpEventObserver,
    ) -> Result<Vec<Self>, (Vec<BoundTcpPort<E>>, ListenError)> {
        // Lock the socket tables of the ifaces in the order of their indexes to avoid deadlocks.
        let mut ifaces: Vec<Arc<dyn Iface<E>>> = bound_ports
            .iter()
            .map(|bound| bound.iface().clone())
            .collect();
        ifaces.sort_by_key(|iface| iface.index());
        ifaces.dedup_by_key(|iface| iface.index());
        let mut socket_tables: Vec<_> = ifaces
            .iter()
            .map(|iface| iface.common().sockets())
            .collect();
        let table_index = |bound: &BoundTcpPort<E>| {
            ifaces
                .iter()
                .position(|iface| iface.index() == bound.iface().index())
                .unwrap()
        };

        let mut sockets = Vec::with_capacity(bound_ports.len());
        for bound in bound_ports.iter() {
            let local_endpoint = bound.endpoint();
            let listener_key = ListenerKey::new(local_endpoint.addr, local_endpoint.port);
            if socket_tables[table_index(bound)]
                .lookup_listener(&listener_key)
                .is_some()
            {
                return Err((bound_ports, ListenError::AddressInUse));
            }

            let mut socket = option.new_socket();
            if let Err(err) = socket.listen(listen_endpoint(local_endpoint)) {
                return Err((bound_ports, err.into()));
            }
            sockets.push(socket);
        }

        let listeners = bound_ports
            .into_iter()
            .zip(sockets)
            .map(|(bound, socket)| {
                let local_endpoint = bound.endpoint();
                let listener_key = ListenerKey::new(local_endpoint.addr, local_endpoint.port);
                let socket_table = &mut socket_tables[table_index(&bound)];

                let backlog = TcpBacklog {
                    socket,
                    max_conn,
                    connecting: BTreeMap::new(),
                    connected: Vec::new(),
                };
                let listener = Self::new(bound, TcpListenerInner::new(backlog, listener_key));
                listener.init_observer(observer.clone());

                // This cannot fail. The bound ports are on different ifaces or have different
                // endpoints, and the listener keys are checked above with the tables locked.
                let res = socket_table.insert_listener(listener.inner().clone());
                debug_assert!(res.is_ok());

                listener
            })
            .collect();

        Ok(listeners)
    }

    /// Accepts a TCP connection.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn accept(&self) -> Option<(TcpConnection<E>, IpEndpoint)> {
        let accepted = {
            let mut backlog = self.0.inner.backlog.lock();
            backlog.connected.pop()?
        };

        let remote_endpoint = {
            // The lock on `accepted` cannot be locked after locking `self`, otherwise we might get
            // a deadlock due to inconsistent lock order problems.
            let mut socket = accepted.0.inner.lock();

            socket.listener = None;

            // A queued connection may have been reset, which clears smoltcp's internal endpoint tuple.
            // Use the saved connection key so that it can still be accepted.
            accepted.0.connection_key().remote_endpoint()
        };

        Some((accepted, remote_endpoint))
    }

    /// Sets the buffer lengths of new connections.
    ///
    /// The buffer length that is `None` is not changed. Connections that have received the SYN
    /// packets are not affected.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn set_buf_lens(&self, recv_buf_len: Option<usize>, send_buf_len: Option<usize>) {
        let (old_recv_buf_len, old_send_buf_len) = {
            let backlog = self.0.inner.backlog.lock();
            (
                backlog.socket.recv_capacity(),
                backlog.socket.send_capacity(),
            )
        };

        // The buffers are allocated without holding the lock.
        let mut new_socket = new_tcp_socket(
            recv_buf_len.unwrap_or(old_recv_buf_len),
            send_buf_len.unwrap_or(old_send_buf_len),
        );

        let old_socket = {
            let mut backlog = self.0.inner.backlog.lock();
            // The listening socket is replaced as soon as it receives a SYN packet in `process`,
            // so it is always in the listening state here.
            RawTcpOption::inherit(&backlog.socket, &mut new_socket);
            new_socket.listen(backlog.socket.listen_endpoint()).unwrap();
            core::mem::replace(&mut backlog.socket, new_socket)
        };
        drop(old_socket);
    }

    /// Returns whether there is a TCP connection to accept.
    ///
    /// It's the caller's responsibility to deal with race conditions when using this method.
    pub fn can_accept(&self) -> bool {
        !self.0.inner.backlog.lock().connected.is_empty()
    }

    /// Closes the listener.
    ///
    /// Polling the iface is _always_ required after this method succeeds.
    ///
    /// Note that this method must be called before dropping the TCP listener to avoid resource
    /// leakage.
    pub fn close(&self) {
        // A TCP listener can be removed immediately.
        self.0.bound.iface().common().remove_tcp_listener(&self.0);

        let (connecting, connected) = {
            let mut socket = self.0.inner.backlog.lock();
            (
                core::mem::take(&mut socket.connecting),
                core::mem::take(&mut socket.connected),
            )
        };

        // The lock on `connecting`/`connected` cannot be locked after locking `self`, otherwise we
        // might get a deadlock due to inconsistent lock order problems.
        connecting.values().for_each(|socket| socket.reset());
        connected.iter().for_each(|socket| socket.reset());
    }
}

impl<E: Ext> RawTcpSetOption for TcpListener<E> {
    fn set_keep_alive(&self, interval: Option<Duration>) -> NeedIfacePoll {
        let mut backlog = self.0.inner.backlog.lock();
        backlog.socket.set_keep_alive(interval);

        NeedIfacePoll::FALSE
    }

    fn set_nagle_enabled(&self, enabled: bool) {
        let mut backlog = self.0.inner.backlog.lock();
        backlog.socket.set_nagle_enabled(enabled);
    }
}

impl<E: Ext> TcpListenerBg<E> {
    pub(crate) const fn listener_key(&self) -> &ListenerKey {
        &self.inner.listener_key
    }
}

impl<E: Ext> TcpListenerBg<E> {
    /// Tries to process an incoming packet and returns whether the packet is processed.
    pub(crate) fn process(
        self: &Arc<Self>,
        iface: &mut PollableIfaceMut<E>,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
        payload: PacketSlice<'_>,
    ) -> (TcpProcessResult, Option<Arc<TcpConnectionBg<E>>>) {
        let mut backlog = self.inner.backlog.lock();

        if !backlog
            .socket
            .accepts(iface.context_mut(), ip_repr, tcp_repr)
        {
            return (TcpProcessResult::NotProcessed, None);
        }

        // FIXME: According to the Linux implementation, `max_conn` is the upper bound of
        // `connected.len()`. We currently limit it to `connected.len() + connecting.len()` for
        // simplicity.
        if backlog.connected.len() + backlog.connecting.len() >= backlog.max_conn {
            return (TcpProcessResult::Processed, None);
        }

        let result = match backlog
            .socket
            .process(iface.context_mut(), ip_repr, tcp_repr, payload)
        {
            None => TcpProcessResult::Processed,
            Some((ip_repr, tcp_repr)) => TcpProcessResult::ProcessedWithReply(ip_repr, tcp_repr),
        };

        if backlog.socket.state() == smoltcp::socket::tcp::State::Listen {
            return (result, None);
        }

        let new_socket = {
            let mut socket = RawTcpOption::new_inherited(&backlog.socket);
            socket.listen(backlog.socket.listen_endpoint()).unwrap();
            socket
        };

        // Bind the connection to the actual local endpoint, which differs from the listener's
        // endpoint if the listener is listening at an unspecified address.
        let local_endpoint = backlog.socket.local_endpoint().unwrap();

        let conn = TcpConnection::new_cyclic(
            self.bound
                .iface()
                .bind_tcp(BindPortConfig::new_backlog(local_endpoint))
                .unwrap(),
            |weak| {
                TcpConnectionInner::new(
                    core::mem::replace(&mut backlog.socket, new_socket),
                    Some(self.clone()),
                    weak,
                )
            },
        );
        let conn_bg = conn.inner().clone();

        let old_conn = backlog.connecting.insert(*conn_bg.connection_key(), conn);
        debug_assert!(old_conn.is_none());

        iface.update_next_poll_at_ms(&conn_bg, PollAt::Now);

        (result, Some(conn_bg))
    }
}

/// Converts the endpoint of a bound port to the endpoint for listening.
///
/// An unspecified address is converted to `None`, which means listening at all addresses.
fn listen_endpoint(endpoint: IpEndpoint) -> IpListenEndpoint {
    let addr = (!endpoint.addr.is_unspecified()).then_some(endpoint.addr);
    IpListenEndpoint {
        addr,
        port: endpoint.port,
    }
}

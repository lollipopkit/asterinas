// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc, vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    iface::Context,
    socket::udp::{RecvError, UdpMetadata},
    storage::SliceLike,
    wire::{IpAddress, IpEndpoint, IpListenEndpoint, IpRepr, UdpRepr},
};

use super::{
    ReceiveBehavior,
    common::{Inner, Socket, SocketBg},
};
use crate::{
    errors::udp::SendError,
    ext::Ext,
    iface::{BoundUdpPort, PacketSlice},
    socket::{RawUdpSocket, event::SocketEvents, unbound::new_udp_socket},
};

pub type UdpSocket<E> = Socket<UdpSocketInner, E>;

/// States needed by [`UdpSocketBg`].
pub struct UdpSocketInner {
    socket: SpinLock<Box<RawUdpSocket>, BottomHalfDisabled>,
    recv_queue: Arc<UdpRecvQueue>,
    need_dispatch: AtomicBool,
    /// Whether the next outgoing packet should confirm that the next hop is reachable.
    pending_confirm: AtomicBool,
    connection: SpinLock<Option<UdpConnection>, BottomHalfDisabled>,
}

/// The receive queue of a UDP socket.
///
/// Like Linux, which has one receive queue for each socket, a socket that has multiple bound
/// sockets (e.g., one on each iface) can share one receive queue among them. So received
/// datagrams are kept in their arrival order, and the queue length is limited for the socket as
/// a whole.
pub struct UdpRecvQueue {
    inner: SpinLock<RecvQueueInner, BottomHalfDisabled>,
    /// The receive buffer size (`sk_rcvbuf` in Linux).
    recv_buf: AtomicUsize,
}

struct RecvQueueInner {
    datagrams: VecDeque<(UdpMetadata, Box<[u8]>)>,
    /// The memory charged for the queued datagrams (`sk_rmem_alloc` in Linux).
    mem_alloc: usize,
}

impl UdpRecvQueue {
    /// Creates an empty receive queue with the receive buffer size.
    pub fn new(recv_buf: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: SpinLock::new(RecvQueueInner {
                datagrams: VecDeque::new(),
                mem_alloc: 0,
            }),
            recv_buf: AtomicUsize::new(recv_buf),
        })
    }

    /// Sets the receive buffer size.
    ///
    /// Datagrams that have been queued are kept even if they exceed the new size.
    pub fn set_recv_buf(&self, recv_buf: usize) {
        self.recv_buf.store(recv_buf, Ordering::Relaxed);
    }

    /// Returns whether there are datagrams to receive.
    pub fn can_recv(&self) -> bool {
        !self.inner.lock().datagrams.is_empty()
    }

    /// Receives a datagram.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn recv<CopyFn, R>(
        &self,
        behavior: ReceiveBehavior,
        copy_fn: CopyFn,
    ) -> Result<R, RecvError>
    where
        CopyFn: FnOnce(&[u8], UdpMetadata) -> R,
    {
        let mut inner = self.inner.lock();

        let result = match behavior {
            ReceiveBehavior::Recv => {
                let (meta, data) = inner.datagrams.pop_front().ok_or(RecvError::Exhausted)?;
                inner.mem_alloc -= datagram_truesize(data.len());
                copy_fn(&data, meta)
            }
            ReceiveBehavior::Peek => {
                let (meta, data) = inner.datagrams.front().ok_or(RecvError::Exhausted)?;
                copy_fn(data, *meta)
            }
        };

        Ok(result)
    }

    /// Queues a received datagram, which is dropped if the receive buffer is full.
    ///
    /// Like Linux, a datagram is dropped if the charged memory would exceed the receive buffer
    /// size, unless the queue is empty.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L1677-L1695>
    fn enqueue(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr, udp_payload: PacketSlice<'_>) {
        let recv_buf = self.recv_buf.load(Ordering::Relaxed);
        let truesize = datagram_truesize(udp_payload.len());

        // The limit is checked before the datagram is copied, so that dropped datagrams are never
        // allocated. The lock is held until the datagram is queued to keep the arrival order.
        let mut inner = self.inner.lock();
        if inner.mem_alloc + truesize > recv_buf
            && (recv_buf > (i32::MAX >> 1) as usize || inner.mem_alloc != 0)
        {
            return;
        }

        let meta = UdpMetadata {
            endpoint: IpEndpoint::new(ip_repr.src_addr(), udp_repr.src_port),
            local_address: Some(ip_repr.dst_addr()),
            meta: Default::default(),
        };
        let mut data = vec![0u8; udp_payload.len()].into_boxed_slice();
        udp_payload.copy_to_slice(&mut data);

        inner.mem_alloc += truesize;
        inner.datagrams.push_back((meta, data));
    }
}

/// Returns the memory charged to the receive buffer for a datagram.
///
/// This approximates `skb->truesize` in Linux with the payload length and the overhead of
/// `SKB_TRUESIZE`, so that small datagrams consume the buffer like in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/skbuff.h#L273-L275>
fn datagram_truesize(len: usize) -> usize {
    const SKB_TRUESIZE_OVERHEAD: usize = 256 + 320;

    len + SKB_TRUESIZE_OVERHEAD
}

/// The association that a UDP socket establishes by connecting.
#[derive(Clone, Copy)]
struct UdpConnection {
    /// The remote endpoint that the socket is connected to.
    remote_endpoint: IpEndpoint,
    /// The local address that replaces the unspecified bound address.
    local_addr: Option<IpAddress>,
}

impl<E: Ext> Inner<E> for UdpSocketInner {
    type BoundPort = BoundUdpPort<E>;
    type Observer = E::UdpEventObserver;

    fn on_drop(this: &Arc<SocketBg<Self, E>>) {
        this.inner.socket.lock().close();

        // A UDP socket can be removed immediately.
        this.bound.iface().common().remove_udp_socket(this);
    }
}

pub(crate) type UdpSocketBg<E> = SocketBg<UdpSocketInner, E>;

impl<E: Ext> UdpSocketBg<E> {
    /// Tries to process an incoming packet and returns whether the packet is processed.
    pub(crate) fn process(
        &self,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        udp_payload: PacketSlice<'_>,
    ) -> bool {
        if self.score(ip_repr, udp_repr).is_none() {
            return false;
        }

        self.inner
            .recv_queue
            .enqueue(ip_repr, udp_repr, udp_payload);

        self.notify_events(SocketEvents::CAN_RECV);

        true
    }

    /// Returns how well an incoming packet matches the socket, or `None` if the socket does not
    /// accept the packet.
    ///
    /// Like Linux, a socket bound at the destination address is preferred over sockets bound at
    /// the unspecified address, since it is looked up first. Among sockets bound at the same
    /// address, a connected socket only accepts packets from its remote endpoint, and is preferred
    /// over unconnected sockets.
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L696-L726>
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/udp.c#L375-L391>
    pub(crate) fn score(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> Option<u8> {
        if udp_repr.dst_port != self.bound.port() {
            return None;
        }

        let connection = *self.inner.connection.lock();

        let local_addr = connection
            .and_then(|connection| connection.local_addr)
            .unwrap_or(*self.bound.addr());
        // The score of matching the local address must exceed any score of matching the remote
        // endpoint below.
        let mut score = if local_addr.is_unspecified() {
            0
        } else if local_addr == ip_repr.dst_addr() {
            4
        } else {
            return None;
        };

        let Some(UdpConnection {
            remote_endpoint: remote,
            ..
        }) = connection
        else {
            return Some(score);
        };

        if remote.addr != ip_repr.src_addr() {
            return None;
        }
        score += 1;
        // A zero port means that the socket is connected to any port of the remote address.
        if remote.port == 0 {
            return Some(score);
        }
        if remote.port != udp_repr.src_port {
            return None;
        }
        Some(score + 1)
    }

    /// Tries to generate an outgoing packet and dispatches the generated packet.
    pub(crate) fn dispatch<D>(&self, cx: &mut Context, dispatch: D)
    where
        D: FnOnce(&mut Context, &IpRepr, &UdpRepr, &[u8]),
    {
        let mut socket = self.inner.socket.lock();

        socket
            .dispatch(cx, |cx, _meta, (ip_repr, udp_repr, udp_payload)| {
                dispatch(cx, &ip_repr, &udp_repr, udp_payload);
                Ok::<(), ()>(())
            })
            .unwrap();

        // For UDP, dequeuing a packet means that we can queue more packets.
        self.notify_events(SocketEvents::CAN_SEND);

        self.inner
            .need_dispatch
            .store(socket.send_queue() > 0, Ordering::Relaxed);
    }

    /// Returns whether the socket _may_ generate an outgoing packet.
    ///
    /// The check is intended to be lock-free and fast, but may have false positives.
    pub(crate) fn need_dispatch(&self) -> bool {
        self.inner.need_dispatch.load(Ordering::Relaxed)
    }

    /// Returns and clears whether the next outgoing packet should confirm the next hop.
    pub(crate) fn take_pending_confirm(&self) -> bool {
        self.inner.pending_confirm.swap(false, Ordering::Relaxed)
    }
}

impl<E: Ext> UdpSocket<E> {
    /// Binds to a specified endpoint.
    ///
    /// Received datagrams are queued in `recv_queue`, which can be shared with other sockets.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn new_bind(
        bound: BoundUdpPort<E>,
        recv_queue: Arc<UdpRecvQueue>,
        observer: E::UdpEventObserver,
    ) -> Result<Self, (BoundUdpPort<E>, smoltcp::socket::udp::BindError)> {
        let local_endpoint = {
            let endpoint = bound.endpoint();

            // This is the address used to send packets. Source addresses can never be the broadcast
            // address, even if it is the address that the socket binds to. No address is used if
            // the socket binds to the unspecified address, so the source address must be specified
            // for each outgoing packet.
            let addr = (!endpoint.addr.is_unspecified()).then(|| {
                let interface = bound.iface().common().interface();
                interface.map_broadcast_to_local(endpoint.addr)
            });

            IpListenEndpoint {
                addr,
                port: endpoint.port,
            }
        };

        let socket = {
            let mut socket = new_udp_socket();

            if let Err(err) = socket.bind(local_endpoint) {
                return Err((bound, err));
            }

            socket
        };

        let inner = UdpSocketInner {
            socket: SpinLock::new(socket),
            recv_queue,
            need_dispatch: AtomicBool::new(false),
            pending_confirm: AtomicBool::new(false),
            connection: SpinLock::new(None),
        };

        let socket = Self::new(bound, inner);
        socket.init_observer(observer);
        socket
            .iface()
            .common()
            .register_udp_socket(socket.inner().clone());

        Ok(socket)
    }

    /// Connects to a remote endpoint.
    ///
    /// After this method returns, only packets from the remote endpoint will be received. Packets
    /// that have already been received are kept.
    ///
    /// If the socket is bound at the unspecified address, `local_addr` can specify the local
    /// address. Then only packets to that address will be received, as if the socket were bound
    /// at that address.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn connect(&self, remote_endpoint: IpEndpoint, local_addr: Option<IpAddress>) {
        debug_assert!(local_addr.is_none() || self.0.bound.addr().is_unspecified());

        *self.0.inner.connection.lock() = Some(UdpConnection {
            remote_endpoint,
            local_addr,
        });
    }

    /// Disconnects from the remote endpoint.
    ///
    /// After this method returns, packets from all remote endpoints will be received again, at the
    /// address that the socket is bound at.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn disconnect(&self) {
        *self.0.inner.connection.lock() = None;
    }

    /// Sends some data to the remote endpoint.
    ///
    /// If `source_addr` is `None`, the address that the socket is bound at is used as the source
    /// address. It must not be `None` if the socket is bound at the unspecified address.
    ///
    /// If `confirm_neighbor` is true, the next outgoing packet confirms that the next hop is
    /// reachable, which is what `MSG_CONFIRM` does in Linux.
    ///
    /// Polling the iface is _always_ required after this method succeeds.
    pub fn send<F, R>(
        &self,
        size: usize,
        remote_endpoint: IpEndpoint,
        source_addr: Option<IpAddress>,
        confirm_neighbor: bool,
        f: F,
    ) -> Result<R, SendError>
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        debug_assert!(source_addr.is_some() || !self.0.bound.addr().is_unspecified());

        let mut socket = self.0.inner.socket.lock();

        if size > socket.payload_send_capacity() {
            return Err(SendError::TooLarge);
        }

        let meta = UdpMetadata {
            local_address: source_addr,
            ..UdpMetadata::from(remote_endpoint)
        };
        let buffer = socket.send(size, meta)?;
        let result = f(buffer);

        if confirm_neighbor {
            self.0.inner.pending_confirm.store(true, Ordering::Relaxed);
        }

        self.0
            .inner
            .need_dispatch
            .store(socket.send_queue() > 0, Ordering::Relaxed);

        Ok(result)
    }

    /// Returns the receive queue.
    pub fn recv_queue(&self) -> &Arc<UdpRecvQueue> {
        &self.0.inner.recv_queue
    }

    /// Calls `f` with an immutable reference to the associated [`RawUdpSocket`].
    //
    // NOTE: If a mutable reference is required, add a method above that correctly updates the next
    // polling time.
    pub fn raw_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&RawUdpSocket) -> R,
    {
        let socket = self.0.inner.socket.lock();
        f(&socket)
    }
}

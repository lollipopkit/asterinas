// SPDX-License-Identifier: MPL-2.0

use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use ostd::sync::{WaitQueue, Waiter};
use spin::Once;

use crate::{
    events::IoEvents,
    net::socket::{
        unix::{
            UnixSocketAddr,
            addr::{UnixSocketAddrBound, UnixSocketAddrKey},
            ctrl_msg::AuxiliaryData,
            datagram::MAX_DGRAM_QLEN,
        },
        util::{ControlMessage, RecvFlags, RecvOutput, buffer_size::SKB_TRUESIZE_OVERHEAD},
    },
    prelude::*,
    process::signal::Pollee,
    util::{MultiRead, MultiWrite},
};

pub(super) struct MessageQueue {
    addr: Once<UnixSocketAddr>,
    inner: Mutex<Option<Inner>>,
    is_pass_cred: AtomicBool,
    pollee: Pollee,
    /// The send buffer size of the socket (`sk_sndbuf` in Linux).
    send_buf: AtomicUsize,
    /// The memory charged for the messages sent by the socket but not received yet
    /// (`sk_wmem_alloc` in Linux).
    wmem_alloc: AtomicUsize,
    /// The wait queue for senders, which are woken up when a message is received from this
    /// queue, or when the messages sent by this socket are received.
    send_wait_queue: WaitQueue,
    /// The maximum length of the receive queue (`sk_max_ack_backlog` in Linux).
    max_qlen: usize,
}

struct Inner {
    messages: VecDeque<Message>,
    is_shutdown: bool,
    /// The queue of the peer that the socket is connected to.
    peer: Option<Weak<MessageQueue>>,
}

impl Inner {
    /// Returns whether the socket accepts messages from the socket that owns `source`.
    fn accepts_from(&self, source: &Arc<MessageQueue>) -> bool {
        self.peer
            .as_ref()
            .is_none_or(|peer| core::ptr::eq(peer.as_ptr(), Arc::as_ptr(source)))
    }

    /// Returns whether the queue is too long for messages from the socket that owns `source`.
    ///
    /// Like Linux, the queue length is limited unless the socket sends to itself or to its peer
    /// that is connected to it.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L2250-L2256>
    fn is_full_for(&self, this: &MessageQueue, source: &Arc<MessageQueue>) -> bool {
        let is_peer = self
            .peer
            .as_ref()
            .is_some_and(|peer| core::ptr::eq(peer.as_ptr(), Arc::as_ptr(source)));
        !core::ptr::eq(this, Arc::as_ptr(source)) && !is_peer && self.messages.len() > this.max_qlen
    }
}

struct Message {
    bytes: Vec<u8>,
    aux: AuxiliaryData,
    src: UnixSocketAddr,
    /// The queue of the sending socket, whose send buffer is charged for the message.
    sender: Arc<MessageQueue>,
}

impl Message {
    /// Returns the memory charged to the send buffer for the message.
    ///
    /// This approximates `skb->truesize` in Linux.
    fn truesize(&self) -> usize {
        self.bytes.len() + SKB_TRUESIZE_OVERHEAD
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        // Like `sock_wfree` in Linux, the send buffer is released when the message is received
        // or discarded.
        self.sender
            .wmem_alloc
            .fetch_sub(self.truesize(), Ordering::Relaxed);
        self.sender.on_write_space();
    }
}

impl MessageQueue {
    /// Looks up a message queue bound to the specific address in the global table.
    pub(super) fn lookup_bound(addr: &UnixSocketAddrKey) -> Result<Arc<MessageQueue>> {
        QUEUE_TABLE.get_queue(addr).ok_or_else(|| {
            Error::with_message(Errno::ECONNREFUSED, "the target socket does not exist")
        })
    }

    pub(super) fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        aux_data: &mut AuxiliaryData,
        source: &MessageReceiver,
    ) -> Result<usize> {
        // Like Linux, the message is not sent until the send buffer is not full. Note that the
        // message can make the used memory exceed the send buffer size.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L3007>
        let sender = &source.queue;
        if sender.wmem_alloc.load(Ordering::Relaxed) >= sender.send_buf.load(Ordering::Relaxed) {
            return_errno_with_message!(Errno::EAGAIN, "the send buffer is full");
        }

        let mut inner = self.inner.lock();
        let Some(inner) = inner.as_mut() else {
            return_errno_with_message!(Errno::ECONNREFUSED, "the target socket is closed");
        };
        if inner.is_shutdown {
            return_errno_with_message!(Errno::EPIPE, "the target socket is shut down");
        }
        // Like Linux, a socket connected to a peer only accepts messages from that peer. This is
        // checked with the lock held, so no messages from an old peer can be queued after the
        // peer changes.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L2187>
        if !inner.accepts_from(&source.queue) {
            return_errno_with_message!(
                Errno::EPERM,
                "the target socket is connected to another socket"
            );
        }

        if inner.is_full_for(self, sender) {
            return_errno_with_message!(Errno::EAGAIN, "the receive queue is full");
        }

        let len = reader.sum_lens();

        let msg = {
            let mut bytes = vec![0; len];
            reader.read(&mut VmWriter::from(bytes.as_mut_slice()))?;

            let mut aux = core::mem::take(aux_data);
            if self.is_pass_cred.load(Ordering::Relaxed)
                || source.queue.is_pass_cred.load(Ordering::Relaxed)
            {
                aux.fill_cred();
            }

            let src = source.queue.addr();

            Message {
                bytes,
                aux,
                src,
                sender: sender.clone(),
            }
        };

        sender
            .wmem_alloc
            .fetch_add(msg.truesize(), Ordering::Relaxed);
        inner.messages.push_back(msg);

        self.pollee.notify(IoEvents::IN);

        Ok(len)
    }

    pub(super) fn addr(&self) -> UnixSocketAddr {
        self.addr.get().cloned().unwrap_or(UnixSocketAddr::Unnamed)
    }

    /// Returns whether the socket accepts messages from the socket that owns `source`.
    ///
    /// A closed socket accepts no messages.
    pub(super) fn accepts_from(&self, source: &Arc<MessageQueue>) -> bool {
        self.inner
            .lock()
            .as_ref()
            .is_some_and(|inner| inner.accepts_from(source))
    }

    /// Blocks until the buffers are free and the `try_send` succeeds, or until interrupted.
    ///
    /// The send buffer of `sender` and the receive queue of this socket are waited for.
    pub(super) fn block_send<F, R>(
        &self,
        sender: &MessageQueue,
        timeout: Option<Duration>,
        mut try_send: F,
    ) -> Result<R>
    where
        F: FnMut() -> Result<R>,
    {
        let (waiter, _) = Waiter::new_pair();
        waiter
            .pause_until_or_timeout(
                || {
                    self.send_wait_queue.enqueue(waiter.waker());
                    if !core::ptr::eq(self, sender) {
                        sender.send_wait_queue.enqueue(waiter.waker());
                    }
                    match try_send() {
                        Err(err) if err.error() == Errno::EAGAIN => None,
                        result => Some(result),
                    }
                },
                timeout.as_ref(),
            )
            .map_err(|err| match err.error() {
                Errno::ETIME => Error::with_message(Errno::EAGAIN, "the socket timeout expired"),
                _ => err,
            })?
    }

    /// Returns the send buffer size.
    pub(super) fn send_buf(&self) -> usize {
        self.send_buf.load(Ordering::Relaxed)
    }

    /// Returns whether the socket is writable, i.e., at most a quarter of the send buffer is
    /// used.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L591-L595>
    pub(super) fn is_writable(&self) -> bool {
        self.wmem_alloc.load(Ordering::Relaxed).saturating_mul(4)
            <= self.send_buf.load(Ordering::Relaxed)
    }

    /// Sets the send buffer size.
    pub(super) fn set_send_buf(&self, send_buf: usize) {
        self.send_buf.store(send_buf, Ordering::Relaxed);
        // Like Linux, wake up the senders since the buffer size may be increased.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L1352-L1353>
        self.on_write_space();
    }

    /// Wakes up the senders and notifies `IoEvents::OUT` if the socket is writable.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L597-L610>
    fn on_write_space(&self) {
        if self.is_writable() {
            self.send_wait_queue.wake_all();
            self.pollee.notify(IoEvents::OUT);
        }
    }
}

// Note that a message receiver corresponds to a live socket and maintains certain invariants. For
// instance, `queue.inner` is always `Some(_)`, and the queue is in the global table if it is bound
// (i.e., `addr` is not `None`).
pub(super) struct MessageReceiver {
    // `addr` should be dropped as soon as the socket file is closed,
    // so it must not belong to `MessageQueue`.
    addr: SpinLock<Option<UnixSocketAddrBound>>,
    queue: Arc<MessageQueue>,
}

impl MessageReceiver {
    pub(super) fn new(send_buf: usize) -> MessageReceiver {
        let inner = Inner {
            messages: VecDeque::new(),
            is_shutdown: false,
            peer: None,
        };

        let queue = MessageQueue {
            addr: Once::new(),
            inner: Mutex::new(Some(inner)),
            is_pass_cred: AtomicBool::new(false),
            pollee: Pollee::new(),
            send_buf: AtomicUsize::new(send_buf),
            wmem_alloc: AtomicUsize::new(0),
            send_wait_queue: WaitQueue::new(),
            // Like Linux, the value is read when the socket is created, and a negative value
            // is converted to a large unsigned value.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L1111>
            max_qlen: MAX_DGRAM_QLEN.load(Ordering::Relaxed) as u32 as usize,
        };

        Self {
            addr: SpinLock::new(None),
            queue: Arc::new(queue),
        }
    }

    pub(super) fn bind(&self, addr_to_bind: UnixSocketAddr) -> Result<()> {
        let mut addr = self.addr.lock();

        if addr.is_some() {
            return addr_to_bind.bind_unnamed();
        }

        let bound_addr = addr_to_bind.bind()?;
        QUEUE_TABLE.add_queue(bound_addr.to_key(), self.queue.clone());
        self.queue.addr.call_once(|| bound_addr.clone().into());
        *addr = Some(bound_addr);

        Ok(())
    }

    pub(super) fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Vec<ControlMessage>, UnixSocketAddr)> {
        let mut inner = self.queue.inner.lock();
        let inner = inner.as_mut().unwrap();

        let Some(msg) = inner.messages.front() else {
            if !inner.is_shutdown {
                return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty");
            } else {
                return Ok((
                    RecvOutput::new_for_packet(flags, 0, 0),
                    Vec::new(),
                    UnixSocketAddr::Unnamed,
                ));
            }
        };

        let message_len = msg.bytes.len();
        let len = writer.write(&mut VmReader::from(msg.bytes.as_slice()))?;

        let is_pass_cred = self.queue.is_pass_cred.load(Ordering::Relaxed);
        let src = msg.src.clone();

        let behavior = flags.receive_behavior();
        let ctrl_msgs = if behavior.will_consume_data() {
            let mut message = inner.messages.pop_front().unwrap();

            self.queue.pollee.invalidate();
            // A writer may still fail if the free space is not enough.
            // So we have to wake up all the writers here.
            self.queue.send_wait_queue.wake_all();

            message.aux.generate_control(behavior, is_pass_cred)
        } else {
            let message = inner.messages.front_mut().unwrap();
            message.aux.generate_control(behavior, is_pass_cred)
        };

        let output = RecvOutput::new_for_packet(flags, len, message_len);
        Ok((output, ctrl_msgs, src))
    }

    /// Sets the queue of the peer that the socket is connected to.
    ///
    /// Like Linux, the received messages are dropped if the socket is disconnected from its peer
    /// or connected to another peer.
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L1572-L1589>
    pub(super) fn set_peer(&self, peer: Option<&Arc<MessageQueue>>) {
        let mut inner = self.queue.inner.lock();
        let inner = inner.as_mut().unwrap();

        let new_peer = peer.map(Arc::downgrade);
        let old_peer = core::mem::replace(&mut inner.peer, new_peer);
        let is_changed = old_peer.is_some_and(|old_peer| {
            inner
                .peer
                .as_ref()
                .is_none_or(|new_peer| !Weak::ptr_eq(&old_peer, new_peer))
        });
        if !is_changed {
            return;
        }

        inner.messages.clear();

        self.queue.pollee.invalidate();
        self.queue.send_wait_queue.wake_all();
    }

    pub(super) fn shutdown(&self) {
        let mut inner = self.queue.inner.lock();
        let inner = inner.as_mut().unwrap();

        inner.is_shutdown = true;
        self.queue.send_wait_queue.wake_all();

        // The caller will notify the pollee.
    }

    pub(super) fn set_pass_cred(&self, is_pass_cred: bool) {
        self.queue
            .is_pass_cred
            .store(is_pass_cred, Ordering::Relaxed);
    }

    pub(super) fn addr(&self) -> UnixSocketAddr {
        self.queue.addr()
    }

    pub(super) fn queue(&self) -> &Arc<MessageQueue> {
        &self.queue
    }

    pub(super) fn pollee(&self) -> &Pollee {
        &self.queue.pollee
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        let inner = self.queue.inner.lock();
        let inner = inner.as_ref().unwrap();

        if inner.is_shutdown {
            IoEvents::IN | IoEvents::RDHUP
        } else if !inner.messages.is_empty() {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }
}

impl Drop for MessageReceiver {
    fn drop(&mut self) {
        if let Some(addr) = self.addr.get_mut().as_mut() {
            QUEUE_TABLE.remove_queue(&addr.to_key());
        }

        *self.queue.inner.lock() = None;
        self.queue.send_wait_queue.wake_all();
    }
}

static QUEUE_TABLE: QueueTable = QueueTable::new();

struct QueueTable {
    message_queues: RwLock<BTreeMap<UnixSocketAddrKey, Arc<MessageQueue>>>,
}

impl QueueTable {
    pub(self) const fn new() -> Self {
        Self {
            message_queues: RwLock::new(BTreeMap::new()),
        }
    }

    pub(self) fn add_queue(&self, addr_key: UnixSocketAddrKey, queue: Arc<MessageQueue>) {
        let old_queue = self.message_queues.write().insert(addr_key, queue);
        debug_assert!(old_queue.is_none());
    }

    pub(self) fn get_queue(&self, addr_key: &UnixSocketAddrKey) -> Option<Arc<MessageQueue>> {
        self.message_queues.read().get(addr_key).cloned()
    }

    pub(self) fn remove_queue(&self, addr_key: &UnixSocketAddrKey) {
        let old_queue = self.message_queues.write().remove(addr_key);
        debug_assert!(old_queue.is_some());
    }
}

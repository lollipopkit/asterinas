// SPDX-License-Identifier: MPL-2.0

use core::{
    num::Wrapping,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use spin::Once;

use crate::{
    events::IoEvents,
    fs::utils::{Endpoint, EndpointState},
    net::socket::{
        unix::{
            UnixSocketAddr, addr::UnixSocketAddrBound, cred::SocketCred, ctrl_msg::AuxiliaryData,
        },
        util::{ControlMessage, RecvFlags, RecvOutput, SockShutdownCmd},
    },
    prelude::*,
    process::signal::Pollee,
    util::{
        MultiRead, MultiWrite,
        ring_buffer::{ProducerU8Ext, RbConsumer, RbProducer, RingBuffer, RingBufferU8Ext},
    },
};

pub(super) struct Connected {
    // `addr` should be dropped as soon as the socket file is closed,
    // so it must not belong to `Inner`.
    addr: Option<UnixSocketAddrBound>,
    inner: Endpoint<Inner>,
}

/// The configuration of one end of a pair of connected sockets.
pub(super) struct EndConfig {
    pub(super) addr: Option<UnixSocketAddrBound>,
    pub(super) state: EndpointState,
    pub(super) cred: SocketCred,
    /// The send buffer size.
    pub(super) send_buf: usize,
}

impl Connected {
    pub(super) fn new_pair(this: EndConfig, peer: EndConfig) -> (Connected, Connected) {
        let (this_writer, peer_reader) =
            RingBuffer::new(initial_buf_capacity(this.send_buf)).split();
        let (peer_writer, this_reader) =
            RingBuffer::new(initial_buf_capacity(peer.send_buf)).split();

        let this_inner = Inner {
            addr: Once::new(),
            state: this.state,
            reader: Mutex::new(this_reader),
            writer: Mutex::new(this_writer),
            send_buf: AtomicUsize::new(this.send_buf),
            all_aux: Mutex::new(VecDeque::new()),
            has_aux: AtomicBool::new(false),
            is_pass_cred: AtomicBool::new(false),
            cred: this.cred,
        };
        let peer_inner = Inner {
            addr: Once::new(),
            state: peer.state,
            reader: Mutex::new(peer_reader),
            writer: Mutex::new(peer_writer),
            send_buf: AtomicUsize::new(peer.send_buf),
            all_aux: Mutex::new(VecDeque::new()),
            has_aux: AtomicBool::new(false),
            is_pass_cred: AtomicBool::new(false),
            cred: peer.cred,
        };

        if let Some(addr) = this.addr.as_ref() {
            this_inner.addr.call_once(|| addr.clone().into());
        }
        if let Some(peer_addr) = peer.addr.as_ref() {
            peer_inner.addr.call_once(|| peer_addr.clone().into());
        }

        let (this_inner, peer_inner) = Endpoint::new_pair(this_inner, peer_inner);

        let this = Connected {
            addr: this.addr,
            inner: this_inner,
        };
        let peer = Connected {
            addr: peer.addr,
            inner: peer_inner,
        };

        (this, peer)
    }

    pub(super) fn addr(&self) -> Option<&UnixSocketAddrBound> {
        self.addr.as_ref()
    }

    pub(super) fn peer_addr(&self) -> UnixSocketAddr {
        self.inner
            .peer_end()
            .addr
            .get()
            .cloned()
            .unwrap_or(UnixSocketAddr::Unnamed)
    }

    pub(super) fn bind(&mut self, addr_to_bind: UnixSocketAddr) -> Result<()> {
        if self.addr.is_some() {
            return addr_to_bind.bind_unnamed();
        }

        let bound_addr = addr_to_bind.bind()?;
        self.inner
            .this_end()
            .addr
            .call_once(|| bound_addr.clone().into());
        self.addr = Some(bound_addr);

        Ok(())
    }

    pub(super) fn try_read(
        &self,
        writer: &mut dyn MultiWrite,
        is_seqpacket: bool,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Vec<ControlMessage>)> {
        let is_empty = writer.is_empty();
        if is_empty && !is_seqpacket {
            if self.inner.this_end().reader.lock().is_empty() {
                return_errno_with_message!(Errno::EAGAIN, "the channel is empty");
            }
            return Ok((RecvOutput::new_for_stream(0), Vec::new()));
        }

        let this_end = self.inner.this_end();
        let peer_end = self.inner.peer_end();

        let mut reader = this_end.reader.lock();
        // `reader.len()` is an `Acquire` operation. So it can guarantee that the `has_aux`
        // check below sees the up-to-date value.
        let no_aux_len = reader.len();

        let is_pass_cred = this_end.is_pass_cred.load(Ordering::Relaxed);
        let behavior = flags.receive_behavior();

        // Fast path: There are no auxiliary data to receive.
        if !peer_end.has_aux.load(Ordering::Relaxed) {
            let read_len = self.inner.read_with(|| {
                let head = reader.head();
                let copy_range = head..head + Wrapping(no_aux_len);
                reader.ring_buffer().pick_fallible(copy_range, writer)
            })?;
            if behavior.will_consume_data() {
                reader.commit_read(read_len);
                if read_len > 0 {
                    self.inner.notify_read();
                }
            }

            let ctrl_msgs = if is_pass_cred {
                AuxiliaryData::default().generate_control(behavior, is_pass_cred)
            } else {
                Vec::new()
            };
            return Ok((RecvOutput::new_for_stream(read_len), ctrl_msgs));
        }

        let mut all_aux = peer_end.all_aux.lock();
        let mut aux_pos = 0;

        let read_base = reader.head();
        let mut read_tot_len = 0;
        let mut trunc_len = 0;

        loop {
            let read_start = read_base + Wrapping(read_tot_len);
            let (aux_len, aux_front) = if let Some(front) = all_aux.get(aux_pos) {
                if front.start == read_start {
                    ((front.end - read_start).0, Some(front))
                } else {
                    ((front.start - read_start).0, None)
                }
            } else {
                ((reader.tail() - read_start).0, None)
            };

            // Unless the auxiliary data we have already received is a subset of the current
            // auxiliary data, we cannot receive additional bytes.
            if read_tot_len > 0 {
                let is_subset = match (aux_pos.checked_sub(1), aux_front.as_ref()) {
                    (Some(prev_pos), Some(front)) => {
                        let prev = all_aux.get(prev_pos).unwrap();
                        prev.data.is_subset_of(&front.data, is_pass_cred)
                    }
                    (Some(prev_pos), None) => {
                        let prev = all_aux.get(prev_pos).unwrap();
                        prev.data
                            .is_subset_of(&AuxiliaryData::default(), is_pass_cred)
                    }
                    (None, Some(front)) => {
                        AuxiliaryData::default().is_subset_of(&front.data, is_pass_cred)
                    }
                    (None, None) => true,
                };
                if !is_subset {
                    break;
                }
            }

            // Read the payload bytes of the current auxiliary data.
            let read_res = if !is_empty && (aux_len > 0 || aux_front.is_none()) {
                self.inner.read_with(|| {
                    let copy_range = read_start..read_start + Wrapping(aux_len);
                    reader.ring_buffer().pick_fallible(copy_range, writer)
                })
            } else {
                Ok(0)
            };
            let read_len = match read_res {
                Ok(read_len) => read_len,
                Err(_) if read_tot_len > 0 => break,
                Err(err) => return Err(err),
            };

            read_tot_len += read_len;
            if aux_front.is_some() {
                aux_pos += 1;
            }

            // Record the current auxiliary data. Break if the read is incomplete or this is a
            // `SOCK_SEQPACKET` socket.
            if is_seqpacket {
                if read_len < aux_len {
                    warn!("setting MSG_TRUNC is not supported");
                    trunc_len = aux_len - read_len;
                }
                break;
            } else if read_len < aux_len {
                break;
            }
        }

        // Consume the payload bytes that we've read.
        if behavior.will_consume_data() {
            let consume_tot_len = read_tot_len + trunc_len;
            reader.commit_read(consume_tot_len);
            if consume_tot_len > 0 {
                self.inner.notify_read();
            }
        }
        drop(reader);

        // Consume the auxiliary data that we've read.
        let ctrl_msgs = if aux_pos >= 1 {
            let aux_data = all_aux.get_mut(aux_pos - 1).unwrap();
            debug_assert!((aux_data.start - read_base).0 <= read_tot_len);

            let ctrl_msgs = aux_data.data.generate_control(behavior, is_pass_cred);
            if behavior.will_consume_data() {
                let remaining_aux_count = all_aux.len() - (aux_pos - 1);
                all_aux.retain_back(remaining_aux_count);
                let consume_len = read_tot_len + trunc_len;
                if (all_aux.front().unwrap().end - read_base).0 <= consume_len {
                    all_aux.pop_front();
                } else {
                    all_aux.front_mut().unwrap().start = read_base + Wrapping(consume_len);
                }
                peer_end
                    .has_aux
                    .store(!all_aux.is_empty(), Ordering::Relaxed);
            }
            ctrl_msgs
        } else {
            let mut default_aux_data = AuxiliaryData::default();
            default_aux_data.generate_control(behavior, is_pass_cred)
        };

        debug_assert!(is_seqpacket || read_tot_len != 0);
        let output = if is_seqpacket {
            let message_len = read_tot_len + trunc_len;
            RecvOutput::new_for_packet(flags, read_tot_len, message_len)
        } else {
            RecvOutput::new_for_stream(read_tot_len)
        };

        Ok((output, ctrl_msgs))
    }

    pub(super) fn try_write(
        &self,
        reader: &mut dyn MultiRead,
        aux_data: &mut AuxiliaryData,
        is_seqpacket: bool,
    ) -> Result<usize> {
        let is_empty = reader.is_empty();
        if is_empty {
            if self.inner.is_shutdown() {
                return_errno_with_message!(Errno::EPIPE, "the channel is shut down");
            }
            if !is_seqpacket {
                return Ok(0);
            }
        }

        let this_end = self.inner.this_end();
        let send_limit = this_end.send_limit();

        // Like Linux, a message must fit in the send buffer.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L2123-L2126>
        if is_seqpacket && reader.sum_lens() > send_limit.saturating_sub(32) {
            return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
        }

        self.reserve(reader.sum_lens(), send_limit);

        let need_pass_cred = this_end.is_pass_cred.load(Ordering::Relaxed)
            || self.inner.peer_end().is_pass_cred.load(Ordering::Relaxed);

        // Fast path: There are no auxiliary data to transmit.
        if aux_data.is_empty() && !is_seqpacket && !need_pass_cred {
            let mut writer = this_end.writer.lock();
            let write_len = self.inner.write_with(move || {
                let max_len = writable_len(&writer, send_limit);
                writer.write_fallible_with_max_len(reader, max_len)
            })?;
            self.inner.notify_write();
            return Ok(write_len);
        }

        let mut all_aux = this_end.all_aux.lock();

        // No matter we succeed later or not, set the flag first to ensure that the auxiliary
        // data are always visible to `try_recv`.
        this_end.has_aux.store(true, Ordering::Relaxed);

        // Write the payload bytes.
        let (write_start, write_res) = if !is_empty {
            let mut writer = this_end.writer.lock();
            let write_start = writer.tail();
            let write_res = self.inner.write_with(move || {
                let max_len = writable_len(&writer, send_limit);
                if is_seqpacket && max_len < reader.sum_lens() {
                    return Ok(0);
                }
                writer.write_fallible_with_max_len(reader, max_len)
            });
            (write_start, write_res)
        } else {
            (this_end.writer.lock().tail(), Ok(0))
        };
        let Ok(write_len) = write_res else {
            this_end
                .has_aux
                .store(!all_aux.is_empty(), Ordering::Relaxed);
            return write_res;
        };

        if need_pass_cred {
            aux_data.fill_cred();
        }

        // Store the auxiliary data.
        let aux_range = RangedAuxiliaryData {
            data: core::mem::take(aux_data),
            start: write_start,
            end: write_start + Wrapping(write_len),
        };
        all_aux.push_back(aux_range);

        self.inner.notify_write();

        Ok(write_len)
    }

    /// Grows the ring buffer if it is too small for `len` more bytes and the send buffer size
    /// allows a larger one.
    ///
    /// The ring buffer is allocated on demand, so that a connection does not take the memory of
    /// the whole send buffer until a writer fills the buffer.
    fn reserve(&self, len: usize, send_limit: usize) {
        let this_end = self.inner.this_end();

        let (capacity, used_len) = {
            let writer = this_end.writer.lock();
            (writer.capacity(), writer.len())
        };
        if capacity >= send_limit || used_len.saturating_add(len) <= capacity {
            return;
        }

        // Lock order: `reader` of the peer -> `writer` of this end
        let mut reader = self.inner.peer_end().reader.lock();
        let mut writer = this_end.writer.lock();
        RingBuffer::grow(&mut writer, &mut reader, send_limit.next_power_of_two());
    }

    /// Sets the send buffer size.
    pub(super) fn set_send_buf(&self, send_buf: usize) {
        let this_end = self.inner.this_end();
        this_end.send_buf.store(send_buf, Ordering::Relaxed);

        // Like Linux, wake up the writers since the buffer size may be increased.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/sock.c#L1352-L1353>
        this_end.state.cloned_pollee().notify(IoEvents::OUT);
    }

    /// Returns the send buffer size.
    pub(super) fn send_buf(&self) -> usize {
        self.inner.this_end().send_buf.load(Ordering::Relaxed)
    }

    pub(super) fn shutdown(&self, cmd: SockShutdownCmd) {
        if cmd.shut_read() {
            self.inner.peer_shutdown();
        }

        if cmd.shut_write() {
            self.inner.shutdown();
        }
    }

    pub(super) fn is_read_shutdown(&self) -> bool {
        self.inner.is_peer_shutdown()
    }

    pub(super) fn is_write_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    pub(super) fn set_pass_cred(&self, is_pass_cred: bool) {
        self.inner
            .this_end()
            .is_pass_cred
            .store(is_pass_cred, Ordering::Relaxed);
    }

    pub(super) fn is_pass_cred(&self) -> bool {
        self.inner.this_end().is_pass_cred.load(Ordering::Relaxed)
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        let this_end = self.inner.this_end();
        let mut events = IoEvents::empty();

        if !this_end.reader.lock().is_empty() {
            events |= IoEvents::IN;
        }

        // Like Linux, the socket is writable if at most a quarter of the send buffer is used.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/unix/af_unix.c#L591-L595>
        if this_end.writer.lock().len().saturating_mul(4) <= this_end.send_limit() {
            events |= IoEvents::OUT;
        }

        events
    }

    pub(super) fn cloned_pollee(&self) -> Pollee {
        self.inner.this_end().state.cloned_pollee()
    }

    pub(super) fn peer_cred(&self) -> &SocketCred {
        &self.inner.peer_end().cred
    }
}

impl Drop for Connected {
    fn drop(&mut self) {
        self.inner.shutdown();
        self.inner.peer_shutdown();
    }
}

struct Inner {
    addr: Once<UnixSocketAddr>,
    state: EndpointState,
    // Lock order: `reader` -> `all_aux` & `all_aux` -> `writer`
    reader: Mutex<RbConsumer<u8>>,
    writer: Mutex<RbProducer<u8>>,
    /// The send buffer size (`sk_sndbuf` in Linux), which limits the bytes written by this end
    /// but not read by the peer yet.
    send_buf: AtomicUsize,
    all_aux: Mutex<VecDeque<RangedAuxiliaryData>>,
    has_aux: AtomicBool,
    is_pass_cred: AtomicBool,
    cred: SocketCred,
}

impl Inner {
    /// Returns the maximum number of bytes written by this end but not read by the peer.
    ///
    /// The send buffer size is limited by [`UNIX_STREAM_MAX_BUF_SIZE`] since the ring buffer is
    /// allocated as a whole.
    fn send_limit(&self) -> usize {
        self.send_buf
            .load(Ordering::Relaxed)
            .min(UNIX_STREAM_MAX_BUF_SIZE)
    }
}

impl AsRef<EndpointState> for Inner {
    fn as_ref(&self) -> &EndpointState {
        &self.state
    }
}

struct RangedAuxiliaryData {
    data: AuxiliaryData,
    start: Wrapping<usize>, // inclusive
    end: Wrapping<usize>,   // exclusive
}

/// Returns the number of bytes that can be written to `writer` within the send buffer.
fn writable_len(writer: &RbProducer<u8>, send_limit: usize) -> usize {
    send_limit
        .saturating_sub(writer.len())
        .min(writer.free_len())
}

/// Returns the initial capacity of a ring buffer.
fn initial_buf_capacity(send_buf: usize) -> usize {
    send_buf
        .clamp(1, UNIX_STREAM_INIT_BUF_SIZE)
        .next_power_of_two()
}

/// The maximum initial capacity of a ring buffer. It grows up to the send buffer size on demand.
const UNIX_STREAM_INIT_BUF_SIZE: usize = 65536;

/// The maximum capacity of a ring buffer.
///
/// This is twice the default `net.core.wmem_max` in Linux, which is the maximum send buffer size
/// that can be set without `CAP_NET_ADMIN`.
const UNIX_STREAM_MAX_BUF_SIZE: usize = 8 << 20;

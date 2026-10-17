// SPDX-License-Identifier: MPL-2.0

use alloc::collections::{btree_map::BTreeMap, vec_deque::VecDeque};

use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetRepr, Ipv4Address};

use crate::{
    iface::wire::ether,
    packet::{LinkLayer, NetworkLayer, TxPacket},
};

/// The maximum number of neighbor entries, including the incomplete ones.
///
/// Like Linux, which refuses to allocate new neighbor entries above `gc_thresh3` (1024 by
/// default), a new entry is not inserted if the table is full, so that peers cannot exhaust the
/// memory.
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L183>
const MAX_NR_ENTRIES: usize = 1024;

/// The maximum number of bytes queued for an incomplete neighbor.
///
/// This is `SK_WMEM_DEFAULT` on 64-bit Linux, i.e., 256 times `SKB_TRUESIZE(256)`.
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L173>
const QUEUE_LEN_BYTES: usize = 212992;

/// The number of broadcast requests to send before giving up resolving a new neighbor.
///
/// Linux starts counting from `UCAST_PROBES` and gives up after `UCAST_PROBES + APP_PROBES +
/// MCAST_PROBES` probes, so `MCAST_PROBES` (3 by default) requests are broadcast.
/// References:
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L166>
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1221>
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1162>
const MCAST_PROBES: u32 = 3;

/// The number of unicast requests to send before giving up reprobing a known neighbor.
///
/// Linux starts counting from zero in `NUD_PROBE` state, and the first `UCAST_PROBES` (3 by
/// default) requests are sent to the known Ethernet address.
/// References:
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L167>
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L376>
const UCAST_PROBES: u32 = 3;

/// The interval between address resolution requests in milliseconds.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L168>
const RETRANS_TIME_MS: u64 = 1000;

/// The time in milliseconds for which a confirmed neighbor is considered reachable.
///
/// TODO: Linux randomizes the time in `[0.5, 1.5) * BASE_REACHABLE_TIME` (see
/// `neigh_rand_reach_time`) so that hosts do not reprobe their neighbors in lockstep. Do the same
/// once a random source is available here.
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L169>
const REACHABLE_TIME_MS: u64 = 30_000;

/// The time in milliseconds to wait for a confirmation before reprobing a stale neighbor in use.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L170>
const DELAY_PROBE_TIME_MS: u64 = 5000;

/// The time in milliseconds during which a neighbor's Ethernet address cannot be overridden.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L177>
const LOCKTIME_MS: u64 = 1000;

/// A cache that maps IPv4 addresses of neighbors to their Ethernet addresses.
///
/// This follows the Linux neighbor state machine:
/// - `Incomplete`: Broadcast requests are sent and packets are queued until a reply arrives.
/// - `Reachable`: The address was confirmed recently. It becomes `Stale` after
///   [`REACHABLE_TIME_MS`].
/// - `Stale`: The address is still used. Sending a packet moves it to `Delay`.
/// - `Delay`: Without confirmations, it moves to `Probe` after [`DELAY_PROBE_TIME_MS`].
/// - `Probe`: Unicast requests are sent to the known address. The entry is removed if no reply
///   arrives.
///
/// TODO: Linux also moves `Delay` entries back to `Reachable` if upper layers (e.g., TCP)
/// confirm that the neighbor is reachable (see `neigh_confirm`). Support such confirmations.
pub(super) struct NeighborCache {
    local_ether: EthernetAddress,
    entries: BTreeMap<Ipv4Address, Neighbor>,
    /// The earliest time at which a timer of an entry may expire.
    ///
    /// This may be earlier than the actual time, in which case [`Self::poll_timers`] does nothing
    /// but recalculate it.
    next_timer_at_ms: Option<u64>,
    /// Packets that are ready to be sent, e.g., packets whose next hops have been resolved.
    ready: VecDeque<TxPacket<LinkLayer>>,
}

struct Neighbor {
    state: State,
    /// The last time at which the state or the address changed, like `neigh->updated` in Linux.
    updated_at_ms: u64,
}

enum State {
    Incomplete {
        queue: PacketQueue,
        probes: u32,
        next_probe_at_ms: u64,
    },
    Reachable {
        ether_addr: EthernetAddress,
        expires_at_ms: u64,
    },
    Stale {
        ether_addr: EthernetAddress,
    },
    Delay {
        ether_addr: EthernetAddress,
        probe_at_ms: u64,
    },
    Probe {
        ether_addr: EthernetAddress,
        probes: u32,
        next_probe_at_ms: u64,
    },
}

#[derive(Default)]
struct PacketQueue {
    packets: VecDeque<TxPacket<NetworkLayer>>,
    len_bytes: usize,
}

/// Describes how a received ARP packet updates a neighbor entry.
pub(super) struct ArpUpdate {
    /// Whether the packet confirms that the neighbor is reachable.
    pub(super) confirms: bool,
    /// Whether the packet can override the Ethernet address within [`LOCKTIME_MS`].
    pub(super) force_override: bool,
    /// Whether a new entry can be created for the neighbor.
    pub(super) may_create: bool,
}

impl NeighborCache {
    pub(super) fn new(local_ether: EthernetAddress) -> Self {
        Self {
            local_ether,
            entries: BTreeMap::new(),
            next_timer_at_ms: None,
            ready: VecDeque::new(),
        }
    }

    /// Prepends the Ethernet header to an IPv4 packet sent to `next_hop`.
    ///
    /// If the Ethernet address of `next_hop` is unknown, the packet is queued until the address
    /// is resolved. If this starts a new resolution, `new_probe` is called to generate a broadcast
    /// address resolution request, which is returned instead.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1202>
    pub(super) fn resolve<F>(
        &mut self,
        next_hop: Ipv4Address,
        packet: TxPacket<NetworkLayer>,
        now_ms: u64,
        new_probe: F,
    ) -> Option<TxPacket<LinkLayer>>
    where
        F: FnOnce() -> Option<TxPacket<LinkLayer>>,
    {
        let len = self.entries.len();

        let Some(neighbor) = self.entries.get_mut(&next_hop) else {
            if len >= MAX_NR_ENTRIES {
                return None;
            }

            // Like Linux, send the first request immediately.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1229>
            let mut queue = PacketQueue::default();
            queue.enqueue(packet);
            self.insert(
                next_hop,
                State::Incomplete {
                    queue,
                    probes: 1,
                    next_probe_at_ms: now_ms + RETRANS_TIME_MS,
                },
                now_ms,
            );
            return new_probe();
        };

        let ether_addr = match &mut neighbor.state {
            State::Incomplete { queue, .. } => {
                queue.enqueue(packet);
                return None;
            }
            State::Stale { ether_addr } => {
                let ether_addr = *ether_addr;
                let probe_at_ms = now_ms + DELAY_PROBE_TIME_MS;
                neighbor.state = State::Delay {
                    ether_addr,
                    probe_at_ms,
                };
                neighbor.updated_at_ms = now_ms;
                self.arm_timer(probe_at_ms);
                ether_addr
            }
            State::Reachable { ether_addr, .. }
            | State::Delay { ether_addr, .. }
            | State::Probe { ether_addr, .. } => *ether_addr,
        };

        Some(ether::emit(packet, &self.ether_repr(ether_addr)))
    }

    /// Updates the mapping between an IPv4 address and an Ethernet address according to a
    /// received ARP packet.
    ///
    /// If packets are waiting for the address, they become ready to be sent.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1376>
    pub(super) fn update(
        &mut self,
        ip_addr: Ipv4Address,
        ether_addr: EthernetAddress,
        update: ArpUpdate,
        now_ms: u64,
    ) {
        let new_state = if update.confirms {
            State::Reachable {
                ether_addr,
                expires_at_ms: now_ms + REACHABLE_TIME_MS,
            }
        } else {
            State::Stale { ether_addr }
        };

        let len = self.entries.len();
        let Some(neighbor) = self.entries.get_mut(&ip_addr) else {
            if update.may_create && len < MAX_NR_ENTRIES {
                self.insert(ip_addr, new_state, now_ms);
            }
            return;
        };

        if let Some(old_ether_addr) = neighbor.state.ether_addr() {
            // If the address changes, it can only be overridden if it has not been updated
            // recently. If the address does not change, a stale update changes nothing.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1459>
            if old_ether_addr != ether_addr {
                if !update.force_override && now_ms <= neighbor.updated_at_ms + LOCKTIME_MS {
                    return;
                }
            } else if !update.confirms {
                return;
            }

            // A confirmation of a reachable neighbor only extends its lifetime.
            if old_ether_addr != ether_addr || !matches!(neighbor.state, State::Reachable { .. }) {
                neighbor.updated_at_ms = now_ms;
            }
            neighbor.state = new_state;
        } else {
            let State::Incomplete { queue, .. } =
                core::mem::replace(&mut neighbor.state, new_state)
            else {
                unreachable!("only incomplete neighbors have no Ethernet addresses");
            };
            neighbor.updated_at_ms = now_ms;

            let ether_repr = self.ether_repr(ether_addr);
            self.ready.extend(
                queue
                    .packets
                    .into_iter()
                    .map(|packet| ether::emit(packet, &ether_repr)),
            );
        }

        if update.confirms {
            self.arm_timer(now_ms + REACHABLE_TIME_MS);
        }
    }

    /// Handles expired timers of the neighbor entries.
    ///
    /// `new_probe` is called to generate an address resolution request for a neighbor. The
    /// request should be sent to the given Ethernet address, or broadcast if it is `None`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1100>
    pub(super) fn poll_timers<F>(&mut self, now_ms: u64, mut new_probe: F)
    where
        F: FnMut(Ipv4Address, Option<EthernetAddress>) -> Option<TxPacket<LinkLayer>>,
    {
        if self.next_timer_at_ms.is_none_or(|at_ms| at_ms > now_ms) {
            return;
        }

        let ready = &mut self.ready;
        let mut next_timer_at_ms = None;

        self.entries.retain(|ip_addr, neighbor| {
            let mut probe = |ether_addr| ready.extend(new_probe(*ip_addr, ether_addr));
            if !neighbor.handle_timer(now_ms, &mut probe) {
                return false;
            }

            if let Some(at_ms) = neighbor.state.timer_at_ms() {
                next_timer_at_ms =
                    Some(next_timer_at_ms.map_or(at_ms, |next: u64| next.min(at_ms)));
            }
            true
        });

        self.next_timer_at_ms = next_timer_at_ms;
    }

    /// Pops a packet that is ready to be sent.
    pub(super) fn pop_ready(&mut self) -> Option<TxPacket<LinkLayer>> {
        self.ready.pop_front()
    }

    /// Returns the time at which [`Self::poll_timers`] should be called next.
    pub(super) fn next_poll_at_ms(&self) -> Option<u64> {
        self.next_timer_at_ms
    }

    fn insert(&mut self, ip_addr: Ipv4Address, state: State, now_ms: u64) {
        if let Some(at_ms) = state.timer_at_ms() {
            self.arm_timer(at_ms);
        }
        self.entries.insert(
            ip_addr,
            Neighbor {
                state,
                updated_at_ms: now_ms,
            },
        );
    }

    fn arm_timer(&mut self, at_ms: u64) {
        self.next_timer_at_ms = Some(self.next_timer_at_ms.map_or(at_ms, |next| next.min(at_ms)));
    }

    fn ether_repr(&self, dst_addr: EthernetAddress) -> EthernetRepr {
        EthernetRepr {
            src_addr: self.local_ether,
            dst_addr,
            ethertype: EthernetProtocol::Ipv4,
        }
    }
}

impl Neighbor {
    /// Handles the timer of the entry and returns whether the entry should be kept.
    fn handle_timer<F>(&mut self, now_ms: u64, probe: &mut F) -> bool
    where
        F: FnMut(Option<EthernetAddress>),
    {
        if self.state.timer_at_ms().is_none_or(|at_ms| at_ms > now_ms) {
            return true;
        }

        match &mut self.state {
            State::Incomplete {
                probes,
                next_probe_at_ms,
                ..
            } => {
                // TODO: Report errors to the senders of the dropped packets, as Linux does by
                // generating ICMP host unreachable errors.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L296>
                if *probes >= MCAST_PROBES {
                    return false;
                }
                *probes += 1;
                *next_probe_at_ms = now_ms + RETRANS_TIME_MS;
                probe(None);
            }
            State::Reachable { ether_addr, .. } => {
                // Linux moves the entry to `NUD_DELAY` instead if it was used within
                // `DELAY_PROBE_TIME`. However, sending through a reachable entry does not mark it
                // as used in Linux (see `neigh_hh_output`), so this rarely happens.
                // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1117>
                self.state = State::Stale {
                    ether_addr: *ether_addr,
                };
                self.updated_at_ms = now_ms;
            }
            State::Stale { .. } => unreachable!("stale neighbors have no timers"),
            State::Delay { ether_addr, .. } => {
                let ether_addr = *ether_addr;
                self.state = State::Probe {
                    ether_addr,
                    probes: 1,
                    next_probe_at_ms: now_ms + RETRANS_TIME_MS,
                };
                self.updated_at_ms = now_ms;
                probe(Some(ether_addr));
            }
            State::Probe {
                ether_addr,
                probes,
                next_probe_at_ms,
            } => {
                if *probes >= UCAST_PROBES {
                    return false;
                }
                *probes += 1;
                *next_probe_at_ms = now_ms + RETRANS_TIME_MS;
                probe(Some(*ether_addr));
            }
        }

        true
    }
}

impl State {
    fn ether_addr(&self) -> Option<EthernetAddress> {
        match self {
            Self::Incomplete { .. } => None,
            Self::Reachable { ether_addr, .. }
            | Self::Stale { ether_addr }
            | Self::Delay { ether_addr, .. }
            | Self::Probe { ether_addr, .. } => Some(*ether_addr),
        }
    }

    fn timer_at_ms(&self) -> Option<u64> {
        match self {
            Self::Incomplete {
                next_probe_at_ms, ..
            }
            | Self::Probe {
                next_probe_at_ms, ..
            } => Some(*next_probe_at_ms),
            Self::Reachable { expires_at_ms, .. } => Some(*expires_at_ms),
            Self::Stale { .. } => None,
            Self::Delay { probe_at_ms, .. } => Some(*probe_at_ms),
        }
    }
}

impl PacketQueue {
    /// Queues a packet, dropping the oldest packets if the queue is full.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1254>
    fn enqueue(&mut self, packet: TxPacket<NetworkLayer>) {
        let packet_len = packet.alloc_len();

        while self.len_bytes + packet_len > QUEUE_LEN_BYTES {
            let Some(dropped) = self.packets.pop_front() else {
                break;
            };
            self.len_bytes -= dropped.alloc_len();
        }

        self.packets.push_back(packet);
        self.len_bytes += packet_len;
    }
}

#[cfg(ktest)]
mod test {
    use alloc::{vec, vec::Vec};

    use ostd::{
        mm::{VmReader, VmWriter},
        prelude::ktest,
    };

    use super::*;
    use crate::packet::{FreshTxPacket, Layer};

    const LOCAL: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 1]);
    const PEER: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 2]);
    const PEER2: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 3]);
    const PEER_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 3);

    const REPLY: ArpUpdate = ArpUpdate {
        confirms: true,
        force_override: false,
        may_create: false,
    };
    const REQUEST: ArpUpdate = ArpUpdate {
        confirms: false,
        force_override: false,
        may_create: false,
    };

    fn tx_packet<L: Layer>(len: usize, tag: u8) -> TxPacket<L> {
        let mut builder = FreshTxPacket::<L>::alloc(len).unwrap().to_builder();
        let payload = vec![tag; len];
        let written = builder
            .append_writer()
            .write(&mut VmReader::from(payload.as_slice()));
        assert_eq!(written, len);
        builder.commit(written);
        builder.build()
    }

    fn probe() -> Option<TxPacket<LinkLayer>> {
        Some(tx_packet(1, 0xff))
    }

    /// Returns the Ethernet header and the first payload byte of a packet.
    fn parse(packet: TxPacket<LinkLayer>) -> (EthernetRepr, u8) {
        let (packet, repr) = ether::parse(packet.to_rx_packet().unwrap()).unwrap();
        let mut tag = [0u8];
        packet
            .reader()
            .read(&mut VmWriter::from(tag.as_mut_slice()));
        (repr, tag[0])
    }

    fn drain_ready(cache: &mut NeighborCache) -> Vec<(EthernetRepr, u8)> {
        core::iter::from_fn(|| cache.pop_ready())
            .map(parse)
            .collect()
    }

    /// Resolves `ip_addr` to `ether_addr` with a reply to our request, dropping the queued packet.
    fn learn(cache: &mut NeighborCache, ip_addr: Ipv4Address, ether_addr: EthernetAddress) {
        cache.resolve(ip_addr, tx_packet(8, 0), 0, || None);
        cache.update(ip_addr, ether_addr, REPLY, 0);
        drain_ready(cache);
        // Recalculate the next timer, which the resolution has armed earlier.
        cache.poll_timers(RETRANS_TIME_MS, |_, _| panic!("probed"));
    }

    /// Returns whether sending a packet to `ip_addr` starts a new resolution.
    fn starts_resolution(cache: &mut NeighborCache, ip_addr: Ipv4Address, now_ms: u64) -> bool {
        let mut nr_probes = 0;
        let packet = cache.resolve(ip_addr, tx_packet(8, 0), now_ms, || {
            nr_probes += 1;
            None
        });
        packet.is_none() && nr_probes == 1
    }

    /// Sends a packet and returns the destination Ethernet address if it is sent directly.
    fn send(cache: &mut NeighborCache, now_ms: u64) -> Option<EthernetAddress> {
        cache
            .resolve(PEER_IP, tx_packet(8, 0), now_ms, || panic!("probed"))
            .map(|packet| parse(packet).0.dst_addr)
    }

    /// Polls the timers and returns the destinations of the generated probes.
    fn poll(cache: &mut NeighborCache, now_ms: u64) -> Vec<Option<EthernetAddress>> {
        let mut probes = Vec::new();
        cache.poll_timers(now_ms, |ip_addr, ether_addr| {
            assert_eq!(ip_addr, PEER_IP);
            probes.push(ether_addr);
            None
        });
        probes
    }

    #[ktest]
    fn queue_until_resolved() {
        let mut cache = NeighborCache::new(LOCAL);

        assert!(cache.resolve(PEER_IP, tx_packet(8, 1), 0, probe).is_some());
        assert!(
            cache
                .resolve(PEER_IP, tx_packet(8, 2), 0, || panic!("probed twice"))
                .is_none()
        );
        assert!(cache.pop_ready().is_none());

        cache.update(PEER_IP, PEER, REPLY, 10);
        let ether_repr = EthernetRepr {
            src_addr: LOCAL,
            dst_addr: PEER,
            ethertype: EthernetProtocol::Ipv4,
        };
        assert_eq!(drain_ready(&mut cache), [(ether_repr, 1), (ether_repr, 2)]);

        // Packets to a reachable neighbor are sent directly.
        assert_eq!(send(&mut cache, 10), Some(PEER));
    }

    #[ktest]
    fn drop_oldest_when_full() {
        let mut cache = NeighborCache::new(LOCAL);

        let len = QUEUE_LEN_BYTES / 3;
        for tag in 1..=3 {
            cache.resolve(PEER_IP, tx_packet(len, tag), 0, probe);
        }

        cache.update(PEER_IP, PEER, REPLY, 0);
        let tags: Vec<_> = drain_ready(&mut cache)
            .into_iter()
            .map(|(_, tag)| tag)
            .collect();
        assert_eq!(tags, [2, 3]);
    }

    #[ktest]
    fn retransmit_and_fail() {
        let mut cache = NeighborCache::new(LOCAL);

        assert!(cache.resolve(PEER_IP, tx_packet(8, 1), 0, probe).is_some());
        assert_eq!(cache.next_poll_at_ms(), Some(RETRANS_TIME_MS));

        assert!(poll(&mut cache, RETRANS_TIME_MS - 1).is_empty());
        assert_eq!(poll(&mut cache, RETRANS_TIME_MS), [None]);
        assert_eq!(poll(&mut cache, RETRANS_TIME_MS * 2), [None]);
        assert_eq!(cache.next_poll_at_ms(), Some(RETRANS_TIME_MS * 3));
        assert!(poll(&mut cache, RETRANS_TIME_MS * 3).is_empty());
        assert_eq!(cache.next_poll_at_ms(), None);

        // The entry is removed with the queued packet, so a late reply is unsolicited and changes
        // nothing.
        cache.update(PEER_IP, PEER, REPLY, RETRANS_TIME_MS * 4);
        assert!(cache.pop_ready().is_none());
        assert!(starts_resolution(&mut cache, PEER_IP, RETRANS_TIME_MS * 4));
    }

    #[ktest]
    fn expire_reprobe_and_fail() {
        let mut cache = NeighborCache::new(LOCAL);
        learn(&mut cache, PEER_IP, PEER);
        assert_eq!(cache.next_poll_at_ms(), Some(REACHABLE_TIME_MS));

        // The entry becomes stale, but it is still used.
        assert!(poll(&mut cache, REACHABLE_TIME_MS).is_empty());
        assert_eq!(cache.next_poll_at_ms(), None);
        let t = REACHABLE_TIME_MS + 100;
        assert_eq!(send(&mut cache, t), Some(PEER));

        // Using the stale entry starts reprobing after the delay.
        let t = t + DELAY_PROBE_TIME_MS;
        assert_eq!(cache.next_poll_at_ms(), Some(t));
        assert_eq!(poll(&mut cache, t), [Some(PEER)]);
        assert_eq!(send(&mut cache, t), Some(PEER));
        assert_eq!(poll(&mut cache, t + RETRANS_TIME_MS), [Some(PEER)]);
        assert_eq!(poll(&mut cache, t + RETRANS_TIME_MS * 2), [Some(PEER)]);

        // Without replies, the entry is removed and the next packet starts a new resolution.
        assert!(poll(&mut cache, t + RETRANS_TIME_MS * 3).is_empty());
        assert_eq!(cache.next_poll_at_ms(), None);
        assert!(starts_resolution(&mut cache, PEER_IP, t + RETRANS_TIME_MS * 3));
    }

    #[ktest]
    fn reprobe_and_confirm() {
        let mut cache = NeighborCache::new(LOCAL);
        learn(&mut cache, PEER_IP, PEER);
        poll(&mut cache, REACHABLE_TIME_MS);

        // A request from a stale neighbor with the same address does not confirm it.
        cache.update(PEER_IP, PEER, REQUEST, REACHABLE_TIME_MS);
        assert_eq!(cache.next_poll_at_ms(), None);

        let t = REACHABLE_TIME_MS;
        send(&mut cache, t);
        assert_eq!(poll(&mut cache, t + DELAY_PROBE_TIME_MS), [Some(PEER)]);

        // A reply confirms the neighbor.
        let t = t + DELAY_PROBE_TIME_MS + 10;
        cache.update(PEER_IP, PEER, REPLY, t);
        assert!(poll(&mut cache, t + RETRANS_TIME_MS * 3).is_empty());
        assert_eq!(cache.next_poll_at_ms(), Some(t + REACHABLE_TIME_MS));
        assert_eq!(send(&mut cache, t + RETRANS_TIME_MS * 3), Some(PEER));
    }

    #[ktest]
    fn update_address() {
        let mut cache = NeighborCache::new(LOCAL);
        learn(&mut cache, PEER_IP, PEER);

        // A different address is ignored within the lock time.
        cache.update(PEER_IP, PEER2, REQUEST, LOCKTIME_MS);
        assert_eq!(send(&mut cache, LOCKTIME_MS), Some(PEER));

        // After the lock time, the address is updated and the entry becomes stale.
        cache.update(PEER_IP, PEER2, REQUEST, LOCKTIME_MS + 1);
        assert_eq!(send(&mut cache, LOCKTIME_MS + 1), Some(PEER2));
        let t = LOCKTIME_MS + 1 + DELAY_PROBE_TIME_MS;
        assert_eq!(cache.next_poll_at_ms(), Some(t));

        // Gratuitous ARP packets override the address at any time.
        let garp = ArpUpdate {
            confirms: false,
            force_override: true,
            may_create: false,
        };
        cache.update(PEER_IP, PEER, garp, LOCKTIME_MS + 2);
        assert_eq!(send(&mut cache, LOCKTIME_MS + 2), Some(PEER));

        // Requests and unsolicited replies do not create new entries.
        let other_ip = Ipv4Address::new(10, 0, 2, 4);
        cache.update(other_ip, PEER, REQUEST, 0);
        cache.update(other_ip, PEER, REPLY, 0);
        assert!(starts_resolution(&mut cache, other_ip, 0));
    }

    #[ktest]
    fn table_full() {
        let mut cache = NeighborCache::new(LOCAL);

        for i in 0..MAX_NR_ENTRIES as u32 {
            learn(&mut cache, Ipv4Address::from_bits(0x0a01_0000 + i), PEER);
        }

        let packet = cache.resolve(PEER_IP, tx_packet(8, 1), 0, || panic!("probed"));
        assert!(packet.is_none());
        cache.update(PEER_IP, PEER, REPLY, 0);
        assert!(
            cache
                .resolve(PEER_IP, tx_packet(8, 1), 0, || None)
                .is_none()
        );
    }
}

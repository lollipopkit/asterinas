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

/// The number of address resolution requests to send before giving up.
///
/// Linux starts counting from `UCAST_PROBES` and gives up after `UCAST_PROBES + APP_PROBES +
/// MCAST_PROBES` probes, so `MCAST_PROBES` (3 by default) requests are broadcast.
/// References:
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L166>
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1221>
/// - <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1162>
const MAX_PROBES: u32 = 3;

/// The interval between address resolution requests in milliseconds.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L168>
const RETRANS_TIME_MS: u64 = 1000;

/// A cache that maps IPv4 addresses of neighbors to their Ethernet addresses.
///
/// Packets sent to a neighbor whose Ethernet address is not yet known are queued until the
/// address is resolved, like the `arp_queue` of a Linux neighbor in `NUD_INCOMPLETE` state.
pub(super) struct NeighborCache {
    local_ether: EthernetAddress,
    reachable: BTreeMap<Ipv4Address, EthernetAddress>,
    incomplete: BTreeMap<Ipv4Address, IncompleteNeighbor>,
    /// Packets that are ready to be sent, e.g., packets whose next hops have been resolved.
    ready: VecDeque<TxPacket<LinkLayer>>,
}

struct IncompleteNeighbor {
    queue: VecDeque<TxPacket<NetworkLayer>>,
    queue_len_bytes: usize,
    probes: u32,
    next_probe_at_ms: u64,
}

impl NeighborCache {
    pub(super) fn new(local_ether: EthernetAddress) -> Self {
        Self {
            local_ether,
            reachable: BTreeMap::new(),
            incomplete: BTreeMap::new(),
            ready: VecDeque::new(),
        }
    }

    /// Prepends the Ethernet header to an IPv4 packet sent to `next_hop`.
    ///
    /// If the Ethernet address of `next_hop` is unknown, the packet is queued until the address
    /// is resolved. If this starts a new resolution, `new_probe` is called to generate an address
    /// resolution request, which is returned instead.
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
        if let Some(ether_addr) = self.reachable.get(&next_hop) {
            return Some(ether::emit(packet, &self.ether_repr(*ether_addr)));
        }

        if let Some(neighbor) = self.incomplete.get_mut(&next_hop) {
            neighbor.enqueue(packet);
            return None;
        }

        if self.len() >= MAX_NR_ENTRIES {
            return None;
        }

        // Like Linux, send the first request immediately.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1229>
        let mut neighbor = IncompleteNeighbor {
            queue: VecDeque::new(),
            queue_len_bytes: 0,
            probes: 1,
            next_probe_at_ms: now_ms + RETRANS_TIME_MS,
        };
        neighbor.enqueue(packet);
        self.incomplete.insert(next_hop, neighbor);

        new_probe()
    }

    /// Inserts or updates the mapping between an IPv4 address and an Ethernet address.
    ///
    /// If packets are waiting for the address, they become ready to be sent.
    ///
    /// TODO: Remove the mapping if it expires.
    pub(super) fn learn(&mut self, ip_addr: Ipv4Address, ether_addr: EthernetAddress) {
        if let Some(neighbor) = self.incomplete.remove(&ip_addr) {
            let ether_repr = self.ether_repr(ether_addr);
            self.ready.extend(
                neighbor
                    .queue
                    .into_iter()
                    .map(|packet| ether::emit(packet, &ether_repr)),
            );
        } else if self.len() >= MAX_NR_ENTRIES && !self.reachable.contains_key(&ip_addr) {
            return;
        }

        self.reachable.insert(ip_addr, ether_addr);
    }

    /// Retransmits address resolution requests and gives up resolutions whose deadlines have
    /// passed.
    ///
    /// `new_probe` is called to generate an address resolution request for a neighbor.
    pub(super) fn poll_timers<F>(&mut self, now_ms: u64, mut new_probe: F)
    where
        F: FnMut(Ipv4Address) -> Option<TxPacket<LinkLayer>>,
    {
        let ready = &mut self.ready;

        self.incomplete.retain(|ip_addr, neighbor| {
            if neighbor.next_probe_at_ms > now_ms {
                return true;
            }

            // TODO: Report errors to the senders of the dropped packets, as Linux does by
            // generating ICMP host unreachable errors.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L296>
            if neighbor.probes >= MAX_PROBES {
                return false;
            }

            neighbor.probes += 1;
            neighbor.next_probe_at_ms = now_ms + RETRANS_TIME_MS;
            ready.extend(new_probe(*ip_addr));
            true
        });
    }

    /// Pops a packet that is ready to be sent.
    pub(super) fn pop_ready(&mut self) -> Option<TxPacket<LinkLayer>> {
        self.ready.pop_front()
    }

    /// Returns the time at which [`Self::poll_timers`] should be called next.
    pub(super) fn next_poll_at_ms(&self) -> Option<u64> {
        self.incomplete
            .values()
            .map(|neighbor| neighbor.next_probe_at_ms)
            .min()
    }

    fn len(&self) -> usize {
        self.reachable.len() + self.incomplete.len()
    }

    fn ether_repr(&self, dst_addr: EthernetAddress) -> EthernetRepr {
        EthernetRepr {
            src_addr: self.local_ether,
            dst_addr,
            ethertype: EthernetProtocol::Ipv4,
        }
    }
}

impl IncompleteNeighbor {
    /// Queues a packet, dropping the oldest packets if the queue is full.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/core/neighbour.c#L1254>
    fn enqueue(&mut self, packet: TxPacket<NetworkLayer>) {
        let packet_len = packet.alloc_len();

        while self.queue_len_bytes + packet_len > QUEUE_LEN_BYTES {
            let Some(dropped) = self.queue.pop_front() else {
                break;
            };
            self.queue_len_bytes -= dropped.alloc_len();
        }

        self.queue.push_back(packet);
        self.queue_len_bytes += packet_len;
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
    const PEER_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 3);

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

    /// Returns the Ethernet header and the first payload byte of each ready packet.
    fn drain_ready(cache: &mut NeighborCache) -> Vec<(EthernetRepr, u8)> {
        let mut result = Vec::new();
        while let Some(packet) = cache.pop_ready() {
            let (packet, repr) = ether::parse(packet.to_rx_packet().unwrap()).unwrap();
            let mut tag = [0u8];
            packet
                .reader()
                .read(&mut VmWriter::from(tag.as_mut_slice()));
            result.push((repr, tag[0]));
        }
        result
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

        cache.learn(PEER_IP, PEER);
        let ether_repr = EthernetRepr {
            src_addr: LOCAL,
            dst_addr: PEER,
            ethertype: EthernetProtocol::Ipv4,
        };
        assert_eq!(drain_ready(&mut cache), [(ether_repr, 1), (ether_repr, 2)]);
        assert_eq!(cache.next_poll_at_ms(), None);

        // Packets to a reachable neighbor are sent directly.
        let packet = cache.resolve(PEER_IP, tx_packet(8, 3), 0, || panic!("probed"));
        assert!(packet.is_some());
    }

    #[ktest]
    fn drop_oldest_when_full() {
        let mut cache = NeighborCache::new(LOCAL);

        let len = QUEUE_LEN_BYTES / 3;
        for tag in 1..=3 {
            cache.resolve(PEER_IP, tx_packet(len, tag), 0, probe);
        }

        cache.learn(PEER_IP, PEER);
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

        let mut nr_probes = 1;
        let mut new_probe = |ip_addr| {
            assert_eq!(ip_addr, PEER_IP);
            nr_probes += 1;
            probe()
        };

        cache.poll_timers(RETRANS_TIME_MS - 1, &mut new_probe);
        cache.poll_timers(RETRANS_TIME_MS, &mut new_probe);
        cache.poll_timers(RETRANS_TIME_MS * 2, &mut new_probe);
        assert_eq!(cache.next_poll_at_ms(), Some(RETRANS_TIME_MS * 3));
        cache.poll_timers(RETRANS_TIME_MS * 3, &mut new_probe);
        assert_eq!(nr_probes, MAX_PROBES);
        assert_eq!(cache.next_poll_at_ms(), None);
        assert_eq!(core::iter::from_fn(|| cache.pop_ready()).count(), 2);

        // The queued packet is dropped, so learning the address later sends nothing.
        cache.learn(PEER_IP, PEER);
        assert!(cache.pop_ready().is_none());
    }

    #[ktest]
    fn table_full() {
        let mut cache = NeighborCache::new(LOCAL);

        for i in 0..MAX_NR_ENTRIES as u32 {
            cache.learn(Ipv4Address::from_bits(0x0a01_0000 + i), PEER);
        }

        let packet = cache.resolve(PEER_IP, tx_packet(8, 1), 0, || panic!("probed"));
        assert!(packet.is_none());
        assert_eq!(cache.next_poll_at_ms(), None);
    }
}

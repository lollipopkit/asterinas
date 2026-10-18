// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    iface::{Config, Context},
    wire::{
        self, ArpOperation, ArpRepr, EthernetAddress, EthernetProtocol, EthernetRepr, IpAddress,
        Ipv4Address, Ipv4AddressExt, Ipv4Cidr,
    },
};

use super::neighbor::{ArpUpdate, NeighborCache};
use crate::{
    device::{AnyNetworkDevice, WithDevice, new_interface},
    ext::Ext,
    iface::{
        Iface, InterfaceFlags, InterfaceName,
        common::{IfaceCommon, InterfaceType, PhyProcessResult, PollPhy, TxPacketWithDst},
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
        wire::{arp, ether},
    },
    packet::{FreshTxPacket, LinkLayer, RxPacket, TransportLayer, TxPacket},
};

pub struct EtherIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
    ether_addr: EthernetAddress,
    neighbors: SpinLock<NeighborCache, BottomHalfDisabled>,
}

impl<D: WithDevice, E: Ext> EtherIface<D, E> {
    pub fn new(
        driver: D,
        ether_addr: EthernetAddress,
        ip_cidr: Ipv4Cidr,
        gateway: Ipv4Address,
        name: InterfaceName,
        sched_poll: E::ScheduleNextPoll,
        flags: InterfaceFlags,
    ) -> Arc<Self> {
        let interface = driver.with(|device| {
            let config = Config::new(wire::HardwareAddress::Ethernet(ether_addr));
            let now = get_network_timestamp();

            let mut interface = new_interface(config, device.capabilities(), now);
            interface.update_ip_addrs(|ip_addrs| {
                debug_assert!(ip_addrs.is_empty());
                ip_addrs.push(wire::IpCidr::Ipv4(ip_cidr)).unwrap();
            });
            interface
                .routes_mut()
                .add_default_ipv4_route(gateway)
                .unwrap();
            interface
        });

        let common = IfaceCommon::new(name, InterfaceType::ETHER, flags, interface, sched_poll);

        Arc::new(Self {
            driver,
            common,
            ether_addr,
            neighbors: SpinLock::new(NeighborCache::new(ether_addr)),
        })
    }
}

impl<D, E: Ext> IfaceInternal<E> for EtherIface<D, E> {
    fn common(&self) -> &IfaceCommon<E> {
        &self.common
    }
}

impl<D: WithDevice + 'static, E: Ext> Iface<E> for EtherIface<D, E> {
    fn ethernet_addr(&self) -> Option<EthernetAddress> {
        Some(self.ether_addr)
    }

    fn poll(&self) {
        self.common.poll(&self.driver, self);
    }

    fn mtu(&self) -> usize {
        self.driver
            .with(|device| device.capabilities().max_transmission_unit)
    }
}

impl<D: WithDevice + 'static, E: Ext> PollPhy for EtherIface<D, E> {
    fn process(
        &self,
        packet: RxPacket<LinkLayer>,
        iface_cx: &mut Context,
    ) -> Option<PhyProcessResult> {
        // Parse the Ethernet header. Ignore the packet if the header is ill-formed.
        let (packet, repr) = ether::parse(packet)?;

        // Ignore the Ethernet frame if it is not sent to us.
        if !repr.dst_addr.is_broadcast() && repr.dst_addr != self.ether_addr {
            return None;
        }

        // Ignore the Ethernet frame if the protocol is not supported.
        match repr.ethertype {
            EthernetProtocol::Ipv4 => Some(PhyProcessResult::Ipv4(packet)),
            EthernetProtocol::Ipv6 => Some(PhyProcessResult::Ipv6(packet)),
            EthernetProtocol::Arp => {
                let (_, arp_repr) = arp::parse(packet)?;
                let is_unicast = repr.dst_addr == self.ether_addr;
                self.process_arp(&arp_repr, is_unicast, iface_cx)
                    .map(PhyProcessResult::Tx)
            }
            _ => None,
        }
    }

    fn dispatch(
        &self,
        packet: TxPacketWithDst,
        iface_cx: &mut Context,
    ) -> Option<TxPacket<LinkLayer>> {
        // Resolve the next-hop IP address.
        let next_hop_ip = match iface_cx.route(&packet.dst_addr, iface_cx.now()) {
            Some(IpAddress::Ipv4(next_hop_ip)) => next_hop_ip,
            Some(IpAddress::Ipv6(_)) => {
                // FIXME: Currently, we drop outbound IPv6 packets because neighbor discovery is not
                // implemented and we have no way to resolve the next-hop link-layer address.
                ostd::debug!("IPv6 neighbor discovery is not implemented for Ethernet interfaces");
                return None;
            }
            None => return None,
        };

        if next_hop_ip.is_broadcast() {
            let ether_repr = EthernetRepr {
                src_addr: self.ether_addr,
                dst_addr: EthernetAddress::BROADCAST,
                ethertype: EthernetProtocol::Ipv4,
            };
            return Some(ether::emit(packet.packet, &ether_repr));
        }

        // Resolve the next-hop Ethernet address. If it is unknown, the packet is queued until the
        // address is resolved.
        let now_ms = iface_cx.now().total_millis() as u64;
        let mut neighbors = self.neighbors.lock();
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/ip_output.c#L234-L236>
        if packet.confirm_neighbor {
            neighbors.confirm(next_hop_ip, now_ms);
        }
        neighbors.resolve(next_hop_ip, packet.packet, now_ms, || {
            self.new_arp_request(next_hop_ip, None, iface_cx)
        })
    }

    fn poll_timers(&self, iface_cx: &Context) {
        let now_ms = iface_cx.now().total_millis() as u64;
        self.neighbors
            .lock()
            .poll_timers(now_ms, |next_hop_ip, dst_addr| {
                self.new_arp_request(next_hop_ip, dst_addr, iface_cx)
            });
    }

    fn pop_tx(&self) -> Option<TxPacket<LinkLayer>> {
        self.neighbors.lock().pop_ready()
    }

    fn next_poll_at_ms(&self) -> Option<u64> {
        self.neighbors.lock().next_poll_at_ms()
    }

    fn alloc_tx_buffer(&self, payload_len: usize) -> Result<FreshTxPacket, ostd::Error> {
        D::Device::alloc_tx_buffer(payload_len)
    }
}

impl<D: WithDevice, E: Ext> EtherIface<D, E> {
    /// Processes an ARP packet and returns the reply to send, if any.
    ///
    /// `is_unicast` indicates whether the Ethernet frame was sent to our Ethernet address.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L702>
    fn process_arp(
        &self,
        arp_repr: &ArpRepr,
        is_unicast: bool,
        iface_cx: &mut Context,
    ) -> Option<TxPacket<LinkLayer>> {
        let ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr,
            source_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        } = arp_repr
        else {
            return None;
        };

        // Ignore the ARP packet if the source addresses are not unicast.
        if !source_hardware_addr.is_unicast() || !source_protocol_addr.x_is_unicast() {
            return None;
        }

        let now_ms = iface_cx.now().total_millis() as u64;
        let is_local = iface_cx.in_same_network(&IpAddress::Ipv4(*source_protocol_addr));

        if *operation == ArpOperation::Request
            && iface_cx
                .ipv4_addr()
                .is_some_and(|addr| addr == *target_protocol_addr)
        {
            // Like Linux, learn the address of the sender, since the sender is likely to
            // receive a reply from us soon. Otherwise, the first reply would be dropped while
            // we resolve the address ourselves. A request does not confirm that the sender is
            // reachable, though.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L853>
            if is_local {
                let update = ArpUpdate {
                    confirms: false,
                    force_override: true,
                    may_create: true,
                };
                self.neighbors.lock().update(
                    *source_protocol_addr,
                    *source_hardware_addr,
                    update,
                    now_ms,
                );
            }

            let reply = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: self.ether_addr,
                source_protocol_addr: *target_protocol_addr,
                target_hardware_addr: *source_hardware_addr,
                target_protocol_addr: *source_protocol_addr,
            };
            return self.alloc_and_emit_arp(&reply, *source_hardware_addr);
        }

        // Ignore the ARP packet if the sender is not local.
        if !is_local {
            return None;
        }

        // Like Linux, update the entry of the sender. Only unicast replies confirm that the
        // sender is reachable. Gratuitous ARP packets can override the address at any time.
        // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L892>
        let is_reply = match operation {
            ArpOperation::Request => false,
            ArpOperation::Reply => true,
            _ => return None,
        };
        let is_garp = source_protocol_addr == target_protocol_addr
            && (!is_reply || source_hardware_addr == target_hardware_addr);
        let update = ArpUpdate {
            confirms: is_reply && is_unicast,
            force_override: is_garp,
            // Like Linux, which does not accept unsolicited ARP replies by default (see
            // `arp_accept`), only existing entries, including those being resolved, are updated.
            may_create: false,
        };
        self.neighbors
            .lock()
            .update(*source_protocol_addr, *source_hardware_addr, update, now_ms);

        None
    }

    /// Generates an ARP request, which is sent to `dst_addr` or broadcast if it is `None`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L376>
    fn new_arp_request(
        &self,
        target_protocol_addr: Ipv4Address,
        dst_addr: Option<EthernetAddress>,
        iface_cx: &Context,
    ) -> Option<TxPacket<LinkLayer>> {
        let arp_repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: self.ether_addr,
            source_protocol_addr: iface_cx.ipv4_addr().unwrap_or(Ipv4Address::UNSPECIFIED),
            // Like Linux, the target hardware address is zeroed since it is unknown.
            // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/ipv4/arp.c#L640>
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr,
        };
        self.alloc_and_emit_arp(&arp_repr, dst_addr.unwrap_or(EthernetAddress::BROADCAST))
    }

    fn alloc_and_emit_arp(
        &self,
        arp_repr: &ArpRepr,
        dst_addr: EthernetAddress,
    ) -> Option<TxPacket<LinkLayer>> {
        let buffer = match D::Device::alloc_tx_buffer(0) {
            Ok(buffer) => buffer,
            Err(err) => {
                ostd::error!("failed to allocate a network packet: {:?}", err);
                return None;
            }
        };

        let ether_repr = EthernetRepr {
            src_addr: self.ether_addr,
            dst_addr,
            ethertype: EthernetProtocol::Arp,
        };
        let packet = buffer.to_builder_at_layer::<TransportLayer>().build();
        let packet = arp::emit(packet, arp_repr);
        Some(ether::emit(packet, &ether_repr))
    }
}

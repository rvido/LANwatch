// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use pnet_packet::arp::{ArpOperations, ArpPacket};
use std::net::IpAddr;

/// Parses an ARP packet payload to extract the sender's MAC and IP address.
pub fn parse_arp_packet(payload: &[u8]) -> Option<([u8; 6], IpAddr)> {
    let arp = ArpPacket::new(payload)?;
    if arp.get_operation() == ArpOperations::Reply || arp.get_operation() == ArpOperations::Request
    {
        let src_mac = arp.get_sender_hw_addr().octets();
        let src_ip = IpAddr::V4(arp.get_sender_proto_addr());
        Some((src_mac, src_ip))
    } else {
        None
    }
}

/// Parses an NDP packet (ICMPv6 neighbor solicitation/advertisement).
pub fn parse_ndp_packet(
    payload: &[u8],
    source_ip: std::net::Ipv6Addr,
    source_mac: [u8; 6],
) -> Option<([u8; 6], IpAddr)> {
    if payload.len() >= 8 {
        let icmpv6_type = payload[0];
        if (icmpv6_type == 135 || icmpv6_type == 136) && !source_ip.is_unspecified() {
            return Some((source_mac, IpAddr::V6(source_ip)));
        }
    }
    None
}

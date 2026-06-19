//! Packet parsing modules for DHCP, mDNS, SSDP, and other network discovery protocols.

// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking

/// DHCP packet parser.
pub mod dhcp;

/// mDNS packet parser.
#[cfg(feature = "mdns")]
pub mod mdns;

/// SSDP/UPnP/LLDP/CDP packet parser.
#[cfg(feature = "ssdp")]
pub mod ssdp;

/// General network packet parsers (ARP, NDP, etc.).
pub mod network;

// Re-export the main parsing entry points and types
pub use dhcp::{is_dhcpv4_ports, is_dhcpv6_ports, parse_dhcpv4_payload, parse_dhcpv6_payload};
pub use network::{parse_arp_packet, parse_ndp_packet};

#[cfg(feature = "mdns")]
pub use mdns::{
    LLMNR_PORT, MDNS_IPV4_MULTICAST, MDNS_IPV6_MULTICAST, MDNS_PORT, MdnsPacket, MdnsPacketView,
    MdnsQuerier, MdnsQuestion, MdnsQuestionView, MdnsRecord, MdnsRecordData, MdnsRecordDataView,
    MdnsRecordType, MdnsRecordView, NbnsPacket, build_mdns_query, parse_mdns_payload,
    parse_nbns_payload,
};

#[cfg(feature = "ssdp")]
pub use ssdp::{
    SSDP_IPV4_MULTICAST, SSDP_IPV6_MULTICAST, SSDP_PORT, SsdpMessageType, SsdpMessageTypeView,
    SsdpPacket, SsdpPacketView, SsdpQuerier, WSD_PORT, WsdPacket, build_ssdp_search_request,
    parse_cdp_packet, parse_cdp_payload, parse_lldp_packet, parse_lldp_payload, parse_ssdp_payload,
    parse_wsd_payload,
};

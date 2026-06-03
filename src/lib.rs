// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

//! # lanwatch
//!
//! A high-performance, low-allocation library for network device discovery and tracking
//! via DHCP, mDNS, SSDP/UPnP, and OUI identification.
//!
//! ## Optimizations
//!
//! This library is optimized for minimal memory allocations, heavily employing borrowed
//! packet views during protocol ingestion to reduce allocations and copies on the hot path.
//!
//! ## Example
//!
//! ```no_run
//! use lanwatch::{DhcpSniffer, DhcpEvent};
//!
//! let mut sniffer = DhcpSniffer::new("en0").expect("Failed to create sniffer");
//!
//! // Process packets with a callback
//! sniffer.run(|event| {
//!     println!("Received: {:?}", event);
//!     true // continue sniffing
//! });
//! ```

use pnet_datalink as datalink;
use pnet_datalink::{Channel::Ethernet, DataLinkReceiver, NetworkInterface};
use pnet_packet::Packet;
#[cfg(any(feature = "mdns", feature = "ssdp"))]
use pnet_packet::arp::{ArpOperations, ArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::udp::UdpPacket;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// DHCPv4 server port
pub const DHCPV4_SERVER_PORT: u16 = 67;
/// DHCPv4 client port
pub const DHCPV4_CLIENT_PORT: u16 = 68;
/// DHCPv6 client port
pub const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server port
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// Errors that can occur during DHCP sniffing
#[derive(Debug)]
pub enum DhcpError {
    /// The specified network interface was not found
    InterfaceNotFound(String),
    /// Failed to create datalink channel
    ChannelCreationFailed(String),
    /// Unsupported channel type
    UnsupportedChannelType,
    /// Packet parsing error
    ParseError(String),
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpError::InterfaceNotFound(name) => write!(f, "Interface not found: {}", name),
            DhcpError::ChannelCreationFailed(msg) => {
                write!(f, "Failed to create channel: {}", msg)
            }
            DhcpError::UnsupportedChannelType => write!(f, "Unsupported channel type"),
            DhcpError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for DhcpError {}

/// DHCPv4 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv4MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl From<u8> for Dhcpv4MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Dhcpv4MessageType::Discover,
            2 => Dhcpv4MessageType::Offer,
            3 => Dhcpv4MessageType::Request,
            4 => Dhcpv4MessageType::Decline,
            5 => Dhcpv4MessageType::Ack,
            6 => Dhcpv4MessageType::Nak,
            7 => Dhcpv4MessageType::Release,
            8 => Dhcpv4MessageType::Inform,
            _ => Dhcpv4MessageType::Unknown(value),
        }
    }
}

impl std::fmt::Display for Dhcpv4MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dhcpv4MessageType::Discover => write!(f, "DISCOVER"),
            Dhcpv4MessageType::Offer => write!(f, "OFFER"),
            Dhcpv4MessageType::Request => write!(f, "REQUEST"),
            Dhcpv4MessageType::Decline => write!(f, "DECLINE"),
            Dhcpv4MessageType::Ack => write!(f, "ACK"),
            Dhcpv4MessageType::Nak => write!(f, "NAK"),
            Dhcpv4MessageType::Release => write!(f, "RELEASE"),
            Dhcpv4MessageType::Inform => write!(f, "INFORM"),
            Dhcpv4MessageType::Unknown(v) => write!(f, "UNKNOWN({})", v),
        }
    }
}

/// DHCPv4 operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv4Operation {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl From<u8> for Dhcpv4Operation {
    fn from(value: u8) -> Self {
        match value {
            1 => Dhcpv4Operation::BootRequest,
            2 => Dhcpv4Operation::BootReply,
            _ => Dhcpv4Operation::Unknown(value),
        }
    }
}

impl std::fmt::Display for Dhcpv4Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dhcpv4Operation::BootRequest => write!(f, "BootRequest (Client)"),
            Dhcpv4Operation::BootReply => write!(f, "BootReply (Server)"),
            Dhcpv4Operation::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// DHCPv6 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv6MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InfoRequest,
    Unknown(u8),
}

impl From<u8> for Dhcpv6MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Dhcpv6MessageType::Solicit,
            2 => Dhcpv6MessageType::Advertise,
            3 => Dhcpv6MessageType::Request,
            4 => Dhcpv6MessageType::Confirm,
            5 => Dhcpv6MessageType::Renew,
            6 => Dhcpv6MessageType::Rebind,
            7 => Dhcpv6MessageType::Reply,
            8 => Dhcpv6MessageType::Release,
            9 => Dhcpv6MessageType::Decline,
            10 => Dhcpv6MessageType::Reconfigure,
            11 => Dhcpv6MessageType::InfoRequest,
            _ => Dhcpv6MessageType::Unknown(value),
        }
    }
}

impl std::fmt::Display for Dhcpv6MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dhcpv6MessageType::Solicit => write!(f, "SOLICIT"),
            Dhcpv6MessageType::Advertise => write!(f, "ADVERTISE"),
            Dhcpv6MessageType::Request => write!(f, "REQUEST"),
            Dhcpv6MessageType::Confirm => write!(f, "CONFIRM"),
            Dhcpv6MessageType::Renew => write!(f, "RENEW"),
            Dhcpv6MessageType::Rebind => write!(f, "REBIND"),
            Dhcpv6MessageType::Reply => write!(f, "REPLY"),
            Dhcpv6MessageType::Release => write!(f, "RELEASE"),
            Dhcpv6MessageType::Decline => write!(f, "DECLINE"),
            Dhcpv6MessageType::Reconfigure => write!(f, "RECONFIGURE"),
            Dhcpv6MessageType::InfoRequest => write!(f, "INFO-REQUEST"),
            Dhcpv6MessageType::Unknown(v) => write!(f, "UNKNOWN({})", v),
        }
    }
}

/// Parsed DHCPv4 packet information
#[derive(Debug, Clone)]
pub struct Dhcpv4Packet {
    /// Source IPv4 address
    pub source_ip: Ipv4Addr,
    /// Destination IPv4 address
    pub dest_ip: Ipv4Addr,
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub dest_port: u16,
    /// DHCP operation type
    pub operation: Dhcpv4Operation,
    /// Client MAC address
    pub client_mac: [u8; 6],
    /// DHCP message type (from options)
    pub message_type: Option<Dhcpv4MessageType>,
    /// Hostname (from options)
    pub hostname: Option<String>,
    /// Requested IP address (from options)
    pub requested_ip: Option<Ipv4Addr>,
    /// Parameter request list (Option 55, from options)
    pub parameter_request_list: Option<Vec<u8>>,
    /// Vendor class identifier (Option 60, from options)
    pub vendor_class_id: Option<String>,
}

impl Dhcpv4Packet {
    /// Formats the client MAC address as a lowercase colon-separated string.
    ///
    /// # Returns
    /// A `String` in the format "aa:bb:cc:dd:ee:ff".
    ///
    /// This is useful for device identification and tracking keys.
    pub fn client_mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.client_mac[0],
            self.client_mac[1],
            self.client_mac[2],
            self.client_mac[3],
            self.client_mac[4],
            self.client_mac[5]
        )
    }
}

/// DHCPv6 option
#[derive(Debug, Clone)]
pub enum Dhcpv6Option {
    ClientId(Vec<u8>),
    ServerId(Vec<u8>),
    IaNa,
    ClientFqdn(String),
    Other { code: u16, data: Vec<u8> },
}

/// Parsed DHCPv6 packet information
#[derive(Debug, Clone)]
pub struct Dhcpv6Packet {
    /// Source IPv6 address
    pub source_ip: Ipv6Addr,
    /// Destination IPv6 address
    pub dest_ip: Ipv6Addr,
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub dest_port: u16,
    /// DHCPv6 message type
    pub message_type: Dhcpv6MessageType,
    /// Transaction ID
    pub transaction_id: [u8; 3],
    /// Parsed options
    pub options: Vec<Dhcpv6Option>,
}

impl Dhcpv6Packet {
    /// Formats the 3-byte DHCPv6 transaction ID as a hex string.
    ///
    /// # Returns
    /// A string prefixed with "0x" followed by the 6-character hex representation.
    ///
    /// Used to correlate DHCPv6 messages across a single transaction.
    pub fn transaction_id_string(&self) -> String {
        format!(
            "0x{:02X}{:02X}{:02X}",
            self.transaction_id[0], self.transaction_id[1], self.transaction_id[2]
        )
    }
}

/// DHCP event - either v4 or v6 packet
#[derive(Debug, Clone)]
pub enum DhcpEvent {
    V4(Dhcpv4Packet),
    V6(Dhcpv6Packet),
}

/// Network event - DHCP, mDNS, or SSDP packet
#[cfg(any(feature = "mdns", feature = "ssdp"))]
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// DHCPv4 packet
    Dhcpv4(Dhcpv4Packet),
    /// DHCPv6 packet
    Dhcpv6(Dhcpv6Packet),
    /// mDNS packet
    #[cfg(feature = "mdns")]
    Mdns(MdnsPacket),
    /// LLMNR packet
    #[cfg(feature = "mdns")]
    Llmnr(MdnsPacket),
    /// SSDP/UPnP packet
    #[cfg(feature = "ssdp")]
    Ssdp(SsdpPacket),
    /// ARP packet
    Arp {
        source_mac: String,
        source_ip: std::net::IpAddr,
    },
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
impl From<DhcpEvent> for NetworkEvent {
    fn from(event: DhcpEvent) -> Self {
        match event {
            DhcpEvent::V4(p) => NetworkEvent::Dhcpv4(p),
            DhcpEvent::V6(p) => NetworkEvent::Dhcpv6(p),
        }
    }
}

/// Returns a list of names for all available network interfaces on the system.
///
/// # Returns
/// A `Vec<String>` containing the names (e.g., "eth0", "en0", "wlan0").
///
/// This list is useful for providing users with options for which interface to sniff.
pub fn list_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}

/// Finds a network interface structure by its name.
///
/// # Arguments
/// * `name` - The string name of the interface to locate.
///
/// # Returns
/// `Some(NetworkInterface)` if found, or `None` if no interface matches the name.
pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

/// Parses a raw DHCPv4 UDP payload into a structured `Dhcpv4Packet`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload (starts at the BOOTP header).
/// * `source_ip` - The IPv4 source address from the IP header.
/// * `dest_ip` - The IPv4 destination address from the IP header.
/// * `source_port` - The UDP source port.
/// * `dest_port` - The UDP destination port.
///
/// # Returns
/// `Some(Dhcpv4Packet)` if the payload is valid and meets minimum length requirements, otherwise `None`.
pub fn parse_dhcpv4_payload(
    payload: &[u8],
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
) -> Option<Dhcpv4Packet> {
    if payload.len() < 240 {
        return None;
    }

    let operation = Dhcpv4Operation::from(payload[0]);
    let client_mac = [
        payload[28],
        payload[29],
        payload[30],
        payload[31],
        payload[32],
        payload[33],
    ];

    let mut message_type = None;
    let mut hostname = None;
    let mut requested_ip = None;
    let mut parameter_request_list = None;
    let mut vendor_class_id = None;

    // BOOTP/DHCP fixed header fields
    // ciaddr: client IP address (set by client in bound/renewing states)
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    // yiaddr: 'your' (client) IP address assigned by server
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    // Parse options starting at offset 240
    let mut index = 240;
    while index < payload.len() {
        let code = payload[index];
        if code == 255 {
            break;
        } // End
        if code == 0 {
            index += 1;
            continue;
        } // Pad

        if index + 1 >= payload.len() {
            break;
        }
        let len = payload[index + 1] as usize;

        if index + 2 + len > payload.len() {
            break;
        }
        let value = &payload[index + 2..index + 2 + len];

        match code {
            53 if !value.is_empty() => {
                // DHCP Message Type
                message_type = Some(Dhcpv4MessageType::from(value[0]));
            }
            12 => {
                // Hostname
                if let Ok(h) = std::str::from_utf8(value) {
                    hostname = sanitize_hostname(h);
                }
            }
            50 if value.len() == 4 => {
                // Requested IP Address
                requested_ip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            55 => {
                // Parameter Request List (Option 55)
                parameter_request_list = Some(value.to_vec());
            }
            60 => {
                // Vendor Class Identifier (Option 60)
                if let Ok(v) = std::str::from_utf8(value) {
                    vendor_class_id = Some(v.to_string());
                }
            }
            _ => {}
        }
        index += 2 + len;
    }

    // If option 50 wasn't present, fall back to ciaddr/yiaddr when available.
    // This keeps the tracking field useful for both client requests and server replies.
    if requested_ip.is_none() {
        if ciaddr != Ipv4Addr::new(0, 0, 0, 0) {
            requested_ip = Some(ciaddr);
        } else if yiaddr != Ipv4Addr::new(0, 0, 0, 0) {
            requested_ip = Some(yiaddr);
        }
    }

    Some(Dhcpv4Packet {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        operation,
        client_mac,
        message_type,
        hostname,
        requested_ip,
        parameter_request_list,
        vendor_class_id,
    })
}

/// Parses a raw DHCPv6 UDP payload into a structured `Dhcpv6Packet`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload (starts at the DHCPv6 message type).
/// * `source_ip` - The IPv6 source address from the IP header.
/// * `dest_ip` - The IPv6 destination address from the IP header.
/// * `source_port` - The UDP source port.
/// * `dest_port` - The UDP destination port.
///
/// # Returns
/// `Some(Dhcpv6Packet)` if the payload is valid and meets minimum length requirements, otherwise `None`.
pub fn parse_dhcpv6_payload(
    payload: &[u8],
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    source_port: u16,
    dest_port: u16,
) -> Option<Dhcpv6Packet> {
    if payload.len() < 4 {
        return None;
    }

    let message_type = Dhcpv6MessageType::from(payload[0]);
    let transaction_id = [payload[1], payload[2], payload[3]];

    let mut options = Vec::new();

    // Parse options starting at byte 4
    let mut index = 4;
    while index < payload.len() {
        if index + 4 > payload.len() {
            break;
        }

        let opt_code = ((payload[index] as u16) << 8) | (payload[index + 1] as u16);
        let opt_len = ((payload[index + 2] as u16) << 8) | (payload[index + 3] as u16);
        let length = opt_len as usize;

        if index + 4 + length > payload.len() {
            break;
        }
        let value = &payload[index + 4..index + 4 + length];

        let option = match opt_code {
            1 => Dhcpv6Option::ClientId(value.to_vec()),
            2 => Dhcpv6Option::ServerId(value.to_vec()),
            3 => Dhcpv6Option::IaNa,
            39 => {
                if let Some(fqdn) = parse_dhcpv6_client_fqdn(value) {
                    Dhcpv6Option::ClientFqdn(fqdn)
                } else {
                    Dhcpv6Option::Other {
                        code: opt_code,
                        data: value.to_vec(),
                    }
                }
            }
            _ => Dhcpv6Option::Other {
                code: opt_code,
                data: value.to_vec(),
            },
        };
        options.push(option);

        index += 4 + length;
    }

    Some(Dhcpv6Packet {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        message_type,
        transaction_id,
        options,
    })
}

/// Keep hostnames printable and safe for CSV/UI output.
fn sanitize_hostname(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();

    let cleaned = cleaned
        .trim_matches('.')
        .trim_matches('-')
        .trim_matches('_')
        .to_string();

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Parse DHCPv6 Client FQDN (option 39).
/// RFC 4704 format: 1-byte flags followed by a DNS wire-format name.
fn parse_dhcpv6_client_fqdn(value: &[u8]) -> Option<String> {
    if value.len() < 2 {
        return None;
    }

    // Skip flags byte
    let name = decode_dns_name(&value[1..])?;
    sanitize_hostname(&name)
}

/// Decode a basic DNS wire-format name (no compression pointers expected here).
fn decode_dns_name(data: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut index = 0usize;

    while index < data.len() {
        let label_len = data[index] as usize;
        index += 1;

        if label_len == 0 {
            break;
        }

        if label_len > 63 || index + label_len > data.len() {
            return None;
        }

        let label_bytes = &data[index..index + label_len];
        let label = std::str::from_utf8(label_bytes).ok()?;
        labels.push(label.to_string());
        index += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn format_duid_identifier(duid: &[u8]) -> String {
    let hex = duid
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    format!("duid:{}", hex)
}

/// Extract a 6-byte Ethernet MAC from DUID-LLT or DUID-LL when possible.
fn extract_mac_from_duid(duid: &[u8]) -> Option<String> {
    if duid.len() < 4 {
        return None;
    }

    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    let hw_type = u16::from_be_bytes([duid[2], duid[3]]);

    // Hardware type 1 == Ethernet
    if hw_type != 1 {
        return None;
    }

    let mac_bytes = match duid_type {
        // DUID-LLT: type(2) + hw(2) + time(4) + lladdr(n)
        1 if duid.len() >= 14 => &duid[8..14],
        // DUID-LL: type(2) + hw(2) + lladdr(n)
        3 if duid.len() >= 10 => &duid[4..10],
        _ => return None,
    };

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    ))
}

/// Checks if a pair of UDP ports corresponds to standard DHCPv4 traffic.
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
pub fn is_dhcpv4_ports(src: u16, dest: u16) -> bool {
    src == DHCPV4_SERVER_PORT
        || src == DHCPV4_CLIENT_PORT
        || dest == DHCPV4_SERVER_PORT
        || dest == DHCPV4_CLIENT_PORT
}

/// Checks if a pair of UDP ports corresponds to standard DHCPv6 traffic.
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
pub fn is_dhcpv6_ports(src: u16, dest: u16) -> bool {
    src == DHCPV6_CLIENT_PORT
        || src == DHCPV6_SERVER_PORT
        || dest == DHCPV6_CLIENT_PORT
        || dest == DHCPV6_SERVER_PORT
}

// ============================================================================
// mDNS (Multicast DNS) Support
// ============================================================================

/// mDNS port (same for queries and responses)
#[cfg(feature = "mdns")]
pub const MDNS_PORT: u16 = 5353;

/// LLMNR port
#[cfg(feature = "mdns")]
pub const LLMNR_PORT: u16 = 5355;

/// mDNS IPv4 multicast address
#[cfg(feature = "mdns")]
pub const MDNS_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS IPv6 multicast address
#[cfg(feature = "mdns")]
pub const MDNS_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// DNS record types relevant for mDNS
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsRecordType {
    /// A record (IPv4 address)
    A,
    /// AAAA record (IPv6 address)
    Aaaa,
    /// PTR record (pointer/alias)
    Ptr,
    /// SRV record (service location)
    Srv,
    /// TXT record (text/metadata)
    Txt,
    /// ANY query (request all records)
    Any,
    /// Unknown record type
    Unknown(u16),
}

#[cfg(feature = "mdns")]
impl From<u16> for MdnsRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => MdnsRecordType::A,
            28 => MdnsRecordType::Aaaa,
            12 => MdnsRecordType::Ptr,
            33 => MdnsRecordType::Srv,
            16 => MdnsRecordType::Txt,
            255 => MdnsRecordType::Any,
            _ => MdnsRecordType::Unknown(value),
        }
    }
}

#[cfg(feature = "mdns")]
impl From<MdnsRecordType> for u16 {
    fn from(value: MdnsRecordType) -> Self {
        match value {
            MdnsRecordType::A => 1,
            MdnsRecordType::Aaaa => 28,
            MdnsRecordType::Ptr => 12,
            MdnsRecordType::Srv => 33,
            MdnsRecordType::Txt => 16,
            MdnsRecordType::Any => 255,
            MdnsRecordType::Unknown(v) => v,
        }
    }
}

/// Information about a known mDNS service type
#[cfg(feature = "mdns")]
#[derive(Debug, Clone)]
pub struct MdnsServiceInfo {
    /// Service type (e.g., "_http._tcp")
    pub service_type: String,
    /// Human-readable description
    pub description: String,
    /// Vendor hint (e.g., "Apple", "Google")
    pub vendor: Option<String>,
    /// Device type (e.g., "Chromecast", "Apple TV", "Printer")
    pub device_type: Option<String>,
}

/// Registry of known mDNS service types
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, Default)]
pub struct MdnsServiceRegistry {
    services: HashMap<String, MdnsServiceInfo>,
}

#[cfg(feature = "mdns")]
impl MdnsServiceRegistry {
    /// Creates a new, empty mDNS service registry.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Creates an mDNS service registry pre-populated with common network services.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.add_default_services();
        registry
    }

    /// Add default well-known services
    fn add_default_services(&mut self) {
        // Apple TV / Streaming devices
        self.add_full(
            "_airplay._tcp",
            "AirPlay",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_raop._tcp",
            "Remote Audio (AirPlay)",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_companion-link._tcp",
            "AirPlay 2 Companion",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_touch-able._tcp",
            "Apple TV Remote",
            Some("Apple"),
            Some("Apple TV"),
        );
        self.add_full(
            "_mediaremotetv._tcp",
            "Apple TV Media Remote",
            Some("Apple"),
            Some("Apple TV"),
        );
        self.add_full(
            "_appletv-v2._tcp",
            "Apple TV",
            Some("Apple"),
            Some("Apple TV"),
        );

        // Apple Mobile / Mac devices
        self.add_full(
            "_airdrop._tcp",
            "AirDrop",
            Some("Apple"),
            Some("Apple Device"),
        );
        self.add_full(
            "_device-info._tcp",
            "Device Info",
            Some("Apple"),
            Some("Apple Device"),
        );
        self.add_full(
            "_apple-mobdev._tcp",
            "Apple Mobile Device",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_apple-mobdev2._tcp",
            "Apple Mobile Device",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_remotepairing._tcp",
            "Apple Remote Pairing",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_atc._tcp",
            "Apple Transfer Control",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_rdlink._tcp",
            "Apple Remote Device Link",
            Some("Apple"),
            Some("Apple iPhone"),
        );

        // Apple Smart Home
        self.add_full(
            "_homekit._tcp",
            "HomeKit",
            Some("Apple"),
            Some("Smart Home Hub"),
        );
        self.add_full(
            "_hap._tcp",
            "HomeKit Accessory",
            Some("Apple"),
            Some("Smart Home Device"),
        );

        // Apple Network/Storage
        self.add_full(
            "_airport._tcp",
            "AirPort Base Station",
            Some("Apple"),
            Some("Router"),
        );
        self.add_full(
            "_daap._tcp",
            "iTunes Library (DAAP)",
            Some("Apple"),
            Some("Media Server"),
        );
        self.add_full(
            "_dpap._tcp",
            "iPhoto Library",
            Some("Apple"),
            Some("Media Server"),
        );
        self.add_full(
            "_afpovertcp._tcp",
            "Apple File Sharing (AFP)",
            Some("Apple"),
            Some("File Server"),
        );

        // Google Chromecast / Android TV
        self.add_full(
            "_googlecast._tcp",
            "Google Chromecast",
            Some("Google"),
            Some("Chromecast"),
        );
        self.add_full(
            "_googlezone._tcp",
            "Google Zone",
            Some("Google"),
            Some("Chromecast"),
        );
        self.add_full(
            "_androidtvremote._tcp",
            "Android TV Remote",
            Some("Google"),
            Some("Android TV"),
        );
        self.add_full(
            "_physicalweb._tcp",
            "Physical Web",
            Some("Google"),
            Some("IoT Beacon"),
        );

        // Amazon Fire TV
        self.add_full(
            "_amzn-wplay._tcp",
            "Amazon Fire TV",
            Some("Amazon"),
            Some("Fire TV"),
        );

        // Printers & Scanners
        self.add_full("_printer._tcp", "LPR Printer", None, Some("Printer"));
        self.add_full("_ipp._tcp", "IPP Printer", None, Some("Printer"));
        self.add_full("_ipps._tcp", "IPP Printer (Secure)", None, Some("Printer"));
        self.add_full("_ippusb._tcp", "IPP USB Printer", None, Some("Printer"));
        self.add_full("_pdl-datastream._tcp", "PDL Printer", None, Some("Printer"));
        self.add_full("_scanner._tcp", "Network Scanner", None, Some("Scanner"));
        self.add_full("_uscan._tcp", "USB Scanner", None, Some("Scanner"));

        // Servers / Workstations
        self.add_full("_http._tcp", "Web Server (HTTP)", None, Some("Server"));
        self.add_full("_https._tcp", "Web Server (HTTPS)", None, Some("Server"));
        self.add_full("_ssh._tcp", "SSH Server", None, Some("Server"));
        self.add_full("_sftp-ssh._tcp", "SFTP over SSH", None, Some("Server"));
        self.add_full("_ftp._tcp", "FTP Server", None, Some("Server"));
        self.add_full(
            "_smb._tcp",
            "Windows/Samba Sharing",
            None,
            Some("File Server"),
        );
        self.add_full(
            "_nfs._tcp",
            "Network File System",
            None,
            Some("File Server"),
        );
        self.add_full("_rfb._tcp", "Screen Sharing (VNC)", None, Some("Desktop"));
        self.add_full("_telnet._tcp", "Telnet", None, Some("Server"));
        self.add_full("_workstation._tcp", "Workstation", None, Some("Desktop"));

        // Media/Entertainment
        self.add_full(
            "_spotify-connect._tcp",
            "Spotify Connect",
            Some("Spotify"),
            Some("Speaker"),
        );
        self.add_full(
            "_nvstream_dbd._tcp",
            "NVIDIA GameStream",
            Some("NVIDIA"),
            Some("Gaming PC"),
        );

        // Smart Home / IoT
        self.add_full(
            "_hue._tcp",
            "Philips Hue",
            Some("Philips"),
            Some("Smart Light"),
        );
        self.add_full(
            "_miio._udp",
            "Xiaomi IoT",
            Some("Xiaomi"),
            Some("IoT Device"),
        );

        // NAS / Storage
        self.add_full(
            "_readynas._tcp",
            "Netgear ReadyNAS",
            Some("Netgear"),
            Some("NAS"),
        );
        self.add_full(
            "_udisks-ssh._tcp",
            "Linux Disk Service",
            Some("Linux"),
            Some("NAS"),
        );

        // Network Equipment
        self.add_full(
            "_csco-sb._tcp",
            "Cisco Small Business",
            Some("Cisco"),
            Some("Router/Switch"),
        );

        // Other
        self.add_full(
            "_teamviewer._tcp",
            "TeamViewer",
            Some("TeamViewer"),
            Some("Desktop"),
        );
        self.add_full(
            "_1password4._tcp",
            "1Password Sync",
            Some("1Password"),
            Some("Desktop"),
        );
        self.add_full(
            "_privet._tcp",
            "Google Cloud Print",
            Some("Google"),
            Some("Printer"),
        );
        self.add_full("_arduino._tcp", "Arduino", None, Some("Microcontroller"));
        self.add_full("_tivo-videos._tcp", "TiVo", Some("TiVo"), Some("DVR"));
        self.add_full("_psia._tcp", "IP Camera (PSIA)", None, Some("IP Camera"));
    }

    /// Add a service to the registry (without device_type, for backward compatibility)
    pub fn add(&mut self, service_type: &str, description: &str, vendor: Option<&str>) {
        let device_type = Self::detect_device_type_from_description(description);
        self.add_full(service_type, description, vendor, device_type.as_deref());
    }

    /// Adds a service to the registry with explicit vendor and device type metadata.
    pub fn add_full(
        &mut self,
        service_type: &str,
        description: &str,
        vendor: Option<&str>,
        device_type: Option<&str>,
    ) {
        let normalized = Self::normalize_service_type(service_type);
        self.services.insert(
            normalized.clone(),
            MdnsServiceInfo {
                service_type: normalized,
                description: description.to_string(),
                vendor: vendor.map(|s| s.to_string()),
                device_type: device_type.map(|s| s.to_string()),
            },
        );
    }

    /// Loads service definitions from a flat file.
    ///
    /// # Arguments
    /// * `path` - Path to the file containing service definitions.
    ///
    /// # Returns
    /// The number of services successfully loaded.
    ///
    /// # File Format
    /// `_service._tcp.local # Description of the service`
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and pure comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse format: service_type # description
            let parts: Vec<&str> = line.splitn(2, '#').collect();
            let service_type = parts[0].trim();

            if service_type.is_empty() {
                continue;
            }

            let description = if parts.len() > 1 {
                parts[1].trim().to_string()
            } else {
                service_type.to_string()
            };

            // Detect vendor and device type from description
            let vendor = Self::detect_vendor_from_description(&description);
            let device_type = Self::detect_device_type_from_description(&description);

            self.add_full(
                service_type,
                &description,
                vendor.as_deref(),
                device_type.as_deref(),
            );
            count += 1;
        }

        Ok(count)
    }

    /// Detect device type from description text
    fn detect_device_type_from_description(description: &str) -> Option<String> {
        let desc_lower = description.to_lowercase();

        // Streaming devices
        if desc_lower.contains("chromecast") || desc_lower.contains("chrome cast") {
            return Some("Chromecast".to_string());
        }
        if desc_lower.contains("apple tv") || desc_lower.contains("appletv") {
            return Some("Apple TV".to_string());
        }
        if desc_lower.contains("fire tv") || desc_lower.contains("firetv") {
            return Some("Fire TV".to_string());
        }
        if desc_lower.contains("airplay") {
            return Some("Media Streamer".to_string());
        }
        if desc_lower.contains("android tv") {
            return Some("Android TV".to_string());
        }
        if desc_lower.contains("tivo") {
            return Some("DVR".to_string());
        }

        // Mobile devices
        if desc_lower.contains("iphone")
            || desc_lower.contains("ipad")
            || desc_lower.contains("ios device")
        {
            return Some("Apple iPhone".to_string());
        }
        if desc_lower.contains("mobile device") {
            return Some("Mobile Device".to_string());
        }

        // Printers & Scanners
        if desc_lower.contains("printer") || desc_lower.contains("printing") {
            return Some("Printer".to_string());
        }
        if desc_lower.contains("scanner") || desc_lower.contains("scanning") {
            return Some("Scanner".to_string());
        }

        // Network equipment
        if desc_lower.contains("router") || desc_lower.contains("base station") {
            return Some("Router".to_string());
        }
        if desc_lower.contains("switch") {
            return Some("Router/Switch".to_string());
        }
        if desc_lower.contains("nas")
            || desc_lower.contains("network attached storage")
            || desc_lower.contains("readynas")
        {
            return Some("NAS".to_string());
        }

        // Smart home
        if desc_lower.contains("homekit") && desc_lower.contains("accessory") {
            return Some("Smart Home Device".to_string());
        }
        if desc_lower.contains("homekit") {
            return Some("Smart Home Hub".to_string());
        }
        if desc_lower.contains("smart light") || desc_lower.contains("hue") {
            return Some("Smart Light".to_string());
        }
        if desc_lower.contains("smart speaker") || desc_lower.contains("speaker") {
            return Some("Speaker".to_string());
        }

        // Cameras
        if desc_lower.contains("camera") || desc_lower.contains("ip cam") {
            return Some("IP Camera".to_string());
        }

        // Servers
        if desc_lower.contains("file sharing") || desc_lower.contains("file server") {
            return Some("File Server".to_string());
        }
        if desc_lower.contains("web server") || desc_lower.contains("http") {
            return Some("Server".to_string());
        }
        if desc_lower.contains("ssh") || desc_lower.contains("ftp") || desc_lower.contains("telnet")
        {
            return Some("Server".to_string());
        }

        // Development
        if desc_lower.contains("arduino") {
            return Some("Microcontroller".to_string());
        }
        if desc_lower.contains("raspberry") {
            return Some("Raspberry Pi".to_string());
        }
        if desc_lower.contains("jenkins") {
            return Some("CI Server".to_string());
        }

        // Desktop/Workstation
        if desc_lower.contains("screen sharing")
            || desc_lower.contains("remote desktop")
            || desc_lower.contains("vnc")
        {
            return Some("Desktop".to_string());
        }
        if desc_lower.contains("workstation") || desc_lower.contains("workgroup") {
            return Some("Desktop".to_string());
        }

        // Media servers
        if desc_lower.contains("itunes")
            || desc_lower.contains("media server")
            || desc_lower.contains("plex")
        {
            return Some("Media Server".to_string());
        }
        if desc_lower.contains("spotify") {
            return Some("Speaker".to_string());
        }

        // Gaming
        if desc_lower.contains("gamestream") || desc_lower.contains("nvidia shield") {
            return Some("Gaming Device".to_string());
        }

        None
    }

    /// Detect vendor from description text
    fn detect_vendor_from_description(description: &str) -> Option<String> {
        let desc_lower = description.to_lowercase();
        if desc_lower.contains("apple")
            || desc_lower.contains("osx")
            || desc_lower.contains("itunes")
            || desc_lower.contains("iphone")
            || desc_lower.contains("ipad")
        {
            Some("Apple".to_string())
        } else if desc_lower.contains("google")
            || desc_lower.contains("chrome")
            || desc_lower.contains("android")
        {
            Some("Google".to_string())
        } else if desc_lower.contains("amazon")
            || desc_lower.contains("fire tv")
            || desc_lower.contains("alexa")
        {
            Some("Amazon".to_string())
        } else if desc_lower.contains("samsung") {
            Some("Samsung".to_string())
        } else if desc_lower.contains("nvidia") {
            Some("NVIDIA".to_string())
        } else if desc_lower.contains("hp") {
            Some("HP".to_string())
        } else if desc_lower.contains("canon") {
            Some("Canon".to_string())
        } else if desc_lower.contains("ubuntu")
            || desc_lower.contains("linux")
            || desc_lower.contains("raspberry")
        {
            Some("Linux".to_string())
        } else if desc_lower.contains("cisco") {
            Some("Cisco".to_string())
        } else if desc_lower.contains("netgear") {
            Some("Netgear".to_string())
        } else {
            None
        }
    }

    /// Normalize a service type (lowercase, ensure .local suffix removed)
    fn normalize_service_type(service_type: &str) -> String {
        service_type
            .to_lowercase()
            .trim_end_matches(".local")
            .to_string()
    }

    /// Looks up service metadata based on the service type string.
    pub fn lookup(&self, service_type: &str) -> Option<&MdnsServiceInfo> {
        let normalized = Self::normalize_service_type(service_type);
        self.services.get(&normalized)
    }

    /// Returns the human-readable description for a service type.
    pub fn get_description(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type).map(|s| s.description.as_str())
    }

    /// Returns the detected vendor associated with a service type.
    pub fn get_vendor(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type).and_then(|s| s.vendor.as_deref())
    }

    /// Returns the inferred device type associated with a service type.
    pub fn get_device_type(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type)
            .and_then(|s| s.device_type.as_deref())
    }

    /// Returns a reference to the internal map of registered services.
    pub fn services(&self) -> &HashMap<String, MdnsServiceInfo> {
        &self.services
    }

    /// Returns the total number of services in the registry.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

// ============================================================================
// OUI Registry (IEEE MAC Address Vendor Database)
// ============================================================================

/// Registry for IEEE OUI (Organizationally Unique Identifier) database.
/// Uses the `oui-data` crate which contains ~40,000+ vendor entries from the IEEE registry.
/// Custom overrides can be loaded from a file to supplement or replace built-in entries.
#[derive(Debug, Clone, Default)]
pub struct OuiRegistry {
    /// Custom vendor overrides (takes priority over the built-in database)
    custom_overrides: HashMap<String, String>,
}

impl OuiRegistry {
    /// Creates a new empty OUI registry.
    /// Note: The built-in `oui-data` database is still accessible for lookups.
    pub fn new() -> Self {
        Self {
            custom_overrides: HashMap::new(),
        }
    }

    /// Creates a new OUI registry with the built-in IEEE database initialized.
    /// This is equivalent to `new()` since oui-data is always available.
    pub fn with_defaults() -> Self {
        Self::new()
    }

    /// Look up vendor name by MAC address.
    /// Checks custom overrides first, then falls back to the oui-data crate.
    ///
    /// The MAC address can be in various formats:
    /// - Full: "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
    /// - OUI only: "AA:BB:CC" or "AABBCC"
    pub fn lookup(&self, mac_address: &str) -> Option<&str> {
        let mut buf = [0u8; 8];
        let len = {
            let mut l = 0;
            for c in mac_address.chars() {
                if l >= 6 {
                    break;
                }
                if c.is_ascii_hexdigit() {
                    let u = c.to_ascii_uppercase() as u8;
                    if l == 0 {
                        buf[0] = u;
                    } else if l == 1 {
                        buf[1] = u;
                    } else if l == 2 {
                        buf[3] = u;
                    } else if l == 3 {
                        buf[4] = u;
                    } else if l == 4 {
                        buf[6] = u;
                    } else if l == 5 {
                        buf[7] = u;
                    }
                    l += 1;
                }
            }
            if l >= 6 {
                buf[2] = b':';
                buf[5] = b':';
                8
            } else {
                let mut idx = 0;
                for c in mac_address.chars() {
                    if idx >= l {
                        break;
                    }
                    if c.is_ascii_hexdigit() {
                        buf[idx] = c.to_ascii_uppercase() as u8;
                        idx += 1;
                    }
                }
                l
            }
        };

        let normalized = std::str::from_utf8(&buf[..len]).ok()?;

        // Check custom overrides first (highest priority)
        if let Some(vendor) = self.custom_overrides.get(normalized) {
            return Some(vendor.as_str());
        }

        // Fall back to oui-data crate (IEEE database with ~40,000 entries)
        if let Some(oui_entry) = oui_data::lookup(normalized) {
            // organization() already provides a borrowed string; avoid allocating on every lookup.
            Some(oui_entry.organization())
        } else {
            None
        }
    }

    /// Load additional OUI entries from a file.
    /// File format: MAC_PREFIX<whitespace>VENDOR_NAME
    /// Example:
    ///   AA:BB:CC  Acme Corporation
    ///   DD-EE-FF  Another Vendor
    ///
    /// Returns the number of entries loaded.
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            // Parse line: MAC_PREFIX<whitespace>VENDOR_NAME
            if let Some((mac, vendor)) = Self::parse_oui_line(line) {
                let normalized = Self::normalize_mac(&mac);
                self.custom_overrides.insert(normalized, vendor);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Adds a manual OUI-to-vendor mapping to the registry.
    pub fn add(&mut self, mac_prefix: &str, vendor: &str) {
        let normalized = Self::normalize_mac(mac_prefix);
        self.custom_overrides.insert(normalized, vendor.to_string());
    }

    /// Returns the total count of OUI entries available (custom plus built-in).
    pub fn len(&self) -> usize {
        // oui-data contains the full IEEE OUI database
        oui_data::OUI_ENTRIES.len() + self.custom_overrides.len()
    }

    /// Check if registry has no entries
    pub fn is_empty(&self) -> bool {
        oui_data::OUI_ENTRIES.is_empty() && self.custom_overrides.is_empty()
    }

    /// Returns the number of custom override entries loaded.
    pub fn custom_count(&self) -> usize {
        self.custom_overrides.len()
    }

    /// Returns the number of entries in the built-in IEEE database.
    pub fn builtin_count() -> usize {
        oui_data::OUI_ENTRIES.len()
    }

    /// Normalize a MAC address to OUI format (first 3 octets, uppercase, colon-separated)
    fn normalize_mac(mac: &str) -> String {
        let mut buf = [0u8; 6];
        let mut len = 0;

        for c in mac.chars() {
            if len >= 6 {
                break;
            }
            if c.is_ascii_hexdigit() {
                buf[len] = c.to_ascii_uppercase() as u8;
                len += 1;
            }
        }

        if len >= 6 {
            let mut s = String::with_capacity(8);
            s.push(buf[0] as char);
            s.push(buf[1] as char);
            s.push(':');
            s.push(buf[2] as char);
            s.push(buf[3] as char);
            s.push(':');
            s.push(buf[4] as char);
            s.push(buf[5] as char);
            s
        } else {
            let mut s = String::with_capacity(len);
            for &b in &buf[..len] {
                s.push(b as char);
            }
            s
        }
    }

    /// Parse a line from an OUI file
    fn parse_oui_line(line: &str) -> Option<(String, String)> {
        // Try tab separator first
        if let Some((mac, vendor)) = line.split_once('\t') {
            let mac = mac.trim();
            let vendor = vendor.trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac.to_string(), vendor.to_string()));
            }
        }

        // Try splitting on first run of spaces (at least 2)
        let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() == 2 {
            let mac = parts[0].trim();
            let vendor = parts[1].trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac.to_string(), vendor.to_string()));
            }
        }

        None
    }

    /// Parse IEEE OUI format line (from official IEEE downloads)
    /// Format: "XX-XX-XX   (hex)\t\tVendor Name"
    fn parse_ieee_oui_line(line: &str) -> Option<(String, String)> {
        // IEEE format: "XX-XX-XX   (hex)		Vendor Name"
        // We look for lines containing "(hex)"
        if !line.contains("(hex)") {
            return None;
        }

        // Split on "(hex)" - MAC is before, vendor is after
        let parts: Vec<&str> = line.splitn(2, "(hex)").collect();
        if parts.len() != 2 {
            return None;
        }

        let mac = parts[0].trim();
        let vendor = parts[1].trim();

        if mac.is_empty() || vendor.is_empty() {
            return None;
        }

        Some((mac.to_string(), vendor.to_string()))
    }

    /// Load OUI entries from IEEE format file (official IEEE OUI download)
    /// This parses the official IEEE OUI format with "(hex)" markers.
    pub fn load_from_ieee_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;

            // Parse IEEE format line
            if let Some((mac, vendor)) = Self::parse_ieee_oui_line(&line) {
                let normalized = Self::normalize_mac(&mac);
                self.custom_overrides.insert(normalized, vendor);
                count += 1;
            }
        }

        Ok(count)
    }
}

/// IEEE OUI database URLs
pub const IEEE_OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.txt";
pub const IEEE_OUI28_URL: &str = "https://standards-oui.ieee.org/oui28/mam.txt";
pub const IEEE_OUI36_URL: &str = "https://standards-oui.ieee.org/oui36/oui36.txt";

/// Download the IEEE OUI database to a file using curl.
/// Returns Ok(()) on success, or an error message on failure.
///
/// # Arguments
/// * `output_path` - Path where the downloaded file will be saved
/// * `url` - Optional custom URL (defaults to IEEE_OUI_URL)
///
/// # Example
/// ```no_run
/// use lanwatch::download_ieee_oui;
/// download_ieee_oui("oui.txt", None).expect("Failed to download OUI database");
/// ```
pub fn download_ieee_oui<P: AsRef<Path>>(output_path: P, url: Option<&str>) -> Result<(), String> {
    let url = url.unwrap_or(IEEE_OUI_URL);
    let output_path = output_path.as_ref();

    // Use curl to download the file
    let output = std::process::Command::new("curl")
        .args([
            "-fsSL", // fail silently, follow redirects, show errors
            "--connect-timeout",
            "30",
            "--max-time",
            "120",
            "-o",
            output_path.to_str().ok_or("Invalid output path")?,
            url,
        ])
        .output()
        .map_err(|e| format!("Failed to execute curl: {}. Is curl installed?", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", stderr.trim()));
    }

    // Verify the file was created and has content
    let metadata = std::fs::metadata(output_path)
        .map_err(|e| format!("Failed to verify downloaded file: {}", e))?;

    if metadata.len() == 0 {
        return Err("Downloaded file is empty".to_string());
    }

    Ok(())
}

/// Download and load IEEE OUI database into an OuiRegistry.
/// Downloads from IEEE and parses the official format.
///
/// # Arguments
/// * `registry` - The OuiRegistry to load entries into
/// * `cache_path` - Optional path to cache the downloaded file (default: "ieee-oui.txt")
///
/// # Returns
/// Number of entries loaded on success, or an error message on failure.
pub fn download_and_load_ieee_oui(
    registry: &mut OuiRegistry,
    cache_path: Option<&str>,
) -> Result<usize, String> {
    let path = cache_path.unwrap_or("ieee-oui.txt");

    // Download the file
    download_ieee_oui(path, None)?;

    // Load the downloaded file
    registry
        .load_from_ieee_file(path)
        .map_err(|e| format!("Failed to parse IEEE OUI file: {}", e))
}

#[cfg(feature = "mdns")]
impl std::fmt::Display for MdnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MdnsRecordType::A => write!(f, "A"),
            MdnsRecordType::Aaaa => write!(f, "AAAA"),
            MdnsRecordType::Ptr => write!(f, "PTR"),
            MdnsRecordType::Srv => write!(f, "SRV"),
            MdnsRecordType::Txt => write!(f, "TXT"),
            MdnsRecordType::Any => write!(f, "ANY"),
            MdnsRecordType::Unknown(v) => write!(f, "UNKNOWN({})", v),
        }
    }
}

/// A DNS resource record from an mDNS packet
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsRecord {
    /// The domain name this record is for
    pub name: String,
    /// Record type (A, AAAA, PTR, SRV, TXT)
    pub record_type: MdnsRecordType,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Record data (interpretation depends on record_type)
    pub data: MdnsRecordData,
}

/// Parsed mDNS record data
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsRecordData {
    /// IPv4 address (A record)
    A(Ipv4Addr),
    /// IPv6 address (AAAA record)
    Aaaa(Ipv6Addr),
    /// Domain name (PTR record)
    Ptr(String),
    /// Service record: priority, weight, port, target
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Text record (key=value pairs or raw strings)
    Txt(Vec<String>),
    /// Raw data for unknown record types
    Raw(Vec<u8>),
}

/// A parsed mDNS packet
#[cfg(feature = "mdns")]
#[derive(Debug, Clone)]
pub struct MdnsPacket {
    /// Source MAC address
    pub source_mac: String,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Destination IP address
    pub dest_ip: std::net::IpAddr,
    /// Transaction ID
    pub transaction_id: u16,
    /// Is this a response? (false = query)
    pub is_response: bool,
    /// Questions (queries)
    pub questions: Vec<MdnsQuestion>,
    /// Answer records
    pub answers: Vec<MdnsRecord>,
    /// Authority records
    pub authority: Vec<MdnsRecord>,
    /// Additional records
    pub additional: Vec<MdnsRecord>,
}

/// An mDNS question (query)
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsQuestion {
    /// The name being queried
    pub name: String,
    /// The record type being requested
    pub record_type: MdnsRecordType,
}

/// Borrowed mDNS question.
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdnsQuestionView<'a> {
    /// The name being queried
    pub name: &'a str,
    /// The record type being requested
    pub record_type: MdnsRecordType,
}

/// Borrowed mDNS record data.
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsRecordDataView<'a> {
    /// IPv4 address (A record)
    A(Ipv4Addr),
    /// IPv6 address (AAAA record)
    Aaaa(Ipv6Addr),
    /// Domain name (PTR record)
    Ptr(&'a str),
    /// Service record: priority, weight, port, target
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: &'a str,
    },
    /// Text record (key=value pairs or raw strings)
    Txt(Vec<&'a str>),
    /// Raw data for unknown record types
    Raw(&'a [u8]),
}

/// Borrowed mDNS record.
#[cfg(feature = "mdns")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsRecordView<'a> {
    /// The domain name this record is for
    pub name: &'a str,
    /// Record type (A, AAAA, PTR, SRV, TXT)
    pub record_type: MdnsRecordType,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Record data (interpretation depends on record_type)
    pub data: MdnsRecordDataView<'a>,
}

/// Borrowed view of a parsed mDNS packet.
#[cfg(feature = "mdns")]
#[derive(Debug, Clone)]
pub struct MdnsPacketView<'a> {
    /// Source MAC address
    pub source_mac: &'a str,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Destination IP address
    pub dest_ip: std::net::IpAddr,
    /// Transaction ID
    pub transaction_id: u16,
    /// Is this a response? (false = query)
    pub is_response: bool,
    /// Questions (queries)
    pub questions: Vec<MdnsQuestionView<'a>>,
    /// Answer records
    pub answers: Vec<MdnsRecordView<'a>>,
    /// Authority records
    pub authority: Vec<MdnsRecordView<'a>>,
    /// Additional records
    pub additional: Vec<MdnsRecordView<'a>>,
}

#[cfg(feature = "mdns")]
impl MdnsPacket {
    /// Creates a borrowed view of this packet.
    pub fn view(&self) -> MdnsPacketView<'_> {
        MdnsPacketView {
            source_mac: self.source_mac.as_str(),
            source_ip: self.source_ip,
            dest_ip: self.dest_ip,
            transaction_id: self.transaction_id,
            is_response: self.is_response,
            questions: self
                .questions
                .iter()
                .map(|question| MdnsQuestionView {
                    name: question.name.as_str(),
                    record_type: question.record_type,
                })
                .collect(),
            answers: self
                .answers
                .iter()
                .map(|record| MdnsRecordView {
                    name: record.name.as_str(),
                    record_type: record.record_type,
                    ttl: record.ttl,
                    data: match &record.data {
                        MdnsRecordData::A(addr) => MdnsRecordDataView::A(*addr),
                        MdnsRecordData::Aaaa(addr) => MdnsRecordDataView::Aaaa(*addr),
                        MdnsRecordData::Ptr(target) => MdnsRecordDataView::Ptr(target.as_str()),
                        MdnsRecordData::Srv {
                            priority,
                            weight,
                            port,
                            target,
                        } => MdnsRecordDataView::Srv {
                            priority: *priority,
                            weight: *weight,
                            port: *port,
                            target: target.as_str(),
                        },
                        MdnsRecordData::Txt(strings) => {
                            MdnsRecordDataView::Txt(strings.iter().map(|s| s.as_str()).collect())
                        }
                        MdnsRecordData::Raw(bytes) => MdnsRecordDataView::Raw(bytes.as_slice()),
                    },
                })
                .collect(),
            authority: self
                .authority
                .iter()
                .map(|record| MdnsRecordView {
                    name: record.name.as_str(),
                    record_type: record.record_type,
                    ttl: record.ttl,
                    data: match &record.data {
                        MdnsRecordData::A(addr) => MdnsRecordDataView::A(*addr),
                        MdnsRecordData::Aaaa(addr) => MdnsRecordDataView::Aaaa(*addr),
                        MdnsRecordData::Ptr(target) => MdnsRecordDataView::Ptr(target.as_str()),
                        MdnsRecordData::Srv {
                            priority,
                            weight,
                            port,
                            target,
                        } => MdnsRecordDataView::Srv {
                            priority: *priority,
                            weight: *weight,
                            port: *port,
                            target: target.as_str(),
                        },
                        MdnsRecordData::Txt(strings) => {
                            MdnsRecordDataView::Txt(strings.iter().map(|s| s.as_str()).collect())
                        }
                        MdnsRecordData::Raw(bytes) => MdnsRecordDataView::Raw(bytes.as_slice()),
                    },
                })
                .collect(),
            additional: self
                .additional
                .iter()
                .map(|record| MdnsRecordView {
                    name: record.name.as_str(),
                    record_type: record.record_type,
                    ttl: record.ttl,
                    data: match &record.data {
                        MdnsRecordData::A(addr) => MdnsRecordDataView::A(*addr),
                        MdnsRecordData::Aaaa(addr) => MdnsRecordDataView::Aaaa(*addr),
                        MdnsRecordData::Ptr(target) => MdnsRecordDataView::Ptr(target.as_str()),
                        MdnsRecordData::Srv {
                            priority,
                            weight,
                            port,
                            target,
                        } => MdnsRecordDataView::Srv {
                            priority: *priority,
                            weight: *weight,
                            port: *port,
                            target: target.as_str(),
                        },
                        MdnsRecordData::Txt(strings) => {
                            MdnsRecordDataView::Txt(strings.iter().map(|s| s.as_str()).collect())
                        }
                        MdnsRecordData::Raw(bytes) => MdnsRecordDataView::Raw(bytes.as_slice()),
                    },
                })
                .collect(),
        }
    }

    /// Returns an iterator over every record in the packet (Answers, Authority, and Additional).
    pub fn all_records(&self) -> impl Iterator<Item = &MdnsRecord> {
        self.answers
            .iter()
            .chain(self.authority.iter())
            .chain(self.additional.iter())
    }

    /// Extracts service instance names from PTR records.
    ///
    /// # Returns
    /// A vector of tuples containing (instance_name, service_type).
    pub fn get_service_instances(&self) -> Vec<(&str, &str)> {
        self.answers
            .iter()
            .chain(self.additional.iter())
            .filter_map(|r| {
                if let MdnsRecordData::Ptr(target) = &r.data {
                    // PTR record name is the service type, data is the instance
                    Some((target.as_str(), r.name.as_str()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts all IPv4 addresses from A records found in the packet.
    ///
    /// # Returns
    /// A vector of tuples containing (host_name, ipv4_address).
    pub fn get_ipv4_addresses(&self) -> Vec<(String, Ipv4Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordData::A(addr) = &r.data {
                    Some((r.name.clone(), *addr))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts all IPv6 addresses from AAAA records found in the packet.
    ///
    /// # Returns
    /// A vector of tuples containing (host_name, ipv6_address).
    pub fn get_ipv6_addresses(&self) -> Vec<(String, Ipv6Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordData::Aaaa(addr) = &r.data {
                    Some((r.name.clone(), *addr))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(feature = "mdns")]
impl<'a> MdnsPacketView<'a> {
    /// Returns an iterator over every record in the packet (Answers, Authority, and Additional).
    pub fn all_records(&self) -> impl Iterator<Item = &MdnsRecordView<'a>> {
        self.answers
            .iter()
            .chain(self.authority.iter())
            .chain(self.additional.iter())
    }

    /// Extracts service instance names from PTR records.
    pub fn get_service_instances(&self) -> Vec<(&'a str, &'a str)> {
        self.answers
            .iter()
            .chain(self.additional.iter())
            .filter_map(|r| {
                if let MdnsRecordDataView::Ptr(target) = &r.data {
                    Some((*target, r.name))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts all IPv4 addresses from A records found in the packet.
    pub fn get_ipv4_addresses(&self) -> Vec<(&'a str, Ipv4Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordDataView::A(addr) = &r.data {
                    Some((r.name, *addr))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts all IPv6 addresses from AAAA records found in the packet.
    pub fn get_ipv6_addresses(&self) -> Vec<(&'a str, Ipv6Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordDataView::Aaaa(addr) = &r.data {
                    Some((r.name, *addr))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Checks if a pair of UDP ports corresponds to standard mDNS traffic (5353).
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
#[cfg(feature = "mdns")]
pub fn is_mdns_ports(src: u16, dest: u16) -> bool {
    src == MDNS_PORT || dest == MDNS_PORT
}

/// Checks if a pair of UDP ports corresponds to standard LLMNR traffic (5355).
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
#[cfg(feature = "mdns")]
pub fn is_llmnr_ports(src: u16, dest: u16) -> bool {
    src == LLMNR_PORT || dest == LLMNR_PORT
}

/// Parses a raw mDNS UDP payload into a structured `MdnsPacket`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload.
/// * `source_mac` - The source MAC address as a string.
/// * `source_ip` - The sender's IP address.
/// * `dest_ip` - The destination IP address.
#[cfg(feature = "mdns")]
pub fn parse_mdns_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
) -> Option<MdnsPacket> {
    // DNS header is 12 bytes minimum
    if payload.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;

    let qd_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let an_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let ns_count = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    let ar_count = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    let mut offset = 12;

    // Parse questions
    let mut questions = Vec::new();
    for _ in 0..qd_count {
        let (name, new_offset) = parse_dns_name(payload, offset)?;
        offset = new_offset;

        if offset + 4 > payload.len() {
            return None;
        }

        let record_type =
            MdnsRecordType::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
        // Skip QCLASS (2 bytes)
        offset += 4;

        questions.push(MdnsQuestion { name, record_type });
    }

    // Parse answer records
    let (answers, new_offset) = parse_dns_records(payload, offset, an_count)?;
    offset = new_offset;

    // Parse authority records
    let (authority, new_offset) = parse_dns_records(payload, offset, ns_count)?;
    offset = new_offset;

    // Parse additional records
    let (additional, _) = parse_dns_records(payload, offset, ar_count)?;

    Some(MdnsPacket {
        source_mac,
        source_ip,
        dest_ip,
        transaction_id,
        is_response,
        questions,
        answers,
        authority,
        additional,
    })
}

/// Parse a DNS name from the packet (handles compression)
#[cfg(feature = "mdns")]
fn parse_dns_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name_parts: Vec<&str> = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut return_offset = 0;
    let mut visited_offsets: Vec<usize> = Vec::new();

    loop {
        if offset >= payload.len() {
            return None;
        }

        let len = payload[offset] as usize;

        if len == 0 {
            offset += 1;
            break;
        }

        // Check for compression pointer (top 2 bits set)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (payload[offset + 1] as usize);
            if pointer >= payload.len() || pointer == offset || visited_offsets.contains(&pointer) {
                return None;
            }
            visited_offsets.push(pointer);
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            continue;
        }

        offset += 1;
        if offset + len > payload.len() {
            return None;
        }

        let part = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
        name_parts.push(part);
        offset += len;
    }

    let final_offset = if jumped { return_offset } else { offset };
    Some((name_parts.join("."), final_offset))
}

/// Parse DNS resource records
#[cfg(feature = "mdns")]
fn parse_dns_records(
    payload: &[u8],
    start: usize,
    count: usize,
) -> Option<(Vec<MdnsRecord>, usize)> {
    let mut records = Vec::new();
    let mut offset = start;

    for _ in 0..count {
        let (name, new_offset) = parse_dns_name(payload, offset)?;
        offset = new_offset;

        if offset + 10 > payload.len() {
            return None;
        }

        let record_type =
            MdnsRecordType::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
        // Skip CLASS (2 bytes) - usually IN (1) with cache-flush bit
        offset += 4;

        let ttl = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        offset += 4;

        let rd_length = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if offset + rd_length > payload.len() {
            return None;
        }

        let data = parse_record_data(payload, offset, rd_length, record_type)?;
        offset += rd_length;

        records.push(MdnsRecord {
            name,
            record_type,
            ttl,
            data,
        });
    }

    Some((records, offset))
}

/// Parse record data based on record type
#[cfg(feature = "mdns")]
fn parse_record_data(
    payload: &[u8],
    offset: usize,
    length: usize,
    record_type: MdnsRecordType,
) -> Option<MdnsRecordData> {
    match record_type {
        MdnsRecordType::A => {
            if length != 4 {
                return None;
            }
            Some(MdnsRecordData::A(Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            )))
        }
        MdnsRecordType::Aaaa => {
            if length != 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            Some(MdnsRecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        MdnsRecordType::Ptr => {
            let (name, _) = parse_dns_name(payload, offset)?;
            Some(MdnsRecordData::Ptr(name))
        }
        MdnsRecordType::Srv => {
            if length < 6 {
                return None;
            }
            let priority = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let weight = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let port = u16::from_be_bytes([payload[offset + 4], payload[offset + 5]]);
            let (target, _) = parse_dns_name(payload, offset + 6)?;
            Some(MdnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        MdnsRecordType::Txt => {
            let mut strings = Vec::new();
            let mut pos = offset;
            let end = offset + length;
            while pos < end {
                let str_len = payload[pos] as usize;
                pos += 1;
                if pos + str_len > end {
                    break;
                }
                let s = String::from_utf8_lossy(&payload[pos..pos + str_len]).to_string();
                strings.push(s);
                pos += str_len;
            }
            Some(MdnsRecordData::Txt(strings))
        }
        _ => Some(MdnsRecordData::Raw(
            payload[offset..offset + length].to_vec(),
        )),
    }
}

// ============================================================================
// mDNS Active Querying
// ============================================================================

/// mDNS querier for active service discovery
#[cfg(feature = "mdns")]
pub struct MdnsQuerier {
    socket: std::net::UdpSocket,
}

#[cfg(feature = "mdns")]
impl MdnsQuerier {
    /// Creates a new mDNS querier and binds a UDP socket.
    pub fn new() -> std::io::Result<Self> {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;

        // Set multicast TTL
        socket.set_multicast_ttl_v4(255)?;

        // Enable reuse
        socket.set_nonblocking(false)?;

        Ok(Self { socket })
    }

    /// Sends a PTR query for a specific mDNS service type.
    ///
    /// # Arguments
    /// * `service_type` - The service type to query (e.g., "_http._tcp.local").
    pub fn query_service(&self, service_type: &str) -> std::io::Result<()> {
        let packet = build_mdns_query(service_type, MdnsRecordType::Ptr);
        self.socket
            .send_to(&packet, (MDNS_IPV4_MULTICAST, MDNS_PORT))?;
        Ok(())
    }

    /// Sends an ANY query for a specific hostname.
    ///
    /// # Arguments
    /// * `hostname` - The hostname to query (e.g., "mydevice.local").
    pub fn query_hostname(&self, hostname: &str) -> std::io::Result<()> {
        let packet = build_mdns_query(hostname, MdnsRecordType::Any);
        self.socket
            .send_to(&packet, (MDNS_IPV4_MULTICAST, MDNS_PORT))?;
        Ok(())
    }

    /// Sends discovery queries for common well-known mDNS service types.
    pub fn query_common_services(&self) -> std::io::Result<()> {
        let services = [
            "_services._dns-sd._udp.local", // Service enumeration
            "_http._tcp.local",             // HTTP servers
            "_https._tcp.local",            // HTTPS servers
            "_airplay._tcp.local",          // Apple AirPlay
            "_raop._tcp.local",             // Apple Remote Audio
            "_googlecast._tcp.local",       // Google Chromecast
            "_googlezone._tcp.local",       // Google Chromecast
            "_spotify-connect._tcp.local",  // Spotify Connect
            "_smb._tcp.local",              // SMB file sharing
            "_afpovertcp._tcp.local",       // AFP file sharing
            "_ssh._tcp.local",              // SSH servers
            "_printer._tcp.local",          // Printers
            "_ipp._tcp.local",              // IPP printers
            "_hap._tcp.local",              // HomeKit accessories
            "_homekit._tcp.local",          // HomeKit
        ];

        for service in services {
            self.query_service(service)?;
            // Small delay to avoid flooding
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }
}

/// Builds a raw mDNS query packet for the specified name and record type.
///
/// # Arguments
/// * `name` - The domain name to query.
/// * `record_type` - The record type requested (e.g., PTR, A).
#[cfg(feature = "mdns")]
pub fn build_mdns_query(name: &str, record_type: MdnsRecordType) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Transaction ID (0 for mDNS)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Flags (standard query)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // Question section
    for part in name.split('.') {
        let len = part.len();
        if len > 0 && len <= 63 {
            packet.push(len as u8);
            packet.extend_from_slice(part.as_bytes());
        }
    }
    packet.push(0x00); // End of name

    // QTYPE
    let qtype: u16 = record_type.into();
    packet.extend_from_slice(&qtype.to_be_bytes());

    // QCLASS (IN with unicast-response bit)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

// ============================================================================
// SSDP / UPnP Support
// ============================================================================

/// SSDP port used for discovery and responses
#[cfg(feature = "ssdp")]
pub const SSDP_PORT: u16 = 1900;

/// SSDP IPv4 multicast address
#[cfg(feature = "ssdp")]
pub const SSDP_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// SSDP IPv6 multicast address
#[cfg(feature = "ssdp")]
pub const SSDP_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);

/// SSDP message types
#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsdpMessageType {
    /// NOTIFY advertisement
    Notify,
    /// M-SEARCH discovery request
    Search,
    /// HTTP/1.1 200 OK response
    Response,
    /// Unknown start line
    Unknown(String),
}

/// Borrowed SSDP message types.
#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpMessageTypeView<'a> {
    /// NOTIFY advertisement
    Notify,
    /// M-SEARCH discovery request
    Search,
    /// HTTP/1.1 200 OK response
    Response,
    /// Unknown start line
    Unknown(&'a str),
}

#[cfg(feature = "ssdp")]
impl std::fmt::Display for SsdpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsdpMessageType::Notify => write!(f, "NOTIFY"),
            SsdpMessageType::Search => write!(f, "M-SEARCH"),
            SsdpMessageType::Response => write!(f, "RESPONSE"),
            SsdpMessageType::Unknown(value) => write!(f, "UNKNOWN({})", value),
        }
    }
}

/// Parsed SSDP / UPnP packet information
#[cfg(feature = "ssdp")]
#[derive(Debug, Clone)]
pub struct SsdpPacket {
    /// Source MAC address
    pub source_mac: String,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Destination IP address
    pub dest_ip: std::net::IpAddr,
    /// Message type inferred from the HTTP-style start line
    pub message_type: SsdpMessageType,
    /// First line of the SSDP message
    pub start_line: String,
    /// Parsed headers keyed by lowercase header name
    pub headers: HashMap<String, String>,
}

/// Borrowed view of a parsed SSDP / UPnP packet.
#[cfg(feature = "ssdp")]
#[derive(Debug, Clone)]
pub struct SsdpPacketView<'a> {
    /// Source MAC address
    pub source_mac: &'a str,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Destination IP address
    pub dest_ip: std::net::IpAddr,
    /// Message type inferred from the HTTP-style start line
    pub message_type: SsdpMessageTypeView<'a>,
    /// First line of the SSDP message
    pub start_line: &'a str,
    /// Parsed headers keyed by lowercase header name
    pub headers: Vec<(&'a str, &'a str)>,
}

#[cfg(feature = "ssdp")]
impl SsdpPacket {
    /// Creates a borrowed view of this packet.
    pub fn view(&self) -> SsdpPacketView<'_> {
        SsdpPacketView {
            source_mac: self.source_mac.as_str(),
            source_ip: self.source_ip,
            dest_ip: self.dest_ip,
            message_type: match &self.message_type {
                SsdpMessageType::Notify => SsdpMessageTypeView::Notify,
                SsdpMessageType::Search => SsdpMessageTypeView::Search,
                SsdpMessageType::Response => SsdpMessageTypeView::Response,
                SsdpMessageType::Unknown(value) => SsdpMessageTypeView::Unknown(value.as_str()),
            },
            start_line: self.start_line.as_str(),
            headers: self
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect(),
        }
    }

    /// Returns the value of a specific header, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns a reference to the complete map of SSDP headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Collect the discovery-oriented identifiers advertised by this packet
    pub fn service_terms(&self) -> Vec<String> {
        let mut terms = Vec::new();
        let mut seen = HashSet::new();
        for header in ["nt", "st", "usn"] {
            if let Some(value) = self.header(header) {
                let normalized = value.trim().to_string();
                if !normalized.is_empty() && seen.insert(normalized.clone()) {
                    terms.push(normalized);
                }
            }
        }
        terms
    }

    /// Combine the useful fingerprint headers into a single string for heuristic matching
    pub fn fingerprint_text(&self) -> String {
        let mut parts = vec![self.start_line.clone()];
        for header in ["nt", "st", "usn", "server", "location"] {
            if let Some(value) = self.header(header) {
                parts.push(value.to_string());
            }
        }
        parts.join(" ")
    }
}

#[cfg(feature = "ssdp")]
impl<'a> SsdpPacketView<'a> {
    /// Returns the value of a specific header, if present.
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    /// Collect the discovery-oriented identifiers advertised by this packet.
    pub fn service_terms(&self) -> Vec<&'a str> {
        let mut terms = Vec::new();
        for header in ["nt", "st", "usn"] {
            if let Some(value) = self.header(header) {
                let normalized = value.trim();
                if !normalized.is_empty() && !terms.contains(&normalized) {
                    terms.push(normalized);
                }
            }
        }
        terms
    }

    /// Combine the useful fingerprint headers into a single string for heuristic matching.
    pub fn fingerprint_text(&self) -> String {
        let mut parts: Vec<&str> = vec![self.start_line];
        for header in ["nt", "st", "usn", "server", "location"] {
            if let Some(value) = self.header(header) {
                parts.push(value.trim());
            }
        }
        parts.join(" ")
    }

    /// Detect vendor from SSDP fingerprints without allocating a combined string.
    pub fn detect_vendor_from_view(&self) -> Option<String> {
        if self.view_contains_any(&["apple", "airport", "airplay"]) {
            return Some("Apple".to_string());
        }
        if self.view_contains_any(&["lenovo", "legion", "thinkpad", "ideapad", "yoga"]) {
            return Some("Lenovo".to_string());
        }
        if self.view_contains_any(&["google", "chromecast", "android tv"]) {
            return Some("Google".to_string());
        }
        if self.view_contains_any(&["amazon", "alexa", "fire tv"]) {
            return Some("Amazon".to_string());
        }
        if self.view_contains_any(&["samsung"]) {
            return Some("Samsung".to_string());
        }
        if self.view_contains_any(&["lg ", "lge"]) {
            return Some("LG".to_string());
        }
        if self.view_contains_any(&["sony"]) {
            return Some("Sony".to_string());
        }
        if self.view_contains_any(&["roku"]) {
            return Some("Roku".to_string());
        }
        if self.view_contains_any(&["sonos"]) {
            return Some("Sonos".to_string());
        }
        if self.view_contains_any(&["microsoft", "windows"]) {
            return Some("Microsoft".to_string());
        }
        if self.view_contains_any(&["philips", "hue"]) {
            return Some("Philips".to_string());
        }
        if self.view_contains_any(&["netgear"]) {
            return Some("Netgear".to_string());
        }
        if self.view_contains_any(&["tp-link", "tplink"]) {
            return Some("TP-Link".to_string());
        }
        if self.view_contains_any(&["ubiquiti", "unifi"]) {
            return Some("Ubiquiti".to_string());
        }
        if self.view_contains_any(&["d-link"]) {
            return Some("D-Link".to_string());
        }
        if self.view_contains_any(&["bose"]) {
            return Some("Bose".to_string());
        }
        if self.view_contains_any(&["denon"]) {
            return Some("Denon".to_string());
        }
        if self.view_contains_any(&["yamaha"]) {
            return Some("Yamaha".to_string());
        }
        if self.view_contains_any(&["synology"]) {
            return Some("Synology".to_string());
        }
        if self.view_contains_any(&["qnap"]) {
            return Some("QNAP".to_string());
        }

        None
    }

    /// Detect device type from SSDP fingerprints without allocating a combined string.
    pub fn detect_device_type_from_view(&self) -> Option<String> {
        if self.view_contains_any(&["mediarenderer", "renderer"]) {
            return Some("Media Renderer".to_string());
        }
        if self.view_contains_any(&["lenovo", "legion", "thinkpad", "ideapad", "yoga"]) {
            return Some("Laptop".to_string());
        }
        if self.view_contains_any(&[
            "googlecast",
            "dial-multiscreen-org",
            "internetgatewaydevice",
        ]) && self.view_contains_any(&["windows", "rvd_", "pc", "lenovo", "legion"])
        {
            return Some("Laptop".to_string());
        }
        if self.view_contains_any(&["mediaserver"]) {
            return Some("Media Server".to_string());
        }
        if self.view_contains_any(&["internetgatewaydevice", "wanconnectiondevice", "router"]) {
            return Some("Router".to_string());
        }
        if self.view_contains_any(&["printer", "print"]) {
            return Some("Printer".to_string());
        }
        if self.view_contains_any(&["scanner"]) {
            return Some("Scanner".to_string());
        }
        if self.view_contains_any(&["television", "tvdevice", "smarttv"]) {
            return Some("TV".to_string());
        }
        if self.view_contains_any(&["camera", "ipcamera"]) {
            return Some("IP Camera".to_string());
        }
        if self.view_contains_any(&["speaker", "soundbar"]) {
            return Some("Speaker".to_string());
        }
        if self.view_contains_any(&["gameconsole", "xbox", "playstation"]) {
            return Some("Gaming Console".to_string());
        }
        if self.view_contains_any(&["set-top", "settop"]) {
            return Some("Set Top Box".to_string());
        }
        if self.view_contains_any(&["nas", "storage"]) {
            return Some("NAS".to_string());
        }
        if self.view_contains_any(&["bridge", "light", "bulb", "homekit"]) {
            return Some("Smart Home Device".to_string());
        }

        None
    }

    fn view_contains_any(&self, needles: &[&str]) -> bool {
        self.view_contains_any_in(self.start_line, needles)
            || self.headers.iter().any(|(name, value)| {
                self.view_contains_any_in(name, needles)
                    || self.view_contains_any_in(value, needles)
            })
    }

    fn view_contains_any_in(&self, haystack: &str, needles: &[&str]) -> bool {
        needles
            .iter()
            .any(|needle| contains_ascii_case_insensitive(haystack, needle))
    }
}

#[cfg(feature = "ssdp")]
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();

    if needle.is_empty() {
        return true;
    }

    if needle.len() > haystack.len() {
        return false;
    }

    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

/// SSDP querier for active M-SEARCH discovery
#[cfg(feature = "ssdp")]
pub struct SsdpQuerier {
    socket: std::net::UdpSocket,
}

#[cfg(feature = "ssdp")]
impl SsdpQuerier {
    /// Creates a new SSDP querier and binds a UDP socket.
    pub fn new() -> std::io::Result<Self> {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;

        // Set multicast TTL
        socket.set_multicast_ttl_v4(255)?;

        // Enable reuse
        socket.set_nonblocking(false)?;

        Ok(Self { socket })
    }

    /// Sends an M-SEARCH discovery request for a specific SSDP search target.
    ///
    /// # Arguments
    /// * `device_type` - The search target (ST) header value (e.g., "ssdp:all").
    pub fn search_device(&self, device_type: &str) -> std::io::Result<()> {
        let request = build_ssdp_search_request(device_type);
        self.socket
            .send_to(&request, (SSDP_IPV4_MULTICAST, SSDP_PORT))?;
        Ok(())
    }

    /// Sends discovery probes for common well-known UPnP device types.
    pub fn search_common_devices(&self) -> std::io::Result<()> {
        let device_types = [
            "ssdp:all",        // All SSDP devices
            "upnp:rootdevice", // All UPnP root devices
            "urn:schemas-upnp-org:device:MediaServer:1",
            "urn:schemas-upnp-org:device:MediaRenderer:1",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1", // Routers
            "urn:schemas-upnp-org:device:PrinterBasic:1",          // Printers
            "urn:dial-multiscreen-org:service:dial-second-screen-service:1", // DIAL servers
        ];

        for device_type in device_types {
            self.search_device(device_type)?;
            // Small delay to avoid flooding
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }
}

/// Builds a raw SSDP M-SEARCH request packet string.
///
/// # Arguments
/// * `search_target` - The value for the ST (Search Target) header.
#[cfg(feature = "ssdp")]
pub fn build_ssdp_search_request(search_target: &str) -> Vec<u8> {
    // M-SEARCH request format per UPnP specification
    let request = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {}\r\n\r\n",
        search_target
    );
    request.into_bytes()
}

/// Checks if a pair of UDP ports corresponds to standard SSDP traffic (1900).
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
#[cfg(feature = "ssdp")]
pub fn is_ssdp_ports(src: u16, dest: u16) -> bool {
    src == SSDP_PORT || dest == SSDP_PORT
}

/// Parses a raw SSDP/UPnP UDP payload into a structured `SsdpPacket`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload.
/// * `source_mac` - The source MAC address as a string.
/// * `source_ip` - The sender's IP address.
/// * `dest_ip` - The destination IP address.
#[cfg(feature = "ssdp")]
pub fn parse_ssdp_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
) -> Option<SsdpPacket> {
    if payload.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(payload);
    let mut lines = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty());
    let start_line = lines.next()?.to_string();

    let message_type = if starts_with_ascii_case_insensitive(&start_line, "M-SEARCH * HTTP/1.1") {
        SsdpMessageType::Search
    } else if starts_with_ascii_case_insensitive(&start_line, "NOTIFY * HTTP/1.1") {
        SsdpMessageType::Notify
    } else if starts_with_ascii_case_insensitive(&start_line, "HTTP/1.1 200") {
        SsdpMessageType::Response
    } else {
        SsdpMessageType::Unknown(start_line.clone())
    };

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let key = name.trim().to_lowercase();
            let value = value.trim().to_string();
            if !key.is_empty() {
                headers.insert(key, value);
            }
        }
    }

    Some(SsdpPacket {
        source_mac,
        source_ip,
        dest_ip,
        message_type,
        start_line,
        headers,
    })
}

#[cfg(feature = "ssdp")]
#[inline(always)]
fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

/// Processes a raw Ethernet frame and extracts a DHCP event (v4 or v6) if present.
///
/// # Arguments
/// * `frame` - Raw bytes of the Ethernet frame.
///
/// # Returns
/// `Some(DhcpEvent)` if the frame contains a valid DHCP packet, otherwise `None`.
pub fn process_ethernet_frame(frame: &[u8]) -> Option<DhcpEvent> {
    let ethernet = EthernetPacket::new(frame)?;

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => process_ipv4_packet(&ethernet),
        EtherTypes::Ipv6 => process_ipv6_packet(&ethernet),
        _ => None,
    }
}

/// Processes a raw Ethernet frame and extracts a `NetworkEvent` (DHCP, mDNS, or SSDP) if present.
///
/// # Arguments
/// * `frame` - Raw bytes of the Ethernet frame.
///
/// # Returns
/// `Some(NetworkEvent)` if the frame contains one of the supported protocols, otherwise `None`.
#[cfg(any(feature = "mdns", feature = "ssdp"))]
pub fn process_ethernet_frame_extended(frame: &[u8]) -> Option<NetworkEvent> {
    let ethernet = EthernetPacket::new(frame)?;

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => process_ipv4_packet_extended(&ethernet),
        EtherTypes::Ipv6 => process_ipv6_packet_extended(&ethernet),
        EtherTypes::Arp => {
            let arp = ArpPacket::new(ethernet.payload())?;
            if arp.get_operation() == ArpOperations::Reply
                || arp.get_operation() == ArpOperations::Request
            {
                let src_mac = arp.get_sender_hw_addr().to_string();
                let src_ip = std::net::IpAddr::V4(arp.get_sender_proto_addr());
                Some(NetworkEvent::Arp {
                    source_mac: src_mac,
                    source_ip: src_ip,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn process_ipv4_packet(ethernet: &EthernetPacket) -> Option<DhcpEvent> {
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv4.payload())?;
    let src = udp.get_source();
    let dest = udp.get_destination();

    if !is_dhcpv4_ports(src, dest) {
        return None;
    }

    let packet = parse_dhcpv4_payload(
        udp.payload(),
        ipv4.get_source(),
        ipv4.get_destination(),
        src,
        dest,
    )?;

    Some(DhcpEvent::V4(packet))
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn process_ipv4_packet_extended(ethernet: &EthernetPacket) -> Option<NetworkEvent> {
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv4.payload())?;
    let src = udp.get_source();
    let dest = udp.get_destination();

    #[cfg(feature = "mdns")]
    if is_mdns_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_mdns_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V4(ipv4.get_source()),
            std::net::IpAddr::V4(ipv4.get_destination()),
        )?;
        return Some(NetworkEvent::Mdns(packet));
    }

    #[cfg(feature = "mdns")]
    if is_llmnr_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_mdns_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V4(ipv4.get_source()),
            std::net::IpAddr::V4(ipv4.get_destination()),
        )?;
        return Some(NetworkEvent::Llmnr(packet));
    }

    #[cfg(feature = "ssdp")]
    if is_ssdp_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_ssdp_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V4(ipv4.get_source()),
            std::net::IpAddr::V4(ipv4.get_destination()),
        )?;
        return Some(NetworkEvent::Ssdp(packet));
    }

    // Check for DHCPv4
    if is_dhcpv4_ports(src, dest) {
        let packet = parse_dhcpv4_payload(
            udp.payload(),
            ipv4.get_source(),
            ipv4.get_destination(),
            src,
            dest,
        )?;
        return Some(NetworkEvent::Dhcpv4(packet));
    }

    None
}

fn process_ipv6_packet(ethernet: &EthernetPacket) -> Option<DhcpEvent> {
    let ipv6 = Ipv6Packet::new(ethernet.payload())?;

    if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv6.payload())?;
    let src = udp.get_source();
    let dest = udp.get_destination();

    if !is_dhcpv6_ports(src, dest) {
        return None;
    }

    let packet = parse_dhcpv6_payload(
        udp.payload(),
        ipv6.get_source(),
        ipv6.get_destination(),
        src,
        dest,
    )?;

    Some(DhcpEvent::V6(packet))
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn process_ipv6_packet_extended(ethernet: &EthernetPacket) -> Option<NetworkEvent> {
    let ipv6 = Ipv6Packet::new(ethernet.payload())?;

    if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv6.payload())?;
    let src = udp.get_source();
    let dest = udp.get_destination();

    #[cfg(feature = "mdns")]
    if is_mdns_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_mdns_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V6(ipv6.get_source()),
            std::net::IpAddr::V6(ipv6.get_destination()),
        )?;
        return Some(NetworkEvent::Mdns(packet));
    }

    #[cfg(feature = "mdns")]
    if is_llmnr_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_mdns_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V6(ipv6.get_source()),
            std::net::IpAddr::V6(ipv6.get_destination()),
        )?;
        return Some(NetworkEvent::Llmnr(packet));
    }

    #[cfg(feature = "ssdp")]
    if is_ssdp_ports(src, dest) {
        let source_mac = ethernet.get_source().to_string();
        let packet = parse_ssdp_payload(
            udp.payload(),
            source_mac,
            std::net::IpAddr::V6(ipv6.get_source()),
            std::net::IpAddr::V6(ipv6.get_destination()),
        )?;
        return Some(NetworkEvent::Ssdp(packet));
    }

    // Check for DHCPv6
    if is_dhcpv6_ports(src, dest) {
        let packet = parse_dhcpv6_payload(
            udp.payload(),
            ipv6.get_source(),
            ipv6.get_destination(),
            src,
            dest,
        )?;
        return Some(NetworkEvent::Dhcpv6(packet));
    }

    None
}

/// DHCP packet sniffer
pub struct DhcpSniffer {
    interface_name: String,
    rx: Box<dyn DataLinkReceiver>,
}

impl DhcpSniffer {
    /// Creates a new DHCP packet sniffer bound to the specified network interface.
    ///
    /// # Arguments
    /// * `interface_name` - The system name of the interface to sniff (e.g., "eth0").
    pub fn new(interface_name: &str) -> Result<Self, DhcpError> {
        let interface = find_interface(interface_name)
            .ok_or_else(|| DhcpError::InterfaceNotFound(interface_name.to_string()))?;

        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(DhcpError::UnsupportedChannelType),
            Err(e) => return Err(DhcpError::ChannelCreationFailed(e.to_string())),
        };

        Ok(Self {
            interface_name: interface_name.to_string(),
            rx,
        })
    }

    /// Returns the name of the network interface used by the sniffer.
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Reads the next packet from the interface and parses it if it is a DHCP message.
    pub fn next_packet(&mut self) -> Result<Option<DhcpEvent>, DhcpError> {
        match self.rx.next() {
            Ok(packet) => Ok(process_ethernet_frame(packet)),
            Err(e) => Err(DhcpError::ParseError(e.to_string())),
        }
    }

    /// Runs the capture loop, invoking a callback for every detected DHCP event.
    ///
    /// # Arguments
    /// * `callback` - A closure that receives a `DhcpEvent`.
    ///
    /// The loop terminates if the callback returns `false`.
    pub fn run<F>(&mut self, mut callback: F)
    where
        F: FnMut(DhcpEvent) -> bool,
    {
        loop {
            match self.next_packet() {
                Ok(Some(event)) => {
                    if !callback(event) {
                        break;
                    }
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("Error reading packet: {}", e);
                }
            }
        }
    }
}

/// Network sniffer that captures DHCP plus optional discovery traffic
#[cfg(any(feature = "mdns", feature = "ssdp"))]
pub struct NetworkSniffer {
    interface_name: String,
    rx: Box<dyn DataLinkReceiver>,
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
impl NetworkSniffer {
    /// Creates a new multi-protocol network sniffer bound to the specified interface.
    ///
    /// # Arguments
    /// * `interface_name` - The system name of the interface to sniff.
    pub fn new(interface_name: &str) -> Result<Self, DhcpError> {
        let interface = find_interface(interface_name)
            .ok_or_else(|| DhcpError::InterfaceNotFound(interface_name.to_string()))?;

        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(DhcpError::UnsupportedChannelType),
            Err(e) => return Err(DhcpError::ChannelCreationFailed(e.to_string())),
        };

        Ok(Self {
            interface_name: interface_name.to_string(),
            rx,
        })
    }

    /// Returns the name of the network interface used by the sniffer.
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Reads the next packet and parses it if it matches DHCP, mDNS, or SSDP.
    pub fn next_packet(&mut self) -> Result<Option<NetworkEvent>, DhcpError> {
        match self.rx.next() {
            Ok(packet) => Ok(process_ethernet_frame_extended(packet)),
            Err(e) => Err(DhcpError::ParseError(e.to_string())),
        }
    }

    /// Runs the capture loop, invoking a callback for every detected `NetworkEvent`.
    ///
    /// # Arguments
    /// * `callback` - A closure that receives a `NetworkEvent`.
    ///
    /// The loop terminates if the callback returns `false`.
    pub fn run<F>(&mut self, mut callback: F)
    where
        F: FnMut(NetworkEvent) -> bool,
    {
        loop {
            match self.next_packet() {
                Ok(Some(event)) => {
                    if !callback(event) {
                        break;
                    }
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("Error reading packet: {}", e);
                }
            }
        }
    }
}

// ============================================================================
// Device Tracking and CSV Export
// ============================================================================

/// Information about a detected DHCP device
#[cfg(feature = "http-api")]
use serde::{Deserialize, Serialize};

/// Information about a detected DHCP device
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(Serialize, Deserialize))]
pub struct DeviceInfo {
    /// MAC address of the device
    pub mac_address: String,
    /// IPv4 address
    #[cfg_attr(
        feature = "http-api",
        serde(
            serialize_with = "serialize_ip_addr",
            deserialize_with = "deserialize_ip_addr"
        )
    )]
    pub ip_address: IpAddr,
    /// IPv6 address if available
    #[cfg_attr(
        feature = "http-api",
        serde(
            serialize_with = "serialize_opt_ip_addr",
            deserialize_with = "deserialize_opt_ip_addr"
        )
    )]
    pub ipv6_address: Option<IpAddr>,
    /// Hostname if available
    pub hostname: Option<String>,
    /// Detected mDNS services (e.g., "_http._tcp", "_airplay._tcp")
    pub services: Vec<String>,
    /// Vendor hint based on services or MAC OUI (e.g., "Apple", "Google")
    pub vendor: Option<String>,
    /// Device type based on mDNS services (e.g., "Chromecast", "Apple TV", "Printer")
    pub device_type: Option<String>,
    /// First seen timestamp (ISO 8601 format)
    #[cfg_attr(
        feature = "http-api",
        serde(
            serialize_with = "serialize_system_time",
            deserialize_with = "deserialize_system_time"
        )
    )]
    pub first_seen: SystemTime,
    /// Last seen timestamp (ISO 8601 format)
    #[cfg_attr(
        feature = "http-api",
        serde(
            serialize_with = "serialize_system_time",
            deserialize_with = "deserialize_system_time"
        )
    )]
    pub last_seen: SystemTime,
}

impl DeviceInfo {
    /// Creates a new `DeviceInfo` instance with timestamps initialized to now.
    pub fn new(mac_address: String, ip_address: IpAddr, hostname: Option<String>) -> Self {
        let timestamp = SystemTime::now();
        Self {
            mac_address,
            ip_address,
            ipv6_address: None,
            hostname,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: timestamp,
            last_seen: timestamp,
        }
    }

    /// Updates the device information with a new IP address and optional hostname.
    ///
    /// # Returns
    /// `true` if any fields were updated, `false` otherwise.
    pub fn update(&mut self, ip_address: IpAddr, hostname: Option<&str>) -> bool {
        let mut changed = false;
        let timestamp = SystemTime::now();

        if self.ip_address != ip_address {
            self.ip_address = ip_address;
            changed = true;
        }

        let new_hostname = hostname.map(|s| s.to_string());
        if self.hostname != new_hostname && new_hostname.is_some() {
            self.hostname = new_hostname;
            changed = true;
        }

        self.last_seen = timestamp;
        changed
    }

    /// Adds a service to the device's service list if not already present.
    ///
    /// # Returns
    /// `true` if a new service was added, `false` if it was already in the list.
    pub fn add_service(&mut self, service: &str) -> bool {
        let normalized = service
            .to_lowercase()
            .trim_end_matches(".local")
            .to_string();
        match self.services.binary_search(&normalized) {
            Ok(_) => false,
            Err(index) => {
                self.services.insert(index, normalized);
                true
            }
        }
    }

    /// Sets the device vendor if it is not already defined.
    ///
    /// # Returns
    /// `true` if the vendor was set, `false` if a vendor already existed.
    pub fn set_vendor(&mut self, vendor: &str) -> bool {
        if self.vendor.is_none() {
            self.vendor = Some(vendor.to_string());
            true
        } else {
            false
        }
    }

    /// Sets the device type if it is not already defined.
    ///
    /// # Returns
    /// `true` if the device type was set, `false` if it already existed.
    pub fn set_device_type(&mut self, device_type: &str) -> bool {
        if self.device_type.is_none() {
            self.device_type = Some(device_type.to_string());
            true
        } else {
            false
        }
    }

    /// Sets or updates the device's IPv6 address.
    ///
    /// # Returns
    /// `true` if the address was changed or set, `false` if it was already identical.
    pub fn set_ipv6_address(&mut self, ipv6: Ipv6Addr) -> bool {
        let new_ipv6 = Some(IpAddr::V6(ipv6));
        if self.ipv6_address != new_ipv6 {
            self.ipv6_address = new_ipv6;
            true
        } else {
            false
        }
    }

    /// Serializes the device information into a CSV string.
    ///
    /// # Format
    /// `first_seen,last_seen,mac_address,ip_address,"ipv6_address","hostname","device_type","vendor","services"`
    pub fn to_csv_line(&self) -> String {
        let services_str = self.services.join(";");
        format!(
            "{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            format_timestamp(self.first_seen),
            format_timestamp(self.last_seen),
            self.mac_address,
            self.ip_address,
            self.ipv6_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            self.hostname.as_deref().unwrap_or(""),
            self.device_type.as_deref().unwrap_or(""),
            self.vendor.as_deref().unwrap_or(""),
            services_str
        )
    }

    /// Parses a device from a CSV line string.
    ///
    /// # Arguments
    /// * `line` - A string representing a single row from a `lanwatch` CSV file.
    ///
    /// # Returns
    /// `Some(DeviceInfo)` if the line is valid, otherwise `None`.
    pub fn from_csv_line(line: &str) -> Option<Self> {
        // Handle quoted fields properly
        let parts = parse_csv_line(line);
        if parts.len() < 4 {
            return None;
        }

        let first_seen = parse_timestamp(parts[0])?;
        let last_seen = if parts.len() > 1 {
            parse_timestamp(parts[1])?
        } else {
            first_seen
        };
        // Normalize MAC address and migrate legacy DHCPv6 DUID-like identifiers.
        let mac_address = normalize_device_identifier(parts[2]);
        let ip_address = parts[3].parse().ok()?;
        let ipv6_address = if parts.len() > 4 {
            let v6 = parts[4].trim_matches('"');
            if v6.is_empty() {
                None
            } else {
                Some(v6.parse().ok()?)
            }
        } else {
            None
        };
        let hostname = if parts.len() > 5 {
            let h = parts[5].trim_matches('"');
            sanitize_hostname(h)
        } else {
            None
        };
        let device_type = if parts.len() > 6 {
            let t = parts[6].trim_matches('"');
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        } else {
            None
        };
        let vendor = if parts.len() > 7 {
            let v = parts[7].trim_matches('"');
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        } else {
            None
        };
        let services = if parts.len() > 8 {
            let s = parts[8].trim_matches('"');
            if s.is_empty() {
                Vec::new()
            } else {
                s.split(';').map(|s| s.to_string()).collect()
            }
        } else {
            Vec::new()
        };

        Some(Self {
            mac_address,
            ip_address,
            ipv6_address,
            hostname,
            services,
            vendor,
            device_type,
            first_seen,
            last_seen,
        })
    }
}

/// Parse a CSV line handling quoted fields without allocations
fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::with_capacity(9);
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;
    let bytes = line.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if bytes[i] == b',' && !in_quotes {
            let mut field = &line[start..i];
            if field.starts_with('"') && field.ends_with('"') && field.len() >= 2 {
                field = &field[1..field.len() - 1];
            }
            fields.push(field);
            start = i + 1;
        }
        i += 1;
    }
    let mut field = &line[start..i];
    if field.starts_with('"') && field.ends_with('"') && field.len() >= 2 {
        field = &field[1..field.len() - 1];
    }
    fields.push(field);
    fields
}

fn parse_timestamp(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if value.len() != 20 || !value.ends_with('Z') {
        return None;
    }

    let year: i32 = value.get(0..4)?.parse().ok()?;
    let month: i32 = value.get(5..7)?.parse().ok()?;
    let day: i32 = value.get(8..10)?.parse().ok()?;
    let hour: u64 = value.get(11..13)?.parse().ok()?;
    let minute: u64 = value.get(14..16)?.parse().ok()?;
    let second: u64 = value.get(17..19)?.parse().ok()?;

    if value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut days = 0u64;
    let mut current_year = 1970;
    while current_year < year {
        days += if is_leap_year(current_year) {
            366u64
        } else {
            365u64
        };
        current_year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for days_in_month in month_days.iter().take((month - 1) as usize) {
        days += *days_in_month as u64;
    }

    days += (day - 1) as u64;

    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

#[cfg(feature = "http-api")]
fn serialize_system_time<S>(value: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format_timestamp(*value))
}

#[cfg(feature = "http-api")]
fn deserialize_system_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    parse_timestamp(&value).ok_or_else(|| serde::de::Error::custom("invalid timestamp"))
}

#[cfg(feature = "http-api")]
fn serialize_ip_addr<S>(value: &IpAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

#[cfg(feature = "http-api")]
fn deserialize_ip_addr<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

#[cfg(feature = "http-api")]
fn serialize_opt_ip_addr<S>(value: &Option<IpAddr>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(ip) => serializer.serialize_some(&ip.to_string()),
        None => serializer.serialize_none(),
    }
}

#[cfg(feature = "http-api")]
fn deserialize_opt_ip_addr<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
    value
        .map(|ip| ip.parse().map_err(serde::de::Error::custom))
        .transpose()
}

/// Format a SystemTime as ISO 8601 timestamp
fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC timestamp calculation
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Calculate year, month, day from days since epoch (1970-01-01)
    let mut year = 1970i32;
    let mut remaining_days = days as i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i32; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn normalize_device_identifier(raw: &str) -> String {
    let candidate = raw.trim().to_lowercase();
    let mut bytes: Vec<u8> = Vec::new();

    let source = candidate.strip_prefix("duid:").unwrap_or(&candidate);
    for token in source.split(':') {
        if token.len() != 2 {
            return candidate;
        }
        let byte = match u8::from_str_radix(token, 16) {
            Ok(b) => b,
            Err(_) => return candidate,
        };
        bytes.push(byte);
    }

    // DUID-LL (type 3), Ethernet hw type 1: 00:03:00:01:xx:xx:xx:xx:xx:xx
    if bytes.len() == 10 && bytes[0..4] == [0x00, 0x03, 0x00, 0x01] {
        return format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9]
        );
    }

    // DUID-LLT (type 1), Ethernet hw type 1: 00:01:00:01:time(4):mac(6)
    if bytes.len() >= 14 && bytes[0..4] == [0x00, 0x01, 0x00, 0x01] {
        return format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13]
        );
    }

    candidate
}

/// Device tracker that maintains a list of seen devices and saves to CSV
pub struct DeviceTracker {
    devices: HashMap<String, DeviceInfo>,
    csv_path: String,
    auto_save: bool,
    /// OUI registry for MAC address vendor lookup
    oui_registry: Option<OuiRegistry>,
    #[cfg(feature = "mdns")]
    service_registry: Option<MdnsServiceRegistry>,
    /// Track updated MAC addresses for incremental journal flushes
    dirty_devices: Mutex<HashSet<String>>,
}

impl DeviceTracker {
    /// Creates a new device tracker, loading existing data from the specified CSV file.
    ///
    /// # Arguments
    /// * `csv_path` - The path to the file used for persistence.
    pub fn new<P: AsRef<Path>>(csv_path: P) -> std::io::Result<Self> {
        let csv_path = csv_path.as_ref().to_string_lossy().to_string();
        let mut tracker = Self {
            devices: HashMap::new(),
            csv_path,
            auto_save: true,
            oui_registry: None,
            #[cfg(feature = "mdns")]
            service_registry: None,
            dirty_devices: Mutex::new(HashSet::new()),
        };

        // Load existing data if file exists
        tracker.load_from_csv()?;

        Ok(tracker)
    }

    /// Sets the OUI registry used to identify device manufacturers from MAC addresses.
    pub fn set_oui_registry(&mut self, registry: OuiRegistry) {
        self.oui_registry = Some(registry);
    }

    /// Returns a reference to the active OUI registry, if set.
    pub fn oui_registry(&self) -> Option<&OuiRegistry> {
        self.oui_registry.as_ref()
    }

    /// Sets the mDNS service registry used for fingerprinting devices based on their services.
    #[cfg(feature = "mdns")]
    pub fn set_service_registry(&mut self, registry: MdnsServiceRegistry) {
        self.service_registry = Some(registry);
    }

    /// Returns a reference to the active mDNS service registry, if set.
    #[cfg(feature = "mdns")]
    pub fn service_registry(&self) -> Option<&MdnsServiceRegistry> {
        self.service_registry.as_ref()
    }

    /// Load devices from existing CSV file
    fn load_from_csv(&mut self) -> std::io::Result<()> {
        let path = Path::new(&self.csv_path);
        if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                // Skip header (supports both old and new formats)
                if line.starts_with("timestamp,")
                    || line.starts_with("last_seen,")
                    || line.starts_with("first_seen,")
                {
                    continue;
                }
                if let Some(device) = DeviceInfo::from_csv_line(&line) {
                    self.devices.insert(device.mac_address.clone(), device);
                }
            }
        }

        // Also apply any journaled updates (newer updates appended to csv_path + ".journal").
        // Only apply a journal if the main CSV exists (incremental updates),
        // or if the journal is recent (created within `JOURNAL_RECENT_SECS`) to
        // avoid loading stale journals left behind from previous runs during
        // test iterations.
        const JOURNAL_RECENT_SECS: u64 = 10;
        let journal_path = format!("{}.journal", &self.csv_path);
        let jpath = Path::new(&journal_path);
        if jpath.exists() {
            let apply_journal = if path.exists() {
                true
            } else {
                // Check modified time is recent
                if let Ok(meta) = jpath.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                            elapsed.as_secs() <= JOURNAL_RECENT_SECS
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if apply_journal && let Ok(jfile) = File::open(jpath) {
                let jreader = BufReader::new(jfile);
                for l in jreader.lines().map_while(Result::ok) {
                    if let Some(device) = DeviceInfo::from_csv_line(&l) {
                        // Journal entries are newer; overwrite existing map entries
                        self.devices.insert(device.mac_address.clone(), device);
                    }
                }
            }
        }

        Ok(())
    }

    /// Persists all current device information to the CSV file.
    /// Full CSV compaction: rewrite the main CSV file from in-memory state
    pub fn save_to_csv(&self) -> std::io::Result<()> {
        // Write to a temp file and atomically replace to avoid partial writes
        let tmp_path = format!("{}.tmp", &self.csv_path);
        let mut file = File::create(&tmp_path)?;

        // Write header
        writeln!(
            file,
            "first_seen,last_seen,mac_address,ip_address,ipv6_address,hostname,device_type,vendor,services"
        )?;

        // Write devices sorted by last_seen (use unstable sort for speed)
        let mut devices: Vec<_> = self.devices.values().collect();
        devices.sort_unstable_by_key(|device| std::cmp::Reverse(device.last_seen));

        for device in devices {
            writeln!(file, "{}", device.to_csv_line())?;
        }

        // Atomically replace main CSV
        std::fs::rename(tmp_path, &self.csv_path)?;

        // Truncate journal after successful compaction
        let journal_path = format!("{}.journal", &self.csv_path);
        let _ = std::fs::remove_file(journal_path);

        // Clear dirty devices as they are now fully persisted in the main CSV
        self.dirty_devices.lock().unwrap().clear();

        Ok(())
    }

    /// Return the path used for the append-only journal file.
    fn journal_path(&self) -> String {
        format!("{}.journal", &self.csv_path)
    }

    /// Append a single device CSV line to the journal. This avoids rewriting
    /// the entire CSV on each update. Periodically triggers compaction when
    /// journal grows large.
    fn append_device_journal(&self, device: &DeviceInfo) -> std::io::Result<()> {
        use std::fs::OpenOptions;

        let jpath = self.journal_path();
        let mut file = OpenOptions::new().create(true).append(true).open(&jpath)?;
        writeln!(file, "{}", device.to_csv_line())?;

        // Lightweight compaction trigger: when journal exceeds 1MB, perform full rewrite.
        if let Ok(meta) = file.metadata() {
            const COMPACT_SIZE: u64 = 1_000_000;
            if meta.len() > COMPACT_SIZE {
                let _ = self.save_to_csv();
            }
        }

        Ok(())
    }

    /// Append a pre-serialized CSV line to the journal. This helper lets callers
    /// prepare the CSV string while holding mutable borrows to device entries,
    /// then write it after the borrow ends to avoid borrowing `self` twice.
    fn append_journal_line(&self, line: &str) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        let jpath = self.journal_path();
        let mut file = OpenOptions::new().create(true).append(true).open(&jpath)?;
        writeln!(file, "{}", line)?;
        // Optionally check compact size
        if let Ok(meta) = file.metadata() {
            const COMPACT_SIZE: u64 = 1_000_000;
            if meta.len() > COMPACT_SIZE {
                let _ = self.save_to_csv();
            }
        }
        Ok(())
    }

    /// Enable or disable automatic CSV writes on each update.
    /// Disabled mode is intended for external batched flush pipelines.
    pub fn set_auto_save(&mut self, enabled: bool) {
        self.auto_save = enabled;
    }

    /// Explicitly flushes the current in-memory device state to the CSV file.
    /// If the main CSV exists, it appends updated devices incrementally to the journal
    /// to avoid rewriting the entire file, triggering compaction when the journal exceeds 1MB.
    pub fn flush_to_csv(&self) -> std::io::Result<()> {
        let dirty = {
            let mut guard = self.dirty_devices.lock().unwrap();
            if guard.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *guard)
        };

        let path = Path::new(&self.csv_path);
        if !path.exists() {
            // If the main CSV doesn't exist, do a full save
            self.save_to_csv()?;
        } else {
            // Append dirty devices to the journal
            for mac in &dirty {
                if let Some(device) = self.devices.get(mac) {
                    self.append_device_journal(device)?;
                }
            }
        }
        Ok(())
    }

    /// Updates the tracker state with information extracted from a DHCPv4 packet.
    ///
    /// # Returns
    /// `true` if a new device was detected or an existing device was significantly updated
    /// (IP change, hostname change, etc.).
    pub fn update_from_dhcpv4(&mut self, packet: &Dhcpv4Packet) -> bool {
        let mac = packet.client_mac_string();

        // Determine client IP address.
        // Prefer DHCP client/assigned fields parsed into requested_ip; avoid treating
        // server source IP (port 67) as client identity.
        let ip = packet.requested_ip.map(IpAddr::V4).unwrap_or_else(|| {
            if packet.source_port == DHCPV4_CLIENT_PORT
                && packet.source_ip != Ipv4Addr::new(0, 0, 0, 0)
            {
                IpAddr::V4(packet.source_ip)
            } else if packet.dest_port == DHCPV4_CLIENT_PORT
                && packet.dest_ip != Ipv4Addr::new(0, 0, 0, 0)
                && packet.dest_ip != Ipv4Addr::new(255, 255, 255, 255)
            {
                IpAddr::V4(packet.dest_ip)
            } else {
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
            }
        });

        let mut changed = self.update_device(&mac, ip, packet.hostname.as_deref());

        // Apply Option 55 and Option 60 fingerprints if present
        let csv_line =
            if packet.parameter_request_list.is_some() || packet.vendor_class_id.is_some() {
                if let Some(device) = self.devices.get_mut(&mac) {
                    let mut opt_vendor = None;
                    let mut opt_type = None;

                    if let Some(ref vc) = packet.vendor_class_id {
                        let (v, t) = Self::detect_device_details_from_dhcp_vendor_class(vc);
                        opt_vendor = v;
                        opt_type = t;
                    }

                    if (opt_vendor.is_none() || opt_type.is_none())
                        && let Some(ref prl) = packet.parameter_request_list
                    {
                        let (v, t) = Self::detect_device_details_from_dhcp_options(prl);
                        if opt_vendor.is_none() {
                            opt_vendor = v;
                        }
                        if opt_type.is_none() {
                            opt_type = t;
                        }
                    }

                    let mut local_changed = false;
                    if let Some(v) = opt_vendor
                        && (device.vendor.is_none()
                            || (device.vendor.as_deref() != Some(v)
                                && device
                                    .vendor
                                    .as_deref()
                                    .map(|ov| ov.to_lowercase())
                                    .as_deref()
                                    == Some("eero inc.")))
                    {
                        device.vendor = Some(v.to_string());
                        local_changed = true;
                    }
                    if let Some(t) = opt_type
                        && device.device_type.is_none()
                    {
                        device.device_type = Some(t.to_string());
                        local_changed = true;
                    }
                    if local_changed {
                        self.dirty_devices.lock().unwrap().insert(mac.clone());
                        changed = true;
                        if self.auto_save {
                            Some(device.to_csv_line())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

        if let Some(line) = csv_line {
            let _ = self.append_journal_line(&line);
        }

        changed
    }

    /// Updates the tracker state with information extracted from a DHCPv6 packet.
    ///
    /// # Returns
    /// `true` if a new device was detected or an existing device was updated.
    pub fn update_from_dhcpv6(&mut self, packet: &Dhcpv6Packet) -> bool {
        // For DHCPv6, use Ethernet MAC from DUID-LL/LLT when available.
        // Fall back to a prefixed DUID identifier for non-Ethernet DUID types.
        let mut client_id = None;
        let mut fqdn = None;

        for option in &packet.options {
            match option {
                Dhcpv6Option::ClientId(data) => {
                    client_id = Some(data.as_slice());
                }
                Dhcpv6Option::ClientFqdn(name) => {
                    fqdn = Some(name.as_str());
                }
                _ => {}
            }
        }

        // If no client-id, we can't track this device
        let mac = match client_id {
            Some(data) => {
                extract_mac_from_duid(data).unwrap_or_else(|| format_duid_identifier(data))
            }
            None => return false,
        };

        let ip = IpAddr::V6(packet.source_ip);
        self.update_device(&mac, ip, fqdn)
    }

    /// Updates the tracker state with hostnames, IP addresses, and services from an mDNS packet.
    ///
    /// # Returns
    /// The count of unique updates applied across all detected devices.
    #[cfg(feature = "mdns")]
    pub fn update_from_mdns(&mut self, packet: &MdnsPacket) -> usize {
        let packet = packet.view();

        let mut updated = 0;
        let mac = &packet.source_mac;
        let oui_vendor = self
            .oui_registry
            .as_ref()
            .and_then(|registry| registry.lookup(mac))
            .map(str::to_string);

        // Track the first hostname and addresses seen (defer String allocation)
        let mut first_hostname: Option<&str> = None;
        let mut first_ipv4: Option<std::net::Ipv4Addr> = None;
        let mut first_ipv6: Option<std::net::Ipv6Addr> = None;
        // Collect services advertised by this device
        let mut services: Vec<&str> = Vec::new();
        let mut seen_services: HashSet<&str> = HashSet::new();

        for record in packet.all_records() {
            match &record.data {
                MdnsRecordDataView::A(addr) => {
                    // Strip .local suffix for hostname and record first IPv4
                    let hostname = record.name.trim_end_matches(".local");
                    if first_hostname.is_none() {
                        first_hostname = Some(hostname);
                    }
                    if first_ipv4.is_none() {
                        first_ipv4 = Some(*addr);
                    }
                }
                MdnsRecordDataView::Aaaa(addr) => {
                    let hostname = record.name.trim_end_matches(".local");
                    if first_hostname.is_none() {
                        first_hostname = Some(hostname);
                    }
                    if first_ipv6.is_none() {
                        first_ipv6 = Some(*addr);
                    }
                }
                MdnsRecordDataView::Ptr(_target) => {
                    // PTR records indicate service advertisements
                    // record.name is the service type (e.g., "_http._tcp.local")
                    // _target is the instance name (not needed for service tracking)
                    let service_type = record.name.trim_end_matches(".local");
                    if service_type.starts_with('_') && seen_services.insert(service_type) {
                        services.push(service_type);
                    }
                }
                MdnsRecordDataView::Srv { .. } => {
                    // SRV records also indicate services
                    // Extract service type from the record name (e.g., "My Device._http._tcp.local")
                    if let Some(service_start) = record.name.find("._") {
                        let service_type =
                            record.name[service_start + 1..].trim_end_matches(".local");
                        if seen_services.insert(service_type) {
                            services.push(service_type);
                        }
                    }
                }
                _ => {}
            }
        }

        // Also check questions for service browsing (queries indicate device capabilities)
        for question in &packet.questions {
            let service_type = question.name.trim_end_matches(".local");
            if service_type.starts_with('_') && seen_services.insert(service_type) {
                services.push(service_type);
            }
        }

        // Determine vendor and device type from services and hostname (before borrowing device)
        let vendor = Self::detect_vendor_from_hostname(first_hostname)
            .map(str::to_string)
            .or_else(|| self.detect_vendor_from_services(&services));
        let device_type = Self::detect_device_type_from_hostname(first_hostname)
            .map(str::to_string)
            .or_else(|| self.detect_device_type_from_services(&services));

        let ipv6_addr = first_ipv6;

        // Get or create device entry and perform updates within a short scope
        let csv_line = {
            let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
                let ip = first_ipv4.map(IpAddr::V4).unwrap_or(packet.source_ip);
                updated += 1;
                DeviceInfo::new(mac.to_string(), ip, None)
            });

            // Update hostname from the first seen A/AAAA
            if device.hostname.is_none()
                && let Some(h) = first_hostname
            {
                device.hostname = Some(h.to_string());
                updated += 1;
            }

            // Update IPv4 if we have a better one
            if let Some(ipv4) = first_ipv4
                && matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified())
            {
                device.ip_address = IpAddr::V4(ipv4);
                updated += 1;
            }

            // Set IPv6 address if available
            if let Some(ipv6) = ipv6_addr
                && device.set_ipv6_address(ipv6)
            {
                updated += 1;
            }

            // Add services
            for service in &services {
                if device.add_service(service) {
                    updated += 1;
                }
            }

            // Set vendor if detected (or fall back to OUI vendor)
            let vendor_to_apply = vendor.or_else(|| oui_vendor.clone());
            if let Some(v) = vendor_to_apply
                && Self::should_replace_vendor(device.vendor.as_deref(), &v, oui_vendor.as_deref())
            {
                if device.vendor.as_deref() != Some(&v) {
                    device.vendor = Some(v.clone());
                }
                updated += 1;
            }

            // Set device type if detected
            if let Some(t) = device_type
                && Self::should_replace_device_type(device.device_type.as_deref(), &t)
            {
                if device.device_type.as_deref() != Some(&t) {
                    device.device_type = Some(t.clone());
                }
                updated += 1;
            }

            // Update timestamp
            device.last_seen = SystemTime::now();

            if updated > 0 && self.auto_save {
                Some(device.to_csv_line())
            } else {
                None
            }
        };

        if let Some(line) = csv_line {
            let _ = self.append_journal_line(&line);
        }

        self.dirty_devices.lock().unwrap().insert(mac.to_string());

        updated
    }

    /// Updates the tracker state with information extracted from an LLMNR packet.
    ///
    /// # Returns
    /// Number of updated/added devices.
    #[cfg(feature = "mdns")]
    pub fn update_from_llmnr(&mut self, packet: &MdnsPacket) -> usize {
        self.update_from_mdns(packet)
    }

    /// Detect vendor and device type from DHCP Option 60 (Vendor Class Identifier)
    fn detect_device_details_from_dhcp_vendor_class(
        vendor_class: &str,
    ) -> (Option<&'static str>, Option<&'static str>) {
        if vendor_class.is_empty() {
            return (None, None);
        }

        let vc = vendor_class.to_lowercase();
        if vc.contains("msft 5.0") || vc.contains("msft 98") || vc.starts_with("msft") {
            return (Some("Microsoft"), Some("PC/Windows"));
        }
        if vc.contains("android-dhcp") {
            return (Some("Google"), Some("Android Phone"));
        }
        if vc.contains("dhcpcd") {
            return (Some("Linux"), Some("IoT Device"));
        }
        if vc.contains("hp jetdirect") || vc.contains("hewlett-packard jetdirect") {
            return (Some("HP"), Some("Printer"));
        }
        if vc.contains("roku") {
            return (Some("Roku"), Some("Media Player"));
        }
        if vc.contains("sonos") {
            return (Some("Sonos"), Some("Smart Speaker"));
        }
        if vc.contains("appletv") || vc.contains("apple tv") {
            return (Some("Apple"), Some("Apple TV"));
        }
        if vc.contains("idevice")
            || vc.contains("iphone")
            || vc.contains("ipad")
            || vc.contains("macintosh")
        {
            return (Some("Apple"), Some("Apple Device"));
        }

        (None, None)
    }

    /// Detect vendor and device type from DHCP Option 55 (Parameter Request List)
    fn detect_device_details_from_dhcp_options(
        prl: &[u8],
    ) -> (Option<&'static str>, Option<&'static str>) {
        if prl.is_empty() {
            return (None, None);
        }

        let has_26 = prl.contains(&26);
        let has_28 = prl.contains(&28);
        let has_95 = prl.contains(&95);
        let has_249 = prl.contains(&249);

        // Windows Signature: contains 249 (MS Classless Route)
        if has_249 {
            return (Some("Microsoft"), Some("PC/Windows"));
        }

        // Apple (iOS/macOS) Signature: contains 95 (LDAP) and lacks 26/28
        if has_95 && !has_26 && !has_28 {
            return (Some("Apple"), Some("Apple Device"));
        }

        // Android / Linux Signature: contains 26 (Interface MTU) and 28 (Broadcast Address)
        if has_26 && has_28 {
            return (Some("Google"), Some("Android Phone"));
        }

        (None, None)
    }

    /// Detect vendor from hostname patterns
    fn detect_vendor_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
        let hostname = hostname?.to_lowercase();

        if hostname.contains("roborock") {
            return Some("Roborock");
        }

        if hostname.contains("rachio") {
            return Some("Rachio");
        }

        if hostname.contains("lenovo")
            || hostname.contains("legion")
            || hostname.contains("thinkpad")
            || hostname.contains("ideapad")
            || hostname.contains("yoga")
        {
            return Some("Lenovo");
        }

        // Google/Nest devices often use WICED platform
        if hostname.starts_with("wiced-hap") || hostname.contains("nest") {
            return Some("Google");
        }

        // Google Pixel phones
        if hostname.contains("pixel") {
            return Some("Google");
        }

        // Apple devices
        if hostname.contains("iphone")
            || hostname.contains("ipad")
            || hostname.contains("macbook")
            || hostname.contains("imac")
            || hostname.contains("mac-mini")
            || hostname.contains("apple")
        {
            return Some("Apple");
        }

        // Samsung devices
        if hostname.contains("samsung") || hostname.contains("galaxy") {
            return Some("Samsung");
        }

        // Motorola devices
        if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola")
        {
            return Some("Motorola");
        }

        // Android devices
        if hostname.starts_with("android") || hostname.starts_with("android_") {
            return Some("Google");
        }

        // HP printers (NPI prefix)
        if hostname.starts_with("npi") {
            return Some("HP");
        }

        None
    }

    /// Detect device type from hostname patterns
    fn detect_device_type_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
        let hostname = hostname?.to_lowercase();

        if hostname.contains("roborock") {
            return Some("Smart Cleaning Device");
        }

        if hostname.contains("rachio") {
            return Some("Smart Watering Device");
        }

        if hostname.contains("lenovo")
            || hostname.contains("legion")
            || hostname.contains("thinkpad")
            || hostname.contains("ideapad")
            || hostname.contains("yoga")
        {
            return Some("Laptop");
        }

        // Google Pixel phones - check before other patterns
        if hostname.contains("pixel") {
            return Some("Pixel Phone");
        }

        // Google/Nest thermostats use WICED-hap prefix
        if hostname.starts_with("wiced-hap") {
            return Some("Thermostat");
        }

        // Nest devices
        if hostname.contains("nest") {
            if hostname.contains("thermostat") {
                return Some("Thermostat");
            }
            if hostname.contains("cam") || hostname.contains("doorbell") {
                return Some("Security Camera");
            }
            return Some("Smart Home Device");
        }

        // iPhones/iPads
        if hostname.contains("iphone") {
            return Some("Apple iPhone");
        }
        if hostname.contains("ipad") {
            return Some("Apple iPad");
        }

        // Macs
        if hostname.contains("macbook")
            || hostname.contains("imac")
            || hostname.contains("mac-mini")
            || hostname.contains("mac-pro")
        {
            return Some("Mac");
        }

        // HP printers (NPI prefix = Network Peripheral Interface)
        if hostname.starts_with("npi") {
            return Some("Printer");
        }

        // Motorola devices
        if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola")
        {
            return Some("Android Phone");
        }

        // Android phones
        if hostname.starts_with("android") || hostname.starts_with("android_") {
            return Some("Android Phone");
        }

        None
    }

    /// Detect vendor from a list of services
    #[cfg(feature = "mdns")]
    fn detect_vendor_from_services(&self, services: &[&str]) -> Option<String> {
        // Check for specific device-type services first to avoid misidentification
        // (e.g., a printer that supports AirPrint shouldn't be labeled as Apple)
        let mut has_printer_services = false;
        let mut has_scanner_services = false;

        for service in services {
            let s = service.to_lowercase();
            if s.contains("_printer")
                || s.contains("_ipp")
                || s.contains("_pdl-datastream")
                || s.contains("_print-caps")
            {
                has_printer_services = true;
            }
            if s.contains("_scanner") || s.contains("_uscan") {
                has_scanner_services = true;
            }
        }

        // If it's a printer/scanner, don't assume vendor from generic protocols
        // (Printers often support AirPrint which uses Apple protocols but doesn't mean vendor is Apple)
        let is_peripheral = has_printer_services || has_scanner_services;

        // First try the registry if available (but skip for peripherals with Apple protocols)
        if let Some(registry) = &self.service_registry {
            for service in services {
                if let Some(vendor) = registry.get_vendor(service) {
                    // Skip Apple vendor assignment for printers/scanners (they support AirPrint but aren't Apple devices)
                    if is_peripheral && vendor.eq_ignore_ascii_case("apple") {
                        continue;
                    }
                    return Some(vendor.to_string());
                }
            }
        }

        // Fallback to built-in detection
        for service in services {
            let s = service.to_lowercase();
            // Google services (specific enough to identify vendor)
            if s.contains("googlecast") || s.contains("googlezone") || s.contains("androidtvremote")
            {
                return Some("Google".to_string());
            }
            // Amazon services
            if s.contains("amzn-wplay") {
                return Some("Amazon".to_string());
            }
            // Spotify
            if s.contains("spotify") {
                return Some("Spotify".to_string());
            }
            // NVIDIA
            if s.contains("nvstream") {
                return Some("NVIDIA".to_string());
            }
            // Apple services - only for non-peripheral devices
            if !is_peripheral
                && (s.contains("airplay")
                    || s.contains("airdrop")
                    || s.contains("homekit")
                    || s.contains("raop")
                    || s.contains("airport")
                    || s.contains("daap")
                    || s.contains("dpap")
                    || s.contains("afpovertcp")
                    || s.contains("apple")
                    || s.contains("companion-link")
                    || s.contains("touch-able")
                    || s.contains("mediaremotetv")
                    || s.contains("hap._tcp")
                    || s.contains("appletv"))
            {
                return Some("Apple".to_string());
            }
        }
        None
    }

    fn should_replace_vendor(
        current: Option<&str>,
        incoming: &str,
        oui_vendor: Option<&str>,
    ) -> bool {
        match current {
            None => true,
            Some(existing) if existing.eq_ignore_ascii_case(incoming) => false,
            Some(existing) => oui_vendor
                .map(|oui| existing.eq_ignore_ascii_case(oui))
                .unwrap_or(false),
        }
    }

    fn should_replace_device_type(current: Option<&str>, incoming: &str) -> bool {
        match current {
            None => true,
            Some(existing) if existing.eq_ignore_ascii_case(incoming) => false,
            Some(existing) => {
                let existing = existing.to_ascii_lowercase();
                let incoming = incoming.to_ascii_lowercase();
                matches!(
                    incoming.as_str(),
                    "smart watering device"
                        | "smart cleaning device"
                        | "laptop"
                        | "android phone"
                        | "pixel phone"
                        | "apple iphone"
                ) && matches!(
                    existing.as_str(),
                    "security camera" | "router" | "smart home device" | "unknown" | "chromecast"
                )
            }
        }
    }

    /// Detect device type from a list of services
    #[cfg(feature = "mdns")]
    fn detect_device_type_from_services(&self, services: &[&str]) -> Option<String> {
        // Priority-based detection: check for specific device types first
        // before falling back to registry lookup (which may give generic results)

        for service in services {
            let s = service.to_lowercase();
            // Chromecast devices (high priority)
            if s.contains("googlecast") || s.contains("googlezone") {
                return Some("Chromecast".to_string());
            }
            // Apple TV (high priority)
            if s.contains("appletv") || s.contains("mediaremotetv") {
                return Some("Apple TV".to_string());
            }
            // Apple iPhone/iPad (check before AirPlay - iPhones also support AirPlay)
            if s.contains("_remotepairing") || s.contains("_atc") || s.contains("_rdlink") {
                return Some("Apple iPhone".to_string());
            }
            // AirPlay devices
            if s.contains("airplay") || s.contains("raop") {
                return Some("AirPlay Device".to_string());
            }
            // Fire TV / Amazon devices
            if s.contains("amzn-wplay") {
                return Some("Fire TV".to_string());
            }
            // Printers - check BEFORE generic server detection
            if s.contains("_printer")
                || s.contains("_ipp")
                || s.contains("_pdl-datastream")
                || s.contains("_print-caps")
            {
                return Some("Printer".to_string());
            }
            // Scanners
            if s.contains("_scanner") || s.contains("_uscan") {
                return Some("Scanner".to_string());
            }
        }

        // Now try the registry for less specific lookups
        if let Some(registry) = &self.service_registry {
            for service in services {
                if let Some(device_type) = registry.get_device_type(service) {
                    return Some(device_type.to_string());
                }
            }
        }

        // Fallback to remaining built-in detection
        for service in services {
            let s = service.to_lowercase();
            // NAS devices
            if s.contains("_smb") || s.contains("_afpovertcp") || s.contains("_nfs") {
                return Some("NAS".to_string());
            }
            // Smart speakers
            if s.contains("_homekit") || s.contains("_hap") {
                return Some("Smart Home Device".to_string());
            }
            // Android TV
            if s.contains("androidtvremote") {
                return Some("Android TV".to_string());
            }
            // NVIDIA Shield
            if s.contains("nvstream") {
                return Some("NVIDIA Shield".to_string());
            }
            // Spotify Connect
            if s.contains("spotify") {
                return Some("Spotify Connect Device".to_string());
            }
        }
        None
    }

    /// Updates the tracker state with information from an SSDP/UPnP advertisement or response.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_ssdp(&mut self, packet: &SsdpPacket) -> usize {
        let packet = packet.view();

        let mut updated = 0;
        let mac = &packet.source_mac;
        let services = packet.service_terms();
        let oui_vendor = self
            .oui_registry
            .as_ref()
            .and_then(|registry| registry.lookup(mac))
            .map(str::to_string);

        let vendor = packet.detect_vendor_from_view();
        let device_type = packet.detect_device_type_from_view();

        let source_ipv4 = match packet.source_ip {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        };
        let source_ipv6 = match packet.source_ip {
            std::net::IpAddr::V6(ip) => Some(ip),
            _ => None,
        };

        let csv_line = {
            let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
                updated += 1;
                let initial_ip = source_ipv4.map(IpAddr::V4).unwrap_or_else(|| {
                    source_ipv6
                        .map(IpAddr::V6)
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                });
                DeviceInfo::new(mac.to_string(), initial_ip, None)
            });

            if let Some(ipv4) = source_ipv4
                && matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified())
            {
                device.ip_address = IpAddr::V4(ipv4);
                updated += 1;
            }

            if let Some(ipv6) = source_ipv6
                && device.set_ipv6_address(ipv6)
            {
                updated += 1;
            }

            for service in &services {
                if device.add_service(service) {
                    updated += 1;
                }
            }

            // Set vendor if detected (or fall back to OUI vendor)
            let vendor_to_apply = vendor.or_else(|| oui_vendor.clone());
            if let Some(v) = vendor_to_apply
                && Self::should_replace_vendor(device.vendor.as_deref(), &v, oui_vendor.as_deref())
            {
                if device.vendor.as_deref() != Some(&v) {
                    device.vendor = Some(v.clone());
                }
                updated += 1;
            }

            if let Some(t) = device_type
                && Self::should_replace_device_type(device.device_type.as_deref(), &t)
            {
                if device.device_type.as_deref() != Some(&t) {
                    device.device_type = Some(t.clone());
                }
                updated += 1;
            }

            device.last_seen = SystemTime::now();

            if updated > 0 && self.auto_save {
                Some(device.to_csv_line())
            } else {
                None
            }
        };

        if let Some(line) = csv_line {
            let _ = self.append_journal_line(&line);
        }

        self.dirty_devices.lock().unwrap().insert(mac.to_string());

        updated
    }

    /// Detect device type from vendor name
    fn detect_device_type_from_vendor(vendor: &str) -> Option<&'static str> {
        let v = vendor.to_lowercase();

        if v.contains("lenovo") {
            return Some("Laptop");
        }

        if v.contains("eero") {
            return Some("Router");
        }

        // Security systems
        if v.contains("simplisafe") {
            return Some("Security System");
        }
        if v.contains("ring") && !v.contains("engineering") {
            return Some("Security Camera");
        }
        if v.contains("arlo") {
            return Some("Security Camera");
        }
        if v.contains("nest") {
            return Some("Smart Home Device");
        }
        if v.contains("alarm") || v.contains("security") {
            return Some("Security System");
        }

        // Smart home devices
        if v.contains("tuya") || v.contains("smartlife") {
            return Some("Smart Home Device");
        }
        if v.contains("philips hue") || v.contains("signify") {
            return Some("Smart Light");
        }
        if v.contains("sonos") {
            return Some("Speaker");
        }
        if v.contains("ecobee") || v.contains("honeywell") {
            return Some("Thermostat");
        }

        // Networking equipment
        if v.contains("ubiquiti")
            || v.contains("netgear")
            || v.contains("tp-link")
            || v.contains("linksys")
        {
            return Some("Network Equipment");
        }
        if v.contains("cisco") {
            return Some("Network Equipment");
        }

        // Gaming consoles
        if v.contains("nintendo") {
            return Some("Gaming Console");
        }
        if v.contains("sony") && (v.contains("playstation") || v.contains("entertainment")) {
            return Some("Gaming Console");
        }
        if v.contains("microsoft") && v.contains("xbox") {
            return Some("Gaming Console");
        }

        // IoT / Microcontrollers
        if v.contains("espressif") {
            return Some("IoT Device");
        }
        if v.contains("raspberry") {
            return Some("Raspberry Pi");
        }
        if v.contains("arduino") {
            return Some("Microcontroller");
        }

        // Printers
        if v.contains("hp") && v.contains("print") {
            return Some("Printer");
        }
        if v.contains("canon")
            || v.contains("epson")
            || v.contains("brother")
            || v.contains("lexmark")
        {
            return Some("Printer");
        }

        // Storage
        if v.contains("synology") || v.contains("qnap") || v.contains("western digital") {
            return Some("NAS");
        }

        None
    }

    /// Update or add a device
    /// # Note
    /// This method assumes `mac` is already normalized to lowercase (which all ingestion paths ensure).
    pub fn update_device(&mut self, mac: &str, ip: IpAddr, hostname: Option<&str>) -> bool {
        let hostname = hostname.and_then(sanitize_hostname);
        let hostname_vendor = Self::detect_vendor_from_hostname(hostname.as_deref());
        let device_type_from_hostname = Self::detect_device_type_from_hostname(hostname.as_deref());

        // We'll defer any journal append until after mutable borrows are dropped
        let mut append_needed = false;
        let result = if let Some(device) = self.devices.get_mut(mac) {
            let changed = device.update(ip, hostname.as_deref());

            // Defer OUI vendor lookup unless we have an incoming hostname vendor that differs,
            // or if the existing device vendor is None and we want to populate it.
            let mut vendor_to_apply = hostname_vendor;
            let mut oui_vendor = None;

            if vendor_to_apply.is_none() && device.vendor.is_none() {
                oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
                vendor_to_apply = oui_vendor;
            }

            if let Some(v) = vendor_to_apply {
                if device.vendor.is_some()
                    && device.vendor.as_deref() != Some(v)
                    && oui_vendor.is_none()
                {
                    oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
                }

                if Self::should_replace_vendor(device.vendor.as_deref(), v, oui_vendor) {
                    device.vendor = Some(v.to_string());
                }
            }

            if let Some(dt) = device_type_from_hostname
                && Self::should_replace_device_type(device.device_type.as_deref(), dt)
            {
                device.device_type = Some(dt.to_string());
            }

            // Set device type from vendor if not already set or replacement is allowed
            if let Some(v) = device.vendor.as_deref()
                && let Some(dt) = Self::detect_device_type_from_vendor(v)
                && Self::should_replace_device_type(device.device_type.as_deref(), dt)
            {
                device.device_type = Some(dt.to_string());
            }

            if self.auto_save {
                append_needed = true;
            }
            changed
        } else {
            // New device
            let vendor = hostname_vendor.map(str::to_string).or_else(|| {
                self.oui_registry
                    .as_ref()
                    .and_then(|r| r.lookup(mac))
                    .map(str::to_string)
            });

            let mut device = DeviceInfo::new(mac.to_string(), ip, hostname);
            if let Some(ref v) = vendor {
                device.vendor = Some(v.clone());
            }
            if let Some(dt) = device_type_from_hostname {
                device.device_type = Some(dt.to_string());
            }
            if let Some(ref v) = vendor
                && let Some(dt) = Self::detect_device_type_from_vendor(v)
            {
                device.device_type = Some(dt.to_string());
            }
            // Insert device first so subsequent persistence sees it.
            self.devices.insert(mac.to_string(), device);
            if self.auto_save {
                // If the main CSV doesn't exist yet, perform an initial full save
                // so callers that only remove the CSV (but not a journal) get a
                // consistent persisted file. Otherwise append to the journal.
                let path = Path::new(&self.csv_path);
                if path.exists() {
                    if let Some(d) = self.devices.get(mac) {
                        let _ = self.append_device_journal(d);
                    }
                } else {
                    let _ = self.save_to_csv();
                }
            }
            true
        };

        if append_needed && let Some(d) = self.devices.get(mac) {
            let _ = self.append_device_journal(d);
        }

        self.dirty_devices.lock().unwrap().insert(mac.to_string());

        result
    }

    /// Returns a reference to the internal map of all tracked devices.
    pub fn devices(&self) -> &HashMap<String, DeviceInfo> {
        &self.devices
    }

    /// Returns the total number of devices currently being tracked.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Returns a reference to a device by its MAC address.
    /// Handles normalization of the provided MAC string.
    pub fn get_device(&self, mac: &str) -> Option<&DeviceInfo> {
        // Try direct lookup with lowercase first
        if let Some(device) = self.devices.get(&mac.to_lowercase()) {
            return Some(device);
        }
        // Fallback to normalized identifier check
        self.devices.get(&normalize_device_identifier(mac))
    }

    /// Returns the path to the CSV file used for persistence.
    pub fn csv_path(&self) -> &str {
        &self.csv_path
    }

    /// Returns a JSON-formatted string of all tracked devices.
    #[cfg(feature = "http-api")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let devices: Vec<&DeviceInfo> = self.devices.values().collect();
        serde_json::to_string_pretty(&devices)
    }

    /// Returns a JSON string of all devices, sorted by the `last_seen` timestamp.
    #[cfg(feature = "http-api")]
    pub fn to_json_sorted(&self) -> Result<String, serde_json::Error> {
        let mut devices: Vec<&DeviceInfo> = self.devices.values().collect();
        devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));
        serde_json::to_string_pretty(&devices)
    }
}

// ============================================================================
// HTTP API Server
// ============================================================================

#[cfg(feature = "http-api")]
use std::sync::{Arc, RwLock};
#[cfg(feature = "http-api")]
use std::thread;
#[cfg(feature = "http-api")]
use tiny_http::{Response, Server};

/// HTTP API server for exposing device data
#[cfg(feature = "http-api")]
pub struct ApiServer {
    server: Server,
    tracker: Arc<RwLock<DeviceTracker>>,
}

/// API response structure
#[cfg(feature = "http-api")]
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    count: usize,
    data: T,
}

/// Error response structure
#[cfg(feature = "http-api")]
#[derive(Serialize)]
struct ApiError {
    success: bool,
    error: String,
}

#[cfg(feature = "http-api")]
impl ApiServer {
    /// Creates a new HTTP API server instance.
    ///
    /// # Arguments
    /// * `addr` - The socket address to listen on (e.g., "127.0.0.1:8080").
    /// * `tracker` - An `Arc<RwLock<DeviceTracker>>` for safe sharing of device data.
    pub fn new(addr: &str, tracker: Arc<RwLock<DeviceTracker>>) -> std::io::Result<Self> {
        let server = Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self { server, tracker })
    }

    /// Starts the API server request handling loop (blocks the current thread).
    pub fn run(&self) {
        println!(
            "API server listening on http://{}",
            self.server.server_addr()
        );
        println!("Endpoints:");
        println!("  GET /devices     - List all devices (JSON)");
        println!("  GET /devices/count - Get device count");
        println!("  GET /health      - Health check");
        println!();

        for request in self.server.incoming_requests() {
            let response = self.handle_request(&request);
            let _ = request.respond(response);
        }
    }

    /// Handle incoming HTTP requests
    fn handle_request(&self, request: &tiny_http::Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let path = request.url();
        let method = request.method();

        match (method.as_str(), path) {
            ("GET", "/devices") => self.handle_devices(),
            ("GET", "/devices/count") => self.handle_device_count(),
            ("GET", "/health") => self.handle_health(),
            ("GET", "/") => self.handle_root(),
            ("GET", p) if p.starts_with("/devices/") => {
                let mac = &p[9..];
                self.handle_device_by_mac(mac)
            }
            _ => self.handle_not_found(),
        }
    }

    fn handle_devices(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                let mut devices: Vec<&DeviceInfo> = tracker.devices().values().collect();
                devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));

                let response = ApiResponse {
                    success: true,
                    count: devices.len(),
                    data: devices,
                };

                let json = serde_json::to_string(&response).unwrap_or_default();
                Response::from_string(json).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Err(_) => self.handle_error("Failed to read device data"),
        }
    }

    fn handle_device_by_mac(&self, mac: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                if let Some(device) = tracker.get_device(mac) {
                    let response = ApiResponse {
                        success: true,
                        count: 1,
                        data: device,
                    };

                    let json = serde_json::to_string(&response).unwrap_or_default();
                    Response::from_string(json).with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    )
                } else {
                    self.handle_not_found()
                }
            }
            Err(_) => self.handle_error("Failed to read device data"),
        }
    }

    fn handle_device_count(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                let json = serde_json::json!({
                    "success": true,
                    "count": tracker.device_count()
                });
                Response::from_string(json.to_string()).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Err(_) => self.handle_error("Failed to read device count"),
        }
    }

    fn handle_health(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "status": "ok",
            "service": "lanwatch"
        });
        Response::from_string(json.to_string())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_root(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "service": "lanwatch",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": {
                "/devices": "GET - List all detected devices",
                "/devices/{mac}": "GET - Get a specific device by MAC address",
                "/devices/count": "GET - Get device count",
                "/health": "GET - Health check"
            }
        });
        Response::from_string(serde_json::to_string(&json).unwrap_or_default())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_not_found(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let error = ApiError {
            success: false,
            error: "Not found".to_string(),
        };
        Response::from_string(serde_json::to_string(&error).unwrap_or_default())
            .with_status_code(404)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_error(&self, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let error = ApiError {
            success: false,
            error: message.to_string(),
        };
        Response::from_string(serde_json::to_string(&error).unwrap_or_default())
            .with_status_code(500)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }
}

/// Starts the HTTP API server in a dedicated background thread.
///
/// # Arguments
/// * `addr` - The address to bind to.
/// * `tracker` - The shared device tracker.
#[cfg(feature = "http-api")]
pub fn start_api_server(
    addr: &str,
    tracker: Arc<RwLock<DeviceTracker>>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let server = ApiServer::new(addr, tracker)?;
    Ok(thread::spawn(move || {
        server.run();
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcpv4_message_type_from_u8() {
        assert_eq!(Dhcpv4MessageType::from(1), Dhcpv4MessageType::Discover);
        assert_eq!(Dhcpv4MessageType::from(2), Dhcpv4MessageType::Offer);
        assert_eq!(Dhcpv4MessageType::from(3), Dhcpv4MessageType::Request);
        assert_eq!(Dhcpv4MessageType::from(5), Dhcpv4MessageType::Ack);
        assert_eq!(Dhcpv4MessageType::from(6), Dhcpv4MessageType::Nak);
        assert_eq!(Dhcpv4MessageType::from(7), Dhcpv4MessageType::Release);
        assert_eq!(Dhcpv4MessageType::from(99), Dhcpv4MessageType::Unknown(99));
    }

    #[test]
    fn test_dhcpv4_message_type_display() {
        assert_eq!(format!("{}", Dhcpv4MessageType::Discover), "DISCOVER");
        assert_eq!(format!("{}", Dhcpv4MessageType::Offer), "OFFER");
        assert_eq!(format!("{}", Dhcpv4MessageType::Unknown(42)), "UNKNOWN(42)");
    }

    #[test]
    fn test_dhcpv4_operation_from_u8() {
        assert_eq!(Dhcpv4Operation::from(1), Dhcpv4Operation::BootRequest);
        assert_eq!(Dhcpv4Operation::from(2), Dhcpv4Operation::BootReply);
        assert_eq!(Dhcpv4Operation::from(99), Dhcpv4Operation::Unknown(99));
    }

    #[test]
    fn test_dhcpv6_message_type_from_u8() {
        assert_eq!(Dhcpv6MessageType::from(1), Dhcpv6MessageType::Solicit);
        assert_eq!(Dhcpv6MessageType::from(2), Dhcpv6MessageType::Advertise);
        assert_eq!(Dhcpv6MessageType::from(7), Dhcpv6MessageType::Reply);
        assert_eq!(Dhcpv6MessageType::from(11), Dhcpv6MessageType::InfoRequest);
        assert_eq!(Dhcpv6MessageType::from(99), Dhcpv6MessageType::Unknown(99));
    }

    #[test]
    fn test_dhcpv6_message_type_display() {
        assert_eq!(format!("{}", Dhcpv6MessageType::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcpv6MessageType::Reply), "REPLY");
        assert_eq!(
            format!("{}", Dhcpv6MessageType::InfoRequest),
            "INFO-REQUEST"
        );
    }

    #[test]
    fn test_is_dhcpv4_ports() {
        assert!(is_dhcpv4_ports(67, 1234));
        assert!(is_dhcpv4_ports(68, 1234));
        assert!(is_dhcpv4_ports(1234, 67));
        assert!(is_dhcpv4_ports(1234, 68));
        assert!(!is_dhcpv4_ports(80, 443));
    }

    #[test]
    fn test_is_dhcpv6_ports() {
        assert!(is_dhcpv6_ports(546, 1234));
        assert!(is_dhcpv6_ports(547, 1234));
        assert!(is_dhcpv6_ports(1234, 546));
        assert!(is_dhcpv6_ports(1234, 547));
        assert!(!is_dhcpv6_ports(80, 443));
    }

    #[test]
    fn test_parse_dhcpv4_payload_too_short() {
        let payload = vec![0u8; 100];
        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dhcpv4_payload_basic() {
        // Create a minimal valid DHCPv4 packet
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Set client MAC at offset 28-33
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0xFF;
        // Add DHCP magic cookie would be at 236-239
        // Add message type option at 240
        payload[240] = 53; // Option: DHCP Message Type
        payload[241] = 1; // Length: 1
        payload[242] = 1; // DISCOVER
        payload[243] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.operation, Dhcpv4Operation::BootRequest);
        assert_eq!(packet.client_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(packet.client_mac_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(packet.message_type, Some(Dhcpv4MessageType::Discover));
        assert_eq!(packet.source_port, 68);
        assert_eq!(packet.dest_port, 67);
    }

    #[test]
    fn test_parse_dhcpv4_with_hostname() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Add hostname option at 240
        payload[240] = 12; // Option: Hostname
        payload[241] = 4; // Length: 4
        payload[242] = b't';
        payload[243] = b'e';
        payload[244] = b's';
        payload[245] = b't';
        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.hostname, Some("test".to_string()));
    }

    #[test]
    fn test_parse_dhcpv4_with_requested_ip() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Add requested IP option at 240
        payload[240] = 50; // Option: Requested IP
        payload[241] = 4; // Length: 4
        payload[242] = 192;
        payload[243] = 168;
        payload[244] = 1;
        payload[245] = 100;
        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.requested_ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_parse_dhcpv4_fallback_to_yiaddr() {
        // Minimal DHCPv4 packet where yiaddr is populated by server reply.
        let mut payload = vec![0u8; 300];
        payload[0] = 2; // BootReply
        // yiaddr (bytes 16..20)
        payload[16] = 192;
        payload[17] = 168;
        payload[18] = 4;
        payload[19] = 81;
        // Client MAC
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0xFF;
        // End options
        payload[240] = 255;

        let packet = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 4, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            67,
            68,
        )
        .unwrap();

        assert_eq!(packet.requested_ip, Some(Ipv4Addr::new(192, 168, 4, 81)));
    }

    #[test]
    fn test_parse_dhcpv6_payload_too_short() {
        let payload = vec![0u8; 2];
        let result = parse_dhcpv6_payload(
            &payload,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            546,
            547,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dhcpv6_payload_basic() {
        // Create a minimal DHCPv6 packet
        let mut payload = vec![0u8; 10];
        payload[0] = 1; // SOLICIT
        payload[1] = 0x12; // Transaction ID byte 1
        payload[2] = 0x34; // Transaction ID byte 2
        payload[3] = 0x56; // Transaction ID byte 3

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Solicit);
        assert_eq!(packet.transaction_id, [0x12, 0x34, 0x56]);
        assert_eq!(packet.transaction_id_string(), "0x123456");
    }

    #[test]
    fn test_parse_dhcpv6_with_client_id() {
        // Exactly 12 bytes: 4 header + 8 option (4 header + 4 data)
        let payload = vec![
            0x01, // Message type: SOLICIT
            0xAB, 0xCD, 0xEF, // Transaction ID
            0x00, 0x01, // Option code: 1 (Client ID)
            0x00, 0x04, // Length: 4
            0xDE, 0xAD, 0xBE, 0xEF, // Client ID data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientId(data) => {
                assert_eq!(data, &vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("Expected ClientId option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_client_fqdn_dns_wire_format() {
        // SOLICIT + option 39 (Client FQDN)
        // value: [flags=0x00][len=8]['CircleV2'][root=0]
        let payload = vec![
            0x01, // Message type: SOLICIT
            0x11, 0x22, 0x33, // Transaction ID
            0x00, 0x27, // Option code: 39 (Client FQDN)
            0x00, 0x0B, // Length: 11
            0x00, // Flags
            0x08, b'C', b'i', b'r', b'c', b'l', b'e', b'V', b'2', 0x00, // Root label
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientFqdn(name) => assert_eq!(name, "CircleV2"),
            _ => panic!("Expected ClientFqdn option"),
        }
    }

    #[test]
    fn test_dhcp_error_display() {
        let err = DhcpError::InterfaceNotFound("eth0".to_string());
        assert_eq!(format!("{}", err), "Interface not found: eth0");

        let err = DhcpError::UnsupportedChannelType;
        assert_eq!(format!("{}", err), "Unsupported channel type");
    }

    #[test]
    fn test_list_interfaces() {
        // Just verify it doesn't panic and returns a valid list
        let interfaces = list_interfaces();
        // Verify it's a valid Vec (this will always pass, but ensures the function works)
        let _ = interfaces;
    }

    #[test]
    fn test_device_info_creation() {
        let device = DeviceInfo::new(
            "aa:bb:cc:dd:ee:ff".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Some("testhost".to_string()),
        );

        assert_eq!(device.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(device.ip_address.to_string(), "192.168.1.100");
        assert_eq!(device.hostname, Some("testhost".to_string()));
        assert_eq!(device.first_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_csv_roundtrip() {
        let device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: Some("fe80::1".parse().unwrap()),
            hostname: Some("testhost".to_string()),
            services: vec!["_http._tcp".to_string(), "_ssh._tcp".to_string()],
            vendor: Some("TestVendor".to_string()),
            device_type: Some("Server".to_string()),
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.ipv6_address, device.ipv6_address);
        assert_eq!(parsed.hostname, device.hostname);
        assert_eq!(parsed.services, device.services);
        assert_eq!(parsed.vendor, device.vendor);
        assert_eq!(parsed.device_type, device.device_type);
        assert_eq!(parsed.first_seen, device.first_seen);
        assert_eq!(parsed.last_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_from_csv_normalizes_legacy_dhcpv6_duid_identifier() {
        let line = "2026-04-07T02:41:49Z,2026-04-07T03:12:39Z,00:03:00:01:8c:e2:da:bc:78:7a,fe80::8ee2:daff:febc:787a,\"\",\"\0\x08CircleV2\0\",\"\",\"Barracuda Networks, Inc.\",\"\"";
        let parsed = DeviceInfo::from_csv_line(line).unwrap();

        assert_eq!(parsed.mac_address, "8c:e2:da:bc:78:7a");
        assert_eq!(parsed.hostname.as_deref(), Some("CircleV2"));
    }

    #[test]
    fn test_device_info_csv_no_hostname() {
        let device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: None,
            hostname: None,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.hostname, None);
    }

    #[test]
    fn test_device_info_update() {
        let mut device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: None,
            hostname: None,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
        };

        // Update with new IP - should return true
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), None);
        assert!(changed);
        assert_eq!(device.ip_address.to_string(), "192.168.1.200");

        // Update with same IP - should return false
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), None);
        assert!(!changed);

        // Update with hostname - should return true
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), Some("newhost"));
        assert!(changed);
        assert_eq!(device.hostname, Some("newhost".to_string()));
    }

    #[test]
    fn test_format_timestamp() {
        // Test epoch
        let epoch = SystemTime::UNIX_EPOCH;
        let ts = format_timestamp(epoch);
        assert_eq!(ts, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(!is_leap_year(1900)); // Not leap (divisible by 100 but not 400)
        assert!(is_leap_year(2000)); // Leap (divisible by 400)
        assert!(is_leap_year(2024)); // Leap (divisible by 4)
        assert!(!is_leap_year(2023)); // Not leap
    }

    #[test]
    fn test_device_tracker_new_device() {
        let temp_path = "/tmp/lanwatch_test_devices.csv";
        let _ = std::fs::remove_file(temp_path); // Clean up any existing file
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Create a test packet
        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("testhost".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
            parameter_request_list: None,
            vendor_class_id: None,
        };

        let is_new = tracker.update_from_dhcpv4(&packet);
        assert!(is_new);
        assert_eq!(tracker.device_count(), 1);

        // Same device should not be "new"
        let is_new = tracker.update_from_dhcpv4(&packet);
        assert!(!is_new);
        assert_eq!(tracker.device_count(), 1);

        // Clean up
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_device_tracker_dhcpv4_does_not_use_server_source_ip() {
        let temp_path = "/tmp/lanwatch_test_dhcpv4_server_ip.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Simulate DHCPv4 server reply without requested_ip/yiaddr fallback data.
        // The server source IP (router) must not be attributed to client MAC.
        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 1),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 67,
            dest_port: 68,
            operation: Dhcpv4Operation::BootReply,
            client_mac: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            message_type: Some(Dhcpv4MessageType::Offer),
            hostname: None,
            requested_ip: None,
            parameter_request_list: None,
            vendor_class_id: None,
        };

        tracker.update_from_dhcpv4(&packet);
        let device = tracker.devices().get("10:20:30:40:50:60").unwrap();
        assert_eq!(device.ip_address.to_string(), "0.0.0.0");

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_update_from_dhcpv6() {
        let temp_path = "/tmp/lanwatch_test_v6_devices.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Create a DHCPv6 packet with ClientId
        let packet = Dhcpv6Packet {
            source_ip: "fe80::1".parse().unwrap(),
            dest_ip: "ff02::1:2".parse().unwrap(),
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x12, 0x34, 0x56],
            options: vec![
                // DUID-LL (type 3), hw type Ethernet (1), MAC aa:bb:cc:dd:ee:ff
                Dhcpv6Option::ClientId(vec![
                    0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                ]),
                Dhcpv6Option::ClientFqdn("myhost.local".to_string()),
            ],
        };

        let is_new = tracker.update_from_dhcpv6(&packet);
        assert!(is_new);
        assert_eq!(tracker.device_count(), 1);

        // Verify the device was stored with extracted Ethernet MAC
        let devices = tracker.devices();
        assert!(devices.contains_key("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            devices
                .get("aa:bb:cc:dd:ee:ff")
                .and_then(|d| d.hostname.as_deref()),
            Some("myhost.local")
        );

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_dhcpv6_no_client_id() {
        let temp_path = "/tmp/lanwatch_test_v6_no_id.csv";
        let _ = std::fs::remove_file(temp_path);
        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // DHCPv6 packet without ClientId should not be tracked
        let packet = Dhcpv6Packet {
            source_ip: "fe80::1".parse().unwrap(),
            dest_ip: "ff02::1:2".parse().unwrap(),
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x12, 0x34, 0x56],
            options: vec![], // No ClientId
        };

        let is_new = tracker.update_from_dhcpv6(&packet);
        assert!(!is_new); // Should return false - can't track without DUID
        assert_eq!(tracker.device_count(), 0);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_prefers_hostname_over_oui_vendor() {
        let temp_path = "/tmp/lanwatch_test_lenovo_fingerprint.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 112),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x48, 0x45, 0xE6, 0x48, 0x4C, 0x85],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("RVD_Legion".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 4, 112)),
            parameter_request_list: None,
            vendor_class_id: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("48:45:e6:48:4c:85").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Lenovo"));
        assert_eq!(device.device_type.as_deref(), Some("Laptop"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_rachio_from_loaded_csv() {
        let temp_path = "/tmp/lanwatch_test_rachio_reclassify.csv";
        let _ = std::fs::remove_file(temp_path);

        let seeded = "first_seen,last_seen,mac_address,ip_address,ipv6_address,hostname,device_type,vendor,services\n2026-05-22T16:50:19Z,2026-05-22T23:52:20Z,9c:50:d1:18:8d:cc,192.168.4.36,\"\",\"rachio-188dcc\",\"Security Camera\",\"Murata Manufacturing Co., Ltd.\",\"\"\n";
        std::fs::write(temp_path, seeded).unwrap();

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 36),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x9C, 0x50, 0xD1, 0x18, 0x8D, 0xCC],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("rachio-188dcc".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 4, 36)),
            parameter_request_list: None,
            vendor_class_id: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("9c:50:d1:18:8d:cc").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Rachio"));
        assert_eq!(device.device_type.as_deref(), Some("Smart Watering Device"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_roborock_from_loaded_csv() {
        let temp_path = "/tmp/lanwatch_test_roborock_reclassify.csv";
        let _ = std::fs::remove_file(temp_path);

        let seeded = "first_seen,last_seen,mac_address,ip_address,ipv6_address,hostname,device_type,vendor,services\n2026-05-22T16:50:19Z,2026-05-22T23:52:20Z,b0:4a:39:e3:3f:da,192.168.7.193,\"\",\"roborock-vacuum-a75\",\"Security Camera\",\"Beijing Roborock Technology Co., Ltd.\",\"\"\n";
        std::fs::write(temp_path, seeded).unwrap();

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 7, 193),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xB0, 0x4A, 0x39, 0xE3, 0x3F, 0xDA],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("roborock-vacuum-a75".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 7, 193)),
            parameter_request_list: None,
            vendor_class_id: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("b0:4a:39:e3:3f:da").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Roborock"));
        assert_eq!(device.device_type.as_deref(), Some("Smart Cleaning Device"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_uses_oui_for_eero_when_no_hostname_present() {
        let temp_path = "/tmp/lanwatch_test_eero_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 7, 1),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xDC, 0x69, 0xB5, 0x95, 0x58, 0xB2],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 7, 1)),
            parameter_request_list: None,
            vendor_class_id: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));
        assert_eq!(device.device_type.as_deref(), Some("Router"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_device_tracker_uses_oui_for_eero_in_mdns_when_no_vendor_present() {
        let temp_path = "/tmp/lanwatch_test_eero_mdns_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = MdnsPacket {
            source_mac: "dc:69:b5:95:58:b2".to_string(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 7, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 1234,
            is_response: true,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        tracker.update_from_mdns(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_uses_oui_for_eero_in_ssdp_when_no_vendor_present() {
        let temp_path = "/tmp/lanwatch_test_eero_ssdp_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = SsdpPacket {
            source_mac: "dc:69:b5:95:58:b2".to_string(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 7, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
            message_type: SsdpMessageType::Response,
            start_line: "HTTP/1.1 200 OK".to_string(),
            headers: HashMap::new(),
        };

        tracker.update_from_ssdp(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_motorola_from_chromecast() {
        let temp_path = "/tmp/lanwatch_test_motorola.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        // 1. Initially seen as Chromecast with an OUI-derived vendor (eero inc.)
        let mut device = DeviceInfo::new(
            "dc:69:b5:33:44:55".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            None,
        );
        device.device_type = Some("Chromecast".to_string());
        device.vendor = Some("eero inc.".to_string());
        tracker.devices.insert(device.mac_address.clone(), device);

        // 2. Updated with Motorola hostname - should override Chromecast type and eero vendor!
        tracker.update_device(
            "dc:69:b5:33:44:55",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            Some("Moto-G-Stylus-2025"),
        );

        let device = tracker.devices().get("dc:69:b5:33:44:55").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Motorola"));
        assert_eq!(device.device_type.as_deref(), Some("Android Phone"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_extract_mac_from_duid_llt() {
        // DUID-LLT type 1, hw type 1 (Ethernet), time 0x12345678, MAC 8c:e2:da:bc:78:7a
        let duid = vec![
            0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x8C, 0xE2, 0xDA, 0xBC, 0x78, 0x7A,
        ];
        assert_eq!(
            extract_mac_from_duid(&duid).as_deref(),
            Some("8c:e2:da:bc:78:7a")
        );
    }

    #[test]
    fn test_sanitize_hostname_removes_control_bytes() {
        assert_eq!(
            sanitize_hostname("\0\u{0008}CircleV2\0").as_deref(),
            Some("CircleV2")
        );
        assert_eq!(sanitize_hostname("....").as_deref(), None);
    }

    #[test]
    fn test_device_tracker_persistence() {
        let temp_path = "/tmp/lanwatch_test_persistence.csv";
        let _ = std::fs::remove_file(temp_path);

        // Create tracker and add a device
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = Dhcpv4Packet {
                source_ip: Ipv4Addr::new(192, 168, 1, 100),
                dest_ip: Ipv4Addr::new(255, 255, 255, 255),
                source_port: 68,
                dest_port: 67,
                operation: Dhcpv4Operation::BootRequest,
                client_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                message_type: Some(Dhcpv4MessageType::Request),
                hostname: Some("persistent-host".to_string()),
                requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
                parameter_request_list: None,
                vendor_class_id: None,
            };
            tracker.update_from_dhcpv4(&packet);
            assert_eq!(tracker.device_count(), 1);
        }

        // Create new tracker and verify data was loaded
        {
            let tracker = DeviceTracker::new(temp_path).unwrap();
            assert_eq!(tracker.device_count(), 1);

            let devices = tracker.devices();
            let device = devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.ip_address.to_string(), "192.168.1.100");
            assert_eq!(device.hostname, Some("persistent-host".to_string()));
        }

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_device_info_json_serialization() {
        let device = DeviceInfo {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: Some("fe80::abcd:1234".parse().unwrap()),
            hostname: Some("jsonhost".to_string()),
            services: vec!["_airplay._tcp".to_string()],
            vendor: Some("Apple".to_string()),
            device_type: Some("AirPlay Device".to_string()),
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("AA:BB:CC:DD:EE:FF"));
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("fe80::abcd:1234"));
        assert!(json.contains("jsonhost"));

        // Deserialize back
        let parsed: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.hostname, device.hostname);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_device_tracker_to_json() {
        let temp_path = "/tmp/lanwatch_test_json.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Add two devices
        let packet1 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("device1".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            parameter_request_list: None,
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet1);

        let packet2 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 2)),
            parameter_request_list: None,
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet2);

        let json = tracker.to_json().unwrap();
        assert!(json.contains("device1"));
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("192.168.1.2"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_parse_dhcpv6_with_server_id() {
        let payload = vec![
            0x02, // Message type: ADVERTISE
            0x12, 0x34, 0x56, // Transaction ID
            0x00, 0x02, // Option code: 2 (Server ID)
            0x00, 0x04, // Length: 4
            0x01, 0x02, 0x03, 0x04, // Server ID data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 547, 546);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Advertise);
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ServerId(data) => {
                assert_eq!(data, &vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected ServerId option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_client_fqdn() {
        let fqdn = "myhost.example.com";
        let mut payload = vec![
            0x01, // Message type: SOLICIT
            0xAB, 0xCD, 0xEF, // Transaction ID
            0x00, 0x27, // Option code: 39 (Client FQDN)
        ];

        // RFC 4704 encoding: flags + DNS wire-format labels
        let fqdn_data = vec![
            0x00, // Flags
            0x06, b'm', b'y', b'h', b'o', b's', b't', // myhost
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // root
        ];

        // Add length (2 bytes big-endian)
        payload.push(0x00);
        payload.push(fqdn_data.len() as u8);
        // Add FQDN data
        payload.extend_from_slice(&fqdn_data);

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientFqdn(name) => {
                assert_eq!(name, fqdn);
            }
            _ => panic!("Expected ClientFqdn option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_ia_na() {
        let payload = vec![
            0x03, // Message type: REQUEST
            0x11, 0x22, 0x33, // Transaction ID
            0x00, 0x03, // Option code: 3 (IA_NA)
            0x00, 0x00, // Length: 0 (minimal)
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Request);
        assert_eq!(packet.options.len(), 1);
        assert!(matches!(packet.options[0], Dhcpv6Option::IaNa));
    }

    #[test]
    fn test_parse_dhcpv6_multiple_options() {
        let payload = vec![
            0x01, // Message type: SOLICIT
            0x00, 0x00, 0x01, // Transaction ID
            // Option 1: ClientId
            0x00, 0x01, // Option code: 1
            0x00, 0x02, // Length: 2
            0xAA, 0xBB, // Data
            // Option 2: IA_NA
            0x00, 0x03, // Option code: 3
            0x00, 0x00, // Length: 0
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 2);
    }

    #[test]
    fn test_parse_dhcpv4_truncated_option() {
        // Payload with option that claims longer length than available
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        payload[240] = 12; // Option: Hostname
        payload[241] = 100; // Length: 100 (but only a few bytes available)
        payload[242] = b't';
        payload[243] = 255; // End option prematurely

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        // Should still parse but might not have hostname
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_dhcpv6_truncated_option() {
        // Option claims 100 bytes but only 2 available
        let payload = vec![
            0x01, // Message type
            0x00, 0x00, 0x01, // Transaction ID
            0x00, 0x01, // Option code
            0x00, 0x64, // Length: 100 (but not enough data)
            0xAA, 0xBB, // Only 2 bytes of data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        // Should parse but truncated option won't be included
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 0); // Option was skipped due to truncation
    }

    #[test]
    fn test_dhcpv4_packet_fields() {
        let mut payload = vec![0u8; 300];
        payload[0] = 2; // BootReply
        // Set client MAC
        for i in 0..6 {
            payload[28 + i] = (i + 1) as u8;
        }
        // Set yiaddr (your IP address) at offset 16
        payload[16] = 10;
        payload[17] = 0;
        payload[18] = 0;
        payload[19] = 100;

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            67,
            68,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.operation, Dhcpv4Operation::BootReply);
        assert_eq!(packet.source_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(packet.dest_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(packet.client_mac, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_dhcpv6_packet_transaction_id_string() {
        let packet = Dhcpv6Packet {
            source_ip: Ipv6Addr::LOCALHOST,
            dest_ip: Ipv6Addr::LOCALHOST,
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x00, 0x00, 0x00],
            options: vec![],
        };
        assert_eq!(packet.transaction_id_string(), "0x000000");

        let packet2 = Dhcpv6Packet {
            source_ip: Ipv6Addr::LOCALHOST,
            dest_ip: Ipv6Addr::LOCALHOST,
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0xFF, 0xFF, 0xFF],
            options: vec![],
        };
        // The format uses uppercase hex
        assert_eq!(packet2.transaction_id_string(), "0xFFFFFF");
    }

    #[test]
    fn test_device_tracker_mac_address_update() {
        let temp_path = "/tmp/lanwatch_test_mac_update.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // First packet with one IP
        let packet1 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
            parameter_request_list: None,
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet1);
        assert_eq!(tracker.device_count(), 1);

        // Same MAC, different IP (simulating DHCP renewal with new IP)
        let packet2 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Request),
            hostname: Some("newname".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 200)),
            parameter_request_list: None,
            vendor_class_id: None,
        };
        let changed = tracker.update_from_dhcpv4(&packet2);
        assert!(changed);
        assert_eq!(tracker.device_count(), 1); // Still only 1 device

        // Verify IP was updated (MAC is lowercase)
        let device = tracker.devices().get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(device.ip_address.to_string(), "192.168.1.200");
        assert_eq!(device.hostname, Some("newname".to_string()));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_api_response_serialization() {
        let response: ApiResponse<Vec<String>> = ApiResponse {
            success: true,
            data: vec!["test".to_string()],
            count: 1,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"count\":1"));
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_api_error_serialization() {
        let error = ApiError {
            success: false,
            error: "Not found".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("Not found"));
    }

    // =========================================================================
    // mDNS Tests
    // =========================================================================

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_record_type_from_u16() {
        assert_eq!(MdnsRecordType::from(1), MdnsRecordType::A);
        assert_eq!(MdnsRecordType::from(28), MdnsRecordType::Aaaa);
        assert_eq!(MdnsRecordType::from(12), MdnsRecordType::Ptr);
        assert_eq!(MdnsRecordType::from(33), MdnsRecordType::Srv);
        assert_eq!(MdnsRecordType::from(16), MdnsRecordType::Txt);
        assert_eq!(MdnsRecordType::from(255), MdnsRecordType::Any);
        assert_eq!(MdnsRecordType::from(99), MdnsRecordType::Unknown(99));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_record_type_display() {
        assert_eq!(format!("{}", MdnsRecordType::A), "A");
        assert_eq!(format!("{}", MdnsRecordType::Aaaa), "AAAA");
        assert_eq!(format!("{}", MdnsRecordType::Ptr), "PTR");
        assert_eq!(format!("{}", MdnsRecordType::Srv), "SRV");
        assert_eq!(format!("{}", MdnsRecordType::Txt), "TXT");
        assert_eq!(format!("{}", MdnsRecordType::Unknown(42)), "UNKNOWN(42)");
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_is_mdns_ports() {
        assert!(is_mdns_ports(5353, 1234));
        assert!(is_mdns_ports(1234, 5353));
        assert!(is_mdns_ports(5353, 5353));
        assert!(!is_mdns_ports(80, 443));
        assert!(!is_mdns_ports(67, 68));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_payload_too_short() {
        let payload = vec![0u8; 10];
        let result = parse_mdns_payload(
            &payload,
            "00:11:22:33:44:55".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );
        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_query() {
        // Build a simple mDNS query for _http._tcp.local
        let mut payload = Vec::new();
        // Transaction ID
        payload.extend_from_slice(&[0x00, 0x00]);
        // Flags (standard query)
        payload.extend_from_slice(&[0x00, 0x00]);
        // Questions: 1
        payload.extend_from_slice(&[0x00, 0x01]);
        // Answer/Authority/Additional: 0
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Question: _http._tcp.local
        payload.push(5);
        payload.extend_from_slice(b"_http");
        payload.push(4);
        payload.extend_from_slice(b"_tcp");
        payload.push(5);
        payload.extend_from_slice(b"local");
        payload.push(0);
        // QTYPE: PTR (12)
        payload.extend_from_slice(&[0x00, 0x0C]);
        // QCLASS: IN (1)
        payload.extend_from_slice(&[0x00, 0x01]);

        let result = parse_mdns_payload(
            &payload,
            "aa:bb:cc:dd:ee:ff".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "aa:bb:cc:dd:ee:ff");
        assert!(!packet.is_response);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "_http._tcp.local");
        assert_eq!(packet.questions[0].record_type, MdnsRecordType::Ptr);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_dns_name_rejects_pointer_cycle() {
        let payload = vec![0xC0, 0x02, 0xC0, 0x00];

        assert!(parse_dns_name(&payload, 0).is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_payload_rejects_large_header_counts() {
        let mut payload = vec![0u8; 12];
        payload[4..6].copy_from_slice(&u16::MAX.to_be_bytes());

        let result = parse_mdns_payload(
            &payload,
            "aa:bb:cc:dd:ee:ff".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_response_with_a_record() {
        let mut payload = Vec::new();
        // Transaction ID
        payload.extend_from_slice(&[0x00, 0x00]);
        // Flags (response)
        payload.extend_from_slice(&[0x84, 0x00]);
        // Questions: 0, Answers: 1, Authority: 0, Additional: 0
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Answer: mydevice.local A 192.168.1.50
        payload.push(8);
        payload.extend_from_slice(b"mydevice");
        payload.push(5);
        payload.extend_from_slice(b"local");
        payload.push(0);
        // TYPE: A (1)
        payload.extend_from_slice(&[0x00, 0x01]);
        // CLASS: IN with cache-flush
        payload.extend_from_slice(&[0x80, 0x01]);
        // TTL: 120
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        // RDLENGTH: 4
        payload.extend_from_slice(&[0x00, 0x04]);
        // RDATA: 192.168.1.50
        payload.extend_from_slice(&[192, 168, 1, 50]);

        let result = parse_mdns_payload(
            &payload,
            "11:22:33:44:55:66".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "11:22:33:44:55:66");
        assert!(packet.is_response);
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.answers[0].name, "mydevice.local");
        assert_eq!(packet.answers[0].record_type, MdnsRecordType::A);
        assert_eq!(packet.answers[0].ttl, 120);
        if let MdnsRecordData::A(addr) = &packet.answers[0].data {
            assert_eq!(*addr, Ipv4Addr::new(192, 168, 1, 50));
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_build_mdns_query() {
        let query = build_mdns_query("_http._tcp.local", MdnsRecordType::Ptr);

        // Should be a valid DNS query packet
        assert!(query.len() >= 12);

        // Check header
        assert_eq!(query[0..2], [0x00, 0x00]); // Transaction ID
        assert_eq!(query[2..4], [0x00, 0x00]); // Flags (query)
        assert_eq!(query[4..6], [0x00, 0x01]); // 1 question
        assert_eq!(query[6..8], [0x00, 0x00]); // 0 answers

        // Parse it back
        let parsed = parse_mdns_payload(
            &query,
            "de:ad:be:ef:00:01".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );
        assert!(parsed.is_some());
        let packet = parsed.unwrap();
        assert!(!packet.is_response);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "_http._tcp.local");
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_packet_get_ipv4_addresses() {
        let packet = MdnsPacket {
            source_mac: "00:11:22:33:44:55".to_string(),
            source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_ip: std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
            transaction_id: 0,
            is_response: true,
            questions: vec![],
            answers: vec![
                MdnsRecord {
                    name: "device1.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 1, 10)),
                },
                MdnsRecord {
                    name: "device2.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 1, 20)),
                },
            ],
            authority: vec![],
            additional: vec![],
        };

        let addresses = packet.get_ipv4_addresses();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&("device1.local".to_string(), Ipv4Addr::new(192, 168, 1, 10))));
        assert!(addresses.contains(&("device2.local".to_string(), Ipv4Addr::new(192, 168, 1, 20))));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_constants() {
        assert_eq!(MDNS_PORT, 5353);
        assert_eq!(MDNS_IPV4_MULTICAST, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(
            MDNS_IPV6_MULTICAST,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)
        );
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_defaults() {
        let registry = MdnsServiceRegistry::with_defaults();

        // Should have some default services
        assert!(!registry.is_empty());

        // Test Apple service lookup
        let airplay = registry.lookup("_airplay._tcp");
        assert!(airplay.is_some());
        let airplay = airplay.unwrap();
        assert_eq!(airplay.vendor, Some("Apple".to_string()));

        // Test Google service lookup
        assert_eq!(registry.get_vendor("_googlecast._tcp"), Some("Google"));

        // Test service without vendor
        let http = registry.lookup("_http._tcp");
        assert!(http.is_some());
        assert!(http.unwrap().vendor.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_add() {
        let mut registry = MdnsServiceRegistry::new();

        registry.add("_custom._tcp", "Custom Service", Some("MyVendor"));

        let service = registry.lookup("_custom._tcp");
        assert!(service.is_some());
        assert_eq!(service.unwrap().description, "Custom Service");
        assert_eq!(registry.get_vendor("_custom._tcp"), Some("MyVendor"));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_normalize() {
        let mut registry = MdnsServiceRegistry::new();

        // Add with .local suffix
        registry.add("_test._tcp.local", "Test Service", None);

        // Should be found with or without .local
        assert!(registry.lookup("_test._tcp").is_some());
        assert!(registry.lookup("_test._tcp.local").is_some());

        // Case insensitive
        assert!(registry.lookup("_TEST._TCP").is_some());
    }

    #[test]
    fn test_device_info_add_service() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Adding a new service should return true
        assert!(device.add_service("_http._tcp"));
        assert_eq!(device.services, vec!["_http._tcp"]);

        // Adding the same service should return false
        assert!(!device.add_service("_http._tcp"));

        // Adding with .local suffix should normalize
        assert!(device.add_service("_ssh._tcp.local"));
        assert!(device.services.contains(&"_ssh._tcp".to_string()));

        // Services should be sorted
        assert_eq!(device.services, vec!["_http._tcp", "_ssh._tcp"]);
    }

    #[test]
    fn test_device_info_set_vendor() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Setting vendor first time should return true
        assert!(device.set_vendor("Apple"));
        assert_eq!(device.vendor, Some("Apple".to_string()));

        // Setting vendor again should return false (first wins)
        assert!(!device.set_vendor("Google"));
        assert_eq!(device.vendor, Some("Apple".to_string()));
    }

    #[test]
    fn test_device_info_set_device_type() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Setting device type first time should return true
        assert!(device.set_device_type("Chromecast"));
        assert_eq!(device.device_type, Some("Chromecast".to_string()));

        // Setting device type again should return false (first wins)
        assert!(!device.set_device_type("Apple TV"));
        assert_eq!(device.device_type, Some("Chromecast".to_string()));
    }

    #[test]
    fn test_device_info_csv_roundtrip_with_device_type() {
        let mut device = DeviceInfo::new(
            "aa:bb:cc:dd:ee:ff".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Some("mydevice".to_string()),
        );
        device.add_service("_googlecast._tcp");
        device.set_vendor("Google");
        device.set_device_type("Chromecast");

        let csv = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv).unwrap();

        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.hostname, device.hostname);
        assert_eq!(parsed.services, device.services);
        assert_eq!(parsed.vendor, device.vendor);
        assert_eq!(parsed.device_type, device.device_type);
    }

    // ========================================================================
    // OUI Registry Tests
    // ========================================================================

    #[test]
    fn test_oui_registry_new() {
        let registry = OuiRegistry::new();
        // The oui-data crate should have entries
        assert!(!registry.is_empty());
        assert!(!registry.is_empty());
        assert_eq!(registry.custom_count(), 0);
        // Built-in IEEE database should have ~40,000+ entries
        assert!(OuiRegistry::builtin_count() > 30000);
    }

    #[test]
    fn test_oui_registry_with_defaults() {
        let registry = OuiRegistry::with_defaults();
        // Should be identical to new()
        assert!(!registry.is_empty());
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_oui_registry_lookup_known_vendor() {
        let registry = OuiRegistry::new();

        // Apple's OUI (well-known)
        let vendor = registry.lookup("00:1B:63:00:00:00");
        assert!(
            vendor.is_some(),
            "Apple OUI should be found in IEEE database"
        );

        // Intel's OUI (well-known)
        let vendor = registry.lookup("00:1B:21:00:00:00");
        assert!(
            vendor.is_some(),
            "Intel OUI should be found in IEEE database"
        );
    }

    #[test]
    fn test_oui_registry_normalize_mac() {
        let registry = OuiRegistry::new();

        // All these formats should normalize to the same OUI lookup
        let mac_formats = [
            "00:1B:63:AA:BB:CC", // colon separated full
            "00-1B-63-AA-BB-CC", // dash separated full
            "001B63AABBCC",      // no separator
            "00:1B:63",          // OUI only
            "001B63",            // OUI only no separator
        ];

        // They should all find the same vendor (or none)
        let first_result = registry.lookup(mac_formats[0]);
        for mac in &mac_formats[1..] {
            assert_eq!(
                registry.lookup(mac),
                first_result,
                "All MAC formats should resolve to same vendor: {}",
                mac
            );
        }
    }

    #[test]
    fn test_oui_registry_custom_override() {
        let mut registry = OuiRegistry::new();

        // Add a custom override
        registry.add("AA:BB:CC", "My Custom Vendor");

        // Custom override should take priority
        let vendor = registry.lookup("AA:BB:CC:DD:EE:FF");
        assert_eq!(vendor, Some("My Custom Vendor"));

        // Custom count should increase
        assert_eq!(registry.custom_count(), 1);
    }

    #[test]
    fn test_oui_registry_custom_overrides_builtin() {
        let mut registry = OuiRegistry::new();

        // Apple's real OUI - check if it exists and remember if we found one
        let has_original = registry.lookup("00:1B:63:00:00:00").is_some();

        // Override Apple's OUI with custom vendor
        registry.add("00:1B:63", "Fake Vendor Override");

        // Custom should now take priority
        let vendor = registry.lookup("00:1B:63:AA:BB:CC");
        assert_eq!(vendor, Some("Fake Vendor Override"));

        // If original existed, verify the override hides it
        if has_original {
            // The override should be what we set, not the original
            assert_eq!(vendor, Some("Fake Vendor Override"));
        }
    }

    #[test]
    fn test_oui_registry_lookup_unknown() {
        let registry = OuiRegistry::new();

        // This OUI is unlikely to exist (private range)
        let vendor = registry.lookup("FE:FF:FF:00:00:00");
        // May or may not be found - just ensure no panic
        let _ = vendor;
    }

    #[test]
    fn test_oui_registry_load_from_file() {
        use std::io::Write;

        let mut registry = OuiRegistry::new();

        // Create a temporary file with OUI entries
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_oui.txt");
        {
            let mut file = File::create(&temp_file).unwrap();
            writeln!(file, "# Comment line").unwrap();
            writeln!(file).unwrap(); // Empty line
            writeln!(file, "AA:BB:CC\tTest Vendor 1").unwrap();
            writeln!(file, "DD:EE:FF  Test Vendor 2").unwrap();
            writeln!(file, "11-22-33  Test Vendor 3").unwrap();
        }

        // Load the file
        let count = registry.load_from_file(&temp_file).unwrap();
        assert_eq!(count, 3);
        assert_eq!(registry.custom_count(), 3);

        // Check lookups
        assert_eq!(registry.lookup("AA:BB:CC:00:00:00"), Some("Test Vendor 1"));
        assert_eq!(registry.lookup("DD:EE:FF:00:00:00"), Some("Test Vendor 2"));
        assert_eq!(registry.lookup("11:22:33:00:00:00"), Some("Test Vendor 3"));

        // Clean up
        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn test_oui_registry_len() {
        let mut registry = OuiRegistry::new();
        let initial_len = registry.len();

        // Add custom entries
        registry.add("AA:BB:CC", "Vendor 1");
        registry.add("DD:EE:FF", "Vendor 2");

        // Length should increase
        assert_eq!(registry.len(), initial_len + 2);
    }

    #[test]
    fn test_oui_registry_load_from_ieee_file() {
        use std::io::Write;

        let mut registry = OuiRegistry::new();

        // Create a temporary file with IEEE OUI format entries
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_ieee_oui.txt");
        {
            let mut file = File::create(&temp_file).unwrap();
            // IEEE format: "XX-XX-XX   (hex)\t\tVendor Name"
            writeln!(file, "OUI/MA-L			Organization").unwrap();
            writeln!(file, "company_id			Organization Address").unwrap();
            writeln!(file).unwrap();
            writeln!(file, "00-00-00   (hex)\t\tXerox Corporation").unwrap();
            writeln!(file, "000000     (base 16)\t\tXerox Corporation").unwrap();
            writeln!(file, "\t\t\t\t26600 SW Parkway").unwrap();
            writeln!(file).unwrap();
            writeln!(file, "00-00-01   (hex)\t\tXerox Corporation").unwrap();
            writeln!(file, "00-00-0C   (hex)\t\tCisco Systems, Inc").unwrap();
            writeln!(file, "00-17-F2   (hex)\t\tApple, Inc.").unwrap();
        }

        // Load the file
        let count = registry.load_from_ieee_file(&temp_file).unwrap();
        assert_eq!(count, 4); // Only (hex) lines are parsed

        // Check lookups
        assert_eq!(
            registry.lookup("00:00:00:11:22:33"),
            Some("Xerox Corporation")
        );
        assert_eq!(
            registry.lookup("00:00:0C:AA:BB:CC"),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(registry.lookup("00:17:F2:12:34:56"), Some("Apple, Inc."));

        // Clean up
        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn test_parse_ieee_oui_line() {
        // Test valid IEEE format lines
        let result = OuiRegistry::parse_ieee_oui_line("00-00-00   (hex)\t\tXerox Corporation");
        assert!(result.is_some());
        let (mac, vendor) = result.unwrap();
        assert_eq!(mac, "00-00-00");
        assert_eq!(vendor, "Xerox Corporation");

        // Test line without (hex) marker - should return None
        let result = OuiRegistry::parse_ieee_oui_line("000000     (base 16)\t\tXerox Corporation");
        assert!(result.is_none());

        // Test empty/whitespace lines
        let result = OuiRegistry::parse_ieee_oui_line("");
        assert!(result.is_none());
        let result = OuiRegistry::parse_ieee_oui_line("   ");
        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_all() {
        let request = build_ssdp_search_request("ssdp:all");
        let request_str = String::from_utf8_lossy(&request);

        // Verify M-SEARCH format
        assert!(request_str.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(request_str.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(request_str.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(request_str.contains("MX: 2\r\n"));
        assert!(request_str.contains("ST: ssdp:all\r\n"));
        assert!(request_str.ends_with("\r\n\r\n"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_upnp_root() {
        let request = build_ssdp_search_request("upnp:rootdevice");
        let request_str = String::from_utf8_lossy(&request);

        // Verify format with different search target
        assert!(request_str.contains("ST: upnp:rootdevice\r\n"));
        assert!(request_str.starts_with("M-SEARCH * HTTP/1.1\r\n"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_media_renderer() {
        let request = build_ssdp_search_request("urn:schemas-upnp-org:device:MediaRenderer:1");
        let request_str = String::from_utf8_lossy(&request);

        // Verify format with URN
        assert!(request_str.contains("urn:schemas-upnp-org:device:MediaRenderer:1"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_querier_new() {
        // Test that SsdpQuerier can be created
        let result = SsdpQuerier::new();
        assert!(result.is_ok(), "SsdpQuerier::new() should succeed");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_notify() {
        let msg_type = SsdpMessageType::Notify;
        assert_eq!(format!("{}", msg_type), "NOTIFY");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_search() {
        let msg_type = SsdpMessageType::Search;
        assert_eq!(format!("{}", msg_type), "M-SEARCH");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_response() {
        let msg_type = SsdpMessageType::Response;
        assert_eq!(format!("{}", msg_type), "RESPONSE");
    }

    #[test]
    fn test_dhcpv4_option55_parsing() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest

        // Option 55 (Parameter Request List)
        // Code 55, Length 4, Values [1, 3, 6, 42]
        payload[240] = 55;
        payload[241] = 4;
        payload[242] = 1;
        payload[243] = 3;
        payload[244] = 6;
        payload[245] = 42;

        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.parameter_request_list, Some(vec![1, 3, 6, 42]));
    }

    #[test]
    fn test_dhcpv4_option60_parsing() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest

        // Option 60 (Vendor Class Identifier)
        // Code 60, Length 8, Value "MSFT 5.0"
        payload[240] = 60;
        payload[241] = 8;
        payload[242..250].copy_from_slice(b"MSFT 5.0");

        payload[250] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.vendor_class_id.as_deref(), Some("MSFT 5.0"));
    }

    #[test]
    fn test_device_tracker_fingerprint_matching() {
        let temp_path = "/tmp/lanwatch_test_fingerprint.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // 1. Windows Option 55 Fingerprint: contains 249 (MS Classless Route)
        let packet_win = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 101)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249]),
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet_win);
        {
            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Microsoft"));
            assert_eq!(device.device_type.as_deref(), Some("PC/Windows"));
        }

        // 2. Apple Option 55 Fingerprint: contains 95 (LDAP) and lacks 26/28
        let packet_apple = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 102)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 95, 119]),
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet_apple);
        {
            let device = tracker.devices.get("22:33:44:55:66:77").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Apple"));
            assert_eq!(device.device_type.as_deref(), Some("Apple Device"));
        }

        // 3. Android Option 55 Fingerprint: contains 26 and 28
        let packet_android = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 103)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 26, 28, 121]),
            vendor_class_id: None,
        };
        tracker.update_from_dhcpv4(&packet_android);
        {
            let device = tracker.devices.get("33:44:55:66:77:88").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Google"));
            assert_eq!(device.device_type.as_deref(), Some("Android Phone"));
        }

        // 4. Windows Option 60 Fingerprint
        let packet_win60 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 104)),
            parameter_request_list: None,
            vendor_class_id: Some("MSFT 5.0".to_string()),
        };
        tracker.update_from_dhcpv4(&packet_win60);
        {
            let device = tracker.devices.get("44:55:66:77:88:99").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Microsoft"));
            assert_eq!(device.device_type.as_deref(), Some("PC/Windows"));
        }

        // 5. HP Option 60 Fingerprint
        let packet_hp60 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 105)),
            parameter_request_list: None,
            vendor_class_id: Some("Hewlett-Packard JetDirect".to_string()),
        };
        tracker.update_from_dhcpv4(&packet_hp60);
        {
            let device = tracker.devices.get("55:66:77:88:99:aa").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("HP"));
            assert_eq!(device.device_type.as_deref(), Some("Printer"));
        }

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn test_parse_arp_packet() {
        let mut frame = vec![0u8; 42];
        // Ethernet Header
        // Destination MAC (Broadcast)
        frame[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC (00:11:22:33:44:55)
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType ARP (0x0806)
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        // ARP Packet
        // Hardware type: Ethernet (0x0001)
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        // Protocol type: IPv4 (0x0800)
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        // Hardware size (6)
        frame[18] = 6;
        // Protocol size (4)
        frame[19] = 4;
        // Opcode: Request (0x0001)
        frame[20..22].copy_from_slice(&[0x00, 0x01]);
        // Sender MAC: 00:11:22:33:44:55
        frame[22..28].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender IP: 192.168.1.50
        frame[28..32].copy_from_slice(&[192, 168, 1, 50]);
        // Target MAC: 00:00:00:00:00:00
        frame[32..38].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Target IP: 192.168.1.1
        frame[38..42].copy_from_slice(&[192, 168, 1, 1]);

        let result = process_ethernet_frame_extended(&frame);
        assert!(result.is_some());
        match result.unwrap() {
            NetworkEvent::Arp {
                source_mac,
                source_ip,
            } => {
                assert_eq!(source_mac, "00:11:22:33:44:55");
                assert_eq!(
                    source_ip,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50))
                );
            }
            _ => panic!("Expected NetworkEvent::Arp"),
        }
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_llmnr_packet() {
        let mut payload = vec![0u8; 30];
        payload[0..2].copy_from_slice(&[0x12, 0x34]); // Transaction ID
        payload[2..4].copy_from_slice(&[0x80, 0x00]); // Response flag
        payload[4..6].copy_from_slice(&[0x00, 0x00]); // Questions: 0
        payload[6..8].copy_from_slice(&[0x00, 0x01]); // Answer RRs: 1
        payload[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Answer Section: Name "myhost", Type A, Class IN, TTL 30, Data 192.168.1.100
        payload[12] = 6;
        payload[13..19].copy_from_slice(b"myhost");
        payload[19] = 0;
        payload[20..22].copy_from_slice(&[0x00, 0x01]); // Type A (1)
        payload[22..24].copy_from_slice(&[0x00, 0x01]); // Class IN (1)
        payload[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL 30
        payload[28..30].copy_from_slice(&[0x00, 0x04]); // RDLength 4
        let mut full_payload = payload;
        full_payload.extend_from_slice(&[192, 168, 1, 100]); // RData: IP 192.168.1.100

        let result = parse_mdns_payload(
            &full_payload,
            "00:11:22:33:44:55".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252)),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "00:11:22:33:44:55");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.answers[0].name, "myhost");

        // Test update_from_llmnr
        let temp_path = "/tmp/lanwatch_test_llmnr.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let updated = tracker.update_from_llmnr(&packet);
        assert_eq!(updated, 2);
        let dev = tracker.devices.get("00:11:22:33:44:55").unwrap();
        assert_eq!(dev.hostname.as_deref(), Some("myhost"));
        let _ = std::fs::remove_file(temp_path);
    }
}

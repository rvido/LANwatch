// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

#![cfg(feature = "mdns")]

use std::net::{Ipv4Addr, Ipv6Addr};

/// mDNS port (same for queries and responses)
pub const MDNS_PORT: u16 = 5353;

/// LLMNR port
pub const LLMNR_PORT: u16 = 5355;

/// mDNS IPv4 multicast address
pub const MDNS_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS IPv6 multicast address
pub const MDNS_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// DNS record types relevant for mDNS
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
        /// Priority of the target host
        priority: u16,
        /// Weight for entries with the same priority
        weight: u16,
        /// Port on the target host for this service
        port: u16,
        /// Target host domain name
        target: String,
    },
    /// Text record (key=value pairs or raw strings)
    Txt(Vec<String>),
    /// Raw data for unknown record types
    Raw(Vec<u8>),
}

/// A parsed NetBIOS Name Service (NBNS) packet
#[derive(Debug, Clone)]
pub struct NbnsPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// NetBIOS name parsed from the packet
    pub name: String,
    /// NetBIOS name type suffix
    pub suffix: u8,
}

/// A parsed mDNS packet
#[derive(Debug, Clone)]
pub struct MdnsPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsQuestion {
    /// The name being queried
    pub name: String,
    /// The record type being requested
    pub record_type: MdnsRecordType,
}

impl MdnsPacket {
    /// Returns an iterator over every record in the packet (Answers, Authority, and Additional).
    pub fn all_records(&self) -> impl Iterator<Item = &MdnsRecord> {
        self.answers
            .iter()
            .chain(self.authority.iter())
            .chain(self.additional.iter())
    }

    /// Returns the records that describe the *sender* of this packet.
    ///
    /// For a response that is every record it carries. For a query it is not:
    /// the answer section of a query holds Known-Answer Suppression records
    /// (RFC 6762 s7.1), which describe the other hosts the querier has already
    /// heard from. Attributing those to the querier gives it a neighbour's
    /// name, services and model -- the reason a sprinkler controller ended up
    /// named after a Chromecast. The authority section (probe records,
    /// s8.2) and the additional section of a query do describe the sender, so
    /// they are kept.
    pub fn attribution_records(&self) -> impl Iterator<Item = &MdnsRecord> {
        let answers: &[MdnsRecord] = if self.is_response { &self.answers } else { &[] };
        answers
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
    /// A vector of tuples containing (host_name, ipv4_address). The name
    /// borrows from the packet rather than being cloned, matching
    /// [`MdnsPacket::get_service_instances`].
    pub fn get_ipv4_addresses(&self) -> Vec<(&str, Ipv4Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordData::A(addr) = &r.data {
                    Some((r.name.as_str(), *addr))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extracts all IPv6 addresses from AAAA records found in the packet.
    ///
    /// # Returns
    /// A vector of tuples containing (host_name, ipv6_address). The name
    /// borrows from the packet rather than being cloned, matching
    /// [`MdnsPacket::get_service_instances`].
    pub fn get_ipv6_addresses(&self) -> Vec<(&str, Ipv6Addr)> {
        self.all_records()
            .filter_map(|r| {
                if let MdnsRecordData::Aaaa(addr) = &r.data {
                    Some((r.name.as_str(), *addr))
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
pub fn is_mdns_ports(src: u16, dest: u16) -> bool {
    src == MDNS_PORT || dest == MDNS_PORT
}

/// Checks if a pair of UDP ports corresponds to standard LLMNR traffic (5355).
///
/// # Arguments
/// * `src` - UDP source port.
/// * `dest` - UDP destination port.
pub fn is_llmnr_ports(src: u16, dest: u16) -> bool {
    src == LLMNR_PORT || dest == LLMNR_PORT
}

/// NetBIOS Name Service port
pub const NBNS_PORT: u16 = 137;

/// Checks if a pair of UDP ports corresponds to standard NBNS traffic (137).
pub fn is_nbns_ports(src: u16, dest: u16) -> bool {
    src == NBNS_PORT || dest == NBNS_PORT
}

/// Decodes a NetBIOS encoded name from the payload starting at the given offset.
/// NetBIOS names are encoded as a length byte (usually 32) followed by 32 characters representing 16 bytes.
/// Returns the decoded String, the 16th byte suffix, and the next offset.
pub fn decode_netbios_name(payload: &[u8], offset: usize) -> Option<(String, u8, usize)> {
    if offset >= payload.len() {
        return None;
    }
    let len = payload[offset] as usize;
    if len != 32 || offset + 1 + len > payload.len() {
        return None;
    }
    let encoded = &payload[offset + 1..offset + 1 + len];
    let mut decoded = Vec::with_capacity(16);
    for i in 0..16 {
        let c1 = encoded[i * 2];
        let c2 = encoded[i * 2 + 1];
        if !(0x41..=0x50).contains(&c1) || !(0x41..=0x50).contains(&c2) {
            return None;
        }
        let b = ((c1 - 0x41) << 4) | (c2 - 0x41);
        decoded.push(b);
    }

    // Suffix is the 16th byte
    let suffix = decoded[15];

    // Convert the first 15 bytes to a trimmed ASCII string
    let name_bytes = &decoded[0..15];
    let name_str = std::str::from_utf8(name_bytes).ok()?;
    let name = name_str.trim().to_string();

    // Next offset is after the label and the zero terminator
    let next_offset = offset + 1 + len;
    if next_offset < payload.len() && payload[next_offset] == 0 {
        Some((name, suffix, next_offset + 1))
    } else {
        Some((name, suffix, next_offset))
    }
}

/// Parses a raw NetBIOS (NBNS) UDP payload into a structured `NbnsPacket`.
pub fn parse_nbns_payload(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<NbnsPacket> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qd_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let an_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut offset = 12;
    if !is_response {
        if qd_count > 0 {
            let (name, suffix, _) = decode_netbios_name(payload, offset)?;
            return Some(NbnsPacket {
                source_mac,
                source_ip,
                name,
                suffix,
            });
        }
    } else {
        for _ in 0..qd_count {
            let (_, _, next_offset) = decode_netbios_name(payload, offset)?;
            if next_offset + 4 <= payload.len() {
                offset = next_offset + 4; // Skip Type and Class
            } else {
                return None;
            }
        }
        if an_count > 0 && offset + 12 <= payload.len() {
            let (name, suffix, next_offset) = decode_netbios_name(payload, offset)?;
            offset = next_offset;
            if offset + 10 <= payload.len() {
                let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                offset += 4; // Skip Type and Class
                offset += 4; // Skip TTL
                let rdlength = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                if rtype == 0x0020 && rdlength >= 6 && offset + rdlength <= payload.len() {
                    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        payload[offset + 2],
                        payload[offset + 3],
                        payload[offset + 4],
                        payload[offset + 5],
                    ));
                    return Some(NbnsPacket {
                        source_mac,
                        source_ip: ip,
                        name,
                        suffix,
                    });
                } else {
                    return Some(NbnsPacket {
                        source_mac,
                        source_ip,
                        name,
                        suffix,
                    });
                }
            }
        }
    }
    None
}

/// Parses a raw mDNS UDP payload into a structured `MdnsPacket`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload.
/// * `source_mac` - The source MAC address, as raw bytes.
/// * `source_ip` - The sender's IP address.
/// * `dest_ip` - The destination IP address.
pub fn parse_mdns_payload(
    payload: &[u8],
    source_mac: [u8; 6],
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

/// Maximum number of compression-pointer jumps tolerated while decoding one
/// name. A legitimate name needs at most a handful; a hostile packet can chain
/// pointers until it runs out of address space. Capping the jump count keeps
/// the walk O(1)-bounded regardless of payload contents.
///
/// This replaces an earlier "have I visited this offset before?" set: that
/// only caught pointers that revisit an offset, so a chain descending through
/// fresh offsets slipped past it and cost a linear scan of the visited set per
/// hop -- quadratic in the chain length, and paid again for every record in
/// the packet.
const MAX_NAME_POINTER_JUMPS: usize = 64;

/// Maximum length of a decoded DNS name, per RFC 1035 s2.3.4. Bounds both the
/// output `String` and the number of labels a single name can contribute.
const MAX_NAME_LEN: usize = 255;

/// Parse a DNS name from the packet (handles compression)
pub(crate) fn parse_dns_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name_parts: Vec<&str> = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut return_offset = 0;
    let mut jumps = 0usize;
    let mut name_len = 0usize;

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
            if pointer >= payload.len() || pointer == offset {
                return None;
            }
            jumps += 1;
            if jumps > MAX_NAME_POINTER_JUMPS {
                return None;
            }
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

        // Account for the label plus the '.' that will join it.
        name_len += len + 1;
        if name_len > MAX_NAME_LEN {
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
                // `into_owned` moves the borrow through untouched when the
                // bytes are already valid UTF-8 (the normal case); `to_string`
                // would copy unconditionally.
                let s = String::from_utf8_lossy(&payload[pos..pos + str_len]).into_owned();
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

/// mDNS querier for active service discovery
pub struct MdnsQuerier {
    socket: std::net::UdpSocket,
}

impl MdnsQuerier {
    /// Creates a new mDNS querier and binds a UDP socket, optionally targeting a specific local interface IP.
    pub fn new(interface_ip: Option<std::net::Ipv4Addr>) -> std::io::Result<Self> {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let bind_ip = interface_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(bind_ip, 0))?;

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
            "_matter._tcp.local",           // Matter commissioned devices
            "_matter._udp.local",           // Matter operational/other devices
            "_matterc._udp.local",          // Matter commissionable devices
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

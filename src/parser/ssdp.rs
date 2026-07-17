// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

#![cfg(feature = "ssdp")]

use crate::types::{CdpPacket, DeviceType, LldpPacket, Vendor};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SSDP port used for discovery and responses
pub const SSDP_PORT: u16 = 1900;

/// SSDP IPv4 multicast address
pub const SSDP_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// SSDP IPv6 multicast address
pub const SSDP_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);

/// SSDP message types
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
#[derive(Debug, Clone)]
pub struct SsdpPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
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
#[derive(Debug, Clone)]
pub struct SsdpPacketView<'a> {
    /// Source MAC address
    pub source_mac: [u8; 6],
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

impl SsdpPacket {
    /// Creates a borrowed view of this packet.
    pub fn view(&self) -> SsdpPacketView<'_> {
        SsdpPacketView {
            source_mac: self.source_mac,
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
    pub fn detect_vendor_from_view(&self) -> Option<Vendor> {
        for rule in SSDP_VENDOR_RULES {
            if self.view_contains_any(rule.patterns) {
                return Some(rule.vendor.clone());
            }
        }
        None
    }

    /// Detect device type from SSDP fingerprints without allocating a combined string.
    pub fn detect_device_type_from_view(&self) -> Option<DeviceType> {
        for rule in SSDP_DEVICE_TYPE_RULES {
            let matches_any = self.view_contains_any(rule.any_patterns);
            let matches_extra =
                rule.extra_patterns.is_empty() || self.view_contains_any(rule.extra_patterns);
            if matches_any && matches_extra {
                return Some(rule.device_type.clone());
            }
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

struct SsdpVendorRule {
    patterns: &'static [&'static str],
    vendor: Vendor,
}

const SSDP_VENDOR_RULES: &[SsdpVendorRule] = &[
    SsdpVendorRule {
        patterns: &["apple", "airport", "airplay"],
        vendor: Vendor::Apple,
    },
    SsdpVendorRule {
        patterns: &["lenovo", "legion", "thinkpad", "ideapad", "yoga"],
        vendor: Vendor::Lenovo,
    },
    SsdpVendorRule {
        patterns: &["google", "chromecast", "android tv"],
        vendor: Vendor::Google,
    },
    SsdpVendorRule {
        patterns: &["amazon", "alexa", "fire tv"],
        vendor: Vendor::Amazon,
    },
    SsdpVendorRule {
        patterns: &["samsung"],
        vendor: Vendor::Samsung,
    },
    SsdpVendorRule {
        patterns: &["lg ", "lge"],
        vendor: Vendor::Lg,
    },
    SsdpVendorRule {
        patterns: &["sony"],
        vendor: Vendor::Sony,
    },
    SsdpVendorRule {
        patterns: &["roku"],
        vendor: Vendor::Roku,
    },
    SsdpVendorRule {
        patterns: &["sonos"],
        vendor: Vendor::Sonos,
    },
    SsdpVendorRule {
        patterns: &["microsoft", "windows"],
        vendor: Vendor::Microsoft,
    },
    SsdpVendorRule {
        patterns: &["philips", "hue"],
        vendor: Vendor::Philips,
    },
    SsdpVendorRule {
        patterns: &["netgear"],
        vendor: Vendor::Netgear,
    },
    SsdpVendorRule {
        patterns: &["tp-link", "tplink"],
        vendor: Vendor::TpLink,
    },
    SsdpVendorRule {
        patterns: &["ubiquiti", "unifi"],
        vendor: Vendor::Ubiquiti,
    },
    SsdpVendorRule {
        patterns: &["d-link"],
        vendor: Vendor::DLink,
    },
    SsdpVendorRule {
        patterns: &["bose"],
        vendor: Vendor::Bose,
    },
    SsdpVendorRule {
        patterns: &["denon"],
        vendor: Vendor::Denon,
    },
    SsdpVendorRule {
        patterns: &["yamaha"],
        vendor: Vendor::Yamaha,
    },
    SsdpVendorRule {
        patterns: &["synology"],
        vendor: Vendor::Synology,
    },
    SsdpVendorRule {
        patterns: &["qnap"],
        vendor: Vendor::Qnap,
    },
];

struct SsdpDeviceTypeRule {
    any_patterns: &'static [&'static str],
    extra_patterns: &'static [&'static str],
    device_type: DeviceType,
}

const SSDP_DEVICE_TYPE_RULES: &[SsdpDeviceTypeRule] = &[
    SsdpDeviceTypeRule {
        any_patterns: &["mediarenderer", "renderer"],
        extra_patterns: &[],
        device_type: DeviceType::MediaRenderer,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["lenovo", "legion", "thinkpad", "ideapad", "yoga"],
        extra_patterns: &[],
        device_type: DeviceType::Laptop,
    },
    SsdpDeviceTypeRule {
        any_patterns: &[
            "googlecast",
            "dial-multiscreen-org",
            "internetgatewaydevice",
        ],
        extra_patterns: &["windows", "rvd_", "pc", "lenovo", "legion"],
        device_type: DeviceType::Laptop,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["mediaserver"],
        extra_patterns: &[],
        device_type: DeviceType::MediaServer,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["internetgatewaydevice", "wanconnectiondevice", "router"],
        extra_patterns: &[],
        device_type: DeviceType::Router,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["printer", "print"],
        extra_patterns: &[],
        device_type: DeviceType::Printer,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["scanner"],
        extra_patterns: &[],
        device_type: DeviceType::Scanner,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["television", "tvdevice", "smarttv"],
        extra_patterns: &[],
        device_type: DeviceType::Tv,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["camera", "ipcamera"],
        extra_patterns: &[],
        device_type: DeviceType::IpCamera,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["speaker", "soundbar"],
        extra_patterns: &[],
        device_type: DeviceType::Speaker,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["gameconsole", "xbox", "playstation"],
        extra_patterns: &[],
        device_type: DeviceType::GamingConsole,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["set-top", "settop"],
        extra_patterns: &[],
        device_type: DeviceType::SetTopBox,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["nas", "storage"],
        extra_patterns: &[],
        device_type: DeviceType::Nas,
    },
    SsdpDeviceTypeRule {
        any_patterns: &["bridge", "light", "bulb", "homekit"],
        extra_patterns: &[],
        device_type: DeviceType::SmartHomeDevice,
    },
];

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
pub struct SsdpQuerier {
    socket: std::net::UdpSocket,
}

impl SsdpQuerier {
    /// Creates a new SSDP querier and binds a UDP socket, optionally targeting a specific local interface IP.
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
pub fn is_ssdp_ports(src: u16, dest: u16) -> bool {
    src == SSDP_PORT || dest == SSDP_PORT
}

/// WS-Discovery port
pub const WSD_PORT: u16 = 3702;

/// Checks if a pair of UDP ports corresponds to standard WSD traffic (3702).
pub fn is_wsd_ports(src: u16, dest: u16) -> bool {
    src == WSD_PORT || dest == WSD_PORT
}

/// A parsed WS-Discovery packet
#[derive(Debug, Clone)]
pub struct WsdPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Detected device type (if any)
    pub device_type: Option<DeviceType>,
    /// Detected vendor (if any)
    pub vendor: Option<Vendor>,
}

/// Parses a raw WS-Discovery UDP payload into a structured `WsdPacket`.
pub fn parse_wsd_payload(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<WsdPacket> {
    let max_len = std::cmp::min(payload.len(), 8192);
    let s = std::str::from_utf8(&payload[..max_len]).ok()?;

    if !s.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery") {
        return None;
    }

    let mut device_type = None;
    let mut vendor = None;

    if s.contains("NetworkVideoTransmitter") {
        device_type = Some(DeviceType::IpCamera);
        vendor = Some(Vendor::Onvif);
    } else if s.contains("PrintDevice") || s.contains("Printer") {
        device_type = Some(DeviceType::Printer);
    } else if s.contains("Computer") {
        device_type = Some(DeviceType::PcComputer);
    }

    if let Some((start, end)) = s
        .find("<pub:ModelName>")
        .and_then(|start| s[start..].find("</pub:ModelName>").map(|end| (start, end)))
    {
        let model = &s[start + 15..start + end].trim();
        if !model.is_empty() {
            let m = model.to_lowercase();
            if m.contains("canon") {
                vendor = Some(Vendor::Canon);
            } else if m.contains("hp") {
                vendor = Some(Vendor::Hp);
            } else if m.contains("epson") {
                vendor = Some(Vendor::Epson);
            } else if m.contains("brother") {
                vendor = Some(Vendor::Brother);
            }
        }
    }

    if device_type.is_some() || vendor.is_some() {
        Some(WsdPacket {
            source_mac,
            source_ip,
            device_type,
            vendor,
        })
    } else {
        None
    }
}

/// Parses a raw SSDP/UPnP UDP payload into a structured `SsdpPacket`.
///
/// # Arguments
/// * `payload` - The raw bytes of the UDP payload.
/// * `source_mac` - The source MAC address, as raw bytes.
/// * `source_ip` - The sender's IP address.
/// * `dest_ip` - The destination IP address.
pub fn parse_ssdp_payload(
    payload: &[u8],
    source_mac: [u8; 6],
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

#[inline(always)]
fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

/// Parses an LLDP (Link Layer Discovery Protocol) Ethernet payload.
///
/// Returns a parsed `LldpPacket` on success, or `None` if parsing fails or crucial TLVs are missing.
pub fn parse_lldp_payload(payload: &[u8], source_mac: [u8; 6]) -> Option<LldpPacket> {
    let mut system_name = None;
    let mut system_description = None;
    let mut port_id = None;
    let mut management_address = None;

    let mut offset = 0;
    let mut loops = 0;

    while offset + 2 <= payload.len() && loops < 100 {
        loops += 1;
        let header = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01FF) as usize;

        offset += 2;
        if offset + tlv_len > payload.len() {
            break;
        }

        let value = &payload[offset..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            0 => {
                // End of LLDPDU
                break;
            }
            2 => {
                // Port ID.
                if value.len() > 1 {
                    let subtype = value[0];
                    let port_bytes = &value[1..];
                    let p_id = match subtype {
                        3 if port_bytes.len() == 6 => {
                            format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                port_bytes[0],
                                port_bytes[1],
                                port_bytes[2],
                                port_bytes[3],
                                port_bytes[4],
                                port_bytes[5]
                            )
                        }
                        _ => String::from_utf8_lossy(port_bytes).trim().to_string(),
                    };
                    if !p_id.is_empty() {
                        port_id = Some(p_id);
                    }
                }
            }
            5 => {
                // System Name
                let name = String::from_utf8_lossy(value).trim().to_string();
                if !name.is_empty() {
                    system_name = Some(name);
                }
            }
            6 => {
                // System Description
                let desc = String::from_utf8_lossy(value).trim().to_string();
                if !desc.is_empty() {
                    system_description = Some(desc);
                }
            }
            8 if value.len() >= 2 => {
                // Management Address
                let addr_str_len = value[0] as usize;
                if addr_str_len >= 1 && addr_str_len <= value.len() {
                    let subtype = value[1];
                    if 2 + (addr_str_len - 1) <= value.len() {
                        let addr_bytes = &value[2..2 + (addr_str_len - 1)];
                        if subtype == 1 && addr_bytes.len() == 4 {
                            management_address = Some(IpAddr::V4(Ipv4Addr::new(
                                addr_bytes[0],
                                addr_bytes[1],
                                addr_bytes[2],
                                addr_bytes[3],
                            )));
                        } else if subtype == 2 && addr_bytes.len() == 16 {
                            let mut ipv6_bytes = [0u8; 16];
                            ipv6_bytes.copy_from_slice(addr_bytes);
                            management_address = Some(IpAddr::V6(Ipv6Addr::from(ipv6_bytes)));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Some(LldpPacket {
        source_mac,
        system_name,
        system_description,
        port_id,
        management_address,
    })
}

/// Parses a CDP (Cisco Discovery Protocol) Ethernet payload.
///
/// Returns a parsed `CdpPacket` on success, or `None` if parsing fails or crucial fields are missing.
pub fn parse_cdp_payload(payload: &[u8], source_mac: [u8; 6]) -> Option<CdpPacket> {
    if payload.len() < 4 {
        return None;
    }

    let mut device_id = None;
    let mut software_version = None;
    let mut port_id = None;
    let mut platform = None;
    let mut management_address = None;

    let mut offset = 4;
    let mut loops = 0;

    while offset + 4 <= payload.len() && loops < 100 {
        loops += 1;
        let tlv_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;

        if tlv_len < 4 {
            break;
        }

        if offset + tlv_len > payload.len() {
            break;
        }

        let value = &payload[offset + 4..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            1 => {
                // Device ID
                let d_id = String::from_utf8_lossy(value).trim().to_string();
                if !d_id.is_empty() {
                    device_id = Some(d_id);
                }
            }
            2 => {
                // Address
                if value.len() >= 4 {
                    let num_addresses =
                        u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as usize;
                    let mut addr_offset = 4;
                    let mut address_loops = 0;
                    while addr_offset < value.len()
                        && address_loops < num_addresses
                        && address_loops < 100
                    {
                        address_loops += 1;
                        if addr_offset + 1 > value.len() {
                            break;
                        }
                        let pt_len = value[addr_offset] as usize;
                        addr_offset += 1;

                        if addr_offset + pt_len > value.len() {
                            break;
                        }
                        let pt = &value[addr_offset..addr_offset + pt_len];
                        addr_offset += pt_len;

                        if addr_offset + 2 > value.len() {
                            break;
                        }
                        let addr_len =
                            u16::from_be_bytes([value[addr_offset], value[addr_offset + 1]])
                                as usize;
                        addr_offset += 2;

                        if addr_offset + addr_len > value.len() {
                            break;
                        }
                        let addr_bytes = &value[addr_offset..addr_offset + addr_len];
                        addr_offset += addr_len;

                        if pt_len == 1 && (pt[0] == 0xcc || pt[0] == 0x01) && addr_len == 4 {
                            management_address = Some(IpAddr::V4(Ipv4Addr::new(
                                addr_bytes[0],
                                addr_bytes[1],
                                addr_bytes[2],
                                addr_bytes[3],
                            )));
                            break;
                        } else if pt_len == 1 && pt[0] == 0x8e && addr_len == 16 {
                            let mut ipv6_bytes = [0u8; 16];
                            ipv6_bytes.copy_from_slice(addr_bytes);
                            management_address = Some(IpAddr::V6(Ipv6Addr::from(ipv6_bytes)));
                            break;
                        }
                    }
                }
            }
            3 => {
                // Port ID
                let p_id = String::from_utf8_lossy(value).trim().to_string();
                if !p_id.is_empty() {
                    port_id = Some(p_id);
                }
            }
            5 => {
                // Software Version
                let ver = String::from_utf8_lossy(value).trim().to_string();
                if !ver.is_empty() {
                    software_version = Some(ver);
                }
            }
            6 => {
                // Platform
                let plat = String::from_utf8_lossy(value).trim().to_string();
                if !plat.is_empty() {
                    platform = Some(plat);
                }
            }
            _ => {}
        }
    }

    Some(CdpPacket {
        source_mac,
        device_id,
        software_version,
        port_id,
        platform,
        management_address,
    })
}

// Aliases for compatibility
pub use parse_cdp_payload as parse_cdp_packet;
pub use parse_lldp_payload as parse_lldp_packet;

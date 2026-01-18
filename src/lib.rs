// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// DHCPsniff - A DHCP (v4 & v6) network traffic sniffer
// See LICENSE file for details.

//! # dhcpsniff
//!
//! A library for parsing and sniffing DHCP (v4 & v6) network traffic.
//!
//! ## Example
//!
//! ```no_run
//! use dhcpsniff::{DhcpSniffer, DhcpEvent};
//!
//! let mut sniffer = DhcpSniffer::new("en0").expect("Failed to create sniffer");
//!
//! // Process packets with a callback
//! sniffer.run(|event| {
//!     println!("Received: {:?}", event);
//!     true // continue sniffing
//! });
//! ```

use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::SystemTime;

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
}

impl Dhcpv4Packet {
    /// Format the client MAC address as a string
    pub fn client_mac_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
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
    /// Format the transaction ID as a hex string
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

/// Returns a list of available network interface names
pub fn list_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}

/// Find a network interface by name
pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

/// Parse a DHCPv4 payload into structured data
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
            53 => {
                // DHCP Message Type
                if !value.is_empty() {
                    message_type = Some(Dhcpv4MessageType::from(value[0]));
                }
            }
            12 => {
                // Hostname
                if let Ok(h) = std::str::from_utf8(value) {
                    hostname = Some(h.to_string());
                }
            }
            50 => {
                // Requested IP Address
                if value.len() == 4 {
                    requested_ip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
            }
            _ => {}
        }
        index += 2 + len;
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
    })
}

/// Parse a DHCPv6 payload into structured data
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
                if let Ok(fqdn) = std::str::from_utf8(value) {
                    Dhcpv6Option::ClientFqdn(fqdn.to_string())
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

/// Check if UDP ports indicate DHCPv4 traffic
pub fn is_dhcpv4_ports(src: u16, dest: u16) -> bool {
    src == DHCPV4_SERVER_PORT
        || src == DHCPV4_CLIENT_PORT
        || dest == DHCPV4_SERVER_PORT
        || dest == DHCPV4_CLIENT_PORT
}

/// Check if UDP ports indicate DHCPv6 traffic
pub fn is_dhcpv6_ports(src: u16, dest: u16) -> bool {
    src == DHCPV6_CLIENT_PORT
        || src == DHCPV6_SERVER_PORT
        || dest == DHCPV6_CLIENT_PORT
        || dest == DHCPV6_SERVER_PORT
}

/// Process an Ethernet frame and extract DHCP event if present
pub fn process_ethernet_frame(frame: &[u8]) -> Option<DhcpEvent> {
    let ethernet = EthernetPacket::new(frame)?;

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => process_ipv4_packet(&ethernet),
        EtherTypes::Ipv6 => process_ipv6_packet(&ethernet),
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

/// DHCP packet sniffer
pub struct DhcpSniffer {
    interface_name: String,
    rx: Box<dyn DataLinkReceiver>,
}

impl DhcpSniffer {
    /// Create a new DHCP sniffer for the specified interface
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

    /// Get the interface name
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Read the next packet and return a DHCP event if it's a DHCP packet
    pub fn next_packet(&mut self) -> Result<Option<DhcpEvent>, DhcpError> {
        match self.rx.next() {
            Ok(packet) => Ok(process_ethernet_frame(packet)),
            Err(e) => Err(DhcpError::ParseError(e.to_string())),
        }
    }

    /// Run the sniffer with a callback for each DHCP event
    /// The callback should return `true` to continue sniffing, `false` to stop
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

// ============================================================================
// Device Tracking and CSV Export
// ============================================================================

/// Information about a detected DHCP device
use serde::{Deserialize, Serialize};

/// Information about a detected DHCP device
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// MAC address of the device
    pub mac_address: String,
    /// IP address (IPv4 or IPv6)
    pub ip_address: String,
    /// Hostname if available
    pub hostname: Option<String>,
    /// First seen timestamp (ISO 8601 format)
    pub first_seen: String,
    /// Last seen timestamp (ISO 8601 format)
    pub last_seen: String,
}

impl DeviceInfo {
    /// Create a new DeviceInfo with current timestamp
    pub fn new(mac_address: String, ip_address: String, hostname: Option<String>) -> Self {
        let timestamp = format_timestamp(SystemTime::now());
        Self {
            mac_address,
            ip_address,
            hostname,
            first_seen: timestamp.clone(),
            last_seen: timestamp,
        }
    }

    /// Update the device info if something changed, returns true if updated
    pub fn update(&mut self, ip_address: &str, hostname: Option<&str>) -> bool {
        let mut changed = false;
        let timestamp = format_timestamp(SystemTime::now());

        if self.ip_address != ip_address {
            self.ip_address = ip_address.to_string();
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

    /// Convert to CSV line
    pub fn to_csv_line(&self) -> String {
        format!(
            "{},{},{},\"{}\",{}",
            self.last_seen,
            self.mac_address,
            self.ip_address,
            self.hostname.as_deref().unwrap_or(""),
            self.first_seen
        )
    }

    /// Parse from CSV line
    pub fn from_csv_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 4 {
            return None;
        }

        let last_seen = parts[0].to_string();
        let mac_address = parts[1].to_string();
        let ip_address = parts[2].to_string();
        let hostname = parts[3].trim_matches('"').to_string();
        let hostname = if hostname.is_empty() {
            None
        } else {
            Some(hostname)
        };
        let first_seen = if parts.len() > 4 {
            parts[4].to_string()
        } else {
            last_seen.clone()
        };

        Some(Self {
            mac_address,
            ip_address,
            hostname,
            first_seen,
            last_seen,
        })
    }
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

/// Device tracker that maintains a list of seen devices and saves to CSV
pub struct DeviceTracker {
    devices: HashMap<String, DeviceInfo>,
    csv_path: String,
}

impl DeviceTracker {
    /// Create a new device tracker with the specified CSV file path
    pub fn new<P: AsRef<Path>>(csv_path: P) -> std::io::Result<Self> {
        let csv_path = csv_path.as_ref().to_string_lossy().to_string();
        let mut tracker = Self {
            devices: HashMap::new(),
            csv_path,
        };

        // Load existing data if file exists
        tracker.load_from_csv()?;

        Ok(tracker)
    }

    /// Load devices from existing CSV file
    fn load_from_csv(&mut self) -> std::io::Result<()> {
        let path = Path::new(&self.csv_path);
        if !path.exists() {
            return Ok(());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            // Skip header
            if line.starts_with("timestamp,") || line.starts_with("last_seen,") {
                continue;
            }
            if let Some(device) = DeviceInfo::from_csv_line(&line) {
                self.devices.insert(device.mac_address.clone(), device);
            }
        }

        Ok(())
    }

    /// Save all devices to CSV file
    pub fn save_to_csv(&self) -> std::io::Result<()> {
        let mut file = File::create(&self.csv_path)?;

        // Write header
        writeln!(file, "last_seen,mac_address,ip_address,hostname,first_seen")?;

        // Write devices sorted by last_seen
        let mut devices: Vec<_> = self.devices.values().collect();
        devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        for device in devices {
            writeln!(file, "{}", device.to_csv_line())?;
        }

        Ok(())
    }

    /// Update or add a device from a DHCPv4 packet
    /// Returns true if the device was new or updated
    pub fn update_from_dhcpv4(&mut self, packet: &Dhcpv4Packet) -> bool {
        let mac = packet.client_mac_string();

        // Determine IP address - use requested_ip if available, otherwise use source
        let ip = packet
            .requested_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| {
                if packet.source_ip != Ipv4Addr::new(0, 0, 0, 0) {
                    packet.source_ip.to_string()
                } else {
                    "0.0.0.0".to_string()
                }
            });

        self.update_device(&mac, &ip, packet.hostname.as_deref())
    }

    /// Update or add a device from a DHCPv6 packet
    /// Returns true if the device was new or updated
    pub fn update_from_dhcpv6(&mut self, packet: &Dhcpv6Packet) -> bool {
        // For DHCPv6, we use client DUID as identifier (converted to hex string)
        let mut duid = None;
        let mut fqdn = None;

        for option in &packet.options {
            match option {
                Dhcpv6Option::ClientId(data) => {
                    duid = Some(
                        data.iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(":"),
                    );
                }
                Dhcpv6Option::ClientFqdn(name) => {
                    fqdn = Some(name.as_str());
                }
                _ => {}
            }
        }

        // If no DUID, we can't track this device
        let mac = match duid {
            Some(d) => d,
            None => return false,
        };

        let ip = packet.source_ip.to_string();
        self.update_device(&mac, &ip, fqdn)
    }

    /// Update or add a device
    fn update_device(&mut self, mac: &str, ip: &str, hostname: Option<&str>) -> bool {
        if let Some(device) = self.devices.get_mut(mac) {
            let changed = device.update(ip, hostname);
            // Always rewrite CSV to update timestamp and avoid duplicates
            let _ = self.save_to_csv();
            changed
        } else {
            // New device
            let device = DeviceInfo::new(
                mac.to_string(),
                ip.to_string(),
                hostname.map(|s| s.to_string()),
            );
            self.devices.insert(mac.to_string(), device);
            // Rewrite CSV to ensure clean state
            let _ = self.save_to_csv();
            true
        }
    }

    /// Get all tracked devices
    pub fn devices(&self) -> &HashMap<String, DeviceInfo> {
        &self.devices
    }

    /// Get device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get the CSV file path
    pub fn csv_path(&self) -> &str {
        &self.csv_path
    }

    /// Get all devices as a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let devices: Vec<&DeviceInfo> = self.devices.values().collect();
        serde_json::to_string_pretty(&devices)
    }

    /// Get all devices as a JSON array sorted by last_seen (most recent first)
    pub fn to_json_sorted(&self) -> Result<String, serde_json::Error> {
        let mut devices: Vec<&DeviceInfo> = self.devices.values().collect();
        devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        serde_json::to_string_pretty(&devices)
    }
}

// ============================================================================
// HTTP API Server
// ============================================================================

use std::sync::{Arc, RwLock};
use std::thread;
use tiny_http::{Response, Server};

/// HTTP API server for exposing device data
pub struct ApiServer {
    server: Server,
    tracker: Arc<RwLock<DeviceTracker>>,
}

/// API response structure
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    count: usize,
    data: T,
}

/// Error response structure
#[derive(Serialize)]
struct ApiError {
    success: bool,
    error: String,
}

impl ApiServer {
    /// Create a new API server on the specified address (e.g., "0.0.0.0:8080")
    pub fn new(addr: &str, tracker: Arc<RwLock<DeviceTracker>>) -> std::io::Result<Self> {
        let server = Server::http(addr).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?;
        Ok(Self { server, tracker })
    }

    /// Run the API server (blocking)
    pub fn run(&self) {
        println!("API server listening on http://{}", self.server.server_addr());
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
            _ => self.handle_not_found(),
        }
    }

    fn handle_devices(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                let mut devices: Vec<&DeviceInfo> = tracker.devices().values().collect();
                devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                
                let response = ApiResponse {
                    success: true,
                    count: devices.len(),
                    data: devices,
                };
                
                let json = serde_json::to_string_pretty(&response).unwrap_or_default();
                Response::from_string(json)
                    .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
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
                Response::from_string(json.to_string())
                    .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
            }
            Err(_) => self.handle_error("Failed to read device count"),
        }
    }

    fn handle_health(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "status": "ok",
            "service": "dhcpsniff"
        });
        Response::from_string(json.to_string())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_root(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "service": "dhcpsniff",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": {
                "/devices": "GET - List all detected devices",
                "/devices/count": "GET - Get device count",
                "/health": "GET - Health check"
            }
        });
        Response::from_string(serde_json::to_string_pretty(&json).unwrap_or_default())
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

/// Start the API server in a background thread
pub fn start_api_server(addr: &str, tracker: Arc<RwLock<DeviceTracker>>) -> std::io::Result<thread::JoinHandle<()>> {
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
        assert_eq!(
            Dhcpv6MessageType::from(11),
            Dhcpv6MessageType::InfoRequest
        );
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
        assert_eq!(
            packet.client_mac_string(),
            "AA:BB:CC:DD:EE:FF"
        );
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

        let result = parse_dhcpv6_payload(
            &payload,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            546,
            547,
        );

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
            0x01,       // Message type: SOLICIT
            0xAB, 0xCD, 0xEF, // Transaction ID
            0x00, 0x01, // Option code: 1 (Client ID)
            0x00, 0x04, // Length: 4
            0xDE, 0xAD, 0xBE, 0xEF, // Client ID data
        ];

        let result = parse_dhcpv6_payload(
            &payload,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            546,
            547,
        );

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
            "AA:BB:CC:DD:EE:FF".to_string(),
            "192.168.1.100".to_string(),
            Some("testhost".to_string()),
        );

        assert_eq!(device.mac_address, "AA:BB:CC:DD:EE:FF");
        assert_eq!(device.ip_address, "192.168.1.100");
        assert_eq!(device.hostname, Some("testhost".to_string()));
        assert!(!device.first_seen.is_empty());
        assert_eq!(device.first_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_csv_roundtrip() {
        let device = DeviceInfo {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: "192.168.1.100".to_string(),
            hostname: Some("testhost".to_string()),
            first_seen: "2026-01-15T10:00:00Z".to_string(),
            last_seen: "2026-01-15T12:00:00Z".to_string(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.hostname, device.hostname);
        assert_eq!(parsed.first_seen, device.first_seen);
        assert_eq!(parsed.last_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_csv_no_hostname() {
        let device = DeviceInfo {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: "192.168.1.100".to_string(),
            hostname: None,
            first_seen: "2026-01-15T10:00:00Z".to_string(),
            last_seen: "2026-01-15T12:00:00Z".to_string(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.hostname, None);
    }

    #[test]
    fn test_device_info_update() {
        let mut device = DeviceInfo {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: "192.168.1.100".to_string(),
            hostname: None,
            first_seen: "2026-01-15T10:00:00Z".to_string(),
            last_seen: "2026-01-15T10:00:00Z".to_string(),
        };

        // Update with new IP - should return true
        let changed = device.update("192.168.1.200", None);
        assert!(changed);
        assert_eq!(device.ip_address, "192.168.1.200");

        // Update with same IP - should return false
        let changed = device.update("192.168.1.200", None);
        assert!(!changed);

        // Update with hostname - should return true
        let changed = device.update("192.168.1.200", Some("newhost"));
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
        let temp_path = "/tmp/dhcpsniff_test_devices.csv";
        let _ = std::fs::remove_file(temp_path); // Clean up any existing file

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
    }
}

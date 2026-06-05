// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking

use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "ssdp")]
use std::net::IpAddr;

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
    /// Vendor specific info (Option 43, from options)
    pub vendor_specific_info: Option<String>,
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
    UserClass(Vec<String>),
    VendorClass {
        enterprise_number: u32,
        data: Vec<String>,
    },
    Other {
        code: u16,
        data: Vec<u8>,
    },
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

#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct LldpPacket {
    pub source_mac: String,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_id: Option<String>,
    pub management_address: Option<IpAddr>,
}

#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct CdpPacket {
    pub source_mac: String,
    pub device_id: Option<String>,
    pub software_version: Option<String>,
    pub port_id: Option<String>,
    pub platform: Option<String>,
    pub management_address: Option<IpAddr>,
}

// Forward declarations for mDNS and SSDP types which will be defined in other modules
// We import/re-export them or define them directly here.
// Since these are re-exported in lib.rs, we import them from the respective modules:
#[cfg(feature = "mdns")]
pub use crate::parser::mdns::{MdnsPacket, NbnsPacket};
#[cfg(feature = "ssdp")]
pub use crate::parser::ssdp::{SsdpPacket, WsdPacket};

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
    /// NetBIOS Name Service packet
    #[cfg(feature = "mdns")]
    Nbns(NbnsPacket),
    /// SSDP/UPnP packet
    #[cfg(feature = "ssdp")]
    Ssdp(SsdpPacket),
    /// WS-Discovery packet
    #[cfg(feature = "ssdp")]
    Wsd(WsdPacket),
    /// ARP packet
    Arp {
        source_mac: String,
        source_ip: std::net::IpAddr,
    },
    /// NDP packet (IPv6 Neighbor Discovery Protocol)
    Ndp {
        source_mac: String,
        source_ip: std::net::IpAddr,
    },
    /// LLDP packet (Link Layer Discovery Protocol)
    #[cfg(feature = "ssdp")]
    Lldp(LldpPacket),
    /// CDP packet (Cisco Discovery Protocol)
    #[cfg(feature = "ssdp")]
    Cdp(CdpPacket),
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

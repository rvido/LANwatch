// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
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
    /// DHCPDISCOVER message
    Discover,
    /// DHCPOFFER message
    Offer,
    /// DHCPREQUEST message
    Request,
    /// DHCPDECLINE message
    Decline,
    /// DHCPACK message
    Ack,
    /// DHCPNAK message
    Nak,
    /// DHCPRELEASE message
    Release,
    /// DHCPINFORM message
    Inform,
    /// Unknown or custom DHCP message type
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
    /// Message is a request from a client (BOOTREQUEST, value 1)
    BootRequest,
    /// Message is a reply from a server (BOOTREPLY, value 2)
    BootReply,
    /// Unknown or unsupported operation code
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
    /// SOLICIT message (value 1)
    Solicit,
    /// ADVERTISE message (value 2)
    Advertise,
    /// REQUEST message (value 3)
    Request,
    /// CONFIRM message (value 4)
    Confirm,
    /// RENEW message (value 5)
    Renew,
    /// REBIND message (value 6)
    Rebind,
    /// REPLY message (value 7)
    Reply,
    /// RELEASE message (value 8)
    Release,
    /// DECLINE message (value 9)
    Decline,
    /// RECONFIGURE message (value 10)
    Reconfigure,
    /// INFORMATION-REQUEST message (value 11)
    InfoRequest,
    /// Unknown DHCPv6 message type
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
    /// Client Identifier Option (Option 1)
    ClientId(Vec<u8>),
    /// Server Identifier Option (Option 2)
    ServerId(Vec<u8>),
    /// Identity Association for Non-temporary Addresses Option (Option 3)
    IaNa,
    /// Client Fully Qualified Domain Name Option (Option 39)
    ClientFqdn(String),
    /// User Class Option (Option 15)
    UserClass(Vec<String>),
    /// Vendor-performing Vendor Class Option (Option 16)
    VendorClass {
        /// Enterprise number identifying the vendor
        enterprise_number: u32,
        /// Vendor class data fields
        data: Vec<String>,
    },
    /// Any other DHCPv6 option that is not parsed specifically
    Other {
        /// The raw option code
        code: u16,
        /// The raw option data bytes
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
    /// A parsed DHCPv4 packet event
    V4(Dhcpv4Packet),
    /// A parsed DHCPv6 packet event
    V6(Dhcpv6Packet),
}

#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
/// Parsed LLDP packet containing system identity and capabilities.
pub struct LldpPacket {
    /// The source MAC address of the device transmitting the LLDP frame.
    pub source_mac: String,
    /// System name assigned to the transmitting device.
    pub system_name: Option<String>,
    /// Detailed system description of the transmitting device.
    pub system_description: Option<String>,
    /// The port identifier from which the packet was sent.
    pub port_id: Option<String>,
    /// The management IP address of the device, if advertised.
    pub management_address: Option<IpAddr>,
}

#[cfg(feature = "ssdp")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
/// Parsed CDP packet containing Cisco device identifier, software version, platform and details.
pub struct CdpPacket {
    /// The source MAC address of the device transmitting the CDP frame.
    pub source_mac: String,
    /// The configured device ID (usually hostname) of the transmitting device.
    pub device_id: Option<String>,
    /// The software version string running on the transmitting device.
    pub software_version: Option<String>,
    /// The physical port name/identifier from which the packet was sent.
    pub port_id: Option<String>,
    /// The hardware platform of the transmitting device.
    pub platform: Option<String>,
    /// The management IP address of the device, if advertised.
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
        /// Source MAC address from the ARP packet
        source_mac: String,
        /// Source IP address from the ARP packet
        source_ip: std::net::IpAddr,
    },
    /// NDP packet (IPv6 Neighbor Discovery Protocol)
    Ndp {
        /// Source MAC address from the NDP packet
        source_mac: String,
        /// Source IP address from the NDP packet
        source_ip: std::net::IpAddr,
    },
    /// LLDP packet (Link Layer Discovery Protocol)
    #[cfg(feature = "ssdp")]
    Lldp(LldpPacket),
    /// CDP packet (Cisco Discovery Protocol)
    #[cfg(feature = "ssdp")]
    Cdp(CdpPacket),
    /// LIFX smart device packet
    #[cfg(feature = "ssdp")]
    Lifx(crate::parser::iot::LifxPacket),
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

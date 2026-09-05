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

/// Formats a raw 6-byte MAC address as a lowercase colon-separated string
/// (e.g. "aa:bb:cc:dd:ee:ff").
///
/// Packet structs carry MAC addresses as `[u8; 6]` to avoid allocating on
/// every parsed frame; this is the single place that formatting happens,
/// typically only once a packet is confirmed useful (e.g. as a device
/// tracking key).
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parses a MAC address from text (colon-, dash-, or unseparated hex, e.g.
/// "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", or "aabbccddeeff") into raw bytes.
///
/// Returns `None` unless exactly 12 hex digits are present.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut nibbles = [0u8; 12];
    let mut count = 0;
    for c in text.chars() {
        if c.is_ascii_hexdigit() {
            if count >= 12 {
                return None;
            }
            nibbles[count] = c.to_digit(16)? as u8;
            count += 1;
        }
    }
    if count != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
    }
    Some(mac)
}

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

/// Known device manufacturer / vendor, detected from hostname patterns, DHCP fingerprints,
/// mDNS/SSDP service metadata, or OUI (MAC prefix) lookups.
///
/// The variant set covers vendors that are directly compared against elsewhere in the
/// codebase (e.g. to protect an "eero inc." classification from being overwritten). Any
/// vendor name that doesn't match a known variant — most notably the free-form manufacturer
/// strings returned by [`crate::oui::OuiRegistry`] — is preserved verbatim in `Other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vendor {
    /// Apple Inc.
    Apple,
    /// Google LLC
    Google,
    /// Amazon.com, Inc.
    Amazon,
    /// Microsoft Corporation
    Microsoft,
    /// Samsung Electronics
    Samsung,
    /// Sony Corporation
    Sony,
    /// LG Electronics
    Lg,
    /// Cisco Systems
    Cisco,
    /// Ubiquiti Inc.
    Ubiquiti,
    /// Netgear Inc.
    Netgear,
    /// TP-Link Technologies
    TpLink,
    /// Philips
    Philips,
    /// HP Inc.
    Hp,
    /// Canon Inc.
    Canon,
    /// Brother Industries
    Brother,
    /// Seiko Epson Corporation
    Epson,
    /// Lenovo Group
    Lenovo,
    /// Dell Technologies
    Dell,
    /// Asus
    Asus,
    /// Acer Inc.
    Acer,
    /// Motorola Mobility
    Motorola,
    /// Nintendo Co., Ltd.
    Nintendo,
    /// Belkin International
    Belkin,
    /// Espressif Systems
    Espressif,
    /// Raspberry Pi Foundation
    RaspberryPi,
    /// Synology Inc.
    Synology,
    /// Roborock
    Roborock,
    /// Rachio, Inc.
    Rachio,
    /// eero inc.
    Eero,
    /// NVIDIA Corporation
    Nvidia,
    /// Spotify AB
    Spotify,
    /// Generic Linux-based device
    Linux,
    /// Sonos, Inc.
    Sonos,
    /// Roku, Inc.
    Roku,
    /// D-Link Corporation
    DLink,
    /// Bose Corporation
    Bose,
    /// Denon
    Denon,
    /// Yamaha Corporation
    Yamaha,
    /// QNAP Systems
    Qnap,
    /// Ring LLC
    Ring,
    /// Yealink Network Technology
    Yealink,
    /// Polycom, Inc.
    Polycom,
    /// Mitel Networks
    Mitel,
    /// Avaya Inc.
    Avaya,
    /// Juniper Networks
    Juniper,
    /// TeamViewer Germany GmbH
    TeamViewer,
    /// AgileBits (1Password)
    OnePassword,
    /// Xiaomi Corporation
    Xiaomi,
    /// TiVo Inc.
    TiVo,
    /// KNX Association / generic KNX device
    Knx,
    /// LIFX
    Lifx,
    /// Hangzhou Hikvision Digital Technology
    Hikvision,
    /// Zhejiang Dahua Technology
    Dahua,
    /// ONVIF-conformant device (unspecified manufacturer)
    Onvif,
    /// Unidentified RTSP-capable camera (no vendor-specific discovery matched)
    GenericRtsp,
    /// Eve Systems
    EveSystems,
    /// Nanoleaf
    Nanoleaf,
    /// Aqara (Lumi United Technology)
    Aqara,
    /// Koogeek
    Koogeek,
    /// Belkin Wemo product line
    BelkinWemo,
    /// ecobee inc.
    Ecobee,
    /// Signify (Philips Hue)
    SignifyPhilipsHue,
    /// Plex, Inc.
    Plex,
    /// Inter IKEA Systems B.V.
    Ikea,
    /// Tuya Smart
    Tuya,
    /// Somfy
    Somfy,
    /// Lutron Electronics
    Lutron,
    /// Yale (Assa Abloy)
    Yale,
    /// Schneider Electric
    SchneiderElectric,
    /// Legrand
    LeGrand,
    /// Robert Bosch GmbH
    Bosch,
    /// Any other vendor name, preserved verbatim (e.g. a raw IEEE OUI manufacturer string).
    Other(String),
}

impl Vendor {
    /// Returns the canonical display string for this vendor.
    pub fn as_str(&self) -> &str {
        match self {
            Vendor::Apple => "Apple",
            Vendor::Google => "Google",
            Vendor::Amazon => "Amazon",
            Vendor::Microsoft => "Microsoft",
            Vendor::Samsung => "Samsung",
            Vendor::Sony => "Sony",
            Vendor::Lg => "LG",
            Vendor::Cisco => "Cisco",
            Vendor::Ubiquiti => "Ubiquiti",
            Vendor::Netgear => "Netgear",
            Vendor::TpLink => "TP-Link",
            Vendor::Philips => "Philips",
            Vendor::Hp => "HP",
            Vendor::Canon => "Canon",
            Vendor::Brother => "Brother",
            Vendor::Epson => "Epson",
            Vendor::Lenovo => "Lenovo",
            Vendor::Dell => "Dell",
            Vendor::Asus => "Asus",
            Vendor::Acer => "Acer",
            Vendor::Motorola => "Motorola",
            Vendor::Nintendo => "Nintendo",
            Vendor::Belkin => "Belkin",
            Vendor::Espressif => "Espressif",
            Vendor::RaspberryPi => "Raspberry Pi",
            Vendor::Synology => "Synology",
            Vendor::Roborock => "Roborock",
            Vendor::Rachio => "Rachio",
            Vendor::Eero => "eero inc.",
            Vendor::Nvidia => "NVIDIA",
            Vendor::Spotify => "Spotify",
            Vendor::Linux => "Linux",
            Vendor::Sonos => "Sonos",
            Vendor::Roku => "Roku",
            Vendor::DLink => "D-Link",
            Vendor::Bose => "Bose",
            Vendor::Denon => "Denon",
            Vendor::Yamaha => "Yamaha",
            Vendor::Qnap => "QNAP",
            Vendor::Ring => "Ring",
            Vendor::Yealink => "Yealink",
            Vendor::Polycom => "Polycom",
            Vendor::Mitel => "Mitel",
            Vendor::Avaya => "Avaya",
            Vendor::Juniper => "Juniper",
            Vendor::TeamViewer => "TeamViewer",
            Vendor::OnePassword => "1Password",
            Vendor::Xiaomi => "Xiaomi",
            Vendor::TiVo => "TiVo",
            Vendor::Knx => "KNX",
            Vendor::Lifx => "LIFX",
            Vendor::Hikvision => "Hikvision",
            Vendor::Dahua => "Dahua",
            Vendor::Onvif => "ONVIF",
            Vendor::GenericRtsp => "Generic RTSP",
            Vendor::EveSystems => "Eve Systems",
            Vendor::Nanoleaf => "Nanoleaf",
            Vendor::Aqara => "Aqara",
            Vendor::Koogeek => "Koogeek",
            Vendor::BelkinWemo => "Belkin (Wemo)",
            Vendor::Ecobee => "ecobee",
            Vendor::SignifyPhilipsHue => "Signify (Philips Hue)",
            Vendor::Plex => "Plex",
            Vendor::Ikea => "IKEA",
            Vendor::Tuya => "Tuya",
            Vendor::Somfy => "Somfy",
            Vendor::Lutron => "Lutron",
            Vendor::Yale => "Yale",
            Vendor::SchneiderElectric => "Schneider Electric",
            Vendor::LeGrand => "LeGrand",
            Vendor::Bosch => "Bosch",
            Vendor::Other(s) => s.as_str(),
        }
    }

    /// Returns `true` if this vendor is eero inc. — several classification paths protect
    /// an eero classification from being overwritten by a weaker signal.
    pub fn is_eero(&self) -> bool {
        matches!(self, Vendor::Eero)
    }
}

impl std::fmt::Display for Vendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Vendor {
    fn from(value: &str) -> Self {
        match value {
            "Apple" => Vendor::Apple,
            "Google" => Vendor::Google,
            "Amazon" => Vendor::Amazon,
            "Microsoft" => Vendor::Microsoft,
            "Samsung" => Vendor::Samsung,
            "Sony" => Vendor::Sony,
            "LG" => Vendor::Lg,
            "Cisco" => Vendor::Cisco,
            "Ubiquiti" => Vendor::Ubiquiti,
            "Netgear" => Vendor::Netgear,
            "TP-Link" => Vendor::TpLink,
            "Philips" => Vendor::Philips,
            "HP" => Vendor::Hp,
            "Canon" => Vendor::Canon,
            "Brother" => Vendor::Brother,
            "Epson" => Vendor::Epson,
            "Lenovo" => Vendor::Lenovo,
            "Dell" => Vendor::Dell,
            "Asus" => Vendor::Asus,
            "Acer" => Vendor::Acer,
            "Motorola" => Vendor::Motorola,
            "Nintendo" => Vendor::Nintendo,
            "Belkin" => Vendor::Belkin,
            "Espressif" => Vendor::Espressif,
            "Raspberry Pi" => Vendor::RaspberryPi,
            "Synology" => Vendor::Synology,
            "Roborock" => Vendor::Roborock,
            "Rachio" => Vendor::Rachio,
            "eero inc." => Vendor::Eero,
            "NVIDIA" => Vendor::Nvidia,
            "Spotify" => Vendor::Spotify,
            "Linux" => Vendor::Linux,
            "Sonos" => Vendor::Sonos,
            "Roku" => Vendor::Roku,
            "D-Link" => Vendor::DLink,
            "Bose" => Vendor::Bose,
            "Denon" => Vendor::Denon,
            "Yamaha" => Vendor::Yamaha,
            "QNAP" => Vendor::Qnap,
            "Ring" => Vendor::Ring,
            "Yealink" => Vendor::Yealink,
            "Polycom" => Vendor::Polycom,
            "Mitel" => Vendor::Mitel,
            "Avaya" => Vendor::Avaya,
            "Juniper" => Vendor::Juniper,
            "TeamViewer" => Vendor::TeamViewer,
            "1Password" => Vendor::OnePassword,
            "Xiaomi" => Vendor::Xiaomi,
            "TiVo" => Vendor::TiVo,
            "KNX" => Vendor::Knx,
            "LIFX" => Vendor::Lifx,
            "Hikvision" => Vendor::Hikvision,
            "Dahua" => Vendor::Dahua,
            "ONVIF" => Vendor::Onvif,
            "Generic RTSP" => Vendor::GenericRtsp,
            "Eve Systems" => Vendor::EveSystems,
            "Nanoleaf" => Vendor::Nanoleaf,
            "Aqara" => Vendor::Aqara,
            "Koogeek" => Vendor::Koogeek,
            "Belkin (Wemo)" => Vendor::BelkinWemo,
            "ecobee" => Vendor::Ecobee,
            "Signify (Philips Hue)" => Vendor::SignifyPhilipsHue,
            "Plex" => Vendor::Plex,
            "IKEA" => Vendor::Ikea,
            "Tuya" => Vendor::Tuya,
            "Somfy" => Vendor::Somfy,
            "Lutron" => Vendor::Lutron,
            "Yale" => Vendor::Yale,
            "Schneider Electric" => Vendor::SchneiderElectric,
            "LeGrand" => Vendor::LeGrand,
            "Bosch" => Vendor::Bosch,
            other => Vendor::Other(other.to_string()),
        }
    }
}

impl From<String> for Vendor {
    fn from(value: String) -> Self {
        // Avoid re-allocating when the value doesn't match a known variant by
        // only falling back to an owned `Other` if `From<&str>` didn't consume it.
        match Vendor::from(value.as_str()) {
            Vendor::Other(_) => Vendor::Other(value),
            known => known,
        }
    }
}

impl serde::Serialize for Vendor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Vendor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Vendor::from(value))
    }
}

/// Known device category / type, detected from hostname patterns, DHCP fingerprints,
/// mDNS/SSDP service metadata, or protocol-specific discovery packets (LLDP, CDP, KNX,
/// CoAP, CCTV, ...).
///
/// Any device type that doesn't match a known variant is preserved verbatim in `Other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceType {
    /// Router
    Router,
    /// Combined router/switch
    RouterSwitch,
    /// Network switch
    Switch,
    /// Generic network infrastructure device
    NetworkDevice,
    /// Generic network equipment (router, switch, or access point)
    NetworkEquipment,
    /// Printer
    Printer,
    /// Scanner
    Scanner,
    /// Laptop computer
    Laptop,
    /// Desktop computer / workstation
    Desktop,
    /// Apple Mac desktop or laptop
    Mac,
    /// Windows PC
    PcWindows,
    /// Generic PC/computer
    PcComputer,
    /// Unspecified Apple device
    AppleDevice,
    /// Apple iPhone
    AppleIPhone,
    /// Apple iPad
    AppleIPad,
    /// Apple TV
    AppleTv,
    /// Google Pixel phone
    PixelPhone,
    /// Android phone
    AndroidPhone,
    /// Android TV
    AndroidTv,
    /// Generic mobile device
    Mobile,
    /// Generic mobile device (alternate classification path)
    MobileDevice,
    /// Media player (e.g. Roku)
    MediaPlayer,
    /// AirPlay/DLNA media streamer
    MediaStreamer,
    /// Media server (e.g. Plex, DAAP)
    MediaServer,
    /// UPnP/DLNA media renderer
    MediaRenderer,
    /// Google Chromecast
    Chromecast,
    /// Amazon Fire TV
    FireTv,
    /// Generic AirPlay-capable device
    AirPlayDevice,
    /// Smart speaker
    SmartSpeaker,
    /// Generic speaker
    Speaker,
    /// Generic audio device
    AudioDevice,
    /// Smart home device (unspecified category)
    SmartHomeDevice,
    /// Smart home hub
    SmartHomeHub,
    /// Smart doorbell
    SmartDoorbell,
    /// Video doorbell
    VideoDoorbell,
    /// Smart plug
    SmartPlug,
    /// Smart outlet
    Outlet,
    /// Smart light
    SmartLight,
    /// Smart lightbulb
    Lightbulb,
    /// Robotic vacuum / smart cleaning device
    SmartCleaningDevice,
    /// Smart irrigation / watering device
    SmartWateringDevice,
    /// Thermostat
    Thermostat,
    /// Security camera
    SecurityCamera,
    /// IP camera
    IpCamera,
    /// Security system / alarm panel
    SecuritySystem,
    /// Network-attached storage (labelled "Storage (NAS)")
    StorageNas,
    /// Network-attached storage (labelled "NAS")
    Nas,
    /// File server
    FileServer,
    /// Generic server
    Server,
    /// IP phone / VoIP handset
    IpPhone,
    /// Generic IoT device
    IotDevice,
    /// IoT beacon (e.g. Physical Web)
    IotBeacon,
    /// Single-board computer (unspecified)
    SingleBoardComputer,
    /// Raspberry Pi
    RaspberryPi,
    /// Microcontroller (e.g. Arduino)
    Microcontroller,
    /// E-reader
    EReader,
    /// Game console
    GameConsole,
    /// Gaming console (alternate classification path)
    GamingConsole,
    /// Gaming device (alternate classification path)
    GamingDevice,
    /// Gaming PC
    GamingPc,
    /// Digital video recorder
    Dvr,
    /// Continuous integration server
    CiServer,
    /// NVIDIA Shield
    NvidiaShield,
    /// Spotify Connect-enabled device
    SpotifyConnectDevice,
    /// Home automation device (e.g. KNX)
    HomeAutomation,
    /// Matter-compatible smart device
    MatterSmartDevice,
    /// Generic HomeKit device
    HomeKitDevice,
    /// HomeKit accessory
    HomeKitAccessory,
    /// Generic sensor
    Sensor,
    /// Humidity sensor
    HumiditySensor,
    /// Occupancy sensor
    OccupancySensor,
    /// Contact sensor
    ContactSensor,
    /// Air conditioner
    AirConditioner,
    /// Air purifier
    AirPurifier,
    /// Smart door lock
    DoorLock,
    /// Television
    Tv,
    /// Set-top box
    SetTopBox,
    /// HomeKit bridge accessory
    Bridge,
    /// Smart fan
    Fan,
    /// Smart garage door opener
    GarageDoor,
    /// Smart lock (HomeKit "Lock" category, distinct from `DoorLock`)
    Lock,
    /// Smart door sensor/opener (HomeKit "Door" category)
    Door,
    /// Smart window sensor/opener
    Window,
    /// Smart window covering (blinds/shades)
    WindowCovering,
    /// Smart heater
    Heater,
    /// Smart cooler
    Cooler,
    /// Smart humidifier
    Humidifier,
    /// Smart dehumidifier
    Dehumidifier,
    /// Smart sprinkler controller
    Sprinkler,
    /// Smart faucet
    Faucet,
    /// Smart shower system
    ShowerSystem,
    /// Television (HomeKit "Television" category, distinct from `Tv`)
    Television,
    /// HomeKit target controller (e.g. remote control accessory)
    TargetController,
    /// Unclassified device
    Unknown,
    /// Any other device type, preserved verbatim.
    Other(String),
}

/// Every canonical device type name, sorted, for a picker to offer.
///
/// `DeviceType` also accepts any other string as `DeviceType::Other`, so this
/// is a menu, not a closed set. `Unknown` is left out on purpose: it is the
/// absence of an answer, and a person choosing from a list should clear the
/// field instead. `test_every_offered_device_type_name_round_trips` proves each
/// entry survives `From<&str>` and comes back out of `as_str` unchanged.
pub const DEVICE_TYPE_NAMES: &[&str] = &[
    "Air Conditioner",
    "Air Purifier",
    "AirPlay Device",
    "Android Phone",
    "Android TV",
    "Apple Device",
    "Apple TV",
    "Apple iPad",
    "Apple iPhone",
    "Audio Device",
    "Bridge",
    "CI Server",
    "Chromecast",
    "Contact Sensor",
    "Cooler",
    "DVR",
    "Dehumidifier",
    "Desktop",
    "Door",
    "Door Lock",
    "Fan",
    "Faucet",
    "File Server",
    "Fire TV",
    "Game Console",
    "Gaming Console",
    "Gaming Device",
    "Gaming PC",
    "Garage Door",
    "Heater",
    "Home Automation",
    "HomeKit Accessory",
    "HomeKit Device",
    "Humidifier",
    "Humidity Sensor",
    "IP Camera",
    "IP Phone",
    "IoT Beacon",
    "IoT Device",
    "Laptop",
    "Lightbulb",
    "Lock",
    "Mac",
    "Matter Smart Device",
    "Media Player",
    "Media Renderer",
    "Media Server",
    "Media Streamer",
    "Microcontroller",
    "Mobile",
    "Mobile Device",
    "NAS",
    "NVIDIA Shield",
    "Network Device",
    "Network Equipment",
    "Occupancy Sensor",
    "Outlet",
    "PC/Computer",
    "PC/Windows",
    "Pixel Phone",
    "Printer",
    "Raspberry Pi",
    "Router",
    "Router/Switch",
    "Scanner",
    "Security Camera",
    "Security System",
    "Sensor",
    "Server",
    "Set Top Box",
    "Shower System",
    "Single-board Computer",
    "Smart Cleaning Device",
    "Smart Doorbell",
    "Smart Home Device",
    "Smart Home Hub",
    "Smart Light",
    "Smart Plug",
    "Smart Speaker",
    "Smart Watering Device",
    "Speaker",
    "Spotify Connect Device",
    "Sprinkler",
    "Storage (NAS)",
    "Switch",
    "TV",
    "Target Controller",
    "Television",
    "Thermostat",
    "Video Doorbell",
    "Window",
    "Window Covering",
    "e-Reader",
];

impl DeviceType {
    /// Returns the canonical display string for this device type.
    pub fn as_str(&self) -> &str {
        match self {
            DeviceType::Router => "Router",
            DeviceType::RouterSwitch => "Router/Switch",
            DeviceType::Switch => "Switch",
            DeviceType::NetworkDevice => "Network Device",
            DeviceType::NetworkEquipment => "Network Equipment",
            DeviceType::Printer => "Printer",
            DeviceType::Scanner => "Scanner",
            DeviceType::Laptop => "Laptop",
            DeviceType::Desktop => "Desktop",
            DeviceType::Mac => "Mac",
            DeviceType::PcWindows => "PC/Windows",
            DeviceType::PcComputer => "PC/Computer",
            DeviceType::AppleDevice => "Apple Device",
            DeviceType::AppleIPhone => "Apple iPhone",
            DeviceType::AppleIPad => "Apple iPad",
            DeviceType::AppleTv => "Apple TV",
            DeviceType::PixelPhone => "Pixel Phone",
            DeviceType::AndroidPhone => "Android Phone",
            DeviceType::AndroidTv => "Android TV",
            DeviceType::Mobile => "Mobile",
            DeviceType::MobileDevice => "Mobile Device",
            DeviceType::MediaPlayer => "Media Player",
            DeviceType::MediaStreamer => "Media Streamer",
            DeviceType::MediaServer => "Media Server",
            DeviceType::MediaRenderer => "Media Renderer",
            DeviceType::Chromecast => "Chromecast",
            DeviceType::FireTv => "Fire TV",
            DeviceType::AirPlayDevice => "AirPlay Device",
            DeviceType::SmartSpeaker => "Smart Speaker",
            DeviceType::Speaker => "Speaker",
            DeviceType::AudioDevice => "Audio Device",
            DeviceType::SmartHomeDevice => "Smart Home Device",
            DeviceType::SmartHomeHub => "Smart Home Hub",
            DeviceType::SmartDoorbell => "Smart Doorbell",
            DeviceType::VideoDoorbell => "Video Doorbell",
            DeviceType::SmartPlug => "Smart Plug",
            DeviceType::Outlet => "Outlet",
            DeviceType::SmartLight => "Smart Light",
            DeviceType::Lightbulb => "Lightbulb",
            DeviceType::SmartCleaningDevice => "Smart Cleaning Device",
            DeviceType::SmartWateringDevice => "Smart Watering Device",
            DeviceType::Thermostat => "Thermostat",
            DeviceType::SecurityCamera => "Security Camera",
            DeviceType::IpCamera => "IP Camera",
            DeviceType::SecuritySystem => "Security System",
            DeviceType::StorageNas => "Storage (NAS)",
            DeviceType::Nas => "NAS",
            DeviceType::FileServer => "File Server",
            DeviceType::Server => "Server",
            DeviceType::IpPhone => "IP Phone",
            DeviceType::IotDevice => "IoT Device",
            DeviceType::IotBeacon => "IoT Beacon",
            DeviceType::SingleBoardComputer => "Single-board Computer",
            DeviceType::RaspberryPi => "Raspberry Pi",
            DeviceType::Microcontroller => "Microcontroller",
            DeviceType::EReader => "e-Reader",
            DeviceType::GameConsole => "Game Console",
            DeviceType::GamingConsole => "Gaming Console",
            DeviceType::GamingDevice => "Gaming Device",
            DeviceType::GamingPc => "Gaming PC",
            DeviceType::Dvr => "DVR",
            DeviceType::CiServer => "CI Server",
            DeviceType::NvidiaShield => "NVIDIA Shield",
            DeviceType::SpotifyConnectDevice => "Spotify Connect Device",
            DeviceType::HomeAutomation => "Home Automation",
            DeviceType::MatterSmartDevice => "Matter Smart Device",
            DeviceType::HomeKitDevice => "HomeKit Device",
            DeviceType::HomeKitAccessory => "HomeKit Accessory",
            DeviceType::Sensor => "Sensor",
            DeviceType::HumiditySensor => "Humidity Sensor",
            DeviceType::OccupancySensor => "Occupancy Sensor",
            DeviceType::ContactSensor => "Contact Sensor",
            DeviceType::AirConditioner => "Air Conditioner",
            DeviceType::AirPurifier => "Air Purifier",
            DeviceType::DoorLock => "Door Lock",
            DeviceType::Tv => "TV",
            DeviceType::SetTopBox => "Set Top Box",
            DeviceType::Bridge => "Bridge",
            DeviceType::Fan => "Fan",
            DeviceType::GarageDoor => "Garage Door",
            DeviceType::Lock => "Lock",
            DeviceType::Door => "Door",
            DeviceType::Window => "Window",
            DeviceType::WindowCovering => "Window Covering",
            DeviceType::Heater => "Heater",
            DeviceType::Cooler => "Cooler",
            DeviceType::Humidifier => "Humidifier",
            DeviceType::Dehumidifier => "Dehumidifier",
            DeviceType::Sprinkler => "Sprinkler",
            DeviceType::Faucet => "Faucet",
            DeviceType::ShowerSystem => "Shower System",
            DeviceType::Television => "Television",
            DeviceType::TargetController => "Target Controller",
            DeviceType::Unknown => "Unknown",
            DeviceType::Other(s) => s.as_str(),
        }
    }

    /// Returns `true` if this is a generic/inferred category that should readily be
    /// upgraded to a more specific type learned from active discovery (mDNS/SSDP/LLDP/CDP).
    /// Every canonical name a picker can offer. See [`DEVICE_TYPE_NAMES`].
    pub fn all_names() -> &'static [&'static str] {
        DEVICE_TYPE_NAMES
    }

    pub fn is_generic(&self) -> bool {
        matches!(
            self,
            DeviceType::Unknown
                | DeviceType::AndroidPhone
                | DeviceType::PcWindows
                | DeviceType::AppleDevice
                | DeviceType::IotDevice
                | DeviceType::SmartHomeDevice
                | DeviceType::MatterSmartDevice
                | DeviceType::HomeKitDevice
                | DeviceType::HomeKitAccessory
        )
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for DeviceType {
    fn from(value: &str) -> Self {
        match value {
            "Router" => DeviceType::Router,
            "Router/Switch" => DeviceType::RouterSwitch,
            "Switch" => DeviceType::Switch,
            "Network Device" => DeviceType::NetworkDevice,
            "Network Equipment" => DeviceType::NetworkEquipment,
            "Printer" => DeviceType::Printer,
            "Scanner" => DeviceType::Scanner,
            "Laptop" => DeviceType::Laptop,
            "Desktop" => DeviceType::Desktop,
            "Mac" => DeviceType::Mac,
            "PC/Windows" => DeviceType::PcWindows,
            "PC/Computer" => DeviceType::PcComputer,
            "Apple Device" => DeviceType::AppleDevice,
            "Apple iPhone" => DeviceType::AppleIPhone,
            "Apple iPad" => DeviceType::AppleIPad,
            "Apple TV" => DeviceType::AppleTv,
            "Pixel Phone" => DeviceType::PixelPhone,
            "Android Phone" => DeviceType::AndroidPhone,
            "Android TV" => DeviceType::AndroidTv,
            "Mobile" => DeviceType::Mobile,
            "Mobile Device" => DeviceType::MobileDevice,
            "Media Player" => DeviceType::MediaPlayer,
            "Media Streamer" => DeviceType::MediaStreamer,
            "Media Server" => DeviceType::MediaServer,
            "Media Renderer" => DeviceType::MediaRenderer,
            "Chromecast" => DeviceType::Chromecast,
            "Fire TV" => DeviceType::FireTv,
            "AirPlay Device" => DeviceType::AirPlayDevice,
            "Smart Speaker" => DeviceType::SmartSpeaker,
            "Speaker" => DeviceType::Speaker,
            "Audio Device" => DeviceType::AudioDevice,
            "Smart Home Device" => DeviceType::SmartHomeDevice,
            "Smart Home Hub" => DeviceType::SmartHomeHub,
            "Smart Doorbell" => DeviceType::SmartDoorbell,
            "Video Doorbell" => DeviceType::VideoDoorbell,
            "Smart Plug" => DeviceType::SmartPlug,
            "Outlet" => DeviceType::Outlet,
            "Smart Light" => DeviceType::SmartLight,
            "Lightbulb" => DeviceType::Lightbulb,
            "Smart Cleaning Device" => DeviceType::SmartCleaningDevice,
            "Smart Watering Device" => DeviceType::SmartWateringDevice,
            "Thermostat" => DeviceType::Thermostat,
            "Security Camera" => DeviceType::SecurityCamera,
            "IP Camera" => DeviceType::IpCamera,
            "Security System" => DeviceType::SecuritySystem,
            "Storage (NAS)" => DeviceType::StorageNas,
            "NAS" => DeviceType::Nas,
            "File Server" => DeviceType::FileServer,
            "Server" => DeviceType::Server,
            "IP Phone" => DeviceType::IpPhone,
            "IoT Device" => DeviceType::IotDevice,
            "IoT Beacon" => DeviceType::IotBeacon,
            "Single-board Computer" => DeviceType::SingleBoardComputer,
            "Raspberry Pi" => DeviceType::RaspberryPi,
            "Microcontroller" => DeviceType::Microcontroller,
            "e-Reader" => DeviceType::EReader,
            "Game Console" => DeviceType::GameConsole,
            "Gaming Console" => DeviceType::GamingConsole,
            "Gaming Device" => DeviceType::GamingDevice,
            "Gaming PC" => DeviceType::GamingPc,
            "DVR" => DeviceType::Dvr,
            "CI Server" => DeviceType::CiServer,
            "NVIDIA Shield" => DeviceType::NvidiaShield,
            "Spotify Connect Device" => DeviceType::SpotifyConnectDevice,
            "Home Automation" => DeviceType::HomeAutomation,
            "Matter Smart Device" => DeviceType::MatterSmartDevice,
            "HomeKit Device" => DeviceType::HomeKitDevice,
            "HomeKit Accessory" => DeviceType::HomeKitAccessory,
            "Sensor" => DeviceType::Sensor,
            "Humidity Sensor" => DeviceType::HumiditySensor,
            "Occupancy Sensor" => DeviceType::OccupancySensor,
            "Contact Sensor" => DeviceType::ContactSensor,
            "Air Conditioner" => DeviceType::AirConditioner,
            "Air Purifier" => DeviceType::AirPurifier,
            "Door Lock" => DeviceType::DoorLock,
            "TV" => DeviceType::Tv,
            "Set Top Box" => DeviceType::SetTopBox,
            "Bridge" => DeviceType::Bridge,
            "Fan" => DeviceType::Fan,
            "Garage Door" => DeviceType::GarageDoor,
            "Lock" => DeviceType::Lock,
            "Door" => DeviceType::Door,
            "Window" => DeviceType::Window,
            "Window Covering" => DeviceType::WindowCovering,
            "Heater" => DeviceType::Heater,
            "Cooler" => DeviceType::Cooler,
            "Humidifier" => DeviceType::Humidifier,
            "Dehumidifier" => DeviceType::Dehumidifier,
            "Sprinkler" => DeviceType::Sprinkler,
            "Faucet" => DeviceType::Faucet,
            "Shower System" => DeviceType::ShowerSystem,
            "Television" => DeviceType::Television,
            "Target Controller" => DeviceType::TargetController,
            "Unknown" => DeviceType::Unknown,
            other => DeviceType::Other(other.to_string()),
        }
    }
}

impl From<String> for DeviceType {
    fn from(value: String) -> Self {
        match DeviceType::from(value.as_str()) {
            DeviceType::Other(_) => DeviceType::Other(value),
            known => known,
        }
    }
}

impl serde::Serialize for DeviceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DeviceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(DeviceType::from(value))
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
        format_mac(self.client_mac)
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
    /// Source MAC address of the Ethernet frame that carried this packet.
    ///
    /// This is the authoritative identity for the client: unlike the DUID, it
    /// is always present and always an Ethernet address. DUID types that carry
    /// no link-layer address (DUID-UUID, RFC 6355) would otherwise force a
    /// synthetic `duid:...` identifier and a phantom device entry.
    pub source_mac: [u8; 6],
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
    pub source_mac: [u8; 6],
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
    pub source_mac: [u8; 6],
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
        source_mac: [u8; 6],
        /// Source IP address from the ARP packet
        source_ip: std::net::IpAddr,
    },
    /// NDP packet (IPv6 Neighbor Discovery Protocol)
    Ndp {
        /// Source MAC address from the NDP packet
        source_mac: [u8; 6],
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
    /// CoAP constrained device packet
    #[cfg(feature = "ssdp")]
    Coap(crate::parser::iot::CoapPacket),
    /// KNXnet/IP building automation packet
    #[cfg(feature = "ssdp")]
    Knx(crate::parser::iot::KnxPacket),
    /// CCTV / IP Camera discovery packet
    #[cfg(feature = "ssdp")]
    Cctv(crate::parser::cctv::CctvPacket),
    /// MQTT / MQTT-SN packet
    #[cfg(feature = "ssdp")]
    Mqtt(crate::parser::mqtt_gdm::MqttPacket),
    /// Plex GDM discovery packet
    #[cfg(feature = "ssdp")]
    Gdm(crate::parser::mqtt_gdm::GdmPacket),
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

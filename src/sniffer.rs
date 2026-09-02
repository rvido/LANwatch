// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use pnet_datalink::{self as datalink, Channel::Ethernet, DataLinkReceiver, NetworkInterface};
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::udp::UdpPacket;

#[cfg(any(feature = "mdns", feature = "ssdp"))]
use pnet_packet::arp::{ArpOperations, ArpPacket};
#[cfg(any(feature = "mdns", feature = "ssdp"))]
use std::net::IpAddr;

use crate::types::{DhcpError, DhcpEvent};

#[cfg(any(feature = "mdns", feature = "ssdp"))]
use crate::types::NetworkEvent;

// Imports from parsers
use crate::parser::dhcp::{
    is_dhcpv4_ports, is_dhcpv6_ports, parse_dhcpv4_payload, parse_dhcpv6_payload,
};

#[cfg(feature = "mdns")]
use crate::parser::mdns::{
    is_llmnr_ports, is_mdns_ports, is_nbns_ports, parse_mdns_payload, parse_nbns_payload,
};

#[cfg(feature = "ssdp")]
use crate::parser::ssdp::{
    is_ssdp_ports, is_wsd_ports, parse_cdp_packet, parse_lldp_packet, parse_ssdp_payload,
    parse_wsd_payload,
};

/// How many back-to-back capture failures a `run` loop tolerates before giving
/// up. A transient read error is worth logging and retrying; a permanent one
/// (the interface was removed, the channel was torn down) repeats forever, and
/// without a ceiling the loop becomes a hot spin writing to stderr with no way
/// out.
const MAX_CONSECUTIVE_CAPTURE_ERRORS: usize = 100;

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

/// Returns the first IPv4 address associated with the network interface.
pub fn get_interface_ipv4(name: &str) -> Option<std::net::Ipv4Addr> {
    find_interface(name).and_then(|iface| {
        iface.ips.into_iter().find_map(|ip_net| {
            if let std::net::IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
    })
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
    let ethertype = ethernet.get_ethertype().0;

    if ethertype == 0x88cc {
        #[cfg(feature = "ssdp")]
        {
            let source_mac = ethernet.get_source().octets();
            return parse_lldp_packet(ethernet.payload(), source_mac).map(NetworkEvent::Lldp);
        }
        #[cfg(not(feature = "ssdp"))]
        return None;
    }

    if ethertype <= 1500 {
        #[cfg(feature = "ssdp")]
        {
            let payload = ethernet.payload();
            if payload.len() >= 8 {
                // LLC Header: DSAP=0xAA, SSAP=0xAA, Control=0x03
                // SNAP Header: OUI=00:00:0C, Protocol ID=0x2000 (CDP)
                if payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03 {
                    let oui = [payload[3], payload[4], payload[5]];
                    let protocol_id = u16::from_be_bytes([payload[6], payload[7]]);
                    if oui == [0x00, 0x00, 0x0C] && protocol_id == 0x2000 {
                        let source_mac = ethernet.get_source().octets();
                        return parse_cdp_packet(&payload[8..], source_mac).map(NetworkEvent::Cdp);
                    }
                }
            }
        }
        return None;
    }

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => process_ipv4_packet_extended(&ethernet),
        EtherTypes::Ipv6 => process_ipv6_packet_extended(&ethernet),
        EtherTypes::Arp => {
            let arp = ArpPacket::new(ethernet.payload())?;
            if arp.get_operation() == ArpOperations::Reply
                || arp.get_operation() == ArpOperations::Request
            {
                let src_mac = arp.get_sender_hw_addr().octets();
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

/// Dispatches a UDP payload to the appropriate discovery-protocol parser based on port
/// number. Shared between the IPv4 and IPv6 extended-frame paths, which differ only in
/// how `source_ip`/`dest_ip` were extracted from the IP header.
#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn dispatch_udp_extended(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: IpAddr,
    dest_ip: IpAddr,
    src: u16,
    dest: u16,
) -> Option<NetworkEvent> {
    #[cfg(feature = "mdns")]
    if is_mdns_ports(src, dest) {
        let packet = parse_mdns_payload(payload, source_mac, source_ip, dest_ip)?;
        return Some(NetworkEvent::Mdns(packet));
    }

    #[cfg(feature = "mdns")]
    if is_llmnr_ports(src, dest) {
        let packet = parse_mdns_payload(payload, source_mac, source_ip, dest_ip)?;
        return Some(NetworkEvent::Llmnr(packet));
    }

    #[cfg(feature = "mdns")]
    if is_nbns_ports(src, dest) {
        let packet = parse_nbns_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Nbns(packet));
    }

    #[cfg(feature = "ssdp")]
    if is_ssdp_ports(src, dest) {
        let packet = parse_ssdp_payload(payload, source_mac, source_ip, dest_ip)?;
        return Some(NetworkEvent::Ssdp(packet));
    }

    #[cfg(feature = "ssdp")]
    if is_wsd_ports(src, dest) {
        let packet = parse_wsd_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Wsd(packet));
    }

    #[cfg(feature = "ssdp")]
    if crate::parser::iot::is_lifx_port(src) || crate::parser::iot::is_lifx_port(dest) {
        let packet = crate::parser::iot::parse_lifx_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Lifx(packet));
    }

    #[cfg(feature = "ssdp")]
    if crate::parser::iot::is_coap_port(src) || crate::parser::iot::is_coap_port(dest) {
        let packet = crate::parser::iot::parse_coap_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Coap(packet));
    }

    #[cfg(feature = "ssdp")]
    if crate::parser::iot::is_knx_port(src) || crate::parser::iot::is_knx_port(dest) {
        let packet = crate::parser::iot::parse_knx_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Knx(packet));
    }

    #[cfg(feature = "ssdp")]
    if src == crate::parser::cctv::SADP_PORT
        || dest == crate::parser::cctv::SADP_PORT
        || src == crate::parser::cctv::SADP_ALT_PORT
        || dest == crate::parser::cctv::SADP_ALT_PORT
    {
        let packet = crate::parser::cctv::parse_sadp_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Cctv(packet));
    }

    #[cfg(feature = "ssdp")]
    if src == crate::parser::cctv::DAHUA_PORT || dest == crate::parser::cctv::DAHUA_PORT {
        let packet = crate::parser::cctv::parse_dahua_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Cctv(packet));
    }

    #[cfg(feature = "ssdp")]
    if crate::parser::mqtt_gdm::is_mqtt_port(src) || crate::parser::mqtt_gdm::is_mqtt_port(dest) {
        let packet =
            crate::parser::mqtt_gdm::parse_mqtt_sn_connect(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Mqtt(packet));
    }

    #[cfg(feature = "ssdp")]
    if crate::parser::mqtt_gdm::is_gdm_port(src) || crate::parser::mqtt_gdm::is_gdm_port(dest) {
        let packet = crate::parser::mqtt_gdm::parse_gdm_payload(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Gdm(packet));
    }

    None
}

/// Dispatches a TCP payload to the appropriate discovery-protocol parser based on port
/// number. Shared between the IPv4 and IPv6 extended-frame paths.
#[cfg(feature = "ssdp")]
fn dispatch_tcp_extended(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: IpAddr,
    src: u16,
    dest: u16,
) -> Option<NetworkEvent> {
    // Only the *responder* side identifies a camera. Matching `dest` too would
    // attribute the event to the Ethernet source of a client-to-camera packet,
    // i.e. tag the laptop dialling the camera as an IP camera itself.
    //
    // Port 554 alone is still a weak signal, so require the payload to look
    // like RTSP as well; a bare SYN/ACK carries nothing and is ignored.
    if src == crate::parser::cctv::RTSP_PORT && crate::parser::cctv::is_rtsp_response(payload) {
        return Some(NetworkEvent::Cctv(crate::parser::cctv::CctvPacket {
            source_mac,
            claimed_mac: None,
            source_ip,
            vendor: crate::types::Vendor::GenericRtsp,
            model: None,
            serial_number: None,
            protocol: "RTSP".to_string(),
        }));
    }
    if crate::parser::mqtt_gdm::is_mqtt_port(src) || crate::parser::mqtt_gdm::is_mqtt_port(dest) {
        let packet = crate::parser::mqtt_gdm::parse_mqtt_connect(payload, source_mac, source_ip)?;
        return Some(NetworkEvent::Mqtt(packet));
    }
    None
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn process_ipv4_packet_extended(ethernet: &EthernetPacket) -> Option<NetworkEvent> {
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    let next_proto = ipv4.get_next_level_protocol();
    let source_ip = IpAddr::V4(ipv4.get_source());
    let dest_ip = IpAddr::V4(ipv4.get_destination());

    if next_proto == IpNextHeaderProtocols::Udp {
        let udp = UdpPacket::new(ipv4.payload())?;
        let src = udp.get_source();
        let dest = udp.get_destination();
        let source_mac = ethernet.get_source().octets();

        if let Some(event) =
            dispatch_udp_extended(udp.payload(), source_mac, source_ip, dest_ip, src, dest)
        {
            return Some(event);
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
    } else if next_proto == IpNextHeaderProtocols::Tcp {
        #[cfg(feature = "ssdp")]
        {
            let tcp = pnet_packet::tcp::TcpPacket::new(ipv4.payload())?;
            let src = tcp.get_source();
            let dest = tcp.get_destination();
            let source_mac = ethernet.get_source().octets();
            return dispatch_tcp_extended(tcp.payload(), source_mac, source_ip, src, dest);
        }
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
        ethernet.get_source().octets(),
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
    let next_header = ipv6.get_next_header();

    if next_header == IpNextHeaderProtocols::Icmpv6 {
        let payload = ipv6.payload();
        if payload.len() >= 8 {
            let icmpv6_type = payload[0];
            if icmpv6_type == 135 || icmpv6_type == 136 {
                let source_ip = ipv6.get_source();
                if !source_ip.is_unspecified() {
                    let source_mac = ethernet.get_source().octets();
                    return Some(NetworkEvent::Ndp {
                        source_mac,
                        source_ip: IpAddr::V6(source_ip),
                    });
                }
            }
        }
        return None;
    }

    if next_header == IpNextHeaderProtocols::Udp {
        let udp = UdpPacket::new(ipv6.payload())?;
        let src = udp.get_source();
        let dest = udp.get_destination();
        let source_mac = ethernet.get_source().octets();
        let source_ip = IpAddr::V6(ipv6.get_source());
        let dest_ip = IpAddr::V6(ipv6.get_destination());

        if let Some(event) =
            dispatch_udp_extended(udp.payload(), source_mac, source_ip, dest_ip, src, dest)
        {
            return Some(event);
        }

        // Check for DHCPv6
        if is_dhcpv6_ports(src, dest) {
            let packet = parse_dhcpv6_payload(
                udp.payload(),
                source_mac,
                ipv6.get_source(),
                ipv6.get_destination(),
                src,
                dest,
            )?;
            return Some(NetworkEvent::Dhcpv6(packet));
        }
    } else if next_header == IpNextHeaderProtocols::Tcp {
        #[cfg(feature = "ssdp")]
        {
            let tcp = pnet_packet::tcp::TcpPacket::new(ipv6.payload())?;
            let src = tcp.get_source();
            let dest = tcp.get_destination();
            let source_mac = ethernet.get_source().octets();
            let source_ip = IpAddr::V6(ipv6.get_source());
            return dispatch_tcp_extended(tcp.payload(), source_mac, source_ip, src, dest);
        }
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
        let mut consecutive_errors = 0usize;
        loop {
            match self.next_packet() {
                Ok(Some(event)) => {
                    consecutive_errors = 0;
                    if !callback(event) {
                        break;
                    }
                }
                Ok(None) => {
                    consecutive_errors = 0;
                    continue;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_CAPTURE_ERRORS {
                        eprintln!(
                            "Capture on {} failed {} times in a row, giving up: {}",
                            self.interface_name, consecutive_errors, e
                        );
                        break;
                    }
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
        let mut consecutive_errors = 0usize;
        loop {
            match self.next_packet() {
                Ok(Some(event)) => {
                    consecutive_errors = 0;
                    if !callback(event) {
                        break;
                    }
                }
                Ok(None) => {
                    consecutive_errors = 0;
                    continue;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_CAPTURE_ERRORS {
                        eprintln!(
                            "Capture on {} failed {} times in a row, giving up: {}",
                            self.interface_name, consecutive_errors, e
                        );
                        break;
                    }
                    eprintln!("Error reading packet: {}", e);
                }
            }
        }
    }
}

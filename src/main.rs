use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet; // Import IPv6 packet
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::env;

fn main() {
    // Select the interface
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        println!("Usage: cargo run <interface_name>");
        println!("Available interfaces:");
        for iface in datalink::interfaces() {
            println!(" - {}", iface.name);
        }
        std::process::exit(1);
    });

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Error handling interface: Interface not found");

    println!("Sniffing DHCP (v4 & v6) traffic on: {}", interface.name);

    // Create the datalink channel
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    // Packet Loop
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();

                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => handle_ipv4(&ethernet),
                    EtherTypes::Ipv6 => handle_ipv6(&ethernet),
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_ipv4(ethernet: &EthernetPacket) {
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                let src = udp.get_source();
                let dest = udp.get_destination();

                // DHCPv4 Ports: 67 (Server), 68 (Client)
                if src == 67 || src == 68 || dest == 67 || dest == 68 {
                    println!("\n[IPv4] DHCP Packet Detected");
                    println!("Source: {}:{}", ipv4.get_source(), src);
                    println!("Dest:   {}:{}", ipv4.get_destination(), dest);
                    parse_dhcpv4_payload(udp.payload());
                    println!("------------------------------");
                }
            }
        }
    }
}

fn handle_ipv6(ethernet: &EthernetPacket) {
    if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
        if ipv6.get_next_header() == IpNextHeaderProtocols::Udp {
            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                let src = udp.get_source();
                let dest = udp.get_destination();

                // DHCPv6 Ports: 546 (Client), 547 (Server)
                if src == 546 || src == 547 || dest == 546 || dest == 547 {
                    println!("\n[IPv6] DHCPv6 Packet Detected");
                    println!("Source: {}:{}", ipv6.get_source(), src);
                    println!("Dest:   {}:{}", ipv6.get_destination(), dest);
                    parse_dhcpv6_payload(udp.payload());
                    println!("------------------------------");
                }
            }
        }
    }
}

// --- DHCPv4 Parsing ---

fn parse_dhcpv4_payload(payload: &[u8]) {
    if payload.len() < 240 { return; } // Too short

    let op = payload[0];
    let op_str = match op {
        1 => "BootRequest (Client)",
        2 => "BootReply (Server)",
        _ => "Unknown",
    };
    println!("Operation: {}", op_str);

    // MAC Address (Client Hardware Address)
    println!("Client MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
             payload[28], payload[29], payload[30], payload[31], payload[32], payload[33]);

    // Parse Options starting at offset 240
    let mut index = 240;
    while index < payload.len() {
        let code = payload[index];
        if code == 255 { break; } // End
        if code == 0 { index += 1; continue; } // Pad

        if index + 1 >= payload.len() { break; }
        let len = payload[index + 1] as usize;
        
        if index + 2 + len > payload.len() { break; }
        let value = &payload[index + 2 .. index + 2 + len];

        match code {
            53 => { // DHCP Message Type
                if !value.is_empty() {
                    let msg = match value[0] {
                        1 => "DISCOVER", 2 => "OFFER", 3 => "REQUEST", 
                        5 => "ACK", 6 => "NAK", 7 => "RELEASE", _ => "UNKNOWN"
                    };
                    println!("-> Type: {}", msg);
                }
            }
            12 => if let Ok(h) = std::str::from_utf8(value) { println!("-> Hostname: {}", h); },
            50 => if value.len() == 4 { 
                println!("-> Req IP: {}.{}.{}.{}", value[0], value[1], value[2], value[3]); 
            },
            _ => {}
        }
        index += 2 + len;
    }
}

// --- DHCPv6 Parsing ---

fn parse_dhcpv6_payload(payload: &[u8]) {
    if payload.len() < 4 {
        println!("Packet too short for DHCPv6");
        return;
    }

    // Byte 0: Message Type
    let msg_type = payload[0];
    let type_str = match msg_type {
        1 => "SOLICIT",
        2 => "ADVERTISE",
        3 => "REQUEST",
        4 => "CONFIRM",
        5 => "RENEW",
        6 => "REBIND",
        7 => "REPLY",
        8 => "RELEASE",
        9 => "DECLINE",
        10 => "RECONFIGURE",
        11 => "INFO-REQUEST",
        _ => "UNKNOWN",
    };
    println!("Message Type: {} ({})", type_str, msg_type);

    // Bytes 1-3: Transaction ID
    println!("Transaction ID: 0x{:02X}{:02X}{:02X}", payload[1], payload[2], payload[3]);

    // Options start at byte 4
    // DHCPv6 Options format: Code (2 bytes), Length (2 bytes), Data (Length bytes)
    let mut index = 4;
    while index < payload.len() {
        if index + 4 > payload.len() { break; }

        // Parse 16-bit Code and 16-bit Length (Big Endian)
        let opt_code = ((payload[index] as u16) << 8) | (payload[index+1] as u16);
        let opt_len = ((payload[index+2] as u16) << 8) | (payload[index+3] as u16);
        let length = opt_len as usize;

        if index + 4 + length > payload.len() { break; }
        let value = &payload[index+4 .. index+4+length];

        match opt_code {
            1 => { // Client Identifier (DUID)
                println!("-> Client ID (DUID): {:02X?}", value);
            },
            2 => { // Server Identifier (DUID)
                println!("-> Server ID (DUID): {:02X?}", value);
            },
            3 => { // IA_NA (Identity Association for Non-temporary Addresses)
                println!("-> IA_NA (IPv6 Lease Request)");
            },
            39 => { // Client FQDN
                 if let Ok(fqdn) = std::str::from_utf8(value) {
                     println!("-> Client FQDN: {}", fqdn);
                 }
            },
            _ => {
                // println!("-> Option {}: {} bytes", opt_code, length);
            }
        }

        index += 4 + length;
    }
}

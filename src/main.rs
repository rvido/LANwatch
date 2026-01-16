// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// DHCPsniff - A DHCP (v4 & v6) network traffic sniffer
// See LICENSE file for details.

use dhcpsniff::{list_interfaces, DhcpEvent, DhcpSniffer, Dhcpv6Option};
use std::env;

fn main() {
    // Select the interface
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        println!("Usage: cargo run <interface_name>");
        println!("Available interfaces:");
        for iface in list_interfaces() {
            println!(" - {}", iface);
        }
        std::process::exit(1);
    });

    println!("Sniffing DHCP (v4 & v6) traffic on: {}", interface_name);

    let mut sniffer = DhcpSniffer::new(&interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    // Run the sniffer with a callback
    sniffer.run(|event| {
        match event {
            DhcpEvent::V4(packet) => {
                println!("\n[IPv4] DHCP Packet Detected");
                println!("Source: {}:{}", packet.source_ip, packet.source_port);
                println!("Dest:   {}:{}", packet.dest_ip, packet.dest_port);
                println!("Operation: {}", packet.operation);
                println!("Client MAC: {}", packet.client_mac_string());
                if let Some(msg_type) = &packet.message_type {
                    println!("-> Type: {}", msg_type);
                }
                if let Some(hostname) = &packet.hostname {
                    println!("-> Hostname: {}", hostname);
                }
                if let Some(req_ip) = &packet.requested_ip {
                    println!("-> Req IP: {}", req_ip);
                }
                println!("------------------------------");
            }
            DhcpEvent::V6(packet) => {
                println!("\n[IPv6] DHCPv6 Packet Detected");
                println!("Source: {}:{}", packet.source_ip, packet.source_port);
                println!("Dest:   {}:{}", packet.dest_ip, packet.dest_port);
                println!("Message Type: {}", packet.message_type);
                println!("Transaction ID: {}", packet.transaction_id_string());
                for option in &packet.options {
                    match option {
                        Dhcpv6Option::ClientId(data) => {
                            println!("-> Client ID (DUID): {:02X?}", data);
                        }
                        Dhcpv6Option::ServerId(data) => {
                            println!("-> Server ID (DUID): {:02X?}", data);
                        }
                        Dhcpv6Option::IaNa => {
                            println!("-> IA_NA (IPv6 Lease Request)");
                        }
                        Dhcpv6Option::ClientFqdn(fqdn) => {
                            println!("-> Client FQDN: {}", fqdn);
                        }
                        Dhcpv6Option::Other { .. } => {}
                    }
                }
                println!("------------------------------");
            }
        }
        true // Continue sniffing
    });
}

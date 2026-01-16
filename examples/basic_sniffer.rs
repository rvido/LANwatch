// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// DHCPsniff - A DHCP (v4 & v6) network traffic sniffer
// See LICENSE file for details.

//! Example: Basic DHCP sniffer
//!
//! This example shows how to use the dhcpsniff library to capture
//! and display DHCP packets on a network interface.
//!
//! Usage: sudo cargo run --example basic_sniffer <interface_name>
//!
//! Note: Root/sudo privileges are typically required for packet capture.

use dhcpsniff::{list_interfaces, DhcpEvent, DhcpSniffer, Dhcpv6Option};
use std::env;

fn main() {
    // Get interface name from command line
    let interface_name = match env::args().nth(1) {
        Some(name) => name,
        None => {
            eprintln!("Usage: sudo cargo run --example basic_sniffer <interface_name>");
            eprintln!("\nAvailable interfaces:");
            for iface in list_interfaces() {
                eprintln!("  - {}", iface);
            }
            std::process::exit(1);
        }
    };

    println!("=== DHCP Sniffer Example ===");
    println!("Listening on interface: {}", interface_name);
    println!("Press Ctrl+C to stop\n");

    // Create the sniffer
    let mut sniffer = match DhcpSniffer::new(&interface_name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create sniffer: {}", e);
            eprintln!("\nTip: You may need to run with sudo for packet capture.");
            std::process::exit(1);
        }
    };

    // Counter for packets
    let mut packet_count = 0u64;

    // Run the sniffer
    sniffer.run(|event| {
        packet_count += 1;
        println!("=== Packet #{} ===", packet_count);

        match event {
            DhcpEvent::V4(pkt) => {
                println!("Protocol: DHCPv4");
                println!("Source:   {}:{}", pkt.source_ip, pkt.source_port);
                println!("Dest:     {}:{}", pkt.dest_ip, pkt.dest_port);
                println!("Operation: {}", pkt.operation);
                println!("Client MAC: {}", pkt.client_mac_string());

                if let Some(ref msg_type) = pkt.message_type {
                    println!("Message Type: {}", msg_type);
                }
                if let Some(ref hostname) = pkt.hostname {
                    println!("Hostname: {}", hostname);
                }
                if let Some(ref ip) = pkt.requested_ip {
                    println!("Requested IP: {}", ip);
                }
            }
            DhcpEvent::V6(pkt) => {
                println!("Protocol: DHCPv6");
                println!("Source:   {}:{}", pkt.source_ip, pkt.source_port);
                println!("Dest:     {}:{}", pkt.dest_ip, pkt.dest_port);
                println!("Message Type: {}", pkt.message_type);
                println!("Transaction ID: {}", pkt.transaction_id_string());

                for opt in &pkt.options {
                    match opt {
                        Dhcpv6Option::ClientId(data) => {
                            println!("Client ID: {:02X?}", data);
                        }
                        Dhcpv6Option::ServerId(data) => {
                            println!("Server ID: {:02X?}", data);
                        }
                        Dhcpv6Option::IaNa => {
                            println!("IA_NA: IPv6 address request");
                        }
                        Dhcpv6Option::ClientFqdn(fqdn) => {
                            println!("Client FQDN: {}", fqdn);
                        }
                        Dhcpv6Option::Other { code, data } => {
                            println!("Option {}: {} bytes", code, data.len());
                        }
                    }
                }
            }
        }
        println!();

        true // Continue sniffing
    });
}

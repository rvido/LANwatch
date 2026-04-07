// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

//! Example: Basic network sniffer with device tracking
//!
//! This example shows how to use the lanwatch library to capture
//! and display DHCP packets on a network interface, while also
//! tracking devices and saving them to a CSV file.
//!
//! Usage: sudo cargo run --example basic_sniffer <interface_name> [csv_file]
//!
//! Note: Root/sudo privileges are typically required for packet capture.

use lanwatch::{DeviceTracker, DhcpEvent, DhcpSniffer, Dhcpv6Option, list_interfaces};
use std::env;

fn main() {
    // Get interface name and optional CSV path from command line
    let args: Vec<String> = env::args().collect();

    let interface_name = match args.get(1) {
        Some(name) => name.clone(),
        None => {
            eprintln!("Usage: sudo cargo run --example basic_sniffer <interface_name> [csv_file]");
            eprintln!("\nAvailable interfaces:");
            for iface in list_interfaces() {
                eprintln!("  - {}", iface);
            }
            std::process::exit(1);
        }
    };

    let csv_path = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("devices_example.csv");

    println!("=== DHCP Sniffer Example ===");
    println!("Listening on interface: {}", interface_name);
    println!("Saving devices to: {}", csv_path);
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

    // Create the device tracker
    let mut tracker = match DeviceTracker::new(csv_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to create device tracker: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "Loaded {} existing devices from CSV\n",
        tracker.device_count()
    );

    // Counter for packets
    let mut packet_count = 0u64;

    // Run the sniffer
    sniffer.run(|event| {
        packet_count += 1;
        println!("=== Packet #{} ===", packet_count);

        match &event {
            DhcpEvent::V4(pkt) => {
                let is_new = tracker.update_from_dhcpv4(pkt);

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

                if is_new {
                    println!(
                        "[NEW/UPDATED] Total devices tracked: {}",
                        tracker.device_count()
                    );
                }
            }
            DhcpEvent::V6(pkt) => {
                let is_new = tracker.update_from_dhcpv6(pkt);

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

                if is_new {
                    println!(
                        "[NEW/UPDATED] Total devices tracked: {}",
                        tracker.device_count()
                    );
                }
            }
        }
        println!();

        true // Continue sniffing
    });
}

// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// DHCPsniff - A DHCP (v4 & v6) network traffic sniffer
// See LICENSE file for details.

use dhcpsniff::{
    list_interfaces, start_api_server, DeviceTracker, DhcpEvent, DhcpSniffer, Dhcpv6Option,
};
use std::env;
use std::sync::{Arc, RwLock};

const DEFAULT_CSV_PATH: &str = "dhcp_devices.csv";
const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let (interface_name, csv_path, api_addr) = parse_args(&args);

    println!("Sniffing DHCP (v4 & v6) traffic on: {}", interface_name);
    println!("Saving device info to: {}", csv_path);

    let mut sniffer = DhcpSniffer::new(&interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let tracker = DeviceTracker::new(&csv_path).unwrap_or_else(|e| {
        eprintln!("Error creating device tracker: {}", e);
        std::process::exit(1);
    });

    println!("Loaded {} existing devices from CSV", tracker.device_count());

    // Wrap tracker in Arc<RwLock> for thread-safe sharing
    let tracker = Arc::new(RwLock::new(tracker));

    // Start API server if address is provided
    if let Some(addr) = api_addr {
        let tracker_clone = Arc::clone(&tracker);
        match start_api_server(&addr, tracker_clone) {
            Ok(_) => println!("API server started on http://{}", addr),
            Err(e) => eprintln!("Warning: Failed to start API server: {}", e),
        }
    }

    println!("Press Ctrl+C to stop\n");

    // Run the sniffer with a callback
    sniffer.run(|event| {
        let mut tracker = match tracker.write() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error acquiring lock: {}", e);
                return true;
            }
        };

        match &event {
            DhcpEvent::V4(packet) => {
                let is_new_or_updated = tracker.update_from_dhcpv4(packet);

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
                if is_new_or_updated {
                    println!("-> [CSV Updated] Total devices: {}", tracker.device_count());
                }
                println!("------------------------------");
            }
            DhcpEvent::V6(packet) => {
                let is_new_or_updated = tracker.update_from_dhcpv6(packet);

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
                if is_new_or_updated {
                    println!("-> [CSV Updated] Total devices: {}", tracker.device_count());
                }
                println!("------------------------------");
            }
        }
        true // Continue sniffing
    });
}

fn parse_args(args: &[String]) -> (String, String, Option<String>) {
    let mut interface_name = None;
    let mut csv_path = DEFAULT_CSV_PATH.to_string();
    let mut api_addr: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    csv_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a file path");
                    std::process::exit(1);
                }
            }
            "-a" | "--api" => {
                if i + 1 < args.len() {
                    api_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    // Use default address if no argument provided
                    api_addr = Some(DEFAULT_API_ADDR.to_string());
                    i += 1;
                }
            }
            "--api-default" => {
                api_addr = Some(DEFAULT_API_ADDR.to_string());
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                interface_name = Some(arg.to_string());
                i += 1;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let interface_name = interface_name.unwrap_or_else(|| {
        print_usage();
        println!("\nAvailable interfaces:");
        for iface in list_interfaces() {
            println!("  - {}", iface);
        }
        std::process::exit(1);
    });

    (interface_name, csv_path, api_addr)
}

fn print_usage() {
    println!("Usage: dhcpsniff <interface_name> [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -o, --output <FILE>    Output CSV file path (default: dhcp_devices.csv)");
    println!("  -a, --api <ADDR:PORT>  Start HTTP API server (e.g., 127.0.0.1:8080)");
    println!("  --api-default          Start HTTP API on default address (127.0.0.1:8080)");
    println!("  -h, --help             Show this help message");
    println!();
    println!("CSV Format: last_seen,mac_address,ip_address,hostname,first_seen");
    println!();
    println!("API Endpoints (when --api is enabled):");
    println!("  GET /devices       - List all devices as JSON");
    println!("  GET /devices/count - Get device count");
    println!("  GET /health        - Health check");
}

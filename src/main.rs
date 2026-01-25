// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

#[cfg(feature = "http-api")]
use lanwatch::start_api_server;
#[cfg(feature = "mdns")]
use lanwatch::{MdnsQuerier, MdnsRecordData, MdnsServiceRegistry, NetworkEvent, NetworkSniffer};
use lanwatch::{list_interfaces, DeviceTracker, DhcpEvent, DhcpSniffer, Dhcpv6Option, OuiRegistry, download_ieee_oui, IEEE_OUI_URL};
use std::env;
use std::sync::{Arc, RwLock};

const DEFAULT_CSV_PATH: &str = "devices.csv";
#[cfg(feature = "http-api")]
const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_OUI_DOWNLOAD_PATH: &str = "ieee-oui.txt";

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Check for --download-oui before normal parsing
    if args.iter().any(|a| a == "--download-oui") {
        handle_download_oui(&args);
        return;
    }

    let config = parse_args(&args);

    println!("Sniffing DHCP (v4 & v6) traffic on: {}", config.interface_name);
    #[cfg(feature = "mdns")]
    if config.enable_mdns {
        println!("mDNS sniffing: enabled");
    }
    println!("Saving device info to: {}", config.csv_path);

    #[allow(unused_mut)]
    let mut tracker = DeviceTracker::new(&config.csv_path).unwrap_or_else(|e| {
        eprintln!("Error creating device tracker: {}", e);
        std::process::exit(1);
    });

    // Load IEEE OUI registry for vendor identification
    {
        let mut oui_registry = OuiRegistry::with_defaults();
        
        // Try to load custom OUI file
        if let Some(ref oui_path) = config.oui_file {
            match oui_registry.load_from_file(oui_path) {
                Ok(count) => println!("Loaded {} OUI entries from {}", count, oui_path),
                Err(e) => eprintln!("Warning: Failed to load OUI file: {}", e),
            }
        } else {
            // Try default location
            let default_oui = "oui.txt";
            if std::path::Path::new(default_oui).exists() {
                match oui_registry.load_from_file(default_oui) {
                    Ok(count) => println!("Loaded {} OUI entries from {}", count, default_oui),
                    Err(e) => eprintln!("Warning: Failed to load OUI file: {}", e),
                }
            }
        }
        
        println!("OUI database: {} vendor entries", oui_registry.len());
        tracker.set_oui_registry(oui_registry);
    }

    // Load mDNS service registry if mdns is enabled
    #[cfg(feature = "mdns")]
    if config.enable_mdns {
        let mut registry = MdnsServiceRegistry::with_defaults();
        
        // Try to load custom services file
        if let Some(ref services_path) = config.services_file {
            match registry.load_from_file(services_path) {
                Ok(count) => println!("Loaded {} services from {}", count, services_path),
                Err(e) => eprintln!("Warning: Failed to load services file: {}", e),
            }
        } else {
            // Try default location
            let default_services = "mdns-services.txt";
            if std::path::Path::new(default_services).exists() {
                match registry.load_from_file(default_services) {
                    Ok(count) => println!("Loaded {} services from {}", count, default_services),
                    Err(e) => eprintln!("Warning: Failed to load services file: {}", e),
                }
            }
        }
        
        tracker.set_service_registry(registry);
    }

    println!("Loaded {} existing devices from CSV", tracker.device_count());

    // Wrap tracker in Arc<RwLock> for thread-safe sharing
    let tracker = Arc::new(RwLock::new(tracker));

    // Start API server if address is provided
    #[cfg(feature = "http-api")]
    if let Some(addr) = &config.api_addr {
        let tracker_clone = Arc::clone(&tracker);
        match start_api_server(addr, tracker_clone) {
            Ok(_) => println!("API server started on http://{}", addr),
            Err(e) => eprintln!("Warning: Failed to start API server: {}", e),
        }
    }

    // Send active mDNS queries if enabled
    #[cfg(feature = "mdns")]
    if config.enable_mdns && config.mdns_query {
        println!("Sending mDNS queries for service discovery...");
        if let Ok(querier) = MdnsQuerier::new() {
            if let Err(e) = querier.query_common_services() {
                eprintln!("Warning: Failed to send mDNS queries: {}", e);
            }
        }
    }

    println!("Press Ctrl+C to stop\n");

    // Choose sniffer based on mDNS feature
    #[cfg(feature = "mdns")]
    if config.enable_mdns {
        run_network_sniffer(&config.interface_name, tracker);
    } else {
        run_dhcp_sniffer(&config.interface_name, tracker);
    }

    #[cfg(not(feature = "mdns"))]
    run_dhcp_sniffer(&config.interface_name, tracker);
}

fn run_dhcp_sniffer(interface_name: &str, tracker: Arc<RwLock<DeviceTracker>>) {
    let mut sniffer = DhcpSniffer::new(interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

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
                print_dhcpv4_packet(packet, is_new_or_updated, tracker.device_count());
            }
            DhcpEvent::V6(packet) => {
                let is_new_or_updated = tracker.update_from_dhcpv6(packet);
                print_dhcpv6_packet(packet, is_new_or_updated, tracker.device_count());
            }
        }
        true
    });
}

#[cfg(feature = "mdns")]
fn run_network_sniffer(interface_name: &str, tracker: Arc<RwLock<DeviceTracker>>) {
    let mut sniffer = NetworkSniffer::new(interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    sniffer.run(|event| {
        let mut tracker = match tracker.write() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error acquiring lock: {}", e);
                return true;
            }
        };

        match &event {
            NetworkEvent::Dhcpv4(packet) => {
                let is_new_or_updated = tracker.update_from_dhcpv4(packet);
                print_dhcpv4_packet(packet, is_new_or_updated, tracker.device_count());
            }
            NetworkEvent::Dhcpv6(packet) => {
                let is_new_or_updated = tracker.update_from_dhcpv6(packet);
                print_dhcpv6_packet(packet, is_new_or_updated, tracker.device_count());
            }
            NetworkEvent::Mdns(packet) => {
                let updated_count = tracker.update_from_mdns(packet);
                print_mdns_packet(packet, updated_count, tracker.device_count());
            }
        }
        true
    });
}

fn print_dhcpv4_packet(packet: &lanwatch::Dhcpv4Packet, is_new_or_updated: bool, total: usize) {
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
        println!("-> [CSV Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

fn print_dhcpv6_packet(packet: &lanwatch::Dhcpv6Packet, is_new_or_updated: bool, total: usize) {
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
        println!("-> [CSV Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "mdns")]
fn print_mdns_packet(packet: &lanwatch::MdnsPacket, updated_count: usize, total: usize) {
    let packet_type = if packet.is_response { "Response" } else { "Query" };
    println!("\n[mDNS] {} from {} (MAC: {})", packet_type, packet.source_ip, packet.source_mac);

    // Print questions
    for q in &packet.questions {
        println!("  ? {} ({})", q.name, q.record_type);
    }

    // Print answers and additional records
    for record in packet.all_records() {
        match &record.data {
            MdnsRecordData::A(addr) => {
                println!("  A: {} -> {}", record.name, addr);
            }
            MdnsRecordData::Aaaa(addr) => {
                println!("  AAAA: {} -> {}", record.name, addr);
            }
            MdnsRecordData::Ptr(target) => {
                println!("  PTR: {} -> {}", record.name, target);
            }
            MdnsRecordData::Srv { port, target, .. } => {
                println!("  SRV: {} -> {}:{}", record.name, target, port);
            }
            MdnsRecordData::Txt(strings) => {
                if !strings.is_empty() {
                    println!("  TXT: {} = {:?}", record.name, strings);
                }
            }
            MdnsRecordData::Raw(_) => {}
        }
    }

    if updated_count > 0 {
        println!("-> [CSV Updated] {} device(s), Total: {}", updated_count, total);
    }
    println!("------------------------------");
}

/// Configuration parsed from command line arguments
struct Config {
    interface_name: String,
    csv_path: String,
    #[cfg(feature = "http-api")]
    api_addr: Option<String>,
    #[cfg(feature = "mdns")]
    enable_mdns: bool,
    #[cfg(feature = "mdns")]
    mdns_query: bool,
    #[cfg(feature = "mdns")]
    services_file: Option<String>,
    oui_file: Option<String>,
}

fn parse_args(args: &[String]) -> Config {
    let mut interface_name = None;
    let mut csv_path = DEFAULT_CSV_PATH.to_string();
    #[cfg(feature = "http-api")]
    let mut api_addr: Option<String> = None;
    #[cfg(feature = "mdns")]
    let mut enable_mdns = false;
    #[cfg(feature = "mdns")]
    let mut mdns_query = false;
    #[cfg(feature = "mdns")]
    let mut services_file: Option<String> = None;
    let mut oui_file: Option<String> = None;

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
            #[cfg(feature = "http-api")]
            "-a" | "--api" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    api_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    api_addr = Some(DEFAULT_API_ADDR.to_string());
                    i += 1;
                }
            }
            #[cfg(feature = "http-api")]
            "--api-default" => {
                api_addr = Some(DEFAULT_API_ADDR.to_string());
                i += 1;
            }
            #[cfg(feature = "mdns")]
            "-m" | "--mdns" => {
                enable_mdns = true;
                i += 1;
            }
            #[cfg(feature = "mdns")]
            "--mdns-query" => {
                enable_mdns = true;
                mdns_query = true;
                i += 1;
            }
            #[cfg(feature = "mdns")]
            "-s" | "--services" => {
                if i + 1 < args.len() {
                    services_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --services requires a file path");
                    std::process::exit(1);
                }
            }
            "-u" | "--oui" => {
                if i + 1 < args.len() {
                    oui_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --oui requires a file path");
                    std::process::exit(1);
                }
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

    Config {
        interface_name,
        csv_path,
        #[cfg(feature = "http-api")]
        api_addr,
        #[cfg(feature = "mdns")]
        enable_mdns,
        #[cfg(feature = "mdns")]
        mdns_query,
        #[cfg(feature = "mdns")]
        services_file,
        oui_file,
    }
}

fn print_usage() {
    println!("Usage: lanwatch <interface_name> [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -o, --output <FILE>    Output CSV file path (default: devices.csv)");
    println!("  -u, --oui <FILE>       Load IEEE OUI database for vendor identification");
    #[cfg(feature = "http-api")]
    {
        println!("  -a, --api <ADDR:PORT>  Start HTTP API server (e.g., 127.0.0.1:8080)");
        println!("  --api-default          Start HTTP API on default address (127.0.0.1:8080)");
    }
    #[cfg(feature = "mdns")]
    {
        println!("  -m, --mdns             Enable mDNS sniffing for device discovery");
        println!("  --mdns-query           Enable mDNS and send active queries for services");
        println!("  -s, --services <FILE>  Load mDNS service definitions from file");
    }
    println!("  -h, --help             Show this help message");
    println!();
    println!("OUI Database Commands:");
    println!("  --download-oui [FILE]  Download latest IEEE OUI database");
    println!("                         Default output: {}", DEFAULT_OUI_DOWNLOAD_PATH);
    println!();
    println!("CSV Format: first_seen,last_seen,mac_address,ip_address,ipv6_address,hostname,device_type,vendor,services");
    println!();
    println!("OUI Database:");
    println!("  Uses IEEE OUI database (40,000+ vendors) for MAC address identification.");
    println!("  Use -u/--oui to load additional custom entries that override the built-in database.");
    println!("  Download latest from: {}", IEEE_OUI_URL);
    #[cfg(feature = "http-api")]
    {
        println!();
        println!("API Endpoints (when --api is enabled):");
        println!("  GET /devices       - List all devices as JSON");
        println!("  GET /devices/count - Get device count");
        println!("  GET /health        - Health check");
    }
    #[cfg(feature = "mdns")]
    {
        println!();
        println!("mDNS Discovery (when --mdns is enabled):");
        println!("  Passively captures mDNS traffic to identify device hostnames and services.");
        println!("  Use --mdns-query to also send active discovery queries.");
    }
}

/// Handle --download-oui command
fn handle_download_oui(args: &[String]) {
    // Find the output path (argument after --download-oui, if any)
    let mut output_path = DEFAULT_OUI_DOWNLOAD_PATH;
    
    for i in 0..args.len() {
        if args[i] == "--download-oui" {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                output_path = &args[i + 1];
            }
            break;
        }
    }

    println!("Downloading IEEE OUI database...");
    println!("  Source: {}", IEEE_OUI_URL);
    println!("  Output: {}", output_path);

    match download_ieee_oui(output_path, None) {
        Ok(()) => {
            // Get file size
            if let Ok(metadata) = std::fs::metadata(output_path) {
                let size_mb = metadata.len() as f64 / 1024.0 / 1024.0;
                println!("  Downloaded: {:.2} MB", size_mb);
            }

            // Count entries in the downloaded file
            println!("  Parsing...");
            let mut registry = OuiRegistry::new();
            match registry.load_from_ieee_file(output_path) {
                Ok(count) => {
                    println!("  Entries: {} vendors", count);
                    println!();
                    println!("Download complete! Use with: lanwatch <interface> -u {}", output_path);
                }
                Err(e) => {
                    eprintln!("Warning: Downloaded but failed to parse: {}", e);
                    eprintln!("The file may be corrupted or in an unexpected format.");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: Failed to download IEEE OUI database");
            eprintln!("  {}", e);
            eprintln!();
            eprintln!("You can manually download from: {}", IEEE_OUI_URL);
            std::process::exit(1);
        }
    }
}

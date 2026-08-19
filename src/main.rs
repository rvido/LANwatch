// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

#[cfg(feature = "http-api")]
use lanwatch::start_api_server;
use lanwatch::{
    DeviceTracker, DeviceType, DhcpEvent, DhcpSniffer, Dhcpv6Option, IEEE_OUI_URL, OuiRegistry,
    download_ieee_oui, list_interfaces,
};
#[cfg(feature = "mdns")]
use lanwatch::{MdnsQuerier, MdnsRecordData, MdnsServiceRegistry};
#[cfg(any(feature = "mdns", feature = "ssdp"))]
use lanwatch::{NetworkEvent, NetworkSniffer, display_safe, format_mac};
#[cfg(feature = "ssdp")]
use lanwatch::{SsdpPacket, SsdpQuerier};
use std::env;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_DB_PATH: &str = "devices.db";
#[cfg(feature = "http-api")]
const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_OUI_DOWNLOAD_PATH: &str = "ieee-oui.txt";
// Tuned defaults for bursty LAN discovery traffic (mDNS/SSDP).
// Aim: absorb short bursts while keeping DB/API state latency low.
const EVENT_CHANNEL_CAPACITY: usize = 4096;
const DB_FLUSH_BATCH_SIZE: usize = 32;
const DB_FLUSH_INTERVAL_MS: u64 = 300;
/// How often (in dropped events) to warn that the worker is falling behind.
const DROPPED_EVENT_REPORT_INTERVAL: u64 = 1000;

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Check for --download-oui before normal parsing
    if args.iter().any(|a| a == "--download-oui") {
        handle_download_oui(&args);
        return;
    }

    let config = parse_args(&args);

    println!(
        "Sniffing DHCP (v4 & v6) traffic on: {}",
        config.interface_name
    );
    #[cfg(feature = "mdns")]
    if config.enable_mdns {
        println!("mDNS sniffing: enabled");
    }
    #[cfg(feature = "ssdp")]
    if config.enable_ssdp {
        println!("SSDP/UPnP sniffing: enabled");
    }
    println!("Saving device info to: {}", config.db_path);

    #[allow(unused_mut)]
    let mut tracker = DeviceTracker::new(&config.db_path).unwrap_or_else(|e| {
        eprintln!("Error creating device tracker: {}", e);
        std::process::exit(1);
    });

    // Load IEEE OUI registry for vendor identification
    {
        let mut oui_registry = OuiRegistry::with_defaults();

        // Try to load custom OUI file
        if let Some(ref oui_path) = config.oui_file {
            match oui_registry.load_auto(oui_path) {
                Ok(count) => println!("Loaded {} OUI entries from {}", count, oui_path),
                Err(e) => eprintln!("Warning: Failed to load OUI file: {}", e),
            }
        } else {
            // Try default locations: prefer the IEEE-format file that
            // --download-oui produces, fall back to a plain oui.txt for
            // users maintaining their own MAC/vendor override list.
            let default_oui = if std::path::Path::new(DEFAULT_OUI_DOWNLOAD_PATH).exists() {
                Some(DEFAULT_OUI_DOWNLOAD_PATH)
            } else if std::path::Path::new("oui.txt").exists() {
                Some("oui.txt")
            } else {
                None
            };
            if let Some(default_oui) = default_oui {
                match oui_registry.load_auto(default_oui) {
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

    // Register manual per-device classification overrides.
    {
        if let Some(ref path) = config.overrides_file {
            match tracker.load_overrides_from_file(path) {
                Ok(count) => println!("Loaded {} device override(s) from {}", count, path),
                Err(e) => eprintln!("Warning: Failed to load overrides file {}: {}", path, e),
            }
        }
        for spec in &config.override_specs {
            match parse_override_spec(spec) {
                Some((mac, type_str)) => {
                    tracker.add_override(mac, Some(DeviceType::from(type_str)), None);
                }
                None => eprintln!(
                    "Warning: Ignoring malformed --override '{}' (expected MAC=Type)",
                    spec
                ),
            }
        }
        if tracker.override_count() > 0 {
            println!("Active device overrides: {}", tracker.override_count());
        }
    }

    println!(
        "Loaded {} existing devices from database",
        tracker.device_count()
    );
    println!(
        "Batching: queue_capacity={}, flush_batch_size={}, flush_interval_ms={}",
        EVENT_CHANNEL_CAPACITY, DB_FLUSH_BATCH_SIZE, DB_FLUSH_INTERVAL_MS
    );

    // Re-evaluate and correct any database entries using the latest classification rules on startup
    tracker.reclassify_all();

    // Use batched DB flushing through worker threads to reduce write amplification.
    tracker.set_auto_save(false);

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
        let interface_ip = lanwatch::get_interface_ipv4(&config.interface_name);
        if let Ok(querier) = MdnsQuerier::new(interface_ip)
            && let Err(e) = querier.query_common_services()
        {
            eprintln!("Warning: Failed to send mDNS queries: {}", e);
        }
    }

    // Send active SSDP queries if enabled
    #[cfg(feature = "ssdp")]
    if config.enable_ssdp && config.ssdp_query {
        println!("Sending SSDP M-SEARCH discovery probes...");
        let interface_ip = lanwatch::get_interface_ipv4(&config.interface_name);
        if let Ok(querier) = SsdpQuerier::new(interface_ip)
            && let Err(e) = querier.search_common_devices()
        {
            eprintln!("Warning: Failed to send SSDP queries: {}", e);
        }
    }

    println!("Press Ctrl+C to stop\n");

    // Choose sniffer based on mDNS feature
    #[cfg(all(feature = "mdns", feature = "ssdp"))]
    if config.enable_mdns || config.enable_ssdp {
        run_network_sniffer(
            &config.interface_name,
            tracker,
            config.enable_mdns,
            config.enable_ssdp,
        );
    } else {
        run_dhcp_sniffer(&config.interface_name, tracker);
    }

    #[cfg(all(feature = "mdns", not(feature = "ssdp")))]
    if config.enable_mdns {
        run_network_sniffer(&config.interface_name, tracker, true, false);
    } else {
        run_dhcp_sniffer(&config.interface_name, tracker);
    }

    #[cfg(all(feature = "ssdp", not(feature = "mdns")))]
    if config.enable_ssdp {
        run_network_sniffer(&config.interface_name, tracker, false, true);
    } else {
        run_dhcp_sniffer(&config.interface_name, tracker);
    }

    #[cfg(not(any(feature = "mdns", feature = "ssdp")))]
    run_dhcp_sniffer(&config.interface_name, tracker);
}

/// Hands `event` to the worker thread without ever blocking the capture loop.
///
/// `SyncSender::send` blocks when the channel is full, which stalls packet
/// capture and silently overflows the kernel's ring buffer -- packets are lost
/// either way, but blocking loses them invisibly. Dropping the event instead
/// keeps capture running and makes the loss countable, so a periodic notice
/// can tell the operator their data has gaps.
///
/// Returns `false` only when the worker is gone, which ends the capture loop.
fn forward_event<T>(tx: &mpsc::SyncSender<T>, event: T, dropped: &mut u64) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) => {
            *dropped += 1;
            if dropped.is_multiple_of(DROPPED_EVENT_REPORT_INTERVAL) {
                eprintln!(
                    "Warning: worker cannot keep up; {} event(s) dropped so far",
                    dropped
                );
            }
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

fn run_dhcp_sniffer(interface_name: &str, tracker: Arc<RwLock<DeviceTracker>>) {
    let (tx, rx) = mpsc::sync_channel::<DhcpEvent>(EVENT_CHANNEL_CAPACITY);
    let worker = start_dhcp_worker(rx, Arc::clone(&tracker));

    let mut sniffer = DhcpSniffer::new(interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let mut dropped = 0u64;
    sniffer.run(|event| forward_event(&tx, event, &mut dropped));

    drop(tx);
    let _ = worker.join();
    report_dropped_events(dropped);
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn run_network_sniffer(
    interface_name: &str,
    tracker: Arc<RwLock<DeviceTracker>>,
    enable_mdns: bool,
    enable_ssdp: bool,
) {
    let (tx, rx) = mpsc::sync_channel::<NetworkEvent>(EVENT_CHANNEL_CAPACITY);
    let worker = start_network_worker(rx, Arc::clone(&tracker), enable_mdns, enable_ssdp);

    let mut sniffer = NetworkSniffer::new(interface_name).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let mut dropped = 0u64;
    sniffer.run(|event| forward_event(&tx, event, &mut dropped));

    drop(tx);
    let _ = worker.join();
    report_dropped_events(dropped);
}

/// Reports the final dropped-event tally, if any, so a run that silently shed
/// load doesn't look like a clean one.
fn report_dropped_events(dropped: u64) {
    if dropped > 0 {
        eprintln!(
            "Warning: {} event(s) were dropped because the database worker fell behind",
            dropped
        );
    }
}

fn start_dhcp_worker(
    rx: Receiver<DhcpEvent>,
    tracker: Arc<RwLock<DeviceTracker>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let flush_interval = Duration::from_millis(DB_FLUSH_INTERVAL_MS);
        let mut pending_updates = 0usize;
        let mut last_flush = Instant::now();

        loop {
            match rx.recv_timeout(flush_interval) {
                Ok(first_event) => {
                    let mut events = Vec::new();
                    events.push(first_event);
                    while let Ok(ev) = rx.try_recv() {
                        events.push(ev);
                        if events.len() >= 256 {
                            break;
                        }
                    }

                    let mut tracker = match tracker.write() {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("Error acquiring lock: {}", e);
                            continue;
                        }
                    };

                    for ev in &events {
                        match ev {
                            DhcpEvent::V4(packet) => {
                                let is_new_or_updated = tracker.update_from_dhcpv4(packet);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_dhcpv4_packet(
                                    packet,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                            DhcpEvent::V6(packet) => {
                                let is_new_or_updated = tracker.update_from_dhcpv6(packet);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_dhcpv6_packet(
                                    packet,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                        }
                    }

                    // Re-pin any device that a heuristic just reclassified away
                    // from its manual override.
                    pending_updates += tracker.apply_overrides();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if pending_updates >= DB_FLUSH_BATCH_SIZE
                || (pending_updates > 0 && last_flush.elapsed() >= flush_interval)
            {
                flush_tracker(&tracker, pending_updates);
                pending_updates = 0;
                last_flush = Instant::now();
            }
        }

        if pending_updates > 0 {
            flush_tracker(&tracker, pending_updates);
        }
    })
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn start_network_worker(
    rx: Receiver<NetworkEvent>,
    tracker: Arc<RwLock<DeviceTracker>>,
    _enable_mdns: bool,
    _enable_ssdp: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let flush_interval = Duration::from_millis(DB_FLUSH_INTERVAL_MS);
        let mut pending_updates = 0usize;
        let mut last_flush = Instant::now();

        loop {
            match rx.recv_timeout(flush_interval) {
                Ok(first_event) => {
                    let mut events = Vec::new();
                    events.push(first_event);
                    while let Ok(ev) = rx.try_recv() {
                        events.push(ev);
                        if events.len() >= 256 {
                            break;
                        }
                    }

                    let mut tracker = match tracker.write() {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("Error acquiring lock: {}", e);
                            continue;
                        }
                    };

                    for ev in &events {
                        match ev {
                            NetworkEvent::Dhcpv4(packet) => {
                                let is_new_or_updated = tracker.update_from_dhcpv4(packet);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_dhcpv4_packet(
                                    packet,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                            NetworkEvent::Dhcpv6(packet) => {
                                let is_new_or_updated = tracker.update_from_dhcpv6(packet);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_dhcpv6_packet(
                                    packet,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                            #[cfg(feature = "mdns")]
                            NetworkEvent::Mdns(packet) => {
                                if _enable_mdns {
                                    let updated_count = tracker.update_from_mdns(packet);
                                    if updated_count > 0 {
                                        pending_updates += 1;
                                    }
                                    print_mdns_packet(
                                        packet,
                                        updated_count,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "mdns")]
                            NetworkEvent::Llmnr(packet) => {
                                if _enable_mdns {
                                    let updated_count = tracker.update_from_llmnr(packet);
                                    if updated_count > 0 {
                                        pending_updates += 1;
                                    }
                                    print_llmnr_packet(
                                        packet,
                                        updated_count,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "mdns")]
                            NetworkEvent::Nbns(packet) => {
                                if _enable_mdns {
                                    let updated_count = tracker.update_from_nbns(packet);
                                    if updated_count > 0 {
                                        pending_updates += 1;
                                    }
                                    print_nbns_packet(
                                        packet,
                                        updated_count,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Ssdp(packet) => {
                                if _enable_ssdp {
                                    let updated_count = tracker.update_from_ssdp(packet);
                                    if updated_count > 0 {
                                        pending_updates += 1;
                                    }
                                    print_ssdp_packet(
                                        packet,
                                        updated_count,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Wsd(packet) => {
                                if _enable_ssdp {
                                    let updated_count = tracker.update_from_wsd(packet);
                                    if updated_count > 0 {
                                        pending_updates += 1;
                                    }
                                    print_wsd_packet(packet, updated_count, tracker.device_count());
                                }
                            }
                            NetworkEvent::Arp {
                                source_mac,
                                source_ip,
                            } => {
                                let mac = format_mac(*source_mac);
                                let is_new_or_updated =
                                    tracker.update_device(&mac, *source_ip, None);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_arp_packet(
                                    &mac,
                                    source_ip,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                            NetworkEvent::Ndp {
                                source_mac,
                                source_ip,
                            } => {
                                let mac = format_mac(*source_mac);
                                let is_new_or_updated =
                                    tracker.update_device(&mac, *source_ip, None);
                                if is_new_or_updated {
                                    pending_updates += 1;
                                }
                                print_ndp_packet(
                                    &mac,
                                    source_ip,
                                    is_new_or_updated,
                                    tracker.device_count(),
                                );
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Lldp(packet) => {
                                if _enable_ssdp {
                                    let is_new_or_updated = tracker.update_from_lldp(packet);
                                    if is_new_or_updated {
                                        pending_updates += 1;
                                    }
                                    print_lldp_packet(
                                        packet,
                                        is_new_or_updated,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Cdp(packet) => {
                                if _enable_ssdp {
                                    let is_new_or_updated = tracker.update_from_cdp(packet);
                                    if is_new_or_updated {
                                        pending_updates += 1;
                                    }
                                    print_cdp_packet(
                                        packet,
                                        is_new_or_updated,
                                        tracker.device_count(),
                                    );
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Lifx(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_lifx(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_lifx_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Coap(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_coap(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_coap_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Knx(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_knx(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_knx_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Cctv(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_cctv(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_cctv_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Mqtt(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_mqtt(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_mqtt_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                            #[cfg(feature = "ssdp")]
                            NetworkEvent::Gdm(packet) => {
                                if _enable_ssdp {
                                    let updates = tracker.update_from_gdm(packet);
                                    if updates > 0 {
                                        pending_updates += updates;
                                    }
                                    print_gdm_packet(packet, updates > 0, tracker.device_count());
                                }
                            }
                        }
                    }

                    // Re-pin any device that a heuristic just reclassified away
                    // from its manual override.
                    pending_updates += tracker.apply_overrides();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if pending_updates >= DB_FLUSH_BATCH_SIZE
                || (pending_updates > 0 && last_flush.elapsed() >= flush_interval)
            {
                flush_tracker(&tracker, pending_updates);
                pending_updates = 0;
                last_flush = Instant::now();
            }
        }

        if pending_updates > 0 {
            flush_tracker(&tracker, pending_updates);
        }
    })
}

fn flush_tracker(tracker: &Arc<RwLock<DeviceTracker>>, pending_updates: usize) {
    let tracker = match tracker.read() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error acquiring lock for DB flush: {}", e);
            return;
        }
    };

    if let Err(e) = tracker.flush_to_db() {
        eprintln!("Warning: Failed to flush DB: {}", e);
    } else {
        println!(
            "-> [DB Flushed] batched updates: {}, Total devices: {}",
            pending_updates,
            tracker.device_count()
        );
    }
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn print_ndp_packet(mac: &str, ip: &std::net::IpAddr, is_new_or_updated: bool, total: usize) {
    println!("\n[NDP] Neighbor Discovery Packet Detected");
    println!("Sender MAC: {}", mac);
    println!("Sender IP:  {}", ip);
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_lldp_packet(packet: &lanwatch::LldpPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[LLDP] Link Layer Discovery Packet Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    if let Some(ref name) = packet.system_name {
        println!("System Name: {}", name);
    }
    if let Some(ref desc) = packet.system_description {
        println!("System Desc: {}", desc);
    }
    if let Some(ref port) = packet.port_id {
        println!("Port ID:     {}", port);
    }
    if let Some(ref ip) = packet.management_address {
        println!("Mgmt IP:     {}", ip);
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_lifx_packet(packet: &lanwatch::LifxPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[LIFX] Smart Device Packet Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    println!("Target MAC: {}", format_mac(packet.target_mac));
    println!("Msg Type:   {}", packet.msg_type);
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_coap_packet(packet: &lanwatch::CoapPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[CoAP] Constrained Device Packet Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    println!("Code:       {}", packet.code);
    println!("Message ID: {}", packet.message_id);
    if let Some(ref payload) = packet.payload {
        println!("Payload:    {}", payload);
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_knx_packet(packet: &lanwatch::KnxPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[KNX] Building Automation Packet Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    println!("Service:    0x{:04x}", packet.service_type);
    if let Some(ref name) = packet.friendly_name {
        println!("Name:       {}", name);
    }
    if let Some(ref serial) = packet.serial_number {
        println!("Serial:     {}", serial);
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_cctv_packet(packet: &lanwatch::CctvPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[CCTV] Physical Security/IP Camera Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    println!("Vendor:     {}", packet.vendor);
    if let Some(ref model) = packet.model {
        println!("Model:      {}", model);
    }
    if let Some(ref serial) = packet.serial_number {
        println!("Serial:     {}", serial);
    }
    println!("Protocol:   {}", packet.protocol);
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_mqtt_packet(packet: &lanwatch::MqttPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[MQTT] IoT Device Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    println!("Client ID:  {}", packet.client_id);
    println!("Protocol:   {}", packet.protocol);
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_gdm_packet(packet: &lanwatch::GdmPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[Plex GDM] Media Device Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    println!("Source IP:  {}", packet.source_ip);
    if let Some(ref name) = packet.name {
        println!("Name:       {}", name);
    }
    if let Some(ref product) = packet.product {
        println!("Product:    {}", product);
    }
    if let Some(ref resource_id) = packet.resource_id {
        println!("UUID:       {}", resource_id);
    }
    if let Some(port) = packet.port {
        println!("Port:       {}", port);
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_cdp_packet(packet: &lanwatch::CdpPacket, is_new_or_updated: bool, total: usize) {
    println!("\n[CDP] Cisco Discovery Packet Detected");
    println!("Source MAC: {}", format_mac(packet.source_mac));
    if let Some(ref dev_id) = packet.device_id {
        println!("Device ID:   {}", dev_id);
    }
    if let Some(ref plat) = packet.platform {
        println!("Platform:    {}", plat);
    }
    if let Some(ref port) = packet.port_id {
        println!("Port ID:     {}", port);
    }
    if let Some(ref ip) = packet.management_address {
        println!("Mgmt IP:     {}", ip);
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn print_arp_packet(mac: &str, ip: &std::net::IpAddr, is_new_or_updated: bool, total: usize) {
    println!("\n[ARP] Packet Detected");
    println!("Sender MAC: {}", mac);
    println!("Sender IP:  {}", ip);
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
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
        println!("-> [DB Updated] Total devices: {}", total);
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
            Dhcpv6Option::UserClass(classes) => {
                println!("-> User Class: {:?}", classes);
            }
            Dhcpv6Option::VendorClass {
                enterprise_number,
                data,
            } => {
                println!("-> Vendor Class (Ent {}): {:?}", enterprise_number, data);
            }
            Dhcpv6Option::Other { .. } => {}
        }
    }
    if is_new_or_updated {
        println!("-> [DB Updated] Total devices: {}", total);
    }
    println!("------------------------------");
}

#[cfg(feature = "mdns")]
fn print_mdns_packet(packet: &lanwatch::MdnsPacket, updated_count: usize, total: usize) {
    let packet_type = if packet.is_response {
        "Response"
    } else {
        "Query"
    };
    println!(
        "\n[mDNS] {} from {} (MAC: {})",
        packet_type,
        packet.source_ip,
        format_mac(packet.source_mac)
    );

    for q in &packet.questions {
        println!("  ? {} ({})", display_safe(&q.name), q.record_type);
    }

    for record in packet.all_records() {
        match &record.data {
            MdnsRecordData::A(addr) => {
                println!("  A: {} -> {}", display_safe(&record.name), addr);
            }
            MdnsRecordData::Aaaa(addr) => {
                println!("  AAAA: {} -> {}", display_safe(&record.name), addr);
            }
            MdnsRecordData::Ptr(target) => {
                println!(
                    "  PTR: {} -> {}",
                    display_safe(&record.name),
                    display_safe(target)
                );
            }
            MdnsRecordData::Srv { port, target, .. } => {
                println!(
                    "  SRV: {} -> {}:{}",
                    display_safe(&record.name),
                    display_safe(target),
                    port
                );
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
        println!(
            "-> [DB Updated] {} device(s), Total: {}",
            updated_count, total
        );
    }
    println!("------------------------------");
}

#[cfg(feature = "mdns")]
fn print_llmnr_packet(packet: &lanwatch::MdnsPacket, updated_count: usize, total: usize) {
    let packet_type = if packet.is_response {
        "Response"
    } else {
        "Query"
    };
    println!(
        "\n[LLMNR] {} from {} (MAC: {})",
        packet_type,
        packet.source_ip,
        format_mac(packet.source_mac)
    );

    for q in &packet.questions {
        println!("  ? {} ({})", display_safe(&q.name), q.record_type);
    }

    for record in packet.all_records() {
        match &record.data {
            MdnsRecordData::A(addr) => {
                println!("  A: {} -> {}", display_safe(&record.name), addr);
            }
            MdnsRecordData::Aaaa(addr) => {
                println!("  AAAA: {} -> {}", display_safe(&record.name), addr);
            }
            _ => {}
        }
    }

    if updated_count > 0 {
        println!(
            "-> [DB Updated] {} device(s), Total: {}",
            updated_count, total
        );
    }
    println!("------------------------------");
}

#[cfg(feature = "mdns")]
fn print_nbns_packet(packet: &lanwatch::NbnsPacket, updated_count: usize, total: usize) {
    println!(
        "\n[NetBIOS] Name Service from {} (MAC: {})",
        packet.source_ip,
        format_mac(packet.source_mac)
    );
    println!("  Name: {}", display_safe(&packet.name));
    let suffix_desc = match packet.suffix {
        0x00 => "Workstation",
        0x03 => "Messenger",
        0x20 => "File Server",
        _ => "Other",
    };
    println!("  Suffix: 0x{:02X} ({})", packet.suffix, suffix_desc);

    if updated_count > 0 {
        println!(
            "-> [DB Updated] {} device(s), Total: {}",
            updated_count, total
        );
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_ssdp_packet(packet: &SsdpPacket, updated_count: usize, total: usize) {
    println!(
        "\n[SSDP] {} from {} (MAC: {})",
        packet.message_type,
        packet.source_ip,
        format_mac(packet.source_mac)
    );
    println!("Start line: {}", display_safe(&packet.start_line));

    if let Some(nt) = packet.header("nt") {
        println!("  NT: {}", display_safe(nt));
    }
    if let Some(st) = packet.header("st") {
        println!("  ST: {}", display_safe(st));
    }
    if let Some(usn) = packet.header("usn") {
        println!("  USN: {}", display_safe(usn));
    }
    if let Some(server) = packet.header("server") {
        println!("  Server: {}", display_safe(server));
    }
    if let Some(location) = packet.header("location") {
        println!("  Location: {}", display_safe(location));
    }

    if updated_count > 0 {
        println!(
            "-> [DB Updated] {} device(s), Total: {}",
            updated_count, total
        );
    }
    println!("------------------------------");
}

#[cfg(feature = "ssdp")]
fn print_wsd_packet(packet: &lanwatch::WsdPacket, updated_count: usize, total: usize) {
    println!(
        "\n[WS-Discovery] Hello/ProbeMatches from {} (MAC: {})",
        packet.source_ip,
        format_mac(packet.source_mac)
    );
    if let Some(ref t) = packet.device_type {
        println!("  Device Type: {}", t);
    }
    if let Some(ref v) = packet.vendor {
        println!("  Vendor: {}", v);
    }

    if updated_count > 0 {
        println!(
            "-> [DB Updated] {} device(s), Total: {}",
            updated_count, total
        );
    }
    println!("------------------------------");
}

/// Configuration parsed from command line arguments
struct Config {
    interface_name: String,
    db_path: String,
    #[cfg(feature = "http-api")]
    api_addr: Option<String>,
    #[cfg(feature = "mdns")]
    enable_mdns: bool,
    #[cfg(feature = "mdns")]
    mdns_query: bool,
    #[cfg(feature = "mdns")]
    services_file: Option<String>,
    #[cfg(feature = "ssdp")]
    enable_ssdp: bool,
    #[cfg(feature = "ssdp")]
    ssdp_query: bool,
    oui_file: Option<String>,
    /// Inline per-device classification overrides (`MAC=Type`).
    override_specs: Vec<String>,
    /// Path to a file of per-device classification overrides.
    overrides_file: Option<String>,
}

fn parse_args(args: &[String]) -> Config {
    let mut interface_name = None;
    let mut db_path = DEFAULT_DB_PATH.to_string();
    #[cfg(feature = "http-api")]
    let mut api_addr: Option<String> = None;
    #[cfg(feature = "mdns")]
    let mut enable_mdns = false;
    #[cfg(feature = "mdns")]
    let mut mdns_query = false;
    #[cfg(feature = "mdns")]
    let mut services_file: Option<String> = None;
    #[cfg(feature = "ssdp")]
    let mut enable_ssdp = false;
    #[cfg(feature = "ssdp")]
    let mut ssdp_query = false;
    let mut oui_file: Option<String> = None;
    let mut override_specs: Vec<String> = Vec::new();
    let mut overrides_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    db_path = args[i + 1].clone();
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
            #[cfg(feature = "ssdp")]
            "-p" | "--ssdp" | "--upnp" => {
                enable_ssdp = true;
                i += 1;
            }
            #[cfg(feature = "ssdp")]
            "--ssdp-query" => {
                enable_ssdp = true;
                ssdp_query = true;
                i += 1;
            }
            #[cfg(not(feature = "ssdp"))]
            "-p" | "--ssdp" | "--upnp" | "--ssdp-query" => {
                eprintln!("Error: SSDP options require a binary built with the 'ssdp' feature.");
                eprintln!("Rebuild with: cargo build --release --features ssdp");
                std::process::exit(1);
            }
            #[cfg(feature = "mdns")]
            "--mdns-query" => {
                enable_mdns = true;
                mdns_query = true;
                i += 1;
            }
            #[cfg(not(feature = "mdns"))]
            "-m" | "--mdns" | "--mdns-query" | "-s" | "--services" => {
                eprintln!("Error: mDNS options require a binary built with the 'mdns' feature.");
                eprintln!("Rebuild with: cargo build --release --features mdns");
                std::process::exit(1);
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
            "--override" => {
                if i + 1 < args.len() {
                    override_specs.push(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --override requires a MAC=Type argument");
                    std::process::exit(1);
                }
            }
            "--overrides" => {
                if i + 1 < args.len() {
                    overrides_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --overrides requires a file path");
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
        db_path,
        #[cfg(feature = "http-api")]
        api_addr,
        #[cfg(feature = "mdns")]
        enable_mdns,
        #[cfg(feature = "mdns")]
        mdns_query,
        #[cfg(feature = "mdns")]
        services_file,
        #[cfg(feature = "ssdp")]
        enable_ssdp,
        #[cfg(feature = "ssdp")]
        ssdp_query,
        oui_file,
        override_specs,
        overrides_file,
    }
}

/// Parses a single `MAC=Type` override spec into its components.
fn parse_override_spec(spec: &str) -> Option<(&str, &str)> {
    let (mac, device_type) = spec.split_once('=')?;
    let mac = mac.trim();
    let device_type = device_type.trim();
    if mac.is_empty() || device_type.is_empty() {
        return None;
    }
    Some((mac, device_type))
}

fn print_usage() {
    println!("Usage: lanwatch <interface_name> [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -o, --output <FILE>    Output database file path (default: devices.db)");
    println!("  -u, --oui <FILE>       Load IEEE OUI database for vendor identification");
    println!(
        "  --override <MAC=Type>  Pin a device's type (e.g. c0:84:7d:b8:58:5e=\"Security System\"); repeatable"
    );
    println!("  --overrides <FILE>     Load per-device overrides (lines: MAC,DeviceType[,Vendor])");
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
    #[cfg(feature = "ssdp")]
    {
        println!("  -p, --ssdp             Enable SSDP/UPnP sniffing for device discovery");
        println!("  --ssdp-query           Enable SSDP and send active M-SEARCH discovery probes");
        println!("  --upnp                 Alias for --ssdp");
    }
    println!("  -h, --help             Show this help message");
    println!();
    println!("OUI Database Commands:");
    println!("  --download-oui [FILE]  Download latest IEEE OUI database");
    println!(
        "                         Default output: {}",
        DEFAULT_OUI_DOWNLOAD_PATH
    );
    println!();
    println!("OUI Database:");
    println!("  Uses IEEE OUI database (40,000+ vendors) for MAC address identification.");
    println!(
        "  Use -u/--oui to load additional custom entries that override the built-in database."
    );
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
    #[cfg(feature = "ssdp")]
    {
        println!();
        println!("SSDP/UPnP Discovery (when --ssdp is enabled):");
        println!(
            "  Passively captures SSDP advertisements and responses to identify UPnP devices."
        );
        println!("  Use --ssdp-query to also send active M-SEARCH discovery probes.");
    }
    #[cfg(not(feature = "ssdp"))]
    {
        println!();
        println!("SSDP/UPnP Discovery:");
        println!("  Not available in this binary. Rebuild with '--features ssdp'.");
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
                    println!(
                        "Download complete! Use with: lanwatch <interface> -u {}",
                        output_path
                    );
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

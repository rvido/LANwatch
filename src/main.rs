// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

#[cfg(feature = "http-api")]
use lanwatch::start_api_server_with_hosts;
#[cfg(feature = "homeassistant")]
use lanwatch::{DEFAULT_MQTT_PORT, HomeAssistantConfig, start_home_assistant};
use lanwatch::{
    DEFAULT_OFFLINE_AFTER, DeviceTracker, DeviceType, DhcpEvent, DhcpSniffer, Dhcpv6Option,
    EventHook, FingerprintCatalogue, IEEE_OUI_URL, OuiRegistry, PresenceKind, download_ieee_oui,
    list_interfaces,
};
#[cfg(feature = "mdns")]
use lanwatch::{MdnsQuerier, MdnsRecordData, MdnsServiceRegistry};
#[cfg(any(feature = "mdns", feature = "ssdp"))]
use lanwatch::{NetworkEvent, NetworkSniffer, display_safe, format_mac};
#[cfg(feature = "ssdp")]
use lanwatch::{SsdpPacket, SsdpQuerier, start_upnp_describer};
use std::env;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const DEFAULT_DB_PATH: &str = "devices.db";
#[cfg(feature = "http-api")]
const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_OUI_DOWNLOAD_PATH: &str = "ieee-oui.txt";

/// Default profile catalogue, loaded when `--fingerprints` is not given.
const DEFAULT_FINGERPRINT_PATH: &str = "lanwatch-fingerprints.txt";
// Tuned defaults for bursty LAN discovery traffic (mDNS/SSDP).
// Aim: absorb short bursts while keeping DB/API state latency low.
const EVENT_CHANNEL_CAPACITY: usize = 4096;
const DB_FLUSH_BATCH_SIZE: usize = 32;
const DB_FLUSH_INTERVAL_MS: u64 = 300;
/// How often (in dropped events) to warn that the worker is falling behind.
const DROPPED_EVENT_REPORT_INTERVAL: u64 = 1000;
/// Shortest accepted `--query-interval`.
///
/// Active discovery puts multicast on the wire, so a typo such as `1` must not
/// turn LANwatch into a flood source on the operator's own LAN.
#[cfg(any(feature = "mdns", feature = "ssdp"))]
const MIN_QUERY_INTERVAL: Duration = Duration::from_secs(30);
/// How often the presence sweep compares `last_seen` against `--offline-after`.
const PRESENCE_SWEEP_INTERVAL: Duration = Duration::from_secs(10);
/// Shortest accepted `--offline-after`. Shorter than a couple of sweeps, and
/// every quiet device would flap between online and offline.
const MIN_OFFLINE_AFTER: Duration = Duration::from_secs(60);

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Check for --download-oui before normal parsing
    if args.iter().any(|a| a == "--download-oui") {
        handle_download_oui(&args);
        return;
    }

    let config = parse_args(&args);

    // Dumping reads what is already in the database, so it needs no interface
    // and no capture session. Run a normal capture for a few days first.
    if let Some(ref dump_path) = config.dump_fingerprints {
        handle_dump_fingerprints(&config.db_path, dump_path);
        return;
    }

    // Forgetting is the deliberate opposite of removing a device in the
    // dashboard: it also drops the manual classification and the collected
    // attribute tokens, so nothing about the device comes back.
    if let Some(ref mac) = config.forget_mac {
        handle_forget(&config.db_path, mac);
        return;
    }

    if config.trust_all || !config.trust_macs.is_empty() {
        handle_trust(&config.db_path, &config.trust_macs, config.trust_all);
        return;
    }

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

    // Load the fingerprint profile catalogue, like the OUI and mDNS registries.
    // Without one the existing heuristics run unchanged, so this only ever adds
    // information.
    {
        let path = config.fingerprints_file.clone().or_else(|| {
            std::path::Path::new(DEFAULT_FINGERPRINT_PATH)
                .exists()
                .then(|| DEFAULT_FINGERPRINT_PATH.to_string())
        });
        if let Some(path) = path {
            let mut catalogue = FingerprintCatalogue::new();
            match catalogue.load_from_file(&path) {
                Ok((count, skips)) => {
                    println!("Loaded {} fingerprint profile(s) from {}", count, path);
                    if !skips.is_empty() {
                        eprintln!(
                            "Warning: skipped {} line(s) in {}: {} bad field count, \
                             {} hash mismatch, {} too long, {} no tokens",
                            skips.total(),
                            path,
                            skips.bad_field_count,
                            skips.hash_mismatch,
                            skips.too_long,
                            skips.no_tokens
                        );
                    }
                    tracker.set_fingerprint_catalogue(catalogue);
                }
                Err(e) => eprintln!("Warning: Failed to load fingerprint file {}: {}", path, e),
            }
        }
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

    if config.no_mac_merge {
        tracker.set_mac_merge(false);
        println!("Random-MAC merging: disabled");
    }

    #[cfg(feature = "ssdp")]
    if config.upnp_describe {
        tracker.set_upnp_describe(true);
        println!("UPnP descriptions: fetching each device's LOCATION once");
    }

    // Wrap tracker in Arc<RwLock> for thread-safe sharing
    let tracker = Arc::new(RwLock::new(tracker));

    // Start API server if address is provided
    #[cfg(feature = "http-api")]
    if let Some(addr) = &config.api_addr {
        let tracker_clone = Arc::clone(&tracker);
        match start_api_server_with_hosts(
            addr,
            tracker_clone,
            config.api_read_only,
            &config.api_hosts,
        ) {
            Ok(_) => {
                println!("API server started on http://{}", addr);
                if config.api_read_only {
                    println!("API is read-only: edits and deletes are refused.");
                }
            }
            Err(e) => eprintln!("Warning: Failed to start API server: {}", e),
        }
    }

    // Send active mDNS queries if enabled
    #[cfg(feature = "mdns")]
    if config.enable_mdns && config.mdns_query {
        println!("Sending mDNS queries for service discovery...");
    }

    // Send active SSDP queries if enabled
    #[cfg(feature = "ssdp")]
    if config.enable_ssdp && config.ssdp_query {
        println!("Sending SSDP M-SEARCH discovery probes...");
    }

    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    send_discovery_probes(&config);

    // Repeat the probes on a timer when asked. One-shot probes only ever reach
    // the devices that were awake and on the LAN in the first second, so a
    // long-running capture needs to ask again.
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    if let Some(interval) = config.query_interval {
        if config.active_probes_enabled() {
            println!(
                "Repeating active discovery probes every {}s",
                interval.as_secs()
            );
            let probe_config = config.clone();
            thread::spawn(move || {
                loop {
                    thread::sleep(interval);
                    send_discovery_probes(&probe_config);
                }
            });
        } else {
            eprintln!(
                "Warning: --query-interval does nothing without --mdns-query or --ssdp-query"
            );
        }
    }

    start_presence_sweep(Arc::clone(&tracker), &config);

    #[cfg(feature = "ssdp")]
    if config.upnp_describe {
        start_upnp_describer(Arc::clone(&tracker));
    }

    #[cfg(feature = "homeassistant")]
    if let Some(ha) = config.home_assistant.clone() {
        println!(
            "Home Assistant: publishing {} devices to {}:{} (discovery prefix '{}')",
            if ha.trusted_only { "trusted" } else { "all" },
            ha.host,
            ha.port,
            ha.discovery_prefix
        );
        start_home_assistant(ha, Arc::clone(&tracker));
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

            // A repeated announcement changes no device field, so
            // `pending_updates` stays at zero, but it can still record a new
            // attribute token. Ask the tracker what is waiting instead of
            // inferring it from the counter, or those tokens are never written.
            if pending_updates >= DB_FLUSH_BATCH_SIZE
                || (last_flush.elapsed() >= flush_interval && tracker_has_pending(&tracker))
            {
                flush_tracker(&tracker, pending_updates);
                pending_updates = 0;
                last_flush = Instant::now();
            }
        }

        if tracker_has_pending(&tracker) {
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

            // A repeated announcement changes no device field, so
            // `pending_updates` stays at zero, but it can still record a new
            // attribute token. Ask the tracker what is waiting instead of
            // inferring it from the counter, or those tokens are never written.
            if pending_updates >= DB_FLUSH_BATCH_SIZE
                || (last_flush.elapsed() >= flush_interval && tracker_has_pending(&tracker))
            {
                flush_tracker(&tracker, pending_updates);
                pending_updates = 0;
                last_flush = Instant::now();
            }
        }

        if tracker_has_pending(&tracker) {
            flush_tracker(&tracker, pending_updates);
        }
    })
}

/// Reports whether the tracker has anything waiting to be written.
///
/// Returns `false` when the lock is poisoned; the flush itself reports that.
fn tracker_has_pending(tracker: &Arc<RwLock<DeviceTracker>>) -> bool {
    match tracker.read() {
        Ok(tracker) => tracker.has_pending_writes(),
        Err(_) => false,
    }
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
///
/// `Clone` because the repeat-probe thread needs its own copy; the fields are
/// all small owned values, so a clone at startup costs nothing.
#[derive(Clone)]
struct Config {
    interface_name: String,
    db_path: String,
    #[cfg(feature = "http-api")]
    api_addr: Option<String>,
    #[cfg(feature = "http-api")]
    api_read_only: bool,
    #[cfg(feature = "http-api")]
    api_hosts: Vec<String>,
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
    /// Fetch each device's UPnP description once.
    #[cfg(feature = "ssdp")]
    upnp_describe: bool,
    /// How often to re-send the active probes. `None` means send them once.
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    query_interval: Option<Duration>,
    oui_file: Option<String>,
    /// Inline per-device classification overrides (`MAC=Type`).
    override_specs: Vec<String>,
    /// Path to a file of per-device classification overrides.
    overrides_file: Option<String>,
    /// Path to a fingerprint profile catalogue.
    fingerprints_file: Option<String>,
    /// Where to write an attribute dump before exiting.
    dump_fingerprints: Option<String>,
    forget_mac: Option<String>,
    /// MACs to add to the trusted list before exiting.
    trust_macs: Vec<String>,
    /// Trust every device in the database, then exit.
    trust_all: bool,
    /// Silence after which a device counts as offline.
    offline_after: Duration,
    /// Shell command run for each presence event.
    on_event: Option<String>,
    /// Skip the hook for trusted devices.
    untrusted_only: bool,
    /// Keep every random MAC as its own device.
    no_mac_merge: bool,
    /// Where to publish devices for Home Assistant, if anywhere.
    #[cfg(feature = "homeassistant")]
    home_assistant: Option<HomeAssistantConfig>,
}

impl Config {
    /// Whether any active probe is switched on.
    ///
    /// A repeat interval with no probe enabled would spawn a thread that sends
    /// nothing, so the caller checks this first.
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn active_probes_enabled(&self) -> bool {
        let mut enabled = false;
        #[cfg(feature = "mdns")]
        {
            enabled |= self.enable_mdns && self.mdns_query;
        }
        #[cfg(feature = "ssdp")]
        {
            enabled |= self.enable_ssdp && self.ssdp_query;
        }
        enabled
    }
}

/// Parses `--mqtt`: `host`, `host:port`, `[v6]` or `[v6]:port`.
#[cfg(feature = "homeassistant")]
fn parse_broker(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(port) => (host, Some(port)),
            None if after.is_empty() => (host, None),
            None => return None,
        }
    } else if value.matches(':').count() > 1 {
        // A bare IPv6 address has no room for a port.
        (value, None)
    } else {
        match value.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(port) => port.parse().ok().filter(|p| *p != 0)?,
        None => DEFAULT_MQTT_PORT,
    };
    Some((host.to_string(), port))
}

/// Parses a duration such as `90s`, `15m` or `2h`. A bare number means seconds.
///
/// Returns `None` for anything it cannot read, so the caller can refuse the
/// argument rather than silently picking a value the operator did not ask for.
fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    // The suffix is matched as a byte, so slicing it off is always on a char
    // boundary even when the rest of the string is not ASCII.
    let (digits, multiplier) = match value.as_bytes().last()? {
        b's' | b'S' => (&value[..value.len() - 1], 1),
        b'm' | b'M' => (&value[..value.len() - 1], 60),
        b'h' | b'H' => (&value[..value.len() - 1], 3600),
        _ => (value, 1),
    };
    let amount: u64 = digits.trim().parse().ok()?;
    amount.checked_mul(multiplier).map(Duration::from_secs)
}

/// Sends one round of active discovery probes.
#[cfg(any(feature = "mdns", feature = "ssdp"))]
fn send_discovery_probes(config: &Config) {
    #[cfg(feature = "mdns")]
    if config.enable_mdns && config.mdns_query {
        let interface_ip = lanwatch::get_interface_ipv4(&config.interface_name);
        if let Ok(querier) = MdnsQuerier::new(interface_ip)
            && let Err(e) = querier.query_common_services()
        {
            eprintln!("Warning: Failed to send mDNS queries: {}", e);
        }
    }

    #[cfg(feature = "ssdp")]
    if config.enable_ssdp && config.ssdp_query {
        let interface_ip = lanwatch::get_interface_ipv4(&config.interface_name);
        if let Ok(querier) = SsdpQuerier::new(interface_ip)
            && let Err(e) = querier.search_common_devices()
        {
            eprintln!("Warning: Failed to send SSDP queries: {}", e);
        }
    }
}

fn parse_args(args: &[String]) -> Config {
    let mut interface_name = None;
    let mut db_path = DEFAULT_DB_PATH.to_string();
    #[cfg(feature = "http-api")]
    let mut api_addr: Option<String> = None;
    #[cfg(feature = "http-api")]
    let mut api_read_only = false;
    #[cfg(feature = "http-api")]
    let mut api_hosts: Vec<String> = Vec::new();
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
    #[cfg(feature = "ssdp")]
    let mut upnp_describe = false;
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    let mut query_interval: Option<Duration> = None;
    let mut oui_file: Option<String> = None;
    let mut override_specs: Vec<String> = Vec::new();
    let mut overrides_file: Option<String> = None;
    let mut fingerprints_file: Option<String> = None;
    let mut dump_fingerprints: Option<String> = None;
    let mut forget_mac: Option<String> = None;
    let mut trust_macs: Vec<String> = Vec::new();
    let mut trust_all = false;
    let mut offline_after = DEFAULT_OFFLINE_AFTER;
    let mut on_event: Option<String> = None;
    let mut untrusted_only = false;
    let mut no_mac_merge = false;
    #[cfg(feature = "homeassistant")]
    let mut mqtt_broker: Option<(String, u16)> = None;
    #[cfg(feature = "homeassistant")]
    let mut mqtt_user: Option<String> = None;
    #[cfg(feature = "homeassistant")]
    let mut mqtt_prefix: Option<String> = None;
    #[cfg(feature = "homeassistant")]
    let mut mqtt_trusted_only = false;

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
            #[cfg(feature = "http-api")]
            "--api-readonly" | "--api-read-only" => {
                api_read_only = true;
                i += 1;
            }
            #[cfg(feature = "http-api")]
            "--api-host" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    api_hosts.push(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --api-host requires a host name");
                    std::process::exit(1);
                }
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
            #[cfg(feature = "ssdp")]
            "--upnp-describe" => {
                enable_ssdp = true;
                upnp_describe = true;
                i += 1;
            }
            #[cfg(not(feature = "ssdp"))]
            "-p" | "--ssdp" | "--upnp" | "--ssdp-query" | "--upnp-describe" => {
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
            #[cfg(any(feature = "mdns", feature = "ssdp"))]
            "--query-interval" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --query-interval requires a duration, e.g. 15m");
                    std::process::exit(1);
                }
                match parse_duration(&args[i + 1]) {
                    Some(interval) if interval >= MIN_QUERY_INTERVAL => {
                        query_interval = Some(interval);
                    }
                    Some(_) => {
                        eprintln!(
                            "Error: --query-interval must be at least {}s",
                            MIN_QUERY_INTERVAL.as_secs()
                        );
                        std::process::exit(1);
                    }
                    None => {
                        eprintln!(
                            "Error: --query-interval could not read '{}'. Use 90s, 15m or 2h.",
                            args[i + 1]
                        );
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            #[cfg(not(any(feature = "mdns", feature = "ssdp")))]
            "--query-interval" => {
                eprintln!(
                    "Error: --query-interval requires a binary built with the 'mdns' or 'ssdp' feature."
                );
                eprintln!("Rebuild with: cargo build --release --features mdns,ssdp");
                std::process::exit(1);
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
            "--fingerprints" => {
                if i + 1 < args.len() {
                    fingerprints_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --fingerprints requires a file path");
                    std::process::exit(1);
                }
            }
            "--dump-fingerprints" => {
                if i + 1 < args.len() {
                    dump_fingerprints = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --dump-fingerprints requires a file path");
                    std::process::exit(1);
                }
            }
            "--forget" => {
                if i + 1 < args.len() {
                    forget_mac = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --forget requires a MAC address");
                    std::process::exit(1);
                }
            }
            "--trust" => {
                if i + 1 < args.len() {
                    trust_macs.push(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --trust requires a MAC address");
                    std::process::exit(1);
                }
            }
            "--trust-all" => {
                trust_all = true;
                i += 1;
            }
            "--offline-after" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --offline-after requires a duration, e.g. 30m");
                    std::process::exit(1);
                }
                match parse_duration(&args[i + 1]) {
                    Some(value) if value >= MIN_OFFLINE_AFTER => offline_after = value,
                    Some(_) => {
                        eprintln!(
                            "Error: --offline-after must be at least {}s",
                            MIN_OFFLINE_AFTER.as_secs()
                        );
                        std::process::exit(1);
                    }
                    None => {
                        eprintln!(
                            "Error: --offline-after could not read '{}'. Use 90s, 15m or 2h.",
                            args[i + 1]
                        );
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "--on-event" => {
                if i + 1 < args.len() {
                    on_event = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --on-event requires a shell command");
                    std::process::exit(1);
                }
            }
            "--untrusted-only" => {
                untrusted_only = true;
                i += 1;
            }
            "--no-mac-merge" => {
                no_mac_merge = true;
                i += 1;
            }
            #[cfg(feature = "homeassistant")]
            "--mqtt" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("Error: --mqtt requires a broker, e.g. 192.168.1.10 or broker:1883");
                    std::process::exit(1);
                };
                match parse_broker(value) {
                    Some(broker) => mqtt_broker = Some(broker),
                    None => {
                        eprintln!(
                            "Error: --mqtt could not read '{}'. Use HOST or HOST:PORT.",
                            value
                        );
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            #[cfg(feature = "homeassistant")]
            "--mqtt-user" => {
                if i + 1 < args.len() {
                    mqtt_user = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --mqtt-user requires a user name");
                    std::process::exit(1);
                }
            }
            #[cfg(feature = "homeassistant")]
            "--mqtt-prefix" => {
                if i + 1 < args.len() {
                    mqtt_prefix = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --mqtt-prefix requires a topic prefix");
                    std::process::exit(1);
                }
            }
            #[cfg(feature = "homeassistant")]
            "--mqtt-trusted-only" => {
                mqtt_trusted_only = true;
                i += 1;
            }
            #[cfg(not(feature = "homeassistant"))]
            "--mqtt" | "--mqtt-user" | "--mqtt-prefix" | "--mqtt-trusted-only" => {
                eprintln!(
                    "Error: MQTT options require a binary built with the 'homeassistant' feature."
                );
                eprintln!("Rebuild with: cargo build --release --features homeassistant");
                std::process::exit(1);
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

    // Dumping reads the database and never opens a socket, so it is the one
    // mode that does not need an interface.
    let interface_name = match interface_name {
        Some(name) => name,
        None if dump_fingerprints.is_some()
            || forget_mac.is_some()
            || trust_all
            || !trust_macs.is_empty() =>
        {
            String::new()
        }
        None => {
            print_usage();
            println!("\nAvailable interfaces:");
            for iface in list_interfaces() {
                println!("  - {}", iface);
            }
            std::process::exit(1);
        }
    };

    // The password comes from the environment only: a command-line argument
    // is visible to every user through `ps`.
    #[cfg(feature = "homeassistant")]
    let home_assistant = match mqtt_broker {
        Some((host, port)) => {
            let mut config = HomeAssistantConfig::new(host, port);
            config.username = mqtt_user;
            config.password = env::var("LANWATCH_MQTT_PASSWORD").ok();
            if config.password.is_some() && config.username.is_none() {
                eprintln!("Warning: LANWATCH_MQTT_PASSWORD is ignored without --mqtt-user");
            }
            if let Some(prefix) = mqtt_prefix {
                config.discovery_prefix = prefix.trim_end_matches('/').to_string();
            }
            config.trusted_only = mqtt_trusted_only;
            let id: String = interface_name
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect();
            config.client_id = format!("lanwatch-{}", id);
            Some(config)
        }
        None => {
            if mqtt_user.is_some() || mqtt_prefix.is_some() || mqtt_trusted_only {
                eprintln!("Warning: MQTT options do nothing without --mqtt");
            }
            None
        }
    };

    Config {
        interface_name,
        db_path,
        #[cfg(feature = "http-api")]
        api_addr,
        #[cfg(feature = "http-api")]
        api_read_only,
        #[cfg(feature = "http-api")]
        api_hosts,
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
        #[cfg(feature = "ssdp")]
        upnp_describe,
        #[cfg(any(feature = "mdns", feature = "ssdp"))]
        query_interval,
        oui_file,
        fingerprints_file,
        dump_fingerprints,
        forget_mac,
        trust_macs,
        trust_all,
        offline_after,
        on_event,
        untrusted_only,
        no_mac_merge,
        #[cfg(feature = "homeassistant")]
        home_assistant,
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
    println!(
        "  --fingerprints <FILE>  Load an attribute fingerprint catalogue (default: {})",
        DEFAULT_FINGERPRINT_PATH
    );
    println!(
        "  --dump-fingerprints <FILE>  Write observed attribute sets from the database, then exit"
    );
    println!(
        "  --forget <MAC>         Erase one device's sightings, attributes and correction, then exit"
    );
    println!("  --trust <MAC>          Add a device to the trusted list, then exit; repeatable");
    println!("  --trust-all            Trust every device in the database, then exit");
    println!(
        "  --offline-after <DUR>  Silence before a device counts as offline (default: {}m; min {}s)",
        DEFAULT_OFFLINE_AFTER.as_secs() / 60,
        MIN_OFFLINE_AFTER.as_secs()
    );
    println!(
        "  --on-event <CMD>       Run CMD (via sh -c) when a device is new, online or offline;"
    );
    println!("                         details in LANWATCH_* variables and as JSON on stdin");
    println!("  --untrusted-only       Run --on-event only for devices not on the trusted list");
    println!("  --no-mac-merge         Keep each random (private) MAC as its own device");
    #[cfg(feature = "homeassistant")]
    {
        println!("  --mqtt <HOST[:PORT]>   Publish devices to Home Assistant via this MQTT broker");
        println!("  --mqtt-user <NAME>     MQTT user name; the password is read from");
        println!("                         the LANWATCH_MQTT_PASSWORD environment variable");
        println!(
            "  --mqtt-prefix <PREFIX> Home Assistant discovery prefix (default: homeassistant)"
        );
        println!("  --mqtt-trusted-only    Publish only devices on the trusted list");
    }
    #[cfg(feature = "http-api")]
    {
        println!("  -a, --api <ADDR:PORT>  Start HTTP API server (e.g., 127.0.0.1:8080)");
        println!("  --api-default          Start HTTP API on default address (127.0.0.1:8080)");
        println!("  --api-readonly         Refuse every API write (edits, deletes)");
        println!("  --api-host <NAME>      Also serve requests for this host name (repeatable;");
        println!("                         IP addresses and localhost are always served)");
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
        println!(
            "  --upnp-describe        Enable SSDP and fetch each device's UPnP description once"
        );
        println!("                         (HTTP to the device itself; names, makers and models)");
    }
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    {
        println!(
            "  --query-interval <DUR> Re-send the active probes every DUR (90s, 15m, 2h; min {}s)",
            MIN_QUERY_INTERVAL.as_secs()
        );
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
/// Writes the attribute sets already in the database to a labelling worksheet.
///
/// This reads the database and exits. Run a normal capture for a few days
/// first, so the sets have time to ripen.
/// Erases one device's sightings, attribute tokens and manual classification.
///
/// Refuses to run against a database another process is writing, because the
/// running service holds the device in memory and would write it straight back.
fn handle_forget(db_path: &str, mac: &str) {
    let mut tracker = match DeviceTracker::new(db_path) {
        Ok(tracker) => tracker,
        Err(e) => {
            eprintln!("Error opening {}: {}", db_path, e);
            std::process::exit(1);
        }
    };

    match tracker.forget_device(mac) {
        Ok(true) => {
            println!("Forgot {}: sightings, attributes and any correction.", mac);
            println!("Stop the LANwatch service first, or a running capture may");
            println!("still hold this device in memory and write it back.");
        }
        Ok(false) => {
            println!("Nothing stored for {}. Check the MAC address.", mac);
        }
        Err(e) => {
            eprintln!("Error forgetting {}: {}", mac, e);
            std::process::exit(1);
        }
    }
}

fn handle_trust(db_path: &str, macs: &[String], all: bool) {
    let mut tracker = match DeviceTracker::new(db_path) {
        Ok(tracker) => tracker,
        Err(e) => {
            eprintln!("Error opening {}: {}", db_path, e);
            std::process::exit(1);
        }
    };

    if all {
        match tracker.trust_all() {
            Ok(count) => println!("Trusted {} more device(s).", count),
            Err(e) => {
                eprintln!("Error trusting devices: {}", e);
                std::process::exit(1);
            }
        }
    }
    for mac in macs {
        match tracker.set_trusted(mac, true) {
            Ok(true) => println!("Trusted {}.", mac),
            Ok(false) => println!("No device {} in {}. Check the MAC address.", mac, db_path),
            Err(e) => {
                eprintln!("Error trusting {}: {}", mac, e);
                std::process::exit(1);
            }
        }
    }
    println!(
        "Trusted list: {} device(s). Restart a running capture to pick this up.",
        tracker.trusted_count()
    );
}

/// Starts the thread that turns `last_seen` into online/offline events.
///
/// It runs whatever sniffer is active, because it reads only the tracker.
/// The hook runs after the write lock is released, so a slow command never
/// holds up capture or the API.
fn start_presence_sweep(tracker: Arc<RwLock<DeviceTracker>>, config: &Config) {
    let offline_after = config.offline_after;
    let hook = config
        .on_event
        .as_ref()
        .map(|command| EventHook::new(command.clone(), config.untrusted_only));

    println!(
        "Devices count as offline after {}s of silence",
        offline_after.as_secs()
    );
    match (&hook, config.untrusted_only) {
        (Some(_), true) => println!("Event hook: enabled, untrusted devices only"),
        (Some(_), false) => println!("Event hook: enabled"),
        (None, true) => eprintln!("Warning: --untrusted-only does nothing without --on-event"),
        (None, false) => {}
    }

    thread::spawn(move || {
        let mut reported_drops = 0;
        // The first sweep may fold together rotations recorded before merging
        // existed, possibly months of them. That is catch-up, not news, so it
        // is printed and stored but not sent to the hook.
        let mut catching_up = true;
        loop {
            let result = match tracker.write() {
                Ok(mut tracker) => tracker.sweep_presence(SystemTime::now(), offline_after),
                Err(_) => return,
            };
            let events = match result {
                Ok(events) => events,
                Err(e) => {
                    eprintln!("Warning: Failed to save presence events: {}", e);
                    Vec::new()
                }
            };
            for event in &events {
                println!(
                    "[presence] {} {}{}{}",
                    event.event,
                    event.mac_address,
                    event
                        .previous_mac
                        .as_deref()
                        .map(|mac| format!(" (was {})", mac))
                        .unwrap_or_default(),
                    event
                        .hostname
                        .as_deref()
                        .map(|name| format!(" ({})", lanwatch::display_safe(name)))
                        .unwrap_or_default()
                );
                if let Some(hook) = &hook
                    && !(catching_up && event.event == PresenceKind::Merged)
                {
                    hook.dispatch(event);
                }
            }
            catching_up = false;
            if let Some(hook) = &hook {
                let dropped = hook.dropped_count();
                if dropped > reported_drops {
                    eprintln!(
                        "Warning: {} event(s) skipped; more than {} hook commands were running",
                        dropped - reported_drops,
                        lanwatch::MAX_RUNNING_HOOKS
                    );
                    reported_drops = dropped;
                }
            }
            thread::sleep(PRESENCE_SWEEP_INTERVAL);
        }
    });
}

fn handle_dump_fingerprints(db_path: &str, dump_path: &str) {
    let tracker = match DeviceTracker::new(db_path) {
        Ok(tracker) => tracker,
        Err(e) => {
            eprintln!("Error opening {}: {}", db_path, e);
            std::process::exit(1);
        }
    };

    match tracker.dump_fingerprints(dump_path) {
        Ok(0) => {
            println!("No device has a ripe attribute set yet. Nothing written.");
            println!("Capture for longer, then run this again.");
        }
        Ok(count) => {
            println!("Wrote {} attribute set(s) to {}", count, dump_path);
            println!("device_type and vendor hold LANwatch's guess. Correct what is");
            println!("wrong, fill in label with the product name, then run:");
            println!("  make fingerprints-merge FILE={}", dump_path);
            println!(
                "Do NOT commit {}: it carries MAC and IP addresses.",
                dump_path
            );
        }
        Err(e) => {
            eprintln!("Error writing {}: {}", dump_path, e);
            std::process::exit(1);
        }
    }
}

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

// `parse_duration` serves `--offline-after` too, so these run in every build.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_query_interval_reads_seconds_minutes_and_hours() {
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("15m"), Some(Duration::from_secs(900)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        // The suffix is accepted in either case, and stray space is trimmed.
        assert_eq!(parse_duration(" 15M "), Some(Duration::from_secs(900)));
    }

    #[test]
    fn test_an_unreadable_query_interval_is_refused() {
        // Refused, never guessed at: a silent fallback would send probes on an
        // interval the operator did not ask for.
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("m"), None);
        assert_eq!(parse_duration("soon"), None);
        assert_eq!(parse_duration("-5m"), None);
        assert_eq!(parse_duration("1.5h"), None);
        // Overflow must not wrap round to a tiny interval.
        assert_eq!(parse_duration("99999999999999999999h"), None);
        assert_eq!(parse_duration(&format!("{}h", u64::MAX)), None);
    }

    #[cfg(feature = "ssdp")]
    #[test]
    fn test_upnp_describe_is_off_by_default_and_turns_on_ssdp() {
        let args = |extra: &[&str]| {
            let mut v = vec!["lanwatch".to_string(), "eth0".to_string()];
            v.extend(extra.iter().map(|a| a.to_string()));
            parse_args(&v)
        };
        let config = args(&["--ssdp-query"]);
        assert!(!config.upnp_describe);
        let config = args(&["--upnp-describe"]);
        assert!(config.upnp_describe && config.enable_ssdp && !config.ssdp_query);
    }

    #[cfg(feature = "homeassistant")]
    #[test]
    fn test_the_mqtt_broker_reads_host_port_and_ipv6() {
        let broker = |host: &str, port| Some((host.to_string(), port));
        assert_eq!(parse_broker("192.168.1.10"), broker("192.168.1.10", 1883));
        assert_eq!(parse_broker("mqtt.local:8883"), broker("mqtt.local", 8883));
        assert_eq!(parse_broker("[fd00::5]:1884"), broker("fd00::5", 1884));
        assert_eq!(parse_broker("[fd00::5]"), broker("fd00::5", 1883));
        assert_eq!(parse_broker("fd00::5"), broker("fd00::5", 1883));
        for bad in ["", ":1883", "host:", "host:0", "host:99999", "[fd00::5]x"] {
            assert_eq!(parse_broker(bad), None, "{}", bad);
        }
    }
}

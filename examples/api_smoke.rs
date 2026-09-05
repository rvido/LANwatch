//! Starts the real API server over a real database, for manual smoke testing.
//!
//! `cargo run --example api_smoke --all-features -- <db path> <addr>`
use lanwatch::{DeviceTracker, Dhcpv4Packet, start_api_server};
use std::sync::{Arc, RwLock};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "smoke.db".to_string());
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:18099".to_string());

    let mut tracker = DeviceTracker::new(&path).expect("open database");

    let packet = Dhcpv4Packet {
        source_ip: "0.0.0.0".parse().unwrap(),
        dest_ip: "255.255.255.255".parse().unwrap(),
        source_port: 68,
        dest_port: 67,
        operation: lanwatch::Dhcpv4Operation::BootRequest,
        client_mac: [0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22],
        message_type: Some(lanwatch::Dhcpv4MessageType::Request),
        hostname: Some("smoke-host".to_string()),
        requested_ip: Some("192.168.9.5".parse().unwrap()),
        parameter_request_list: Some(vec![1, 3, 6, 15, 119, 252]),
        vendor_class_id: Some("MSFT 5.0".to_string()),
        vendor_specific_info: None,
    };
    tracker.update_from_dhcpv4(&packet);
    tracker.flush_to_db().expect("flush");

    let tracker = Arc::new(RwLock::new(tracker));
    start_api_server(&addr, Arc::clone(&tracker)).expect("start api");
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("READY {}", addr);
    std::thread::sleep(std::time::Duration::from_secs(30));
}

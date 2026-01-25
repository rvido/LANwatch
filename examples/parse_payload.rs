// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking
// See LICENSE file for details.

//! Example: Parse raw DHCP payloads
//!
//! This example demonstrates how to use the parsing functions directly
//! without network capture, useful for testing or analyzing saved packets.

use lanwatch::{
    parse_dhcpv4_payload, parse_dhcpv6_payload, Dhcpv4MessageType, Dhcpv6MessageType,
};
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {
    println!("=== DHCPv4 Payload Parsing Example ===\n");

    // Create a sample DHCPv4 DISCOVER packet
    let dhcpv4_packet = create_sample_dhcpv4_discover();

    if let Some(parsed) = parse_dhcpv4_payload(
        &dhcpv4_packet,
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        68,
        67,
    ) {
        println!("Parsed DHCPv4 packet:");
        println!("  Operation: {}", parsed.operation);
        println!("  Client MAC: {}", parsed.client_mac_string());
        println!(
            "  Message Type: {}",
            parsed
                .message_type
                .map(|t| t.to_string())
                .unwrap_or_else(|| "None".to_string())
        );
        println!(
            "  Hostname: {}",
            parsed.hostname.as_deref().unwrap_or("None")
        );
        println!(
            "  Requested IP: {}",
            parsed
                .requested_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string())
        );
    }

    println!("\n=== DHCPv6 Payload Parsing Example ===\n");

    // Create a sample DHCPv6 SOLICIT packet
    let dhcpv6_packet = create_sample_dhcpv6_solicit();

    if let Some(parsed) = parse_dhcpv6_payload(
        &dhcpv6_packet,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2),
        546,
        547,
    ) {
        println!("Parsed DHCPv6 packet:");
        println!("  Message Type: {}", parsed.message_type);
        println!("  Transaction ID: {}", parsed.transaction_id_string());
        println!("  Options count: {}", parsed.options.len());
    }

    println!("\n=== Message Type Conversion Examples ===\n");

    // Demonstrate message type conversions
    for i in 1..=8 {
        let msg_type = Dhcpv4MessageType::from(i);
        println!("  DHCPv4 type {} = {}", i, msg_type);
    }

    println!();

    for i in 1..=11 {
        let msg_type = Dhcpv6MessageType::from(i);
        println!("  DHCPv6 type {} = {}", i, msg_type);
    }
}

/// Create a sample DHCPv4 DISCOVER packet payload
fn create_sample_dhcpv4_discover() -> Vec<u8> {
    let mut payload = vec![0u8; 300];

    // Op: 1 = BootRequest
    payload[0] = 1;
    // Hardware type: 1 = Ethernet
    payload[1] = 1;
    // Hardware address length: 6
    payload[2] = 6;
    // Hops: 0
    payload[3] = 0;

    // Transaction ID (4 bytes)
    payload[4] = 0xDE;
    payload[5] = 0xAD;
    payload[6] = 0xBE;
    payload[7] = 0xEF;

    // Client hardware address at offset 28
    payload[28] = 0x00;
    payload[29] = 0x11;
    payload[30] = 0x22;
    payload[31] = 0x33;
    payload[32] = 0x44;
    payload[33] = 0x55;

    // DHCP Magic Cookie at offset 236
    payload[236] = 0x63;
    payload[237] = 0x82;
    payload[238] = 0x53;
    payload[239] = 0x63;

    // Options start at offset 240
    let mut idx = 240;

    // Option 53: DHCP Message Type = 1 (DISCOVER)
    payload[idx] = 53;
    payload[idx + 1] = 1;
    payload[idx + 2] = 1;
    idx += 3;

    // Option 12: Hostname = "testhost"
    payload[idx] = 12;
    payload[idx + 1] = 8;
    let hostname = b"testhost";
    payload[idx + 2..idx + 2 + 8].copy_from_slice(hostname);
    idx += 10;

    // Option 50: Requested IP = 192.168.1.100
    payload[idx] = 50;
    payload[idx + 1] = 4;
    payload[idx + 2] = 192;
    payload[idx + 3] = 168;
    payload[idx + 4] = 1;
    payload[idx + 5] = 100;
    idx += 6;

    // Option 255: End
    payload[idx] = 255;

    payload
}

/// Create a sample DHCPv6 SOLICIT packet payload
fn create_sample_dhcpv6_solicit() -> Vec<u8> {
    let mut payload = Vec::new();

    // Message Type: 1 = SOLICIT
    payload.push(1);

    // Transaction ID (3 bytes)
    payload.push(0x12);
    payload.push(0x34);
    payload.push(0x56);

    // Option 1: Client Identifier (DUID)
    payload.push(0x00);
    payload.push(0x01); // Option code
    payload.push(0x00);
    payload.push(0x0A); // Length = 10
    // DUID-LLT (Link-layer address plus time)
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB]);

    // Option 3: IA_NA
    payload.push(0x00);
    payload.push(0x03); // Option code
    payload.push(0x00);
    payload.push(0x0C); // Length = 12
    // IAID (4 bytes)
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // T1 (4 bytes)
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // T2 (4 bytes)
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    payload
}

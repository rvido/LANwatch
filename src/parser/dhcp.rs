// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use crate::device::sanitize_hostname;
use crate::types::{
    DHCPV4_CLIENT_PORT, DHCPV4_SERVER_PORT, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT,
    Dhcpv4MessageType, Dhcpv4Operation, Dhcpv4Packet, Dhcpv6MessageType, Dhcpv6Option,
    Dhcpv6Packet,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parses a raw DHCPv4 UDP payload into a structured `Dhcpv4Packet`.
pub fn parse_dhcpv4_payload(
    payload: &[u8],
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
) -> Option<Dhcpv4Packet> {
    if payload.len() < 240 {
        return None;
    }

    let operation = Dhcpv4Operation::from(payload[0]);
    let client_mac = [
        payload[28],
        payload[29],
        payload[30],
        payload[31],
        payload[32],
        payload[33],
    ];

    let mut message_type = None;
    let mut hostname = None;
    let mut requested_ip = None;
    let mut parameter_request_list = None;
    let mut vendor_class_id = None;
    let mut vendor_specific_info = None;

    // BOOTP/DHCP fixed header fields
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    // Parse options starting at offset 240
    let mut index = 240;
    while index < payload.len() {
        let code = payload[index];
        if code == 255 {
            break;
        } // End
        if code == 0 {
            index += 1;
            continue;
        } // Pad

        if index + 1 >= payload.len() {
            break;
        }
        let len = payload[index + 1] as usize;

        if index + 2 + len > payload.len() {
            break;
        }
        let value = &payload[index + 2..index + 2 + len];

        match code {
            53 if !value.is_empty() => {
                message_type = Some(Dhcpv4MessageType::from(value[0]));
            }
            12 => {
                if let Ok(h) = std::str::from_utf8(value) {
                    hostname = sanitize_hostname(h);
                }
            }
            50 if value.len() == 4 => {
                requested_ip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            55 => {
                parameter_request_list = Some(value.to_vec());
            }
            60 => {
                if let Ok(v) = std::str::from_utf8(value) {
                    vendor_class_id = Some(v.to_string());
                }
            }
            43 => {
                let mut ascii_parts = Vec::new();
                let mut current = Vec::new();
                for &b in value {
                    if (32..=126).contains(&b) {
                        current.push(b);
                    } else {
                        if current.len() >= 4 {
                            let res = std::str::from_utf8(&current);
                            if let Ok(s) = res {
                                ascii_parts.push(s.trim().to_string());
                            }
                        }
                        current.clear();
                    }
                }
                if current.len() >= 4 {
                    let res = std::str::from_utf8(&current);
                    if let Ok(s) = res {
                        ascii_parts.push(s.trim().to_string());
                    }
                }
                if !ascii_parts.is_empty() {
                    vendor_specific_info = Some(ascii_parts.join(" "));
                }
            }
            _ => {}
        }
        index += 2 + len;
    }

    if requested_ip.is_none() {
        if ciaddr != Ipv4Addr::new(0, 0, 0, 0) {
            requested_ip = Some(ciaddr);
        } else if yiaddr != Ipv4Addr::new(0, 0, 0, 0) {
            requested_ip = Some(yiaddr);
        }
    }

    Some(Dhcpv4Packet {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        operation,
        client_mac,
        message_type,
        hostname,
        requested_ip,
        parameter_request_list,
        vendor_class_id,
        vendor_specific_info,
    })
}

/// Parses a raw DHCPv6 UDP payload into a structured `Dhcpv6Packet`.
pub fn parse_dhcpv6_payload(
    payload: &[u8],
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    source_port: u16,
    dest_port: u16,
) -> Option<Dhcpv6Packet> {
    if payload.len() < 4 {
        return None;
    }

    let message_type = Dhcpv6MessageType::from(payload[0]);
    let transaction_id = [payload[1], payload[2], payload[3]];

    let mut options = Vec::new();

    let mut index = 4;
    while index < payload.len() {
        if index + 4 > payload.len() {
            break;
        }

        let opt_code = u16::from_be_bytes([payload[index], payload[index + 1]]);
        let opt_len = u16::from_be_bytes([payload[index + 2], payload[index + 3]]) as usize;

        if index + 4 + opt_len > payload.len() {
            break;
        }

        let opt_value = &payload[index + 4..index + 4 + opt_len];

        match opt_code {
            1 => {
                options.push(Dhcpv6Option::ClientId(opt_value.to_vec()));
            }
            2 => {
                options.push(Dhcpv6Option::ServerId(opt_value.to_vec()));
            }
            3 => {
                options.push(Dhcpv6Option::IaNa);
            }
            15 => {
                let mut data_strings = Vec::new();
                let mut sub_idx = 0;
                while sub_idx < opt_value.len() {
                    if sub_idx + 2 > opt_value.len() {
                        break;
                    }
                    let str_len =
                        u16::from_be_bytes([opt_value[sub_idx], opt_value[sub_idx + 1]]) as usize;
                    if sub_idx + 2 + str_len > opt_value.len() {
                        break;
                    }
                    let str_bytes = &opt_value[sub_idx + 2..sub_idx + 2 + str_len];
                    if let Ok(s) = std::str::from_utf8(str_bytes) {
                        data_strings.push(s.to_string());
                    }
                    sub_idx += 2 + str_len;
                }
                options.push(Dhcpv6Option::UserClass(data_strings));
            }
            16 => {
                if opt_value.len() >= 4 {
                    let enterprise_number = u32::from_be_bytes([
                        opt_value[0],
                        opt_value[1],
                        opt_value[2],
                        opt_value[3],
                    ]);
                    let mut data_strings = Vec::new();
                    let mut sub_idx = 4;
                    while sub_idx < opt_value.len() {
                        if sub_idx + 2 > opt_value.len() {
                            break;
                        }
                        let str_len =
                            u16::from_be_bytes([opt_value[sub_idx], opt_value[sub_idx + 1]])
                                as usize;
                        if sub_idx + 2 + str_len > opt_value.len() {
                            break;
                        }
                        let str_bytes = &opt_value[sub_idx + 2..sub_idx + 2 + str_len];
                        if let Ok(s) = std::str::from_utf8(str_bytes) {
                            data_strings.push(s.to_string());
                        }
                        sub_idx += 2 + str_len;
                    }
                    options.push(Dhcpv6Option::VendorClass {
                        enterprise_number,
                        data: data_strings,
                    });
                }
            }
            39 => {
                if let Some(fqdn) = parse_dhcpv6_client_fqdn(opt_value) {
                    options.push(Dhcpv6Option::ClientFqdn(fqdn));
                }
            }
            _ => {
                options.push(Dhcpv6Option::Other {
                    code: opt_code,
                    data: opt_value.to_vec(),
                });
            }
        }

        index += 4 + opt_len;
    }

    Some(Dhcpv6Packet {
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        message_type,
        transaction_id,
        options,
    })
}

/// Parse DHCPv6 Client FQDN (option 39).
/// RFC 4704 format: 1-byte flags followed by a DNS wire-format name.
fn parse_dhcpv6_client_fqdn(value: &[u8]) -> Option<String> {
    if value.len() < 2 {
        return None;
    }
    let name = decode_dns_name(&value[1..])?;
    sanitize_hostname(&name)
}

/// Decode a basic DNS wire-format name (no compression pointers expected here).
fn decode_dns_name(data: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut index = 0usize;

    while index < data.len() {
        let label_len = data[index] as usize;
        index += 1;

        if label_len == 0 {
            break;
        }

        if label_len > 63 || index + label_len > data.len() {
            return None;
        }

        let label_bytes = &data[index..index + label_len];
        let label = std::str::from_utf8(label_bytes).ok()?;
        labels.push(label.to_string());
        index += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub(crate) fn format_duid_identifier(duid: &[u8]) -> String {
    let hex = duid
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    format!("duid:{}", hex)
}

/// Extract a 6-byte Ethernet MAC from DUID-LLT or DUID-LL when possible.
pub(crate) fn extract_mac_from_duid(duid: &[u8]) -> Option<String> {
    if duid.len() < 4 {
        return None;
    }

    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    let hw_type = u16::from_be_bytes([duid[2], duid[3]]);

    if hw_type != 1 {
        return None;
    }

    let mac_bytes = match duid_type {
        1 if duid.len() >= 14 => &duid[8..14],
        3 if duid.len() >= 10 => &duid[4..10],
        _ => return None,
    };

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    ))
}

/// Checks if a pair of UDP ports corresponds to standard DHCPv4 traffic.
pub fn is_dhcpv4_ports(src: u16, dest: u16) -> bool {
    src == DHCPV4_SERVER_PORT
        || src == DHCPV4_CLIENT_PORT
        || dest == DHCPV4_SERVER_PORT
        || dest == DHCPV4_CLIENT_PORT
}

/// Checks if a pair of UDP ports corresponds to standard DHCPv6 traffic.
pub fn is_dhcpv6_ports(src: u16, dest: u16) -> bool {
    src == DHCPV6_CLIENT_PORT
        || src == DHCPV6_SERVER_PORT
        || dest == DHCPV6_CLIENT_PORT
        || dest == DHCPV6_SERVER_PORT
}

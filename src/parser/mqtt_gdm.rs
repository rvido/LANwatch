// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! MQTT, MQTT-SN, and Plex GDM (Good Day Mate) discovery parsers.

use crate::device::sanitize_display_string;

/// MQTT standard TCP/UDP port
pub const MQTT_PORT: u16 = 1883;

/// Plex GDM discovery ports
pub const GDM_PORTS: &[u16] = &[32410, 32412, 32414];

/// Parsed MQTT/MQTT-SN packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct MqttPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Client ID parsed from CONNECT payload
    pub client_id: String,
    /// Protocol type ("MQTT" or "MQTT-SN")
    pub protocol: String,
}

/// Parsed Plex GDM discovery packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct GdmPacket {
    /// Source MAC address
    pub source_mac: [u8; 6],
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Friendly Name of the Plex device
    pub name: Option<String>,
    /// Product name (e.g. "Plex Media Server", "Plex for Apple TV")
    pub product: Option<String>,
    /// Unique Resource Identifier (UUID)
    pub resource_id: Option<String>,
    /// Port of the server service (typically 32400)
    pub port: Option<u16>,
}

/// Checks if the port matches the MQTT discovery port.
pub fn is_mqtt_port(port: u16) -> bool {
    port == MQTT_PORT
}

/// Checks if the port matches any Plex GDM discovery port.
pub fn is_gdm_port(port: u16) -> bool {
    GDM_PORTS.contains(&port)
}

/// Parses a standard MQTT over TCP CONNECT payload.
pub fn parse_mqtt_connect(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<MqttPacket> {
    if payload.len() < 12 {
        return None;
    }
    // Fixed header: packet type must be CONNECT (1) in the upper 4 bits
    let packet_type = (payload[0] >> 4) & 0x0F;
    if packet_type != 1 {
        return None;
    }

    // Parse variable remaining length
    let mut offset = 1;
    let mut multiplier = 1usize;
    let mut _remaining_len = 0usize;
    loop {
        if offset >= payload.len() {
            return None;
        }
        let byte = payload[offset];
        offset = offset.checked_add(1)?;
        _remaining_len =
            _remaining_len.checked_add(((byte & 127) as usize).checked_mul(multiplier)?)?;
        if multiplier > 128 * 128 * 128 {
            return None;
        }
        multiplier = multiplier.checked_mul(128)?;
        if (byte & 128) == 0 {
            break;
        }
    }

    // Now at offset is the variable header
    if offset.checked_add(2)? > payload.len() {
        return None;
    }

    // Protocol name length
    let proto_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset = offset.checked_add(2)?;
    if offset.checked_add(proto_len)?.checked_add(4)? > payload.len() {
        return None;
    }

    let proto_name = std::str::from_utf8(&payload[offset..offset + proto_len]).ok()?;
    if proto_name != "MQTT" && proto_name != "MQIsdp" {
        return None;
    }
    offset = offset.checked_add(proto_len)?;

    // Skip proto level (1 byte) and connect flags (1 byte)
    offset = offset.checked_add(2)?;
    // Keep alive (2 bytes)
    offset = offset.checked_add(2)?;

    // Payload: Client Identifier
    if offset.checked_add(2)? > payload.len() {
        return None;
    }
    let client_id_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset = offset.checked_add(2)?;
    if offset.checked_add(client_id_len)? > payload.len() {
        return None;
    }

    let client_id = std::str::from_utf8(&payload[offset..offset + client_id_len]).ok()?;
    Some(MqttPacket {
        source_mac,
        source_ip,
        client_id: sanitize_display_string(client_id)?,
        protocol: "MQTT".to_string(),
    })
}

/// Parses an MQTT-SN over UDP CONNECT payload.
pub fn parse_mqtt_sn_connect(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<MqttPacket> {
    if payload.is_empty() {
        return None;
    }
    let (msg_type, client_id_offset) = if payload[0] == 0x01 {
        if payload.len() < 9 {
            return None;
        }
        (payload[3], 8)
    } else {
        if payload.len() < 7 {
            return None;
        }
        (payload[1], 6)
    };

    if msg_type != 0x04 {
        return None;
    }

    // The client ID runs to the end of the datagram, so this is the one field
    // whose length an attacker picks freely; `sanitize_display_string` caps it.
    let client_id = std::str::from_utf8(&payload[client_id_offset..]).ok()?;
    Some(MqttPacket {
        source_mac,
        source_ip,
        client_id: sanitize_display_string(client_id)?,
        protocol: "MQTT-SN".to_string(),
    })
}

/// Parses a Plex GDM payload.
pub fn parse_gdm_payload(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<GdmPacket> {
    let s = std::str::from_utf8(payload).ok()?;
    if !s.contains("Resource-Identifier") && !s.contains("Product") && !s.contains("Plex") {
        return None;
    }

    let mut name = None;
    let mut product = None;
    let mut resource_id = None;
    let mut port = None;

    for line in s.lines() {
        let line = line.trim();
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let Some(val) = sanitize_display_string(&line[colon + 1..]) else {
                continue;
            };
            match key.as_str() {
                "name" => name = Some(val),
                "product" => product = Some(val),
                "resource-identifier" => resource_id = Some(val),
                "port" => port = val.parse::<u16>().ok(),
                _ => {}
            }
        }
    }

    if name.is_some() || product.is_some() || resource_id.is_some() {
        Some(GdmPacket {
            source_mac,
            source_ip,
            name,
            product,
            resource_id,
            port,
        })
    } else {
        None
    }
}

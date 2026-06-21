// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! IP Camera & CCTV discovery parsers (ONVIF, Hikvision SADP, Dahua, RTSP).

/// Hikvision SADP discovery port
pub const SADP_PORT: u16 = 9999;

/// Hikvision SADP alternate discovery port
pub const SADP_ALT_PORT: u16 = 37020;

/// Dahua discovery port
pub const DAHUA_PORT: u16 = 37810;

/// RTSP control port
pub const RTSP_PORT: u16 = 554;

/// Parsed CCTV/IP Camera discovery packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct CctvPacket {
    /// Source MAC address
    pub source_mac: String,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Inferred vendor (e.g. "Hikvision", "Dahua", "ONVIF", "Generic RTSP")
    pub vendor: String,
    /// Specific model name/information
    pub model: Option<String>,
    /// Serial number of the camera
    pub serial_number: Option<String>,
    /// Details about the protocol/discovery method
    pub protocol: String,
}

/// Checks if the port matches any of the CCTV discovery ports (SADP, Dahua, RTSP).
pub fn is_cctv_port(port: u16) -> bool {
    port == SADP_PORT || port == SADP_ALT_PORT || port == DAHUA_PORT || port == RTSP_PORT
}

/// Parses a Hikvision SADP UDP payload.
pub fn parse_sadp_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
) -> Option<CctvPacket> {
    let s = std::str::from_utf8(payload).ok()?;
    if !s.contains("<Probe") && !s.contains("<Response") {
        return None;
    }

    let is_sadp = s.contains("SADP") || s.contains("DeviceType") || s.contains("IPv4Address");
    if !is_sadp {
        return None;
    }

    // Extract fields using safe XML tag extractors
    let model = extract_xml_tag_bytes(payload, "DeviceType")
        .or_else(|| extract_xml_tag_bytes(payload, "DeviceDescription"));
    let serial = extract_xml_tag_bytes(payload, "DeviceSN");
    let payload_mac =
        extract_xml_tag_bytes(payload, "MAC").or_else(|| extract_xml_tag_bytes(payload, "Mac"));

    let final_mac = payload_mac.unwrap_or(source_mac);

    Some(CctvPacket {
        source_mac: final_mac,
        source_ip,
        vendor: "Hikvision".to_string(),
        model,
        serial_number: serial,
        protocol: "SADP".to_string(),
    })
}

/// Parses a Dahua discovery packet.
pub fn parse_dahua_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
) -> Option<CctvPacket> {
    // If it's DHIP binary or text
    let s = std::str::from_utf8(payload).ok()?;

    let has_dahua_marker = s.contains("DHIP")
        || s.contains("DVRIP")
        || s.contains("dhclient")
        || s.contains("deviceType");
    if !has_dahua_marker {
        return None;
    }

    let mut model = None;
    let mut serial = None;
    let mut payload_mac = None;

    if s.contains('{') && s.contains('}') {
        model = extract_json_field_bytes(payload, "deviceType");
        serial = extract_json_field_bytes(payload, "serial")
            .or_else(|| extract_json_field_bytes(payload, "sn"))
            .or_else(|| extract_json_field_bytes(payload, "serialNo"));
        payload_mac = extract_json_field_bytes(payload, "mac");
    }

    let final_mac = payload_mac.unwrap_or(source_mac);

    Some(CctvPacket {
        source_mac: final_mac,
        source_ip,
        vendor: "Dahua".to_string(),
        model,
        serial_number: serial,
        protocol: "Dahua Discovery".to_string(),
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extract_xml_tag_bytes(payload: &[u8], tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag).into_bytes();
    let close_tag = format!("</{}>", tag).into_bytes();

    let start = find_subslice(payload, &open_tag)?;
    let offset = start.checked_add(open_tag.len())?;
    if offset > payload.len() {
        return None;
    }
    let rest = &payload[offset..];
    let end = find_subslice(rest, &close_tag)?;

    let val_bytes = &rest[..end];
    String::from_utf8(val_bytes.to_vec())
        .ok()
        .map(|s| s.trim().to_string())
}

fn extract_json_field_bytes(payload: &[u8], field: &str) -> Option<String> {
    let key = format!("\"{}\"", field).into_bytes();
    let start = find_subslice(payload, &key)?;
    let offset = start.checked_add(key.len())?;
    if offset > payload.len() {
        return None;
    }
    let rest = &payload[offset..];

    let colon = rest.iter().position(|&b| b == b':')?;
    let val_part_start = colon.checked_add(1)?;
    if val_part_start > rest.len() {
        return None;
    }
    let val_part = &rest[val_part_start..];

    let first_non_ws = val_part.iter().position(|&b| !b.is_ascii_whitespace())?;
    let val_part = &val_part[first_non_ws..];

    if val_part.is_empty() {
        return None;
    }

    if val_part[0] == b'"' {
        let val_rest = &val_part[1..];
        let end_quote = val_rest.iter().position(|&b| b == b'"')?;
        String::from_utf8(val_rest[..end_quote].to_vec())
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        let end = val_part
            .iter()
            .position(|&b| b == b',' || b == b'}' || b == b'\n' || b == b'\r')?;
        String::from_utf8(val_part[..end].to_vec())
            .ok()
            .map(|s| s.trim().to_string())
    }
}

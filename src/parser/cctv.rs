// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! IP Camera & CCTV discovery parsers (ONVIF, Hikvision SADP, Dahua, RTSP).

use crate::device::sanitize_display_string;
use crate::types::{Vendor, parse_mac};

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
    /// Source MAC address, as observed in the Ethernet header.
    ///
    /// This is always the *observed* sender, never a MAC asserted by the
    /// packet body -- see [`CctvPacket::claimed_mac`].
    pub source_mac: [u8; 6],
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// MAC address the payload claims to describe, when the discovery message
    /// carries one (Hikvision SADP `<MAC>`, Dahua `"mac"`).
    ///
    /// Purely self-reported and trivially forged by anyone on the segment, so
    /// it is recorded for reference but never used as a device's identity;
    /// treating it as one would let a single crafted datagram create or
    /// overwrite an arbitrary entry in the inventory.
    pub claimed_mac: Option<[u8; 6]>,
    /// Inferred vendor (e.g. Hikvision, Dahua, ONVIF, Generic RTSP)
    pub vendor: Vendor,
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

/// Returns true if `payload` begins like an RTSP server response or request,
/// per RFC 2326 -- a status line (`RTSP/1.0 200 OK`) or a method line ending
/// in the RTSP version token.
///
/// Used to confirm that traffic on port 554 really is RTSP before recording a
/// camera, since the port number on its own says nothing about what is
/// actually speaking on it.
pub fn is_rtsp_response(payload: &[u8]) -> bool {
    if payload.starts_with(b"RTSP/") {
        return true;
    }
    // A method line ("OPTIONS rtsp://... RTSP/1.0"); only inspect the first
    // line so a long body can't turn this into a full-payload scan.
    let head_len = payload.len().min(256);
    let head = &payload[..head_len];
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head_len);
    head[..line_end].windows(5).any(|window| window == b"RTSP/")
}

/// Parses a Hikvision SADP UDP payload.
pub fn parse_sadp_payload(
    payload: &[u8],
    source_mac: [u8; 6],
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
    let claimed_mac = extract_xml_tag_bytes(payload, "MAC")
        .or_else(|| extract_xml_tag_bytes(payload, "Mac"))
        .and_then(|s| parse_mac(&s));

    Some(CctvPacket {
        source_mac,
        claimed_mac,
        source_ip,
        vendor: Vendor::Hikvision,
        model,
        serial_number: serial,
        protocol: "SADP".to_string(),
    })
}

/// Parses a Dahua discovery packet.
pub fn parse_dahua_payload(
    payload: &[u8],
    source_mac: [u8; 6],
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
    let mut claimed_mac = None;

    if s.contains('{') && s.contains('}') {
        model = extract_json_field_bytes(payload, "deviceType");
        serial = extract_json_field_bytes(payload, "serial")
            .or_else(|| extract_json_field_bytes(payload, "sn"))
            .or_else(|| extract_json_field_bytes(payload, "serialNo"));
        claimed_mac = extract_json_field_bytes(payload, "mac").and_then(|s| parse_mac(&s));
    }

    Some(CctvPacket {
        source_mac,
        claimed_mac,
        source_ip,
        vendor: Vendor::Dahua,
        model,
        serial_number: serial,
        protocol: "Dahua Discovery".to_string(),
    })
}

/// Longest field value (model, serial, MAC) accepted out of a discovery
/// payload. These land in the device record and are attacker-controlled, so
/// they are bounded here rather than letting a 64 KiB datagram put 64 KiB in
/// a database column.
const MAX_FIELD_LEN: usize = 255;

/// Decodes an extracted field: rejects it outright if it exceeds
/// [`MAX_FIELD_LEN`], since a value that long is malformed rather than merely
/// verbose, and silently truncating it would fabricate a plausible-looking
/// model or serial that no device ever reported.
fn decode_field(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_FIELD_LEN {
        return None;
    }
    // Neutralize terminal escapes, bidi overrides and the like here rather
    // than at each place the value is later printed or stored.
    sanitize_display_string(std::str::from_utf8(bytes).ok()?)
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

    decode_field(&rest[..end])
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
        decode_field(&val_rest[..end_quote])
    } else {
        let end = val_part
            .iter()
            .position(|&b| b == b',' || b == b'}' || b == b'\n' || b == b'\r')?;
        decode_field(&val_part[..end])
    }
}

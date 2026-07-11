// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! IoT and Smart Home protocol parsers (LIFX, HomeKit HAP, Matter).

use std::collections::HashMap;

/// LIFX UDP discovery port
pub const LIFX_PORT: u16 = 56700;

/// Parsed LIFX protocol packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct LifxPacket {
    /// Source MAC address of the LIFX device
    pub source_mac: String,
    /// Source IP address of the LIFX device
    pub source_ip: std::net::IpAddr,
    /// Target MAC address specified in the frame header (usually zero for broadcasts)
    pub target_mac: String,
    /// LIFX Message type (e.g. 2 = GetService, 3 = StateService)
    pub msg_type: u16,
    /// Size of the packet in bytes
    pub size: u16,
}

/// Checks if the port matches the LIFX discovery port.
pub fn is_lifx_port(port: u16) -> bool {
    port == LIFX_PORT
}

/// Parses a LIFX packet payload from a UDP frame.
///
/// Returns `Some(LifxPacket)` if parsing succeeds and the protocol number matches.
pub fn parse_lifx_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
) -> Option<LifxPacket> {
    if payload.len() < 36 {
        return None;
    }

    let size = u16::from_le_bytes([payload[0], payload[1]]);
    if (size as usize) > payload.len() {
        return None;
    }

    // Verify protocol number in the header (must be 1024 / 0x400)
    let protocol = u16::from_le_bytes([payload[2], payload[3]]) & 0x0FFF;
    if protocol != 1024 {
        return None;
    }

    let msg_type = u16::from_le_bytes([payload[32], payload[33]]);

    // Extract target MAC address (starts at byte index 8, 6 bytes long)
    let target_bytes = &payload[8..14];
    let target_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        target_bytes[0],
        target_bytes[1],
        target_bytes[2],
        target_bytes[3],
        target_bytes[4],
        target_bytes[5]
    );

    Some(LifxPacket {
        source_mac,
        source_ip,
        target_mac,
        msg_type,
        size,
    })
}

/// Parsed IoT metadata from mDNS discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IotMetadata {
    /// Inferred vendor name
    pub vendor: Option<String>,
    /// Inferred device type
    pub device_type: Option<String>,
    /// Specific model name/information
    pub model: Option<String>,
    /// Status description (e.g. "Unpaired / Pairing Mode")
    pub status: Option<String>,
}

/// Extracts IoT metadata from mDNS services and TXT attributes.
///
/// Supports Matter and HomeKit (HAP) protocols.
pub fn extract_iot_metadata(services: &[&str], txt_attrs: &HashMap<String, &str>) -> IotMetadata {
    let mut meta = IotMetadata::default();

    // 1. Matter Protocol Identification
    if services.iter().any(|s| s.contains("_matter")) {
        meta.device_type = Some("Matter Smart Device".to_string());

        let mut vid_str = None;
        let mut pid_str = None;

        if let Some(vid) = txt_attrs.get("vid") {
            vid_str = Some(*vid);
            let parsed_vid = if vid.starts_with("0x") || vid.starts_with("0X") {
                u32::from_str_radix(&vid[2..], 16).ok()
            } else {
                vid.parse::<u32>().ok()
            };

            if let Some(v) = parsed_vid {
                meta.vendor = match v {
                    0x10B1 => Some("Google".to_string()),
                    0x1141 => Some("Apple".to_string()),
                    0x121A => Some("Amazon".to_string()),
                    0x111D => Some("Samsung".to_string()),
                    0x100B => Some("Signify (Philips Hue)".to_string()),
                    0x1224 => Some("Eve Systems".to_string()),
                    0x115C => Some("Aqara".to_string()),
                    0x118C => Some("IKEA".to_string()),
                    0x1339 => Some("Nanoleaf".to_string()),
                    0x10F2 => Some("Tuya".to_string()),
                    0x120F => Some("Somfy".to_string()),
                    0x135A => Some("TP-Link".to_string()),
                    0x120D => Some("Lutron".to_string()),
                    0x130B => Some("Yale".to_string()),
                    0x1325 => Some("Schneider Electric".to_string()),
                    0x1249 => Some("LeGrand".to_string()),
                    0x135E => Some("Belkin".to_string()),
                    0x139B => Some("Bosch".to_string()),
                    _ => None,
                };
            }
        }

        if let Some(pid) = txt_attrs.get("pid") {
            pid_str = Some(*pid);
        }

        if let (Some(v), Some(p)) = (vid_str, pid_str) {
            meta.model = Some(format!("Matter Device (VID: {}, PID: {})", v, p));
        } else if let Some(v) = vid_str {
            meta.model = Some(format!("Matter Device (VID: {})", v));
        } else {
            meta.model = Some("Matter Device".to_string());
        }

        if let Some(dt) = txt_attrs.get("dt") {
            let parsed_dt = if dt.starts_with("0x") || dt.starts_with("0X") {
                u32::from_str_radix(&dt[2..], 16).ok()
            } else {
                dt.parse::<u32>().ok()
            };
            if let Some(d) = parsed_dt {
                match d {
                    769 => meta.device_type = Some("Thermostat".to_string()),
                    256 | 257 | 268 | 269 => meta.device_type = Some("Smart Light".to_string()),
                    266 | 267 => meta.device_type = Some("Smart Plug".to_string()),
                    15 | 16 => meta.device_type = Some("Switch".to_string()),
                    90 => meta.device_type = Some("Door Lock".to_string()),
                    768 => meta.device_type = Some("Sensor".to_string()),
                    772 => meta.device_type = Some("Humidity Sensor".to_string()),
                    774 => meta.device_type = Some("Occupancy Sensor".to_string()),
                    775 => meta.device_type = Some("Contact Sensor".to_string()),
                    10 | 113 => meta.device_type = Some("Air Conditioner".to_string()),
                    43 => meta.device_type = Some("Air Purifier".to_string()),
                    18 => meta.device_type = Some("Video Doorbell".to_string()),
                    34 => meta.device_type = Some("Chromecast".to_string()),
                    _ => {}
                }
            }
        }
    }
    // 2. HomeKit (HAP) Protocol Identification
    else if services.iter().any(|s| s.contains("_hap")) {
        if let Some(md) = txt_attrs.get("md") {
            meta.model = Some((*md).to_string());

            let model_lower = md.to_lowercase();
            if model_lower.starts_with("eve") {
                meta.vendor = Some("Eve Systems".to_string());
            } else if model_lower.starts_with("nanoleaf") {
                meta.vendor = Some("Nanoleaf".to_string());
            } else if model_lower.starts_with("aqara") {
                meta.vendor = Some("Aqara".to_string());
            } else if model_lower.starts_with("koogeek") {
                meta.vendor = Some("Koogeek".to_string());
            } else if model_lower.starts_with("wemo") {
                meta.vendor = Some("Belkin (Wemo)".to_string());
            } else if model_lower.starts_with("ecobee") {
                meta.vendor = Some("ecobee".to_string());
            } else if model_lower.starts_with("hue") || model_lower.contains("philips") {
                meta.vendor = Some("Signify (Philips Hue)".to_string());
            }
        }

        if let Some(ci) = txt_attrs.get("ci") {
            meta.device_type = match *ci {
                "1" => Some("HomeKit Accessory".to_string()),
                "2" => Some("Bridge".to_string()),
                "3" => Some("Fan".to_string()),
                "4" => Some("Garage Door".to_string()),
                "5" => Some("Lightbulb".to_string()),
                "6" => Some("Lock".to_string()),
                "7" => Some("Outlet".to_string()),
                "8" => Some("Switch".to_string()),
                "9" => Some("Thermostat".to_string()),
                "10" => Some("Sensor".to_string()),
                "11" => Some("Security System".to_string()),
                "12" => Some("Door".to_string()),
                "13" => Some("Window".to_string()),
                "14" => Some("Window Covering".to_string()),
                "15" => Some("Switch".to_string()),
                "17" => Some("IP Camera".to_string()),
                "18" => Some("Video Doorbell".to_string()),
                "19" => Some("Air Purifier".to_string()),
                "20" => Some("Heater".to_string()),
                "21" => Some("Cooler".to_string()),
                "22" => Some("Humidifier".to_string()),
                "23" => Some("Dehumidifier".to_string()),
                "24" => Some("Apple TV".to_string()),
                "28" => Some("Sprinkler".to_string()),
                "29" => Some("Faucet".to_string()),
                "30" => Some("Shower System".to_string()),
                "32" => Some("Television".to_string()),
                "33" => Some("Target Controller".to_string()),
                _ => Some("HomeKit Device".to_string()),
            };
        } else {
            meta.device_type = Some("HomeKit Device".to_string());
        }

        if let Some(sf) = txt_attrs.get("sf")
            && let Ok(flags) = sf.parse::<u32>()
        {
            if flags & 1 != 0 {
                meta.status = Some("Unpaired / Pairing Mode".to_string());
            } else {
                meta.status = Some("Paired".to_string());
            }
        }
    }

    meta
}

/// CoAP UDP port
pub const COAP_PORT: u16 = 5683;

/// Checks if the port matches the CoAP discovery port.
pub fn is_coap_port(port: u16) -> bool {
    port == COAP_PORT
}

/// Parsed CoAP protocol packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct CoapPacket {
    /// Source MAC address
    pub source_mac: String,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// CoAP message code (class and detail)
    pub code: u8,
    /// Message ID
    pub message_id: u16,
    /// Optional CoAP payload string (e.g. CoRE Link Format)
    pub payload: Option<String>,
}

/// Parses a CoAP packet from UDP payload bytes.
pub fn parse_coap_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
) -> Option<CoapPacket> {
    if payload.len() < 4 {
        return None;
    }
    // Verify version (must be 1 in the first 2 bits of byte 0)
    let version = (payload[0] >> 6) & 0x03;
    if version != 1 {
        return None;
    }
    let token_len = (payload[0] & 0x0F) as usize;
    let code = payload[1];
    let message_id = u16::from_be_bytes([payload[2], payload[3]]);

    let header_and_token_len = 4usize.checked_add(token_len)?;
    if payload.len() < header_and_token_len {
        return None;
    }

    // Skip options to find the payload marker (0xFF)
    let mut offset = header_and_token_len;
    let mut payload_start = None;

    while offset < payload.len() {
        if payload[offset] == 0xFF {
            payload_start = Some(offset + 1);
            break;
        }
        // CoAP option delta & length parsing
        let delta_byte = payload[offset];
        offset = offset.checked_add(1)?;

        let mut _option_delta = (delta_byte >> 4) as usize;
        let mut option_len = (delta_byte & 0x0F) as usize;

        if _option_delta == 13 {
            if offset >= payload.len() {
                return None;
            }
            _option_delta = payload[offset] as usize + 13;
            offset = offset.checked_add(1)?;
        } else if _option_delta == 14 {
            if offset + 1 >= payload.len() {
                return None;
            }
            _option_delta =
                u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize + 269;
            offset = offset.checked_add(2)?;
        }

        if option_len == 13 {
            if offset >= payload.len() {
                return None;
            }
            option_len = payload[offset] as usize + 13;
            offset = offset.checked_add(1)?;
        } else if option_len == 14 {
            if offset + 1 >= payload.len() {
                return None;
            }
            option_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize + 269;
            offset = offset.checked_add(2)?;
        }

        offset = offset.checked_add(option_len)?;
    }

    let parsed_payload = if let Some(start) = payload_start {
        if start < payload.len() {
            String::from_utf8(payload[start..].to_vec())
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    } else {
        None
    };

    Some(CoapPacket {
        source_mac,
        source_ip,
        code,
        message_id,
        payload: parsed_payload,
    })
}

/// KNXnet/IP UDP port
pub const KNX_PORT: u16 = 3671;

/// Checks if the port matches the KNXnet/IP port.
pub fn is_knx_port(port: u16) -> bool {
    port == KNX_PORT
}

/// Parsed KNXnet/IP protocol packet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct KnxPacket {
    /// Source MAC address
    pub source_mac: String,
    /// Source IP address
    pub source_ip: std::net::IpAddr,
    /// Service Type Identifier
    pub service_type: u16,
    /// Friendly Name of the KNX device
    pub friendly_name: Option<String>,
    /// Serial Number of the KNX device (hex string format)
    pub serial_number: Option<String>,
}

/// Parses a KNXnet/IP packet from UDP payload bytes.
pub fn parse_knx_payload(
    payload: &[u8],
    source_mac: String,
    source_ip: std::net::IpAddr,
) -> Option<KnxPacket> {
    if payload.len() < 6 {
        return None;
    }
    // Verify header length (typically 6) and protocol version (0x10 or 0x20)
    let header_len = payload[0] as usize;
    if header_len < 6 || header_len > payload.len() {
        return None;
    }
    let version = payload[1];
    if version != 0x10 && version != 0x20 {
        return None;
    }

    let service_type = u16::from_be_bytes([payload[2], payload[3]]);
    let total_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if total_len > payload.len() {
        return None;
    }

    let mut friendly_name = None;
    let mut serial_number = None;

    // Search response (0x0202) or Description response (0x0204)
    if (service_type == 0x0202 || service_type == 0x0204) && payload.len() > header_len {
        let mut offset = header_len;
        // Parse DIBs (Device Information Blocks)
        while offset + 2 <= payload.len() {
            let dib_len = payload[offset] as usize;
            if dib_len == 0 {
                break;
            }
            let next_offset = match offset.checked_add(dib_len) {
                Some(val) => val,
                None => break,
            };
            if next_offset > payload.len() {
                break;
            }
            let dib_type = payload[offset + 1];

            // Device Info DIB (type 0x01 or 0x02)
            if (dib_type == 0x01 || dib_type == 0x02) && dib_len >= 54 {
                // Serial number (6 bytes starting at index 12 in the DIB)
                let serial_bytes = &payload[offset + 12..offset + 18];
                serial_number = Some(format!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    serial_bytes[0],
                    serial_bytes[1],
                    serial_bytes[2],
                    serial_bytes[3],
                    serial_bytes[4],
                    serial_bytes[5]
                ));

                // Friendly name (30 bytes starting at index 22 in the DIB)
                let name_bytes = &payload[offset + 22..offset + 52];
                // Find first null byte to trim name
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(30);
                if end > 0
                    && let Ok(name) = String::from_utf8(name_bytes[..end].to_vec())
                {
                    let name_trimmed = name.trim().to_string();
                    if !name_trimmed.is_empty() {
                        friendly_name = Some(name_trimmed);
                    }
                }
                break;
            }
            offset = next_offset;
        }
    }

    Some(KnxPacket {
        source_mac,
        source_ip,
        service_type,
        friendly_name,
        serial_number,
    })
}

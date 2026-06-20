// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
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

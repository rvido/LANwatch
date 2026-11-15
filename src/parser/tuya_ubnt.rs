// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! Tuya and Ubiquiti discovery parsers.
//!
//! Both are vendor broadcasts a device sends on its own, so listening is
//! enough: LANwatch never asks.
//!
//! * **Tuya** smart plugs, bulbs and switches broadcast a framed message every
//!   few seconds to UDP 6666 (protocol 3.1, plain JSON) or UDP 6667 (protocol
//!   3.3 and later, encrypted). The encrypted form is recognised by its frame
//!   and names the sender as a Tuya device; its fields are not read, because
//!   that needs a cipher this crate does not carry.
//! * **Ubiquiti** access points, switches and routers announce themselves on
//!   UDP 10001 as a list of type-length-value fields: host name, model,
//!   firmware.

/// UDP port of the plain-text Tuya broadcast (protocol 3.1).
pub const TUYA_PLAIN_PORT: u16 = 6666;

/// UDP port of the encrypted Tuya broadcast (protocol 3.3 and later).
pub const TUYA_ENCRYPTED_PORT: u16 = 6667;

/// UDP port of the Ubiquiti discovery protocol.
pub const UBNT_PORT: u16 = 10001;

/// Frame prefix of Tuya protocols 3.1 to 3.4.
const TUYA_PREFIX_55AA: [u8; 4] = [0x00, 0x00, 0x55, 0xAA];

/// Frame prefix of Tuya protocol 3.5.
const TUYA_PREFIX_6699: [u8; 4] = [0x00, 0x00, 0x66, 0x99];

/// Bytes of a 55AA frame before its body: prefix, sequence, command, length.
const TUYA_HEADER_LEN: usize = 16;

/// Longest value kept from a Tuya JSON field or a Ubiquiti text field.
const MAX_FIELD_LEN: usize = 64;

/// A Tuya discovery broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct TuyaPacket {
    /// Source MAC address of the device
    pub source_mac: [u8; 6],
    /// Source IP address of the device
    pub source_ip: std::net::IpAddr,
    /// Whether the body was encrypted, so none of the fields below were read
    pub encrypted: bool,
    /// The device's Tuya ID (`gwId`)
    pub device_id: Option<String>,
    /// The product key, shared by every unit of one product
    pub product_key: Option<String>,
    /// The protocol version the device speaks, e.g. `3.1`
    pub version: Option<String>,
}

/// Whether a UDP destination port carries Tuya broadcasts.
///
/// Only the destination counts: the device is always the sender, so a packet
/// *from* one of these ports says nothing.
pub fn is_tuya_port(dest: u16) -> bool {
    dest == TUYA_PLAIN_PORT || dest == TUYA_ENCRYPTED_PORT
}

/// Parses a Tuya discovery broadcast.
///
/// Returns `None` unless the payload opens with a Tuya frame prefix. A frame
/// whose body is not readable JSON is still a Tuya device, reported with
/// `encrypted` set.
pub fn parse_tuya_payload(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<TuyaPacket> {
    if payload.len() < TUYA_HEADER_LEN + 8 {
        return None;
    }
    let prefix = payload.get(..4)?;
    if prefix != TUYA_PREFIX_55AA && prefix != TUYA_PREFIX_6699 {
        return None;
    }

    let mut packet = TuyaPacket {
        source_mac,
        source_ip,
        encrypted: true,
        device_id: None,
        product_key: None,
        version: None,
    };

    // A plain body is one JSON object somewhere after the header; a return
    // code may sit in front of it, and a checksum and suffix follow it.
    let body = payload.get(TUYA_HEADER_LEN..)?;
    let json = body
        .iter()
        .position(|&b| b == b'{')
        .zip(body.iter().rposition(|&b| b == b'}'))
        .filter(|(start, end)| start < end)
        .and_then(|(start, end)| std::str::from_utf8(body.get(start..=end)?).ok());

    if prefix == TUYA_PREFIX_55AA
        && let Some(json) = json
    {
        packet.device_id = json_string_field(json, "gwId");
        packet.product_key = json_string_field(json, "productKey");
        packet.version = json_string_field(json, "version");
        packet.encrypted =
            packet.device_id.is_none() && packet.product_key.is_none() && packet.version.is_none();
    }

    Some(packet)
}

/// Reads the string value of `"key":"value"` from a flat JSON object.
///
/// This is not a JSON parser: it serves the fixed, flat shape of the Tuya
/// broadcast. A value with an escape, a control character, or more than
/// [`MAX_FIELD_LEN`] bytes is refused rather than guessed at.
fn json_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut search = json;
    loop {
        let at = search.find(&needle)?;
        let rest = search.get(at + needle.len()..)?;
        search = rest;
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            // The needle was a value, not a key. Look further on.
            continue;
        };
        let value = rest.trim_start().strip_prefix('"')?;
        let end = value.find('"')?;
        let value = value.get(..end)?;
        if value.is_empty()
            || value.len() > MAX_FIELD_LEN
            || value.chars().any(|c| c == '\\' || c.is_control())
        {
            return None;
        }
        return Some(value.to_string());
    }
}

/// Field types of the Ubiquiti discovery protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbntField {
    /// The device's MAC address (6 bytes)
    MacAddress,
    /// A MAC address followed by an IPv4 address (10 bytes)
    MacAndIp,
    /// Firmware version string
    Firmware,
    /// Host name set by the owner
    Hostname,
    /// Short platform name, e.g. `U7PG2`
    Platform,
    /// Full model name (protocol version 1)
    ModelFull,
    /// Model name (protocol version 2)
    Model,
    /// Firmware version string (protocol version 2)
    FirmwareV2,
    /// A field LANwatch does not read
    Other(u8),
}

impl From<u8> for UbntField {
    fn from(value: u8) -> Self {
        match value {
            0x01 => UbntField::MacAddress,
            0x02 => UbntField::MacAndIp,
            0x03 => UbntField::Firmware,
            0x0B => UbntField::Hostname,
            0x0C => UbntField::Platform,
            0x14 => UbntField::ModelFull,
            0x15 => UbntField::Model,
            0x16 => UbntField::FirmwareV2,
            other => UbntField::Other(other),
        }
    }
}

/// A Ubiquiti discovery announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "http-api", derive(serde::Serialize, serde::Deserialize))]
pub struct UbntPacket {
    /// Source MAC address of the frame
    pub source_mac: [u8; 6],
    /// Source IP address of the frame
    pub source_ip: std::net::IpAddr,
    /// Protocol version, 1 or 2
    pub version: u8,
    /// The MAC address the device reports for itself. Not used as identity:
    /// the frame's own source is.
    pub announced_mac: Option<[u8; 6]>,
    /// Host name set by the owner
    pub hostname: Option<String>,
    /// Model, the most specific name the device gave
    pub model: Option<String>,
    /// Firmware version string
    pub firmware: Option<String>,
}

/// Whether either UDP port is the Ubiquiti discovery port.
pub fn is_ubnt_ports(src: u16, dest: u16) -> bool {
    src == UBNT_PORT || dest == UBNT_PORT
}

/// Parses a Ubiquiti discovery announcement.
///
/// Returns `None` for the 4-byte query a discovery tool sends (it names no
/// device), for a field list that does not end exactly where the header says,
/// and for one that carries no field LANwatch knows -- UDP 10001 is not
/// reserved, and other software uses it.
pub fn parse_ubnt_payload(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: std::net::IpAddr,
) -> Option<UbntPacket> {
    let version = *payload.first()?;
    if version != 1 && version != 2 {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]));
    let fields = payload.get(4..)?;
    if declared == 0 || declared != fields.len() {
        return None;
    }

    let mut packet = UbntPacket {
        source_mac,
        source_ip,
        version,
        announced_mac: None,
        hostname: None,
        model: None,
        firmware: None,
    };
    let mut platform = None;
    let mut model_full = None;
    let mut model = None;
    let mut known = false;

    let mut rest = fields;
    while !rest.is_empty() {
        let field = UbntField::from(*rest.first()?);
        let len = usize::from(u16::from_be_bytes([*rest.get(1)?, *rest.get(2)?]));
        let value = rest.get(3..3 + len)?;
        rest = rest.get(3 + len..)?;

        match field {
            UbntField::MacAddress if len == 6 => {
                packet.announced_mac = value.try_into().ok();
                known = true;
            }
            UbntField::MacAndIp if len == 10 => {
                if packet.announced_mac.is_none() {
                    packet.announced_mac = value.get(..6).and_then(|mac| mac.try_into().ok());
                }
                known = true;
            }
            UbntField::Hostname => packet.hostname = ubnt_text(value),
            UbntField::Platform => platform = ubnt_text(value),
            UbntField::ModelFull => model_full = ubnt_text(value),
            UbntField::Model => model = ubnt_text(value),
            UbntField::Firmware | UbntField::FirmwareV2 if packet.firmware.is_none() => {
                packet.firmware = ubnt_text(value);
            }
            _ => {}
        }
    }

    packet.model = model_full.or(model).or(platform);
    known |= packet.hostname.is_some() || packet.model.is_some() || packet.firmware.is_some();
    known.then_some(packet)
}

/// A Ubiquiti text field: UTF-8, no control characters, not over-long.
fn ubnt_text(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value)
        .ok()?
        .trim_end_matches('\0')
        .trim();
    (!text.is_empty() && text.len() <= MAX_FIELD_LEN && !text.chars().any(char::is_control))
        .then(|| text.to_string())
}

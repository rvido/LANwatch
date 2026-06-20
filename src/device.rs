// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Information about a detected DHCP device
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// MAC address of the device
    pub mac_address: String,
    /// IPv4 address
    #[serde(
        serialize_with = "serialize_ip_addr",
        deserialize_with = "deserialize_ip_addr"
    )]
    pub ip_address: IpAddr,
    /// IPv6 address if available
    #[serde(
        serialize_with = "serialize_opt_ip_addr",
        deserialize_with = "deserialize_opt_ip_addr"
    )]
    pub ipv6_address: Option<IpAddr>,
    /// List of all detected IPv6 addresses for this device
    #[serde(default)]
    pub ipv6_addresses: Vec<Ipv6Addr>,
    /// Hostname if available
    pub hostname: Option<String>,
    /// System description if available (e.g., from LLDP or CDP)
    pub system_description: Option<String>,
    /// Detected mDNS services (e.g., "_http._tcp", "_airplay._tcp")
    pub services: Vec<String>,
    /// Vendor hint based on services or MAC OUI (e.g., "Apple", "Google")
    pub vendor: Option<String>,
    /// Device type based on mDNS services (e.g., "Chromecast", "Apple TV", "Printer")
    pub device_type: Option<String>,
    /// First seen timestamp (ISO 8601 format)
    #[serde(
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub first_seen: SystemTime,
    /// Last seen timestamp (ISO 8601 format)
    #[serde(
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub last_seen: SystemTime,
}

impl DeviceInfo {
    /// Creates a new `DeviceInfo` instance with timestamps initialized to now.
    pub fn new(mac_address: String, ip_address: IpAddr, hostname: Option<String>) -> Self {
        let timestamp = SystemTime::now();
        let mut ipv6_addresses = Vec::new();
        let ipv6_address = match ip_address {
            IpAddr::V6(ipv6) => {
                ipv6_addresses.push(ipv6);
                Some(IpAddr::V6(ipv6))
            }
            _ => None,
        };
        Self {
            mac_address,
            ip_address,
            ipv6_address,
            ipv6_addresses,
            hostname,
            system_description: None,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: timestamp,
            last_seen: timestamp,
        }
    }

    /// Updates the device information with a new IP address and optional hostname.
    ///
    /// # Returns
    /// `true` if any fields were updated, `false` otherwise.
    pub fn update(&mut self, ip_address: IpAddr, hostname: Option<&str>) -> bool {
        let mut changed = false;
        let timestamp = SystemTime::now();

        match ip_address {
            IpAddr::V4(_) => {
                if self.ip_address != ip_address {
                    if let IpAddr::V6(old_v6) = self.ip_address {
                        self.set_ipv6_address(old_v6);
                    }
                    self.ip_address = ip_address;
                    changed = true;
                }
            }
            IpAddr::V6(ipv6) => {
                if self.set_ipv6_address(ipv6) {
                    changed = true;
                }
                if self.ip_address.is_unspecified() {
                    self.ip_address = ip_address;
                    changed = true;
                }
            }
        }

        let new_hostname = hostname.and_then(sanitize_hostname);
        if self.hostname != new_hostname && new_hostname.is_some() {
            self.hostname = new_hostname;
            changed = true;
        }

        self.last_seen = timestamp;
        changed
    }

    /// Adds a service to the device's service list if not already present.
    ///
    /// # Returns
    /// `true` if a new service was added, `false` if it was already in the list.
    pub fn add_service(&mut self, service: &str) -> bool {
        let normalized = service
            .to_lowercase()
            .trim_end_matches(".local")
            .to_string();
        match self.services.binary_search(&normalized) {
            Ok(_) => false,
            Err(index) => {
                self.services.insert(index, normalized);
                true
            }
        }
    }

    /// Sets the device vendor if it is not already defined.
    ///
    /// # Returns
    /// `true` if the vendor was set, `false` if a vendor already existed.
    pub fn set_vendor(&mut self, vendor: &str) -> bool {
        if self.vendor.is_none() {
            self.vendor = Some(vendor.to_string());
            true
        } else {
            false
        }
    }

    /// Sets the device type if it is not already defined.
    ///
    /// # Returns
    /// `true` if the device type was set, `false` if it already existed.
    pub fn set_device_type(&mut self, device_type: &str) -> bool {
        if self.device_type.is_none() {
            self.device_type = Some(device_type.to_string());
            true
        } else {
            false
        }
    }

    /// Sets or updates the device's IPv6 address.
    ///
    /// # Returns
    /// `true` if the address list or primary address was changed or set, `false` if it was already identical.
    pub fn set_ipv6_address(&mut self, ipv6: Ipv6Addr) -> bool {
        let mut changed = false;
        if !self.ipv6_addresses.contains(&ipv6) {
            self.ipv6_addresses.push(ipv6);
            changed = true;
        }

        let current_pref = self
            .ipv6_address
            .and_then(|ip| match ip {
                IpAddr::V6(v6) => Some(ipv6_preference_score(&v6)),
                _ => None,
            })
            .unwrap_or(0);

        let new_pref = ipv6_preference_score(&ipv6);

        // If the new address has a higher preference score, or if there is no primary IPv6 address set yet
        if self.ipv6_address.is_none() || new_pref > current_pref {
            let new_ipv6 = Some(IpAddr::V6(ipv6));
            if self.ipv6_address != new_ipv6 {
                self.ipv6_address = new_ipv6;
                changed = true;
            }
        }
        changed
    }

    /// Serializes the device information into a CSV string.
    ///
    /// # Format
    /// `first_seen,last_seen,mac_address,ip_address,"ipv6_address","hostname","device_type","vendor","services","system_description"`
    pub fn to_csv_line(&self) -> String {
        let services_str = self.services.join(";");
        let v6_addresses_str = self
            .ipv6_addresses
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(";");
        format!(
            "{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            format_timestamp(self.first_seen),
            format_timestamp(self.last_seen),
            self.mac_address,
            self.ip_address,
            self.ipv6_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            self.hostname.as_deref().unwrap_or(""),
            self.device_type.as_deref().unwrap_or(""),
            self.vendor.as_deref().unwrap_or(""),
            services_str,
            self.system_description.as_deref().unwrap_or(""),
            v6_addresses_str
        )
    }

    /// Parses a device from a CSV line string.
    ///
    /// # Arguments
    /// * `line` - A string representing a single row from a `lanwatch` CSV file.
    ///
    /// # Returns
    /// `Some(DeviceInfo)` if the line is valid, otherwise `None`.
    pub fn from_csv_line(line: &str) -> Option<Self> {
        let parts = parse_csv_line(line);
        if parts.len() < 4 {
            return None;
        }

        let first_seen = parse_timestamp(parts[0])?;
        let last_seen = if parts.len() > 1 {
            parse_timestamp(parts[1])?
        } else {
            first_seen
        };
        let mac_address = normalize_device_identifier(parts[2]);
        let ip_address = parts[3].parse().ok()?;
        let ipv6_address = if parts.len() > 4 {
            let v6 = parts[4].trim_matches('"');
            if v6.is_empty() {
                None
            } else {
                Some(v6.parse().ok()?)
            }
        } else {
            None
        };
        let hostname = if parts.len() > 5 {
            let h = parts[5].trim_matches('"');
            sanitize_hostname(h)
        } else {
            None
        };
        let device_type = if parts.len() > 6 {
            let t = parts[6].trim_matches('"');
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        } else {
            None
        };
        let vendor = if parts.len() > 7 {
            let v = parts[7].trim_matches('"');
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        } else {
            None
        };
        let services = if parts.len() > 8 {
            let s = parts[8].trim_matches('"');
            if s.is_empty() {
                Vec::new()
            } else {
                s.split(';').map(|s| s.to_string()).collect()
            }
        } else {
            Vec::new()
        };
        let system_description = if parts.len() > 9 {
            let desc = parts[9].trim_matches('"');
            if desc.is_empty() {
                None
            } else {
                Some(desc.to_string())
            }
        } else {
            None
        };

        let ipv6_addresses = if parts.len() > 10 {
            let v6s = parts[10].trim_matches('"');
            if v6s.is_empty() {
                let mut list = Vec::new();
                if let Some(IpAddr::V6(v6)) = ipv6_address {
                    list.push(v6);
                }
                list
            } else {
                v6s.split(';')
                    .filter_map(|s| s.parse::<Ipv6Addr>().ok())
                    .collect()
            }
        } else {
            let mut list = Vec::new();
            if let Some(IpAddr::V6(v6)) = ipv6_address {
                list.push(v6);
            }
            list
        };

        Some(Self {
            mac_address,
            ip_address,
            ipv6_address,
            ipv6_addresses,
            hostname,
            system_description,
            services,
            vendor,
            device_type,
            first_seen,
            last_seen,
        })
    }
}

/// Parse a CSV line handling quoted fields without allocations
fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::with_capacity(9);
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;
    let bytes = line.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if bytes[i] == b',' && !in_quotes {
            let mut field = &line[start..i];
            if field.starts_with('"') && field.ends_with('"') && field.len() >= 2 {
                field = &field[1..field.len() - 1];
            }
            fields.push(field);
            start = i + 1;
        }
        i += 1;
    }
    let mut field = &line[start..i];
    if field.starts_with('"') && field.ends_with('"') && field.len() >= 2 {
        field = &field[1..field.len() - 1];
    }
    fields.push(field);
    fields
}

/// Parses an ISO 8601 UTC timestamp format (YYYY-MM-DDTHH:MM:SSZ) into a `SystemTime`.
///
/// Returns `None` if the format is invalid or cannot be parsed.
pub fn parse_timestamp(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if value.len() != 20 || !value.ends_with('Z') {
        return None;
    }

    let year: i32 = value.get(0..4)?.parse().ok()?;
    let month: i32 = value.get(5..7)?.parse().ok()?;
    let day: i32 = value.get(8..10)?.parse().ok()?;
    let hour: u64 = value.get(11..13)?.parse().ok()?;
    let minute: u64 = value.get(14..16)?.parse().ok()?;
    let second: u64 = value.get(17..19)?.parse().ok()?;

    if value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut days = 0u64;
    let mut current_year = 1970;
    while current_year < year {
        days += if is_leap_year(current_year) {
            366u64
        } else {
            365u64
        };
        current_year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for days_in_month in month_days.iter().take((month - 1) as usize) {
        days += *days_in_month as u64;
    }

    days += (day - 1) as u64;

    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn serialize_system_time<S>(value: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format_timestamp(*value))
}

fn deserialize_system_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    parse_timestamp(&value).ok_or_else(|| serde::de::Error::custom("invalid timestamp"))
}

fn serialize_ip_addr<S>(value: &IpAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_ip_addr<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

fn serialize_opt_ip_addr<S>(value: &Option<IpAddr>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(ip) => serializer.serialize_some(&ip.to_string()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_opt_ip_addr<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
    value
        .map(|ip| ip.parse().map_err(serde::de::Error::custom))
        .transpose()
}

/// Formats a `SystemTime` as an ISO 8601 UTC timestamp string (YYYY-MM-DDTHH:MM:SSZ).
pub fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    let mut year = 1970i32;
    let mut remaining_days = days as i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i32; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

pub(crate) fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub(crate) fn normalize_device_identifier(raw: &str) -> String {
    let candidate = raw.trim().to_lowercase();
    let mut bytes: Vec<u8> = Vec::new();

    let source = candidate.strip_prefix("duid:").unwrap_or(&candidate);
    for token in source.split(':') {
        if token.len() != 2 {
            return candidate;
        }
        let byte = match u8::from_str_radix(token, 16) {
            Ok(b) => b,
            Err(_) => return candidate,
        };
        bytes.push(byte);
    }

    // DUID-LL (type 3), Ethernet hw type 1: 00:03:00:01:xx:xx:xx:xx:xx:xx
    if bytes.len() == 10 && bytes[0..4] == [0x00, 0x03, 0x00, 0x01] {
        return format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9]
        );
    }

    // DUID-LLT (type 1), Ethernet hw type 1: 00:01:00:01:time(4):mac(6)
    if bytes.len() >= 14 && bytes[0..4] == [0x00, 0x01, 0x00, 0x01] {
        return format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13]
        );
    }

    candidate
}

/// Keep hostnames printable and safe for CSV/UI output.
pub(crate) fn sanitize_hostname(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();

    let cleaned = cleaned
        .trim_matches('.')
        .trim_matches('-')
        .trim_matches('_')
        .to_string();

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Helper function to rank preference of different IPv6 address types:
/// - Global Unicast Address (GUA): 3
/// - Unique Local Address (ULA): 2
/// - Link-Local Address (LLA): 1
/// - Unspecified/Multicast/Loopback: 0
fn ipv6_preference_score(ip: &Ipv6Addr) -> u8 {
    if ip.is_multicast() || ip.is_loopback() || ip.is_unspecified() {
        return 0;
    }
    let first_word = ip.segments()[0];
    if (first_word & 0xffc0) == 0xfe80 {
        1 // Link-Local
    } else if (first_word & 0xfe00) == 0xfc00 {
        2 // Unique-Local
    } else if (first_word & 0xe000) == 0x2000 {
        3 // Global Unicast (GUA)
    } else {
        1 // Other unicast
    }
}

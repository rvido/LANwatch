// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Registry for IEEE OUI (Organizationally Unique Identifier) database.
/// OUI entries can be loaded from an external file to perform MAC-to-vendor resolution.
#[derive(Debug, Clone, Default)]
pub struct OuiRegistry {
    /// Custom vendor overrides
    custom_overrides: HashMap<String, String>,
}

impl OuiRegistry {
    /// Creates a new empty OUI registry.
    pub fn new() -> Self {
        Self {
            custom_overrides: HashMap::new(),
        }
    }

    /// Creates a new OUI registry.
    pub fn with_defaults() -> Self {
        Self::new()
    }

    /// Look up vendor name by MAC address from the registered database entries.
    /// Checks loaded overrides first.
    ///
    /// The MAC address can be in various formats:
    /// - Full: "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
    /// - OUI only: "AA:BB:CC" or "AABBCC"
    pub fn lookup(&self, mac_address: &str) -> Option<&str> {
        let mut buf = [0u8; 8];
        let len = {
            let mut l = 0;
            for c in mac_address.chars() {
                if l >= 6 {
                    break;
                }
                if c.is_ascii_hexdigit() {
                    let u = c.to_ascii_uppercase() as u8;
                    if l == 0 {
                        buf[0] = u;
                    } else if l == 1 {
                        buf[1] = u;
                    } else if l == 2 {
                        buf[3] = u;
                    } else if l == 3 {
                        buf[4] = u;
                    } else if l == 4 {
                        buf[6] = u;
                    } else if l == 5 {
                        buf[7] = u;
                    }
                    l += 1;
                }
            }
            if l >= 6 {
                buf[2] = b':';
                buf[5] = b':';
                8
            } else {
                let mut idx = 0;
                for c in mac_address.chars() {
                    if idx >= l {
                        break;
                    }
                    if c.is_ascii_hexdigit() {
                        buf[idx] = c.to_ascii_uppercase() as u8;
                        idx += 1;
                    }
                }
                l
            }
        };

        let normalized = std::str::from_utf8(&buf[..len]).ok()?;

        // Check custom overrides first (highest priority)
        if let Some(vendor) = self.custom_overrides.get(normalized) {
            return Some(vendor.as_str());
        }

        None
    }

    /// Load additional OUI entries from a file.
    /// File format: `MAC_PREFIX<whitespace>VENDOR_NAME`
    /// Example:
    ///   AA:BB:CC  Acme Corporation
    ///   DD-EE-FF  Another Vendor
    ///
    /// Returns the number of entries loaded.
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            // Parse line: MAC_PREFIX<whitespace>VENDOR_NAME
            if let Some((mac, vendor)) = Self::parse_oui_line(line) {
                let normalized = Self::normalize_mac(&mac);
                self.custom_overrides.insert(normalized, vendor);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Adds a manual OUI-to-vendor mapping to the registry.
    pub fn add(&mut self, mac_prefix: &str, vendor: &str) {
        let normalized = Self::normalize_mac(mac_prefix);
        self.custom_overrides.insert(normalized, vendor.to_string());
    }

    /// Returns the total count of OUI entries available.
    pub fn len(&self) -> usize {
        self.custom_overrides.len()
    }

    /// Check if registry has no entries
    pub fn is_empty(&self) -> bool {
        self.custom_overrides.is_empty()
    }

    /// Returns the number of custom override entries loaded.
    pub fn custom_count(&self) -> usize {
        self.custom_overrides.len()
    }

    /// Returns the number of entries in the built-in IEEE database.
    pub fn builtin_count() -> usize {
        0
    }

    /// Normalize a MAC address to OUI format (first 3 octets, uppercase, colon-separated)
    fn normalize_mac(mac: &str) -> String {
        let mut buf = [0u8; 6];
        let mut len = 0;

        for c in mac.chars() {
            if len >= 6 {
                break;
            }
            if c.is_ascii_hexdigit() {
                buf[len] = c.to_ascii_uppercase() as u8;
                len += 1;
            }
        }

        if len >= 6 {
            let mut s = String::with_capacity(8);
            s.push(buf[0] as char);
            s.push(buf[1] as char);
            s.push(':');
            s.push(buf[2] as char);
            s.push(buf[3] as char);
            s.push(':');
            s.push(buf[4] as char);
            s.push(buf[5] as char);
            s
        } else {
            let mut s = String::with_capacity(len);
            for &b in &buf[..len] {
                s.push(b as char);
            }
            s
        }
    }

    /// Parse a line from an OUI file
    fn parse_oui_line(line: &str) -> Option<(String, String)> {
        // Try tab separator first
        if let Some((mac, vendor)) = line.split_once('\t') {
            let mac = mac.trim();
            let vendor = vendor.trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac.to_string(), vendor.to_string()));
            }
        }

        // Try splitting on first run of spaces (at least 2)
        let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() == 2 {
            let mac = parts[0].trim();
            let vendor = parts[1].trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac.to_string(), vendor.to_string()));
            }
        }

        None
    }

    /// Parse IEEE OUI format line (from official IEEE downloads)
    /// Format: "XX-XX-XX   (hex)\t\tVendor Name"
    pub(crate) fn parse_ieee_oui_line(line: &str) -> Option<(String, String)> {
        // IEEE format: "XX-XX-XX   (hex)		Vendor Name"
        // We look for lines containing "(hex)"
        if !line.contains("(hex)") {
            return None;
        }

        // Split on "(hex)" - MAC is before, vendor is after
        let parts: Vec<&str> = line.splitn(2, "(hex)").collect();
        if parts.len() != 2 {
            return None;
        }

        let mac = parts[0].trim();
        let vendor = parts[1].trim();

        if mac.is_empty() || vendor.is_empty() {
            return None;
        }

        Some((mac.to_string(), vendor.to_string()))
    }

    /// Load OUI entries from IEEE format file (official IEEE OUI download)
    /// This parses the official IEEE OUI format with "(hex)" markers.
    pub fn load_from_ieee_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;

            // Parse IEEE format line
            if let Some((mac, vendor)) = Self::parse_ieee_oui_line(&line) {
                let normalized = Self::normalize_mac(&mac);
                self.custom_overrides.insert(normalized, vendor);
                count += 1;
            }
        }

        Ok(count)
    }
}

/// IEEE OUI database URLs
pub const IEEE_OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.txt";
/// IEEE OUI-28 (Medium Authority MAC) registry URL.
pub const IEEE_OUI28_URL: &str = "https://standards-oui.ieee.org/oui28/mam.txt";
/// IEEE OUI-36 (Individual Address Block) registry URL.
pub const IEEE_OUI36_URL: &str = "https://standards-oui.ieee.org/oui36/oui36.txt";

/// Download the IEEE OUI database to a file using curl.
/// Returns Ok(()) on success, or an error message on failure.
///
/// # Arguments
/// * `output_path` - Path where the downloaded file will be saved
/// * `url` - Optional custom URL (defaults to IEEE_OUI_URL)
pub fn download_ieee_oui<P: AsRef<Path>>(output_path: P, url: Option<&str>) -> Result<(), String> {
    let url = url.unwrap_or(IEEE_OUI_URL);
    let output_path = output_path.as_ref();

    // Use curl to download the file
    let output = std::process::Command::new("curl")
        .args([
            "-fsSL", // fail silently, follow redirects, show errors
            "--connect-timeout",
            "30",
            "--max-time",
            "120",
            "-o",
            output_path.to_str().ok_or("Invalid output path")?,
            url,
        ])
        .output()
        .map_err(|e| format!("Failed to execute curl: {}. Is curl installed?", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", stderr.trim()));
    }

    // Verify the file was created and has content
    let metadata = std::fs::metadata(output_path)
        .map_err(|e| format!("Failed to verify downloaded file: {}", e))?;

    if metadata.len() == 0 {
        return Err("Downloaded file is empty".to_string());
    }

    Ok(())
}

/// Download and load IEEE OUI database into an OuiRegistry.
/// Downloads from IEEE and parses the official format.
///
/// # Arguments
/// * `registry` - The OuiRegistry to load entries into
/// * `cache_path` - Optional path to cache the downloaded file (default: "ieee-oui.txt")
///
/// # Returns
/// Number of entries loaded on success, or an error message on failure.
pub fn download_and_load_ieee_oui(
    registry: &mut OuiRegistry,
    cache_path: Option<&str>,
) -> Result<usize, String> {
    let path = cache_path.unwrap_or("ieee-oui.txt");

    // Download the file
    download_ieee_oui(path, None)?;

    // Load the downloaded file
    registry
        .load_from_ieee_file(path)
        .map_err(|e| format!("Failed to parse IEEE OUI file: {}", e))
}

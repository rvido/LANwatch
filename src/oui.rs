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
    /// Custom vendor overrides, keyed on the OUI packed into the low 24 bits
    /// of a `u32`.
    ///
    /// An OUI is three bytes, so it fits in an integer key exactly. Keying on
    /// the `"AA:BB:CC"` string instead cost a separate heap allocation per
    /// entry -- roughly 35k of them, for nothing, once the full IEEE database
    /// is loaded -- plus a string hash and comparison on every lookup.
    custom_overrides: HashMap<u32, Box<str>>,
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
    ///
    /// Devices identified by a non-Ethernet DHCPv6 DUID (stored as
    /// `"duid:..."`, see `format_duid_identifier`) have no OUI to resolve;
    /// this is rejected up front rather than hex-scanned like a MAC, since
    /// "duid" itself contains hex digits that would otherwise decode into a
    /// bogus `DD:xx:xx` OUI.
    pub fn lookup(&self, mac_address: &str) -> Option<&str> {
        if mac_address.starts_with("duid:") {
            return None;
        }

        // Check custom overrides first (highest priority)
        if let Some(key) = Self::oui_key(mac_address)
            && let Some(vendor) = self.custom_overrides.get(&key)
        {
            return Some(vendor);
        }

        // Check if it is a private/randomized MAC address
        if is_private_mac(mac_address) {
            return Some("Private MAC Address");
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
            if let Some((mac, vendor)) = Self::parse_oui_line(line)
                && let Some(key) = Self::oui_key(mac)
            {
                self.custom_overrides.insert(key, vendor.into());
                count += 1;
            }
        }

        Ok(count)
    }

    /// Adds a manual OUI-to-vendor mapping to the registry.
    ///
    /// `mac_prefix` must contain at least six hex digits (an OUI); anything
    /// shorter is ignored, since a partial prefix could never match a lookup,
    /// which always normalizes a full MAC down to its first six digits.
    pub fn add(&mut self, mac_prefix: &str, vendor: &str) {
        if let Some(key) = Self::oui_key(mac_prefix) {
            self.custom_overrides.insert(key, vendor.into());
        }
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

    /// Packs the first three octets of `mac` into the low 24 bits of a `u32`,
    /// which is the registry's lookup key.
    ///
    /// Accepts any of the usual spellings -- `AA:BB:CC`, `AA-BB-CC`, `AABBCC`,
    /// or a full MAC -- by simply taking the first six hex digits and ignoring
    /// whatever separators sit between them. Returns `None` if there aren't
    /// six, since a shorter prefix isn't an OUI.
    fn oui_key(mac: &str) -> Option<u32> {
        let mut key = 0u32;
        let mut digits = 0;
        for c in mac.chars() {
            if let Some(value) = c.to_digit(16) {
                key = (key << 4) | value;
                digits += 1;
                if digits == 6 {
                    return Some(key);
                }
            }
        }
        None
    }

    /// Parse a line from an OUI file
    fn parse_oui_line(line: &str) -> Option<(&str, &str)> {
        // Try tab separator first
        if let Some((mac, vendor)) = line.split_once('\t') {
            let mac = mac.trim();
            let vendor = vendor.trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac, vendor));
            }
        }

        // Try splitting on first run of spaces (at least 2)
        let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() == 2 {
            let mac = parts[0].trim();
            let vendor = parts[1].trim();
            if !mac.is_empty() && !vendor.is_empty() {
                return Some((mac, vendor));
            }
        }

        None
    }

    /// Parse IEEE OUI format line (from official IEEE downloads)
    /// Format: "XX-XX-XX   (hex)\t\tVendor Name"
    pub(crate) fn parse_ieee_oui_line(line: &str) -> Option<(&str, &str)> {
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

        Some((mac, vendor))
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
            if let Some((mac, vendor)) = Self::parse_ieee_oui_line(&line)
                && let Some(key) = Self::oui_key(mac)
            {
                self.custom_overrides.insert(key, vendor.into());
                count += 1;
            }
        }

        Ok(count)
    }

    /// Load OUI entries from a file, auto-detecting whether it's the plain
    /// `MAC_PREFIX<whitespace>VENDOR_NAME` format or the official IEEE OUI
    /// download format (lines containing `(hex)`). Callers that just point
    /// at "whatever file `--download-oui` produced, or a hand-written
    /// override list" should use this instead of picking a parser manually.
    pub fn load_auto<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let path = path.as_ref();
        const PROBE_LINES: usize = 50;
        let is_ieee_format = {
            let file = File::open(path)?;
            BufReader::new(file)
                .lines()
                .take(PROBE_LINES)
                .filter_map(|l| l.ok())
                .any(|l| l.contains("(hex)"))
        };

        if is_ieee_format {
            self.load_from_ieee_file(path)
        } else {
            self.load_from_file(path)
        }
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

    // Only fetch over TLS. This also rejects anything starting with '-', which
    // curl would otherwise read as an option rather than a URL -- `-K<file>`,
    // for instance, makes it load a caller-chosen config file.
    if !url.starts_with("https://") {
        return Err(format!(
            "Refusing to download from {:?}: only https:// URLs are accepted",
            url
        ));
    }

    let output_path_str = output_path.to_str().ok_or("Invalid output path")?;
    if output_path_str.starts_with('-') {
        return Err("Refusing an output path starting with '-'".to_string());
    }

    // Use curl to download the file. `--` terminates option parsing so the URL
    // can never be mistaken for a flag.
    let output = std::process::Command::new("curl")
        .args([
            "-fsSL", // fail silently, follow redirects, show errors
            "--proto",
            "=https", // and don't let a redirect downgrade the scheme
            "--connect-timeout",
            "30",
            "--max-time",
            "120",
            "-o",
            output_path_str,
            "--",
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

/// Returns true if the MAC address is a private, randomized, or locally administered address.
/// These addresses have 2, 6, A, or E as their second hexadecimal digit.
pub fn is_private_mac(mac: &str) -> bool {
    let mut hex_count = 0;
    for c in mac.chars() {
        if c.is_ascii_hexdigit() {
            if hex_count == 1 {
                let u = c.to_ascii_uppercase();
                return u == '2' || u == '6' || u == 'A' || u == 'E';
            }
            hex_count += 1;
        }
    }
    false
}

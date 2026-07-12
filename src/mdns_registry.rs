// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Information about a known mDNS service type
#[derive(Debug, Clone)]
pub struct MdnsServiceInfo {
    /// Service type (e.g., "_http._tcp")
    pub service_type: String,
    /// Human-readable description
    pub description: String,
    /// Vendor hint (e.g., "Apple", "Google")
    pub vendor: Option<String>,
    /// Device type (e.g., "Chromecast", "Apple TV", "Printer")
    pub device_type: Option<String>,
}

/// Registry of known mDNS service types
#[derive(Debug, Clone, Default)]
pub struct MdnsServiceRegistry {
    services: HashMap<String, MdnsServiceInfo>,
}

impl MdnsServiceRegistry {
    /// Creates a new, empty mDNS service registry.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Creates an mDNS service registry pre-populated with common network services.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.add_default_services();
        registry
    }

    /// Add default well-known services
    fn add_default_services(&mut self) {
        // Apple TV / Streaming devices
        self.add_full(
            "_airplay._tcp",
            "AirPlay",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_raop._tcp",
            "Remote Audio (AirPlay)",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_companion-link._tcp",
            "AirPlay 2 Companion",
            Some("Apple"),
            Some("Media Streamer"),
        );
        self.add_full(
            "_touch-able._tcp",
            "Apple TV Remote",
            Some("Apple"),
            Some("Apple TV"),
        );
        self.add_full(
            "_mediaremotetv._tcp",
            "Apple TV Media Remote",
            Some("Apple"),
            Some("Apple TV"),
        );
        self.add_full(
            "_appletv-v2._tcp",
            "Apple TV",
            Some("Apple"),
            Some("Apple TV"),
        );

        // Apple Mobile / Mac devices
        self.add_full(
            "_airdrop._tcp",
            "AirDrop",
            Some("Apple"),
            Some("Apple Device"),
        );
        self.add_full(
            "_device-info._tcp",
            "Device Info",
            Some("Apple"),
            Some("Apple Device"),
        );
        self.add_full(
            "_apple-mobdev._tcp",
            "Apple Mobile Device",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_apple-mobdev2._tcp",
            "Apple Mobile Device",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_remotepairing._tcp",
            "Apple Remote Pairing",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_atc._tcp",
            "Apple Transfer Control",
            Some("Apple"),
            Some("Apple iPhone"),
        );
        self.add_full(
            "_rdlink._tcp",
            "Apple Remote Device Link",
            Some("Apple"),
            Some("Apple iPhone"),
        );

        // Apple Smart Home
        self.add_full(
            "_homekit._tcp",
            "HomeKit",
            Some("Apple"),
            Some("Smart Home Hub"),
        );
        self.add_full(
            "_hap._tcp",
            "HomeKit Accessory",
            Some("Apple"),
            Some("Smart Home Device"),
        );

        // Apple Network/Storage
        self.add_full(
            "_airport._tcp",
            "AirPort Base Station",
            Some("Apple"),
            Some("Router"),
        );
        self.add_full(
            "_daap._tcp",
            "iTunes Library (DAAP)",
            Some("Apple"),
            Some("Media Server"),
        );
        self.add_full(
            "_dpap._tcp",
            "iPhoto Library",
            Some("Apple"),
            Some("Media Server"),
        );
        self.add_full(
            "_afpovertcp._tcp",
            "Apple File Sharing (AFP)",
            Some("Apple"),
            Some("File Server"),
        );

        // Google Chromecast / Android TV
        self.add_full(
            "_googlecast._tcp",
            "Google Chromecast",
            Some("Google"),
            Some("Chromecast"),
        );
        self.add_full(
            "_googlezone._tcp",
            "Google Zone",
            Some("Google"),
            Some("Chromecast"),
        );
        self.add_full(
            "_androidtvremote._tcp",
            "Android TV Remote",
            Some("Google"),
            Some("Android TV"),
        );
        self.add_full(
            "_physicalweb._tcp",
            "Physical Web",
            Some("Google"),
            Some("IoT Beacon"),
        );

        // Amazon Fire TV
        self.add_full(
            "_amzn-wplay._tcp",
            "Amazon Fire TV",
            Some("Amazon"),
            Some("Fire TV"),
        );

        // Printers & Scanners
        self.add_full("_printer._tcp", "LPR Printer", None, Some("Printer"));
        self.add_full("_ipp._tcp", "IPP Printer", None, Some("Printer"));
        self.add_full("_ipps._tcp", "IPP Printer (Secure)", None, Some("Printer"));
        self.add_full("_ippusb._tcp", "IPP USB Printer", None, Some("Printer"));
        self.add_full("_pdl-datastream._tcp", "PDL Printer", None, Some("Printer"));
        self.add_full("_scanner._tcp", "Network Scanner", None, Some("Scanner"));
        self.add_full("_uscan._tcp", "USB Scanner", None, Some("Scanner"));

        // Servers / Workstations
        self.add_full("_http._tcp", "Web Server (HTTP)", None, Some("Server"));
        self.add_full("_https._tcp", "Web Server (HTTPS)", None, Some("Server"));
        self.add_full("_ssh._tcp", "SSH Server", None, Some("Server"));
        self.add_full("_sftp-ssh._tcp", "SFTP over SSH", None, Some("Server"));
        self.add_full("_ftp._tcp", "FTP Server", None, Some("Server"));
        self.add_full(
            "_smb._tcp",
            "Windows/Samba Sharing",
            None,
            Some("File Server"),
        );
        self.add_full(
            "_nfs._tcp",
            "Network File System",
            None,
            Some("File Server"),
        );
        self.add_full("_rfb._tcp", "Screen Sharing (VNC)", None, Some("Desktop"));
        self.add_full("_telnet._tcp", "Telnet", None, Some("Server"));
        self.add_full("_workstation._tcp", "Workstation", None, Some("Desktop"));

        // Media/Entertainment
        self.add_full(
            "_spotify-connect._tcp",
            "Spotify Connect",
            Some("Spotify"),
            Some("Speaker"),
        );
        self.add_full(
            "_nvstream_dbd._tcp",
            "NVIDIA GameStream",
            Some("NVIDIA"),
            Some("Gaming PC"),
        );

        // Smart Home / IoT
        self.add_full(
            "_hue._tcp",
            "Philips Hue",
            Some("Philips"),
            Some("Smart Light"),
        );
        self.add_full(
            "_miio._udp",
            "Xiaomi IoT",
            Some("Xiaomi"),
            Some("IoT Device"),
        );
        self.add_full(
            "_matter._tcp",
            "Matter Commissioned Device",
            None,
            Some("Smart Home Device"),
        );
        self.add_full(
            "_matter._udp",
            "Matter Operational Device",
            None,
            Some("Smart Home Device"),
        );
        self.add_full(
            "_matterc._udp",
            "Matter Commissionable Device",
            None,
            Some("Smart Home Device"),
        );

        // NAS / Storage
        self.add_full(
            "_readynas._tcp",
            "Netgear ReadyNAS",
            Some("Netgear"),
            Some("NAS"),
        );
        self.add_full(
            "_udisks-ssh._tcp",
            "Linux Disk Service",
            Some("Linux"),
            Some("NAS"),
        );

        // Network Equipment
        self.add_full(
            "_csco-sb._tcp",
            "Cisco Small Business",
            Some("Cisco"),
            Some("Router/Switch"),
        );

        // Other
        self.add_full(
            "_teamviewer._tcp",
            "TeamViewer",
            Some("TeamViewer"),
            Some("Desktop"),
        );
        self.add_full(
            "_1password4._tcp",
            "1Password Sync",
            Some("1Password"),
            Some("Desktop"),
        );
        self.add_full(
            "_privet._tcp",
            "Google Cloud Print",
            Some("Google"),
            Some("Printer"),
        );
        self.add_full("_arduino._tcp", "Arduino", None, Some("Microcontroller"));
        self.add_full("_tivo-videos._tcp", "TiVo", Some("TiVo"), Some("DVR"));
        self.add_full("_psia._tcp", "IP Camera (PSIA)", None, Some("IP Camera"));
    }

    /// Add a service to the registry (without device_type, for backward compatibility)
    pub fn add(&mut self, service_type: &str, description: &str, vendor: Option<&str>) {
        let device_type = Self::detect_device_type_from_description(description);
        self.add_full(service_type, description, vendor, device_type);
    }

    /// Adds a service to the registry with explicit vendor and device type metadata.
    pub fn add_full(
        &mut self,
        service_type: &str,
        description: &str,
        vendor: Option<&str>,
        device_type: Option<&str>,
    ) {
        let normalized = Self::normalize_service_type(service_type);
        self.services.insert(
            normalized.clone(),
            MdnsServiceInfo {
                service_type: normalized,
                description: description.to_string(),
                vendor: vendor.map(|s| s.to_string()),
                device_type: device_type.map(|s| s.to_string()),
            },
        );
    }

    /// Loads service definitions from a flat file.
    ///
    /// # Arguments
    /// * `path` - Path to the file containing service definitions.
    ///
    /// # Returns
    /// The number of services successfully loaded.
    ///
    /// # File Format
    /// `_service._tcp.local # Description of the service`
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and pure comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse format: service_type # description
            let parts: Vec<&str> = line.splitn(2, '#').collect();
            let service_type = parts[0].trim();

            if service_type.is_empty() {
                continue;
            }

            let description = if parts.len() > 1 {
                parts[1].trim().to_string()
            } else {
                service_type.to_string()
            };

            // Detect vendor and device type from description
            let vendor = Self::detect_vendor_from_description(&description);
            let device_type = Self::detect_device_type_from_description(&description);

            self.add_full(service_type, &description, vendor, device_type);
            count += 1;
        }

        Ok(count)
    }

    /// Detect device type from description text
    fn detect_device_type_from_description(description: &str) -> Option<&'static str> {
        let desc_lower = description.to_lowercase();

        for rule in DEVICE_TYPE_RULES {
            let matches_any = rule.any_patterns.is_empty()
                || rule.any_patterns.iter().any(|p| desc_lower.contains(p));
            let matches_all = rule.all_patterns.is_empty()
                || rule.all_patterns.iter().all(|p| desc_lower.contains(p));
            if matches_any && matches_all {
                return Some(rule.device_type);
            }
        }
        None
    }

    /// Detect vendor from description text
    fn detect_vendor_from_description(description: &str) -> Option<&'static str> {
        let desc_lower = description.to_lowercase();

        for rule in VENDOR_RULES {
            if rule.patterns.iter().any(|p| desc_lower.contains(p)) {
                return Some(rule.vendor);
            }
        }
        None
    }

    /// Normalize a service type (lowercase, ensure .local suffix removed)
    fn normalize_service_type(service_type: &str) -> String {
        service_type
            .to_lowercase()
            .trim_end_matches(".local")
            .to_string()
    }

    /// Looks up service metadata based on the service type string.
    pub fn lookup(&self, service_type: &str) -> Option<&MdnsServiceInfo> {
        let normalized = Self::normalize_service_type(service_type);
        self.services.get(&normalized)
    }

    /// Returns the human-readable description for a service type.
    pub fn get_description(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type).map(|s| s.description.as_str())
    }

    /// Returns the detected vendor associated with a service type.
    pub fn get_vendor(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type).and_then(|s| s.vendor.as_deref())
    }

    /// Returns the inferred device type associated with a service type.
    pub fn get_device_type(&self, service_type: &str) -> Option<&str> {
        self.lookup(service_type)
            .and_then(|s| s.device_type.as_deref())
    }

    /// Returns a reference to the internal map of registered services.
    pub fn services(&self) -> &HashMap<String, MdnsServiceInfo> {
        &self.services
    }

    /// Returns the total number of services in the registry.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

struct DeviceTypeRule {
    any_patterns: &'static [&'static str],
    all_patterns: &'static [&'static str],
    device_type: &'static str,
}

const DEVICE_TYPE_RULES: &[DeviceTypeRule] = &[
    // Streaming devices
    DeviceTypeRule {
        any_patterns: &["chromecast", "chrome cast"],
        all_patterns: &[],
        device_type: "Chromecast",
    },
    DeviceTypeRule {
        any_patterns: &["apple tv", "appletv"],
        all_patterns: &[],
        device_type: "Apple TV",
    },
    DeviceTypeRule {
        any_patterns: &["fire tv", "firetv"],
        all_patterns: &[],
        device_type: "Fire TV",
    },
    DeviceTypeRule {
        any_patterns: &["airplay"],
        all_patterns: &[],
        device_type: "Media Streamer",
    },
    DeviceTypeRule {
        any_patterns: &["android tv"],
        all_patterns: &[],
        device_type: "Android TV",
    },
    DeviceTypeRule {
        any_patterns: &["tivo"],
        all_patterns: &[],
        device_type: "DVR",
    },
    // Mobile devices
    DeviceTypeRule {
        any_patterns: &["iphone", "ipad", "ios device"],
        all_patterns: &[],
        device_type: "Apple iPhone",
    },
    DeviceTypeRule {
        any_patterns: &["mobile device"],
        all_patterns: &[],
        device_type: "Mobile Device",
    },
    // Printers & Scanners
    DeviceTypeRule {
        any_patterns: &["printer", "printing"],
        all_patterns: &[],
        device_type: "Printer",
    },
    DeviceTypeRule {
        any_patterns: &["scanner", "scanning"],
        all_patterns: &[],
        device_type: "Scanner",
    },
    // Network equipment
    DeviceTypeRule {
        any_patterns: &["router", "base station"],
        all_patterns: &[],
        device_type: "Router",
    },
    DeviceTypeRule {
        any_patterns: &["switch"],
        all_patterns: &[],
        device_type: "Router/Switch",
    },
    DeviceTypeRule {
        any_patterns: &["nas", "network attached storage", "readynas"],
        all_patterns: &[],
        device_type: "NAS",
    },
    // Smart home
    DeviceTypeRule {
        any_patterns: &[],
        all_patterns: &["homekit", "accessory"],
        device_type: "Smart Home Device",
    },
    DeviceTypeRule {
        any_patterns: &["homekit"],
        all_patterns: &[],
        device_type: "Smart Home Hub",
    },
    DeviceTypeRule {
        any_patterns: &["smart light", "hue"],
        all_patterns: &[],
        device_type: "Smart Light",
    },
    DeviceTypeRule {
        any_patterns: &["smart speaker", "speaker"],
        all_patterns: &[],
        device_type: "Speaker",
    },
    // Cameras
    DeviceTypeRule {
        any_patterns: &["camera", "ip cam"],
        all_patterns: &[],
        device_type: "IP Camera",
    },
    // Servers
    DeviceTypeRule {
        any_patterns: &["file sharing", "file server"],
        all_patterns: &[],
        device_type: "File Server",
    },
    DeviceTypeRule {
        any_patterns: &["web server", "http", "ssh", "ftp", "telnet"],
        all_patterns: &[],
        device_type: "Server",
    },
    // Development
    DeviceTypeRule {
        any_patterns: &["arduino"],
        all_patterns: &[],
        device_type: "Microcontroller",
    },
    DeviceTypeRule {
        any_patterns: &["raspberry"],
        all_patterns: &[],
        device_type: "Raspberry Pi",
    },
    DeviceTypeRule {
        any_patterns: &["jenkins"],
        all_patterns: &[],
        device_type: "CI Server",
    },
    // Desktop/Workstation
    DeviceTypeRule {
        any_patterns: &[
            "screen sharing",
            "remote desktop",
            "vnc",
            "workstation",
            "workgroup",
        ],
        all_patterns: &[],
        device_type: "Desktop",
    },
    // Media servers
    DeviceTypeRule {
        any_patterns: &["itunes", "media server", "plex"],
        all_patterns: &[],
        device_type: "Media Server",
    },
    DeviceTypeRule {
        any_patterns: &["spotify"],
        all_patterns: &[],
        device_type: "Speaker",
    },
    // Gaming
    DeviceTypeRule {
        any_patterns: &["gamestream", "nvidia shield"],
        all_patterns: &[],
        device_type: "Gaming Device",
    },
];

struct VendorRule {
    patterns: &'static [&'static str],
    vendor: &'static str,
}

const VENDOR_RULES: &[VendorRule] = &[
    VendorRule {
        patterns: &["apple", "osx", "itunes", "iphone", "ipad"],
        vendor: "Apple",
    },
    VendorRule {
        patterns: &["google", "chrome", "android"],
        vendor: "Google",
    },
    VendorRule {
        patterns: &["amazon", "fire tv", "alexa"],
        vendor: "Amazon",
    },
    VendorRule {
        patterns: &["samsung"],
        vendor: "Samsung",
    },
    VendorRule {
        patterns: &["nvidia"],
        vendor: "NVIDIA",
    },
    VendorRule {
        patterns: &["hp"],
        vendor: "HP",
    },
    VendorRule {
        patterns: &["canon"],
        vendor: "Canon",
    },
    VendorRule {
        patterns: &["ubuntu", "linux", "raspberry"],
        vendor: "Linux",
    },
    VendorRule {
        patterns: &["cisco"],
        vendor: "Cisco",
    },
    VendorRule {
        patterns: &["netgear"],
        vendor: "Netgear",
    },
];

// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use rusqlite::{Connection, params};

use crate::device::{DeviceInfo, normalize_device_identifier, sanitize_hostname};
use crate::oui::OuiRegistry;
use crate::types::{DHCPV4_CLIENT_PORT, Dhcpv4Packet, Dhcpv6Packet};

#[cfg(feature = "mdns")]
use crate::mdns_registry::MdnsServiceRegistry;
#[cfg(feature = "mdns")]
use crate::parser::mdns::{MdnsPacket, MdnsRecordDataView, NbnsPacket};

#[cfg(feature = "ssdp")]
use crate::parser::ssdp::{SsdpPacket, WsdPacket};
#[cfg(feature = "ssdp")]
use crate::types::{CdpPacket, LldpPacket};

// Imports from dhcp parser module for helper functions
use crate::parser::dhcp::{extract_mac_from_duid, format_duid_identifier};

fn is_confirmed_phone(hostname: Option<&str>) -> bool {
    let Some(h) = hostname else {
        return false;
    };
    let h = h.to_lowercase();
    h.contains("moto")
        || h.contains("stylus")
        || h.contains("motorola")
        || h.contains("samsung")
        || h.contains("galaxy")
        || h.contains("pixel")
        || h.contains("iphone")
        || h.contains("ipad")
}

/// Device tracker that maintains a list of seen devices and saves to SQLite
pub struct DeviceTracker {
    pub(crate) devices: HashMap<String, DeviceInfo>,
    pub(crate) db_path: String,
    pub(crate) auto_save: bool,
    /// OUI registry for MAC address vendor lookup
    pub(crate) oui_registry: Option<OuiRegistry>,
    #[cfg(feature = "mdns")]
    pub(crate) service_registry: Option<MdnsServiceRegistry>,
    /// Track updated MAC addresses for incremental journal flushes
    pub(crate) dirty_devices: Mutex<HashSet<String>>,
    /// SQLite database connection
    pub(crate) conn: Mutex<Connection>,
}

impl DeviceTracker {
    /// Creates a new device tracker, loading existing data from the specified SQLite database file.
    ///
    /// # Arguments
    /// * `db_path` - The path to the database file used for persistence.
    pub fn new<P: AsRef<Path>>(db_path: P) -> std::io::Result<Self> {
        let db_path_str = db_path.as_ref().to_string_lossy().to_string();

        let conn = Connection::open(&db_path_str)
            .map_err(|e| std::io::Error::other(format!("Failed to open SQLite database: {}", e)))?;

        // Enable WAL mode and normal synchronous writes
        let _ = conn.execute("PRAGMA journal_mode = WAL;", []);
        let _ = conn.execute("PRAGMA synchronous = NORMAL;", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                ipv6_address TEXT,
                ipv6_addresses TEXT,
                hostname TEXT,
                system_description TEXT,
                services TEXT,
                vendor TEXT,
                device_type TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );",
            [],
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create SQLite schema: {}", e)))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);",
            [],
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create SQLite index: {}", e)))?;

        let mut tracker = Self {
            devices: HashMap::new(),
            db_path: db_path_str,
            auto_save: true,
            oui_registry: None,
            #[cfg(feature = "mdns")]
            service_registry: None,
            dirty_devices: Mutex::new(HashSet::new()),
            conn: Mutex::new(conn),
        };

        tracker.load_from_db()?;

        Ok(tracker)
    }

    /// Sets the OUI registry used to identify device manufacturers from MAC addresses.
    pub fn set_oui_registry(&mut self, registry: OuiRegistry) {
        self.oui_registry = Some(registry);
    }

    /// Returns a reference to the active OUI registry, if set.
    pub fn oui_registry(&self) -> Option<&OuiRegistry> {
        self.oui_registry.as_ref()
    }

    /// Sets the mDNS service registry used for fingerprinting devices based on their services.
    #[cfg(feature = "mdns")]
    pub fn set_service_registry(&mut self, registry: MdnsServiceRegistry) {
        self.service_registry = Some(registry);
    }

    /// Returns a reference to the active mDNS service registry, if set.
    #[cfg(feature = "mdns")]
    pub fn service_registry(&self) -> Option<&MdnsServiceRegistry> {
        self.service_registry.as_ref()
    }

    /// Re-evaluates classification (device_type, vendor) for all loaded devices
    /// using current hostname rules, OUI registry, and mDNS service registry.
    pub fn reclassify_all(&mut self) {
        let mut changed_devices = Vec::new();

        for device in self.devices.values_mut() {
            let mut changed = false;

            // 1. Hostname-based vendor & type
            let hostname_vendor = Self::detect_vendor_from_hostname(device.hostname.as_deref());
            let hostname_device_type =
                Self::detect_device_type_from_hostname(device.hostname.as_deref());

            // 2. OUI-based vendor
            let mut oui_vendor = None;
            if let Some(registry) = &self.oui_registry {
                oui_vendor = registry.lookup(&device.mac_address);
            }

            // 3. mDNS service-based type
            #[cfg(feature = "mdns")]
            let service_device_type = if let Some(registry) = &self.service_registry {
                let services_slice: Vec<&str> =
                    device.services.iter().map(|s| s.as_str()).collect();
                let mut detected = None;
                for s in services_slice {
                    if let Some(dt) = registry.get_device_type(s) {
                        detected = Some(dt.to_string());
                        break;
                    }
                }
                if let Some(dt) = &detected {
                    if is_confirmed_phone(device.hostname.as_deref()) {
                        let dt_lower = dt.to_lowercase();
                        if !dt_lower.contains("phone")
                            && !dt_lower.contains("iphone")
                            && !dt_lower.contains("mobile")
                            && !dt_lower.contains("tablet")
                        {
                            detected = None;
                        }
                    }
                }
                detected
            } else {
                None
            };
            #[cfg(not(feature = "mdns"))]
            let service_device_type: Option<String> = None;

            // Re-evaluate device type
            let incoming_type =
                service_device_type.or_else(|| hostname_device_type.map(|t| t.to_string()));

            if let Some(t) = incoming_type {
                if device.device_type.as_deref() != Some(&t) {
                    if Self::should_replace_device_type(device, &t) {
                        device.device_type = Some(t);
                        changed = true;
                    }
                }
            }

            // Re-evaluate vendor
            let incoming_vendor = hostname_vendor
                .map(|v| v.to_string())
                .or_else(|| oui_vendor.map(|v| v.to_string()));

            if let Some(v) = incoming_vendor {
                if device.vendor.as_deref() != Some(&v) {
                    if Self::should_replace_vendor(device.vendor.as_deref(), &v, oui_vendor) {
                        device.vendor = Some(v);
                        changed = true;
                    }
                }
            }

            if changed {
                changed_devices.push(device.mac_address.clone());
            }
        }

        // Mark changed devices as dirty to trigger DB saving
        if !changed_devices.is_empty() {
            {
                let mut dirty = self.dirty_devices.lock().unwrap();
                for mac in changed_devices {
                    dirty.insert(mac);
                }
            } // Lock is dropped here

            // If auto-save is enabled, flush changes
            if self.auto_save {
                let _ = self.save_to_db();
            }
        }
    }

    /// Load devices from existing SQLite database file
    fn load_from_db(&mut self) -> std::io::Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT mac_address, ip_address, ipv6_address, ipv6_addresses, hostname,
                    system_description, services, vendor, device_type, first_seen, last_seen
             FROM devices;",
            )
            .map_err(std::io::Error::other)?;

        let device_iter = stmt
            .query_map([], |row| {
                let mac_address: String = row.get(0)?;
                let ip_address_str: String = row.get(1)?;
                let ipv6_address_str: Option<String> = row.get(2)?;
                let ipv6_addresses_str: Option<String> = row.get(3)?;
                let hostname: Option<String> = row.get(4)?;
                let system_description: Option<String> = row.get(5)?;
                let services_str: Option<String> = row.get(6)?;
                let vendor: Option<String> = row.get(7)?;
                let device_type: Option<String> = row.get(8)?;
                let first_seen_str: String = row.get(9)?;
                let last_seen_str: String = row.get(10)?;

                let ip_address: IpAddr = ip_address_str
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let ipv6_address: Option<IpAddr> = ipv6_address_str.and_then(|s| s.parse().ok());
                let mut ipv6_addresses = Vec::new();
                if let Some(s) = ipv6_addresses_str {
                    for ip in s.split(';') {
                        if let Ok(ipv6) = ip.parse() {
                            ipv6_addresses.push(ipv6);
                        }
                    }
                }

                let mut services = Vec::new();
                if let Some(s) = services_str {
                    for service in s.split(';') {
                        if !service.is_empty() {
                            services.push(service.to_string());
                        }
                    }
                }

                let first_seen =
                    crate::device::parse_timestamp(&first_seen_str).unwrap_or_else(SystemTime::now);
                let last_seen =
                    crate::device::parse_timestamp(&last_seen_str).unwrap_or_else(SystemTime::now);

                Ok(DeviceInfo {
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
            })
            .map_err(std::io::Error::other)?;

        for device in device_iter.flatten() {
            self.devices.insert(device.mac_address.clone(), device);
        }

        Ok(())
    }

    /// Persists all current device information to the SQLite database file.
    pub fn save_to_db(&self) -> std::io::Result<()> {
        let dirty = {
            let mut guard = self.dirty_devices.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        if dirty.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| std::io::Error::other(format!("Failed to start transaction: {}", e)))?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO devices (
                    mac_address, ip_address, ipv6_address, ipv6_addresses, hostname,
                    system_description, services, vendor, device_type, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    ipv6_address = excluded.ipv6_address,
                    ipv6_addresses = excluded.ipv6_addresses,
                    hostname = excluded.hostname,
                    system_description = excluded.system_description,
                    services = excluded.services,
                    vendor = excluded.vendor,
                    device_type = excluded.device_type,
                    last_seen = excluded.last_seen;",
                )
                .map_err(std::io::Error::other)?;

            for mac in &dirty {
                if let Some(device) = self.devices.get(mac) {
                    let ip_address = device.ip_address.to_string();
                    let ipv6_address = device.ipv6_address.map(|ip| ip.to_string());
                    let ipv6_addresses = device
                        .ipv6_addresses
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(";");
                    let services = device.services.join(";");
                    let first_seen = crate::device::format_timestamp(device.first_seen);
                    let last_seen = crate::device::format_timestamp(device.last_seen);

                    stmt.execute(params![
                        device.mac_address,
                        ip_address,
                        ipv6_address,
                        ipv6_addresses,
                        device.hostname,
                        device.system_description,
                        services,
                        device.vendor,
                        device.device_type,
                        first_seen,
                        last_seen,
                    ])
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "Failed to insert device {}: {}",
                            device.mac_address, e
                        ))
                    })?;
                }
            }
        }

        tx.commit()
            .map_err(|e| std::io::Error::other(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }

    /// Enable or disable automatic writes on each update.
    pub fn set_auto_save(&mut self, enabled: bool) {
        self.auto_save = enabled;
    }

    /// Explicitly flushes the current in-memory device state to the database file.
    pub fn flush_to_db(&self) -> std::io::Result<()> {
        self.save_to_db()
    }

    /// Returns a vector of all tracked devices pre-sorted by `last_seen` descending from the SQL database.
    pub fn get_devices_sorted(&self) -> Vec<DeviceInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT mac_address, ip_address, ipv6_address, ipv6_addresses, hostname,
                    system_description, services, vendor, device_type, first_seen, last_seen
             FROM devices
             ORDER BY last_seen DESC;",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let device_iter = match stmt.query_map([], |row| {
            let mac_address: String = row.get(0)?;
            let ip_address_str: String = row.get(1)?;
            let ipv6_address_str: Option<String> = row.get(2)?;
            let ipv6_addresses_str: Option<String> = row.get(3)?;
            let hostname: Option<String> = row.get(4)?;
            let system_description: Option<String> = row.get(5)?;
            let services_str: Option<String> = row.get(6)?;
            let vendor: Option<String> = row.get(7)?;
            let device_type: Option<String> = row.get(8)?;
            let first_seen_str: String = row.get(9)?;
            let last_seen_str: String = row.get(10)?;

            let ip_address: IpAddr = ip_address_str
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let ipv6_address: Option<IpAddr> = ipv6_address_str.and_then(|s| s.parse().ok());
            let mut ipv6_addresses = Vec::new();
            if let Some(s) = ipv6_addresses_str {
                for ip in s.split(';') {
                    if let Ok(ipv6) = ip.parse() {
                        ipv6_addresses.push(ipv6);
                    }
                }
            }

            let mut services = Vec::new();
            if let Some(s) = services_str {
                for service in s.split(';') {
                    if !service.is_empty() {
                        services.push(service.to_string());
                    }
                }
            }

            let first_seen =
                crate::device::parse_timestamp(&first_seen_str).unwrap_or_else(SystemTime::now);
            let last_seen =
                crate::device::parse_timestamp(&last_seen_str).unwrap_or_else(SystemTime::now);

            Ok(DeviceInfo {
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
        }) {
            Ok(it) => it,
            Err(_) => return Vec::new(),
        };

        let mut list = Vec::new();
        for device in device_iter.flatten() {
            list.push(device);
        }
        list
    }

    /// Updates the tracker state with information extracted from a DHCPv4 packet.
    ///
    /// # Returns
    /// `true` if a new device was detected or an existing device was significantly updated
    /// (IP change, hostname change, etc.).
    pub fn update_from_dhcpv4(&mut self, packet: &Dhcpv4Packet) -> bool {
        let mac = packet.client_mac_string();

        // Determine client IP address.
        // Prefer DHCP client/assigned fields parsed into requested_ip; avoid treating
        // server source IP (port 67) as client identity.
        let ip = packet.requested_ip.map(IpAddr::V4).unwrap_or_else(|| {
            if packet.source_port == DHCPV4_CLIENT_PORT
                && packet.source_ip != Ipv4Addr::new(0, 0, 0, 0)
            {
                IpAddr::V4(packet.source_ip)
            } else if packet.dest_port == DHCPV4_CLIENT_PORT
                && packet.dest_ip != Ipv4Addr::new(0, 0, 0, 0)
                && packet.dest_ip != Ipv4Addr::new(255, 255, 255, 255)
            {
                IpAddr::V4(packet.dest_ip)
            } else {
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
            }
        });

        let mut changed = self.update_device(&mac, ip, packet.hostname.as_deref());

        // Apply Option 55, 60, and 43 fingerprints if present
        if (packet.parameter_request_list.is_some()
            || packet.vendor_class_id.is_some()
            || packet.vendor_specific_info.is_some())
            && let Some(device) = self.devices.get_mut(&mac)
        {
            let mut opt_vendor = None;
            let mut opt_type = None;

            if let Some(ref vc) = packet.vendor_class_id {
                let (v, t) = Self::detect_device_details_from_dhcp_vendor_class(vc);
                opt_vendor = v;
                opt_type = t;
            }

            if let Some(ref vsi) = packet.vendor_specific_info {
                let vsi_lower = vsi.to_lowercase();
                let inferred_vendor = if vsi_lower.contains("ubnt") || vsi_lower.contains("unifi") {
                    Some("Ubiquiti")
                } else if vsi_lower.contains("yealink") {
                    Some("Yealink")
                } else if vsi_lower.contains("polycom") {
                    Some("Polycom")
                } else if vsi_lower.contains("cisco") {
                    Some("Cisco")
                } else if vsi_lower.contains("mitel") {
                    Some("Mitel")
                } else if vsi_lower.contains("avaya") {
                    Some("Avaya")
                } else {
                    None
                };
                if let Some(vendor) = inferred_vendor {
                    if opt_vendor.is_none() {
                        opt_vendor = Some(vendor);
                    }
                    if opt_type.is_none() {
                        if vendor == "Ubiquiti" {
                            opt_type = Some("Network Device");
                        } else if vendor == "Yealink"
                            || vendor == "Polycom"
                            || vendor == "Mitel"
                            || vendor == "Avaya"
                        {
                            opt_type = Some("IP Phone");
                        }
                    }
                }
            }

            if (opt_vendor.is_none() || opt_type.is_none())
                && let Some(ref prl) = packet.parameter_request_list
            {
                let (v, t) = Self::detect_device_details_from_dhcp_options(prl);
                if opt_vendor.is_none() {
                    opt_vendor = v;
                }
                if opt_type.is_none() {
                    opt_type = t;
                }
            }

            let mut local_changed = false;
            if let Some(v) = opt_vendor
                && (device.vendor.is_none()
                    || (device.vendor.as_deref() != Some(v)
                        && device
                            .vendor
                            .as_deref()
                            .map(|ov| ov.eq_ignore_ascii_case("eero inc."))
                            == Some(true)))
            {
                device.vendor = Some(v.to_string());
                local_changed = true;
            }
            if let Some(t) = opt_type
                && device.device_type.is_none()
            {
                device.device_type = Some(t.to_string());
                local_changed = true;
            }
            if local_changed {
                self.dirty_devices.lock().unwrap().insert(mac.clone());
                changed = true;
                if self.auto_save {
                    let _ = self.save_to_db();
                }
            }
        }

        changed
    }

    /// Helper for fingerprinting DHCPv6 packet values
    fn fingerprint_dhcpv6(
        enterprise_number: Option<u32>,
        data_strings: &[String],
    ) -> (Option<&'static str>, Option<&'static str>) {
        let mut vendor = None;
        let mut device_type = None;

        if let Some(ent) = enterprise_number {
            match ent {
                311 => vendor = Some("Microsoft"),
                9 => {
                    vendor = Some("Cisco");
                    device_type = Some("Network Device");
                }
                93 | 3247 => vendor = Some("Apple"),
                _ => {}
            }
        }

        for s in data_strings {
            let owned;
            let lower = if s.bytes().any(|b| b.is_ascii_uppercase()) {
                owned = s.to_ascii_lowercase();
                owned.as_str()
            } else {
                s.as_str()
            };
            if lower.contains("android") {
                vendor = Some("Google");
                device_type = Some("Mobile");
            } else if lower.contains("apple") {
                vendor = Some("Apple");
            } else if lower.contains("sonos") {
                vendor = Some("Sonos");
                device_type = Some("Audio Device");
            } else if lower.contains("msft") || lower.contains("microsoft") {
                vendor = Some("Microsoft");
            } else if lower.contains("cisco") {
                vendor = Some("Cisco");
                device_type = Some("Network Device");
            }
        }

        (vendor, device_type)
    }

    /// Updates the tracker state with information extracted from a DHCPv6 packet.
    ///
    /// # Returns
    /// `true` if a new device was detected or an existing device was updated.
    pub fn update_from_dhcpv6(&mut self, packet: &Dhcpv6Packet) -> bool {
        // For DHCPv6, use Ethernet MAC from DUID-LL/LLT when available.
        // Fall back to a prefixed DUID identifier for non-Ethernet DUID types.
        let mut client_id = None;
        let mut fqdn = None;
        let mut user_class = None;
        let mut vendor_class = None;

        for option in &packet.options {
            match option {
                crate::types::Dhcpv6Option::ClientId(data) => {
                    client_id = Some(data.as_slice());
                }
                crate::types::Dhcpv6Option::ClientFqdn(name) => {
                    fqdn = Some(name.as_str());
                }
                crate::types::Dhcpv6Option::UserClass(classes) => {
                    user_class = Some(classes);
                }
                crate::types::Dhcpv6Option::VendorClass {
                    enterprise_number,
                    data,
                } => {
                    vendor_class = Some((*enterprise_number, data));
                }
                _ => {}
            }
        }

        // If no client-id, we can't track this device
        let mac = match client_id {
            Some(data) => {
                extract_mac_from_duid(data).unwrap_or_else(|| format_duid_identifier(data))
            }
            None => return false,
        };

        let ip = IpAddr::V6(packet.source_ip);
        let mut changed = self.update_device(&mac, ip, fqdn);

        // Apply Option 15 and 16 fingerprints if present
        let mut opt_vendor = None;
        let mut opt_type = None;

        if let Some((ent, data)) = vendor_class {
            let (v, t) = Self::fingerprint_dhcpv6(Some(ent), data);
            if opt_vendor.is_none() {
                opt_vendor = v;
            }
            if opt_type.is_none() {
                opt_type = t;
            }
        }

        if let Some(data) = user_class {
            let (v, t) = Self::fingerprint_dhcpv6(None, data);
            if opt_vendor.is_none() {
                opt_vendor = v;
            }
            if opt_type.is_none() {
                opt_type = t;
            }
        }

        if (opt_vendor.is_some() || opt_type.is_some())
            && let Some(device) = self.devices.get_mut(&mac)
        {
            let mut local_changed = false;
            if let Some(v) = opt_vendor
                && (device.vendor.is_none() || device.vendor.as_deref() != Some(v))
            {
                device.vendor = Some(v.to_string());
                local_changed = true;
            }
            if let Some(t) = opt_type
                && (device.device_type.is_none() || device.device_type.as_deref() != Some(t))
            {
                device.device_type = Some(t.to_string());
                local_changed = true;
            }
            if local_changed {
                self.dirty_devices.lock().unwrap().insert(mac.clone());
                changed = true;
                if self.auto_save {
                    let _ = self.save_to_db();
                }
            }
        }

        changed
    }

    /// Updates or inserts a device in the tracker using information from an LLDP packet.
    ///
    /// Returns `true` if the device's information was updated or if a new device was added.
    #[cfg(feature = "ssdp")]
    pub fn update_from_lldp(&mut self, packet: &LldpPacket) -> bool {
        let mac = &packet.source_mac;
        let mut ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        if let Some(m_addr) = packet.management_address {
            ip = m_addr;
        }

        let mut changed = self.update_device(mac, ip, packet.system_name.as_deref());

        if let Some(device) = self.devices.get_mut(mac) {
            let mut local_changed = false;

            if let Some(ref desc) = packet.system_description {
                if device.system_description.as_ref() != Some(desc) {
                    device.system_description = Some(desc.clone());
                    local_changed = true;
                }

                let owned_desc;
                let desc_lower = if desc.bytes().any(|b| b.is_ascii_uppercase()) {
                    owned_desc = desc.to_ascii_lowercase();
                    owned_desc.as_str()
                } else {
                    desc.as_str()
                };
                let inferred_vendor = if desc_lower.contains("cisco") {
                    Some("Cisco")
                } else if desc_lower.contains("hp") || desc_lower.contains("procurve") {
                    Some("HP")
                } else if desc_lower.contains("juniper") {
                    Some("Juniper")
                } else if desc_lower.contains("ubiquiti") || desc_lower.contains("unifi") {
                    Some("Ubiquiti")
                } else if desc_lower.contains("eero") {
                    Some("eero inc.")
                } else {
                    None
                };

                if let Some(vendor) = inferred_vendor {
                    if device.vendor.as_deref() != Some(vendor) {
                        device.vendor = Some(vendor.to_string());
                        local_changed = true;
                    }

                    let dtype = if vendor == "eero inc." {
                        "Router"
                    } else {
                        "Network Device"
                    };

                    if device.device_type.as_deref() != Some("Switch")
                        && device.device_type.as_deref() != Some("Router")
                    {
                        device.device_type = Some(dtype.to_string());
                        local_changed = true;
                    }
                }
            }

            if device.device_type.is_none() {
                device.device_type = Some("Network Device".to_string());
                local_changed = true;
            }

            if local_changed {
                self.dirty_devices.lock().unwrap().insert(mac.clone());
                changed = true;
                if self.auto_save {
                    let _ = self.save_to_db();
                }
            }
        }

        changed
    }

    /// Updates or inserts a device in the tracker using information from a CDP packet.
    ///
    /// Returns `true` if the device's information was updated or if a new device was added.
    #[cfg(feature = "ssdp")]
    pub fn update_from_cdp(&mut self, packet: &CdpPacket) -> bool {
        let mac = &packet.source_mac;
        let mut ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        if let Some(m_addr) = packet.management_address {
            ip = m_addr;
        }

        let hostname = packet.device_id.as_deref();
        let mut changed = self.update_device(mac, ip, hostname);

        if let Some(device) = self.devices.get_mut(mac) {
            let mut local_changed = false;

            if let Some(ref soft) = packet.software_version {
                let current_desc = device.system_description.as_ref();
                if current_desc != Some(soft) {
                    device.system_description = Some(soft.clone());
                    local_changed = true;
                }
            }

            if device.vendor.as_deref() != Some("Cisco") {
                device.vendor = Some("Cisco".to_string());
                local_changed = true;
            }

            let mut dtype = "Network Device";
            if let Some(ref plat) = packet.platform {
                let owned_plat;
                let plat_lower = if plat.bytes().any(|b| b.is_ascii_uppercase()) {
                    owned_plat = plat.to_ascii_lowercase();
                    owned_plat.as_str()
                } else {
                    plat.as_str()
                };
                if plat_lower.contains("ip phone") {
                    dtype = "IP Phone";
                } else if plat_lower.contains("switch")
                    || plat_lower.contains("ws-c")
                    || plat_lower.contains("catalyst")
                    || plat_lower.contains("nexus")
                {
                    dtype = "Switch";
                } else if plat_lower.contains("router") {
                    dtype = "Router";
                }
            }

            if device.device_type.as_deref() != Some(dtype) {
                device.device_type = Some(dtype.to_string());
                local_changed = true;
            }

            if local_changed {
                self.dirty_devices.lock().unwrap().insert(mac.clone());
                changed = true;
                if self.auto_save {
                    let _ = self.save_to_db();
                }
            }
        }

        changed
    }

    /// Updates the tracker state with hostnames, IP addresses, and services from an mDNS packet.
    ///
    /// # Returns
    /// The count of unique updates applied across all detected devices.
    #[cfg(feature = "mdns")]
    pub fn update_from_mdns(&mut self, packet: &MdnsPacket) -> usize {
        let packet = packet.view();

        // 1. Target MAC resolution logic to handle proxying/relaying (e.g. from Eero routers)
        let mut advertised_ips = Vec::new();
        for record in packet.all_records() {
            match &record.data {
                MdnsRecordDataView::A(addr) => {
                    advertised_ips.push(IpAddr::V4(*addr));
                }
                MdnsRecordDataView::Aaaa(addr) => {
                    advertised_ips.push(IpAddr::V6(*addr));
                }
                _ => {}
            }
        }

        let target_mac = if advertised_ips.is_empty() {
            Some(packet.source_mac.to_string())
        } else {
            let directly_from_host = advertised_ips.contains(&packet.source_ip);
            if directly_from_host {
                Some(packet.source_mac.to_string())
            } else {
                // Relayed/proxied packet: try to find an existing device matching any of the advertised IPs
                let mut resolved = None;
                for ip in &advertised_ips {
                    let found = self.devices.values().find(|d| {
                        d.ip_address == *ip
                            || match ip {
                                IpAddr::V4(_) => false,
                                IpAddr::V6(ipv6) => d.ipv6_addresses.contains(ipv6),
                            }
                    });
                    if let Some(dev) = found {
                        resolved = Some(dev.mac_address.clone());
                        break;
                    }
                }
                resolved
            }
        };

        // If target_mac cannot be resolved, skip processing to avoid polluting the router's entry
        let target_mac = match target_mac {
            Some(m) => m,
            None => return 0,
        };

        let mut updated = 0;
        let oui_vendor = self
            .oui_registry
            .as_ref()
            .and_then(|registry| registry.lookup(&target_mac))
            .map(str::to_string);

        // Track the first hostname and addresses seen (defer String allocation)
        let mut first_hostname: Option<&str> = None;
        let mut first_ipv4: Option<std::net::Ipv4Addr> = None;
        let mut first_ipv6: Option<std::net::Ipv6Addr> = None;
        // Collect services advertised by this device
        let mut services: Vec<&str> = Vec::new();
        let mut seen_services: HashSet<&str> = HashSet::new();
        let mut txt_attrs = HashMap::new();

        for record in packet.all_records() {
            match &record.data {
                MdnsRecordDataView::A(addr) => {
                    // Strip .local suffix for hostname and record first IPv4
                    let hostname = record.name.trim_end_matches(".local");
                    if first_hostname.is_none() {
                        first_hostname = Some(hostname);
                    }
                    if first_ipv4.is_none() {
                        first_ipv4 = Some(*addr);
                    }
                }
                MdnsRecordDataView::Aaaa(addr) => {
                    let hostname = record.name.trim_end_matches(".local");
                    if first_hostname.is_none() {
                        first_hostname = Some(hostname);
                    }
                    if first_ipv6.is_none() {
                        first_ipv6 = Some(*addr);
                    }
                }
                MdnsRecordDataView::Ptr(_target) => {
                    // PTR records indicate service advertisements
                    let service_type = record.name.trim_end_matches(".local");
                    if service_type.starts_with('_') && seen_services.insert(service_type) {
                        services.push(service_type);
                    }
                }
                MdnsRecordDataView::Srv { .. } => {
                    // SRV records also indicate services
                    if let Some(service_start) = record.name.find("._") {
                        let service_type =
                            record.name[service_start + 1..].trim_end_matches(".local");
                        if seen_services.insert(service_type) {
                            services.push(service_type);
                        }
                    }
                }
                MdnsRecordDataView::Txt(strings) => {
                    for s in strings {
                        if let Some(eq_idx) = s.find('=') {
                            let key = s[..eq_idx].trim().to_ascii_lowercase();
                            let val = s[eq_idx + 1..].trim();
                            if !val.is_empty() {
                                txt_attrs.insert(key, val);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Extract IoT-specific metadata (Matter, HAP)
        let iot_meta = crate::parser::iot::extract_iot_metadata(&services, &txt_attrs);

        let mut txt_vendor = iot_meta.vendor.clone();
        let mut txt_device_type = iot_meta.device_type.clone();
        let txt_model = iot_meta.model.clone();

        if txt_vendor.is_none()
            && txt_device_type.is_none()
            && let Some(model) = txt_attrs
                .get("model")
                .or_else(|| txt_attrs.get("md"))
                .or_else(|| txt_attrs.get("ty"))
        {
            let owned_m;
            let m = if model.bytes().any(|b| b.is_ascii_uppercase()) {
                owned_m = model.to_ascii_lowercase();
                owned_m.as_str()
            } else {
                model
            };
            if m.contains("appletv") || m.contains("apple tv") {
                txt_vendor = Some("Apple".to_string());
                txt_device_type = Some("Apple TV".to_string());
            } else if m.contains("macbook")
                || m.contains("imac")
                || m.contains("macmini")
                || m.contains("macpro")
            {
                txt_vendor = Some("Apple".to_string());
                txt_device_type = Some("Mac".to_string());
            } else if m.contains("chromecast") {
                txt_vendor = Some("Google".to_string());
                txt_device_type = Some("Media Player".to_string());
            } else if m.contains("hp ")
                || m.contains("laserjet")
                || m.contains("officejet")
                || m.contains("deskjet")
            {
                txt_vendor = Some("HP".to_string());
                txt_device_type = Some("Printer".to_string());
            } else if m.contains("epson") {
                txt_vendor = Some("Epson".to_string());
                txt_device_type = Some("Printer".to_string());
            } else if m.contains("canon") {
                txt_vendor = Some("Canon".to_string());
                txt_device_type = Some("Printer".to_string());
            } else if m.contains("brother") {
                txt_vendor = Some("Brother".to_string());
                txt_device_type = Some("Printer".to_string());
            } else if m.contains("sonos") {
                txt_vendor = Some("Sonos".to_string());
                txt_device_type = Some("Smart Speaker".to_string());
            }
        }

        // Determine vendor and device type from services and hostname (before borrowing device)
        let vendor = Self::detect_vendor_from_hostname(first_hostname)
            .map(str::to_string)
            .or_else(|| txt_vendor.clone())
            .or_else(|| self.detect_vendor_from_services(&services));
        let device_type = Self::detect_device_type_from_hostname(first_hostname)
            .map(str::to_string)
            .or_else(|| txt_device_type.clone())
            .or_else(|| self.detect_device_type_from_services(&services));

        let ipv6_addr = first_ipv6;

        // Get or create device entry and perform updates within a short scope
        {
            let device = self
                .devices
                .entry(target_mac.to_string())
                .or_insert_with(|| {
                    let ip = first_ipv4.map(IpAddr::V4).unwrap_or(packet.source_ip);
                    updated += 1;
                    DeviceInfo::new(target_mac.to_string(), ip, None)
                });

            // Update hostname from the first seen A/AAAA
            if device.hostname.is_none()
                && let Some(h) = first_hostname
            {
                device.hostname = Some(h.to_string());
                updated += 1;
            }

            // Update IPv4 if we have a better one
            if let Some(ipv4) = first_ipv4
                && matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified())
            {
                device.ip_address = IpAddr::V4(ipv4);
                updated += 1;
            }

            // Set IPv6 address if available
            if let Some(ipv6) = ipv6_addr
                && device.set_ipv6_address(ipv6)
            {
                updated += 1;
            }

            // Add services
            for service in &services {
                if device.add_service(service) {
                    updated += 1;
                }
            }

            // Set vendor if detected (or fall back to OUI vendor)
            let vendor_to_apply = vendor.or_else(|| oui_vendor.clone());
            if let Some(v) = vendor_to_apply
                && Self::should_replace_vendor(device.vendor.as_deref(), &v, oui_vendor.as_deref())
            {
                // Protect Eero devices from being overwritten by other vendors
                let is_eero = first_hostname
                    .map(|h| h.to_ascii_lowercase().contains("eero"))
                    .unwrap_or(false)
                    || device
                        .hostname
                        .as_deref()
                        .map(|h| h.to_ascii_lowercase().contains("eero"))
                        .unwrap_or(false)
                    || device
                        .vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false)
                    || oui_vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false);
                if !is_eero || v.eq_ignore_ascii_case("eero inc.") {
                    if device.vendor.as_deref() != Some(&v) {
                        device.vendor = Some(v.clone());
                    }
                    updated += 1;
                }
            }

            // Set device type if detected
            let mut dt_to_apply = device_type.clone();
            if let Some(ref dt) = dt_to_apply {
                let effective_hostname = first_hostname.or(device.hostname.as_deref());
                if is_confirmed_phone(effective_hostname) {
                    let dt_lower = dt.to_lowercase();
                    if !dt_lower.contains("phone")
                        && !dt_lower.contains("iphone")
                        && !dt_lower.contains("mobile")
                        && !dt_lower.contains("tablet")
                    {
                        dt_to_apply = None;
                    }
                }
            }

            if let Some(t) = dt_to_apply
                && Self::should_replace_device_type(device, &t)
            {
                // Protect Eero devices from being overwritten by other device types
                let is_eero = first_hostname
                    .map(|h| h.to_ascii_lowercase().contains("eero"))
                    .unwrap_or(false)
                    || device
                        .hostname
                        .as_deref()
                        .map(|h| h.to_ascii_lowercase().contains("eero"))
                        .unwrap_or(false)
                    || device
                        .vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false)
                    || oui_vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false);
                if !is_eero || t.eq_ignore_ascii_case("Router") {
                    if device.device_type.as_deref() != Some(&t) {
                        device.device_type = Some(t.clone());
                    }
                    updated += 1;
                }
            }

            // Set system description if IoT model is present
            if let Some(ref desc) = txt_model {
                // Protect Eero devices from being overwritten by other system descriptions
                let is_eero = first_hostname
                    .map(|h| h.to_ascii_lowercase().contains("eero"))
                    .unwrap_or(false)
                    || device
                        .hostname
                        .as_deref()
                        .map(|h| h.to_ascii_lowercase().contains("eero"))
                        .unwrap_or(false)
                    || device
                        .vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false)
                    || oui_vendor
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("eero inc."))
                        .unwrap_or(false);
                if (!is_eero || desc.to_ascii_lowercase().contains("eero"))
                    && device.system_description.as_ref() != Some(desc)
                {
                    device.system_description = Some(desc.clone());
                    updated += 1;
                }
            }

            // Update timestamp
            device.last_seen = SystemTime::now();
        }

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        self.dirty_devices
            .lock()
            .unwrap()
            .insert(target_mac.to_string());

        updated
    }

    /// Updates the tracker state with information extracted from an LLMNR packet.
    ///
    /// # Returns
    /// Number of updated/added devices.
    #[cfg(feature = "mdns")]
    pub fn update_from_llmnr(&mut self, packet: &MdnsPacket) -> usize {
        self.update_from_mdns(packet)
    }

    /// Updates the tracker state with information extracted from a NetBIOS Name Service (NBNS) packet.
    ///
    /// # Returns
    /// Number of updated/added devices.
    #[cfg(feature = "mdns")]
    pub fn update_from_nbns(&mut self, packet: &NbnsPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let hostname = Some(packet.name.as_str());
        let mut vendor = Self::detect_vendor_from_hostname(hostname).map(str::to_string);
        let mut device_type = Self::detect_device_type_from_hostname(hostname).map(str::to_string);

        // Customize vendor/device type based on NetBIOS specific suffix rules
        if packet.suffix == 0x20 && device_type.is_none() {
            device_type = Some("File Server".to_string());
        }
        let contains_samba = if packet.name.bytes().any(|b| b.is_ascii_uppercase()) {
            packet.name.to_ascii_lowercase().contains("samba")
        } else {
            packet.name.contains("samba")
        };
        if contains_samba {
            if vendor.is_none() {
                vendor = Some("Linux".to_string());
            }
            if device_type.is_none() {
                device_type = Some("Storage (NAS)".to_string());
            }
        }

        {
            let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
                updated += 1;
                DeviceInfo::new(mac.to_string(), packet.source_ip, None)
            });

            // Update IP if currently unspecified
            if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
                device.ip_address = packet.source_ip;
                updated += 1;
            }

            // Update hostname
            if device.hostname.is_none() {
                device.hostname = Some(packet.name.clone());
                updated += 1;
            }

            // Update vendor
            if let Some(ref v) = vendor {
                let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
                if Self::should_replace_vendor(device.vendor.as_deref(), v, oui_vendor) {
                    device.vendor = Some(v.clone());
                    updated += 1;
                }
            }

            // Update device type
            if let Some(ref t) = device_type
                && Self::should_replace_device_type(device, t)
            {
                device.device_type = Some(t.clone());
                updated += 1;
            }

            device.last_seen = SystemTime::now();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.clone());
            if self.auto_save {
                let _ = self.save_to_db();
            }
        }

        updated
    }

    /// Detect vendor and device type from DHCP Option 60 (Vendor Class Identifier)
    fn detect_device_details_from_dhcp_vendor_class(
        vendor_class: &str,
    ) -> (Option<&'static str>, Option<&'static str>) {
        if vendor_class.is_empty() {
            return (None, None);
        }

        let owned_holder;
        let vc = if vendor_class.bytes().any(|b| b.is_ascii_uppercase()) {
            owned_holder = vendor_class.to_ascii_lowercase();
            owned_holder.as_str()
        } else {
            vendor_class
        };
        if vc.contains("msft 5.0") || vc.contains("msft 98") || vc.starts_with("msft") {
            return (Some("Microsoft"), Some("PC/Windows"));
        }
        if vc.contains("android-dhcp") {
            return (Some("Google"), Some("Android Phone"));
        }
        if vc.contains("dhcpcd") {
            return (Some("Linux"), Some("IoT Device"));
        }
        if vc.contains("hp jetdirect") || vc.contains("hewlett-packard jetdirect") {
            return (Some("HP"), Some("Printer"));
        }
        if vc.contains("roku") {
            return (Some("Roku"), Some("Media Player"));
        }
        if vc.contains("sonos") {
            return (Some("Sonos"), Some("Smart Speaker"));
        }
        if vc.contains("appletv") || vc.contains("apple tv") {
            return (Some("Apple"), Some("Apple TV"));
        }
        if vc.contains("idevice")
            || vc.contains("iphone")
            || vc.contains("ipad")
            || vc.contains("macintosh")
        {
            return (Some("Apple"), Some("Apple Device"));
        }

        (None, None)
    }

    /// Detect vendor and device type from DHCP Option 55 (Parameter Request List)
    fn detect_device_details_from_dhcp_options(
        prl: &[u8],
    ) -> (Option<&'static str>, Option<&'static str>) {
        if prl.is_empty() {
            return (None, None);
        }

        let has_26 = prl.contains(&26);
        let has_28 = prl.contains(&28);
        let has_95 = prl.contains(&95);
        let has_249 = prl.contains(&249);

        // Windows Signature: contains 249 (MS Classless Route)
        if has_249 {
            return (Some("Microsoft"), Some("PC/Windows"));
        }

        // Apple (iOS/macOS) Signature: contains 95 (LDAP) and lacks 26/28
        if has_95 && !has_26 && !has_28 {
            return (Some("Apple"), Some("Apple Device"));
        }

        // Android / Linux Signature: contains 26 (Interface MTU) and 28 (Broadcast Address)
        if has_26 && has_28 {
            return (Some("Google"), Some("Android Phone"));
        }

        (None, None)
    }

    /// Detect vendor from hostname patterns
    pub(crate) fn detect_vendor_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
        crate::classifier::detect_vendor_from_hostname(hostname)
    }

    /// Detect device type from hostname patterns
    pub(crate) fn detect_device_type_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
        crate::classifier::detect_device_type_from_hostname(hostname)
    }

    /// Detect vendor from a list of services
    #[cfg(feature = "mdns")]
    fn detect_vendor_from_services(&self, services: &[&str]) -> Option<String> {
        let mut has_printer_services = false;
        let mut has_scanner_services = false;

        for service in services {
            let owned;
            let s = if service.bytes().any(|b| b.is_ascii_uppercase()) {
                owned = service.to_ascii_lowercase();
                owned.as_str()
            } else {
                service
            };
            if s.contains("_printer")
                || s.contains("_ipp")
                || s.contains("_pdl-datastream")
                || s.contains("_print-caps")
            {
                has_printer_services = true;
            }
            if s.contains("_scanner") || s.contains("_uscan") {
                has_scanner_services = true;
            }
        }

        let is_peripheral = has_printer_services || has_scanner_services;

        if let Some(registry) = &self.service_registry {
            for service in services {
                if let Some(vendor) = registry.get_vendor(service) {
                    if is_peripheral && vendor.eq_ignore_ascii_case("apple") {
                        continue;
                    }
                    return Some(vendor.to_string());
                }
            }
        }

        for service in services {
            let owned;
            let s = if service.bytes().any(|b| b.is_ascii_uppercase()) {
                owned = service.to_ascii_lowercase();
                owned.as_str()
            } else {
                service
            };
            if s.contains("googlecast") || s.contains("googlezone") || s.contains("androidtvremote")
            {
                return Some("Google".to_string());
            }
            if s.contains("amzn-wplay") {
                return Some("Amazon".to_string());
            }
            if s.contains("spotify") {
                return Some("Spotify".to_string());
            }
            if s.contains("nvstream") {
                return Some("NVIDIA".to_string());
            }
            if s.contains("eero") {
                return Some("eero inc.".to_string());
            }
            if !is_peripheral
                && (s.contains("airplay")
                    || s.contains("airdrop")
                    || s.contains("homekit")
                    || s.contains("raop")
                    || s.contains("airport")
                    || s.contains("daap")
                    || s.contains("dpap")
                    || s.contains("afpovertcp")
                    || s.contains("apple")
                    || s.contains("companion-link")
                    || s.contains("touch-able")
                    || s.contains("mediaremotetv")
                    || s.contains("hap._tcp")
                    || s.contains("appletv"))
            {
                return Some("Apple".to_string());
            }
        }
        None
    }

    fn should_replace_vendor(
        current: Option<&str>,
        incoming: &str,
        oui_vendor: Option<&str>,
    ) -> bool {
        match current {
            None => true,
            Some(existing) if existing.eq_ignore_ascii_case(incoming) => false,
            Some(existing) => {
                // If the incoming vendor is from a confirmed phone, allow the correction
                // (e.g. replacing generic "Google" or "Apple" with the actual phone manufacturer).
                if incoming.eq_ignore_ascii_case("Motorola")
                    || incoming.eq_ignore_ascii_case("Samsung")
                    || incoming.eq_ignore_ascii_case("Apple")
                    || incoming.eq_ignore_ascii_case("Google")
                {
                    if existing.eq_ignore_ascii_case("Google")
                        || existing.eq_ignore_ascii_case("Apple")
                    {
                        return true;
                    }
                }

                if existing.eq_ignore_ascii_case("Google")
                    && incoming.eq_ignore_ascii_case("Rachio")
                {
                    return true;
                }
                oui_vendor
                    .map(|oui| existing.eq_ignore_ascii_case(oui))
                    .unwrap_or(false)
            }
        }
    }

    fn should_replace_device_type(device: &DeviceInfo, incoming: &str) -> bool {
        let current = device.device_type.as_deref();
        match current {
            None => true,
            Some(existing) if existing.eq_ignore_ascii_case(incoming) => false,
            Some(existing) => {
                let existing = existing.to_ascii_lowercase();
                let incoming = incoming.to_ascii_lowercase();

                // Define priority categories:
                // Inferred/Generic types (Priority 0) should be overwritten by specific active-discovery types (Priority 1).
                let is_generic = |t: &str| -> bool {
                    matches!(
                        t,
                        "unknown"
                            | "android phone"
                            | "pc/windows"
                            | "apple device"
                            | "linux"
                            | "iot device"
                            | "smart home device"
                    )
                };

                // Do not downgrade a device classified via mDNS/SSDP cast services (like Chromecast) to a generic Android Phone
                // UNLESS the hostname explicitly confirms it is a specific mobile device.
                if existing == "chromecast"
                    && incoming == "android phone"
                    && !is_confirmed_phone(device.hostname.as_deref())
                {
                    let has_cast_service = device
                        .services
                        .iter()
                        .any(|s| s.contains("googlecast") || s.contains("androidtvremote2"));
                    if has_cast_service {
                        return false;
                    }
                }

                // Do not downgrade a device with active mDNS/SSDP discovery services to a generic class,
                // UNLESS the hostname explicitly confirms it is a specific mobile device (e.g. Moto, Samsung, iPhone).
                if !is_generic(&existing) && is_generic(&incoming) {
                    if !is_confirmed_phone(device.hostname.as_deref()) {
                        return false;
                    }
                }

                // Upgrade from generic/inferred to specific/refined,
                // UNLESS the device is a confirmed mobile phone/tablet (in which case do not override it with a smart/media type).
                if is_generic(&existing) && !is_generic(&incoming) {
                    if is_confirmed_phone(device.hostname.as_deref()) {
                        return false;
                    }
                    return true;
                }

                // If both are specific/refined, allow allowed corrections
                matches!(
                    incoming.as_str(),
                    "smart watering device"
                        | "smart cleaning device"
                        | "laptop"
                        | "android phone"
                        | "pixel phone"
                        | "apple iphone"
                ) && matches!(
                    existing.as_str(),
                    "security camera"
                        | "router"
                        | "smart home device"
                        | "unknown"
                        | "chromecast"
                        | "thermostat"
                )
            }
        }
    }

    /// Detect device type from a list of services
    #[cfg(feature = "mdns")]
    fn detect_device_type_from_services(&self, services: &[&str]) -> Option<String> {
        for service in services {
            let owned;
            let s = if service.bytes().any(|b| b.is_ascii_uppercase()) {
                owned = service.to_ascii_lowercase();
                owned.as_str()
            } else {
                service
            };
            if s.contains("googlecast") || s.contains("googlezone") {
                return Some("Chromecast".to_string());
            }
            if s.contains("appletv") || s.contains("mediaremotetv") {
                return Some("Apple TV".to_string());
            }
            if s.contains("_remotepairing") || s.contains("_atc") || s.contains("_rdlink") {
                return Some("Apple iPhone".to_string());
            }
            if s.contains("airplay") || s.contains("raop") {
                return Some("AirPlay Device".to_string());
            }
            if s.contains("amzn-wplay") {
                return Some("Fire TV".to_string());
            }
            if s.contains("eero") {
                return Some("Router".to_string());
            }
            if s.contains("_printer")
                || s.contains("_ipp")
                || s.contains("_pdl-datastream")
                || s.contains("_print-caps")
            {
                return Some("Printer".to_string());
            }
            if s.contains("_scanner") || s.contains("_uscan") {
                return Some("Scanner".to_string());
            }
        }

        if let Some(registry) = &self.service_registry {
            for service in services {
                if let Some(device_type) = registry.get_device_type(service) {
                    return Some(device_type.to_string());
                }
            }
        }

        for service in services {
            let owned;
            let s = if service.bytes().any(|b| b.is_ascii_uppercase()) {
                owned = service.to_ascii_lowercase();
                owned.as_str()
            } else {
                service
            };
            if s.contains("_smb") || s.contains("_afpovertcp") || s.contains("_nfs") {
                return Some("NAS".to_string());
            }
            if s.contains("_homekit") || s.contains("_hap") {
                return Some("Smart Home Device".to_string());
            }
            if s.contains("androidtvremote") {
                return Some("Android TV".to_string());
            }
            if s.contains("nvstream") {
                return Some("NVIDIA Shield".to_string());
            }
            if s.contains("spotify") {
                return Some("Spotify Connect Device".to_string());
            }
        }
        None
    }

    /// Updates the tracker state with information from an SSDP/UPnP advertisement or response.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_ssdp(&mut self, packet: &SsdpPacket) -> usize {
        let packet = packet.view();

        let mut updated = 0;
        let mac = &packet.source_mac;
        let services = packet.service_terms();
        let oui_vendor = self
            .oui_registry
            .as_ref()
            .and_then(|registry| registry.lookup(mac))
            .map(str::to_string);

        let vendor = packet.detect_vendor_from_view();
        let device_type = packet.detect_device_type_from_view();

        let source_ipv4 = match packet.source_ip {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        };
        let source_ipv6 = match packet.source_ip {
            std::net::IpAddr::V6(ip) => Some(ip),
            _ => None,
        };

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            let initial_ip = source_ipv4.map(IpAddr::V4).unwrap_or_else(|| {
                source_ipv6
                    .map(IpAddr::V6)
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
            });
            DeviceInfo::new(mac.to_string(), initial_ip, None)
        });

        if let Some(ipv4) = source_ipv4
            && matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified())
        {
            device.ip_address = IpAddr::V4(ipv4);
            updated += 1;
        }

        if let Some(ipv6) = source_ipv6
            && device.set_ipv6_address(ipv6)
        {
            updated += 1;
        }

        for service in &services {
            if device.add_service(service) {
                updated += 1;
            }
        }

        // Set vendor if detected (or fall back to OUI vendor)
        let vendor_to_apply = vendor.or_else(|| oui_vendor.clone());
        if let Some(v) = vendor_to_apply
            && Self::should_replace_vendor(device.vendor.as_deref(), &v, oui_vendor.as_deref())
        {
            if device.vendor.as_deref() != Some(&v) {
                device.vendor = Some(v.clone());
            }
            updated += 1;
        }

        if let Some(t) = device_type
            && Self::should_replace_device_type(device, &t)
        {
            if device.device_type.as_deref() != Some(&t) {
                device.device_type = Some(t.clone());
            }
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        self.dirty_devices.lock().unwrap().insert(mac.to_string());

        updated
    }

    /// Updates the tracker state with information from a WS-Discovery (WSD) packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_wsd(&mut self, packet: &WsdPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Update vendor
        if let Some(ref v) = packet.vendor {
            let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
            if Self::should_replace_vendor(device.vendor.as_deref(), v, oui_vendor) {
                device.vendor = Some(v.clone());
                updated += 1;
            }
        }

        // Update device type
        if let Some(ref t) = packet.device_type
            && Self::should_replace_device_type(device, t)
        {
            device.device_type = Some(t.clone());
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from a LIFX packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_lifx(&mut self, packet: &crate::parser::iot::LifxPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Set LIFX as vendor if not set or if we should replace it
        let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
        if Self::should_replace_vendor(device.vendor.as_deref(), "LIFX", oui_vendor) {
            device.vendor = Some("LIFX".to_string());
            updated += 1;
        }

        // Set Lightbulb as device type if not set
        if Self::should_replace_device_type(device, "Lightbulb") {
            device.device_type = Some("Lightbulb".to_string());
            updated += 1;
        }

        // Update description with msg_type info
        let desc = format!("LIFX device (msg_type: {})", packet.msg_type);
        if device.system_description.as_ref() != Some(&desc) {
            device.system_description = Some(desc);
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from a CoAP packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_coap(&mut self, packet: &crate::parser::iot::CoapPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        let mut dev_type = "IoT Device";

        // Parse payload to infer device type / details if available
        if let Some(ref payload) = packet.payload {
            if device.system_description.as_ref() != Some(payload) {
                device.system_description = Some(payload.clone());
                updated += 1;
            }

            let payload_lower = payload.to_lowercase();
            // Basic inference from CoAP CoRE Link Format
            if payload_lower.contains("temp") || payload_lower.contains("therm") {
                dev_type = "Sensor";
            } else if payload_lower.contains("light") || payload_lower.contains("lamp") {
                dev_type = "Lightbulb";
            } else if payload_lower.contains("plug") || payload_lower.contains("outlet") {
                dev_type = "Outlet";
            }
        }

        // Set the final device type
        if Self::should_replace_device_type(device, dev_type) {
            device.device_type = Some(dev_type.to_string());
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from a KNXnet/IP packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_knx(&mut self, packet: &crate::parser::iot::KnxPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Set vendor if friendly name or serial number suggests one, otherwise generic KNX
        let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
        if Self::should_replace_vendor(device.vendor.as_deref(), "KNX Device", oui_vendor) {
            device.vendor = Some("KNX".to_string());
            updated += 1;
        }

        // Set device type if not set
        if Self::should_replace_device_type(device, "Home Automation") {
            device.device_type = Some("Home Automation".to_string());
            updated += 1;
        }

        // Use friendly name as hostname
        if let Some(ref name) = packet.friendly_name
            && device.hostname.as_ref() != Some(name)
        {
            device.hostname = Some(name.clone());
            updated += 1;
        }

        // Description with serial / service type
        let desc = match (&packet.friendly_name, &packet.serial_number) {
            (Some(name), Some(serial)) => format!("KNX Device ({} Serial: {})", name, serial),
            (_, Some(serial)) => format!("KNX Device (Serial: {})", serial),
            _ => format!("KNXnet/IP Service 0x{:04x}", packet.service_type),
        };

        if device.system_description.as_ref() != Some(&desc) {
            device.system_description = Some(desc);
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from a CCTV/IP Camera packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_cctv(&mut self, packet: &crate::parser::cctv::CctvPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Set vendor if appropriate
        let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
        if Self::should_replace_vendor(device.vendor.as_deref(), &packet.vendor, oui_vendor) {
            device.vendor = Some(packet.vendor.clone());
            updated += 1;
        }

        // Set device type to "IP Camera"
        if Self::should_replace_device_type(device, "IP Camera") {
            device.device_type = Some("IP Camera".to_string());
            updated += 1;
        }

        // Hostname / Model
        if let Some(ref model) = packet.model
            && device.hostname.as_ref() != Some(model)
        {
            device.hostname = Some(model.clone());
            updated += 1;
        }

        // System Description with serial / protocol
        let desc = match (&packet.model, &packet.serial_number) {
            (Some(model), Some(serial)) => format!(
                "IP Camera ({} Serial: {}) via {}",
                model, serial, packet.protocol
            ),
            (_, Some(serial)) => format!("IP Camera (Serial: {}) via {}", serial, packet.protocol),
            (Some(model), _) => format!("IP Camera ({}) via {}", model, packet.protocol),
            _ => format!("IP Camera via {}", packet.protocol),
        };

        if device.system_description.as_ref() != Some(&desc) {
            device.system_description = Some(desc);
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from an MQTT packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_mqtt(&mut self, packet: &crate::parser::mqtt_gdm::MqttPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Set device type to "IoT Device"
        if Self::should_replace_device_type(device, "IoT Device") {
            device.device_type = Some("IoT Device".to_string());
            updated += 1;
        }

        // System Description
        let desc = format!(
            "MQTT Client ID: {} via {}",
            packet.client_id, packet.protocol
        );
        if device.system_description.as_ref() != Some(&desc) {
            device.system_description = Some(desc);
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Updates the tracker state with information from a Plex GDM packet.
    ///
    /// # Returns
    /// The count of unique updates applied to the device entry.
    #[cfg(feature = "ssdp")]
    pub fn update_from_gdm(&mut self, packet: &crate::parser::mqtt_gdm::GdmPacket) -> usize {
        let mac = &packet.source_mac;
        let mut updated = 0;

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| {
            updated += 1;
            DeviceInfo::new(mac.to_string(), packet.source_ip, None)
        });

        // Update IP if currently unspecified
        if matches!(device.ip_address, IpAddr::V4(addr) if addr.is_unspecified()) {
            device.ip_address = packet.source_ip;
            updated += 1;
        }

        // Set vendor to "Plex"
        let vendor_name = "Plex".to_string();
        let oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
        if Self::should_replace_vendor(device.vendor.as_deref(), &vendor_name, oui_vendor) {
            device.vendor = Some(vendor_name);
            updated += 1;
        }

        // Classify device type as "Media Server" or "Media Player"
        let dt = if let Some(ref prod) = packet.product {
            if prod.to_lowercase().contains("server") {
                "Media Server"
            } else {
                "Media Player"
            }
        } else {
            "Media Server"
        };
        if Self::should_replace_device_type(device, dt) {
            device.device_type = Some(dt.to_string());
            updated += 1;
        }

        // Hostname set to server/device name
        if let Some(ref name) = packet.name
            && device.hostname.as_ref() != Some(name)
        {
            device.hostname = Some(name.clone());
            updated += 1;
        }

        // System Description
        let desc = match (&packet.product, &packet.resource_id) {
            (Some(prod), Some(uuid)) => format!("Plex device: {} ({})", prod, uuid),
            (Some(prod), None) => format!("Plex device: {}", prod),
            _ => "Plex Media Service".to_string(),
        };
        if device.system_description.as_ref() != Some(&desc) {
            device.system_description = Some(desc);
            updated += 1;
        }

        device.last_seen = SystemTime::now();

        if updated > 0 && self.auto_save {
            let _ = self.save_to_db();
        }

        if updated > 0 {
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }

        updated
    }

    /// Detect device type from vendor name
    fn detect_device_type_from_vendor(vendor: &str) -> Option<&'static str> {
        let owned_holder;
        let v = if vendor.bytes().any(|b| b.is_ascii_uppercase()) {
            owned_holder = vendor.to_ascii_lowercase();
            owned_holder.as_str()
        } else {
            vendor
        };

        if v.contains("lenovo") {
            return Some("Laptop");
        }

        if v.contains("eero") {
            return Some("Router");
        }

        if v.contains("simplisafe") {
            return Some("Security System");
        }
        if v.contains("ring") && !v.contains("engineering") {
            return Some("Security Camera");
        }
        if v.contains("arlo") {
            return Some("Security Camera");
        }
        if v.contains("nest") {
            return Some("Smart Home Device");
        }
        if v.contains("alarm") || v.contains("security") {
            return Some("Security System");
        }

        if v.contains("tuya") || v.contains("smartlife") {
            return Some("Smart Home Device");
        }
        if v.contains("philips hue") || v.contains("signify") {
            return Some("Smart Light");
        }
        if v.contains("sonos") {
            return Some("Speaker");
        }
        if v.contains("ecobee") || v.contains("honeywell") {
            return Some("Thermostat");
        }

        if v.contains("ubiquiti")
            || v.contains("netgear")
            || v.contains("tp-link")
            || v.contains("linksys")
        {
            return Some("Network Equipment");
        }
        if v.contains("cisco") {
            return Some("Network Equipment");
        }

        if v.contains("nintendo") {
            return Some("Gaming Console");
        }
        if v.contains("sony") && (v.contains("playstation") || v.contains("entertainment")) {
            return Some("Gaming Console");
        }
        if v.contains("microsoft") && v.contains("xbox") {
            return Some("Gaming Console");
        }

        if v.contains("espressif") {
            return Some("IoT Device");
        }
        if v.contains("raspberry") {
            return Some("Raspberry Pi");
        }
        if v.contains("arduino") {
            return Some("Microcontroller");
        }

        if v.contains("hp") && v.contains("print") {
            return Some("Printer");
        }
        if v.contains("canon")
            || v.contains("epson")
            || v.contains("brother")
            || v.contains("lexmark")
        {
            return Some("Printer");
        }

        if v.contains("synology") || v.contains("qnap") || v.contains("western digital") {
            return Some("NAS");
        }

        None
    }

    /// Update or add a device
    /// # Note
    /// This method assumes `mac` is already normalized to lowercase (which all ingestion paths ensure).
    pub fn update_device(&mut self, mac: &str, ip: IpAddr, hostname: Option<&str>) -> bool {
        let hostname = hostname.and_then(sanitize_hostname);
        let hostname_vendor = Self::detect_vendor_from_hostname(hostname.as_deref());
        let device_type_from_hostname = Self::detect_device_type_from_hostname(hostname.as_deref());

        let result = if let Some(device) = self.devices.get_mut(mac) {
            let changed = device.update(ip, hostname.as_deref());

            let mut vendor_to_apply = hostname_vendor;
            let mut oui_vendor = None;

            if vendor_to_apply.is_none() && device.vendor.is_none() {
                oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
                vendor_to_apply = oui_vendor;
            }

            if let Some(v) = vendor_to_apply {
                if device.vendor.is_some()
                    && device.vendor.as_deref() != Some(v)
                    && oui_vendor.is_none()
                {
                    oui_vendor = self.oui_registry.as_ref().and_then(|r| r.lookup(mac));
                }

                if Self::should_replace_vendor(device.vendor.as_deref(), v, oui_vendor) {
                    device.vendor = Some(v.to_string());
                }
            }

            if let Some(dt) = device_type_from_hostname
                && Self::should_replace_device_type(device, dt)
            {
                device.device_type = Some(dt.to_string());
            }

            if let Some(v) = device.vendor.as_deref()
                && let Some(dt) = Self::detect_device_type_from_vendor(v)
                && Self::should_replace_device_type(device, dt)
            {
                device.device_type = Some(dt.to_string());
            }

            changed
        } else {
            let vendor = hostname_vendor.map(str::to_string).or_else(|| {
                self.oui_registry
                    .as_ref()
                    .and_then(|r| r.lookup(mac))
                    .map(str::to_string)
            });

            let mut device = DeviceInfo::new(mac.to_string(), ip, hostname);
            if let Some(ref v) = vendor {
                device.vendor = Some(v.clone());
            }
            if let Some(dt) = device_type_from_hostname {
                device.device_type = Some(dt.to_string());
            }
            if let Some(ref v) = vendor
                && let Some(dt) = Self::detect_device_type_from_vendor(v)
            {
                device.device_type = Some(dt.to_string());
            }
            self.devices.insert(mac.to_string(), device);
            true
        };

        self.dirty_devices.lock().unwrap().insert(mac.to_string());

        if result && self.auto_save {
            let _ = self.save_to_db();
        }

        result
    }

    /// Returns a reference to the internal map of all tracked devices.
    pub fn devices(&self) -> &HashMap<String, DeviceInfo> {
        &self.devices
    }

    /// Returns the total number of devices currently being tracked.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Returns a reference to a device by its MAC address.
    pub fn get_device(&self, mac: &str) -> Option<&DeviceInfo> {
        // Zero-allocation fast-path for already normalized MACs
        let is_normalized = mac.len() == 17
            && mac.as_bytes().iter().enumerate().all(|(idx, &b)| {
                if idx == 2 || idx == 5 || idx == 8 || idx == 11 || idx == 14 {
                    b == b':'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            });

        if is_normalized {
            let res = self.devices.get(mac);
            if res.is_some() {
                return res;
            }
        }

        if let Some(device) = self.devices.get(&mac.to_lowercase()) {
            return Some(device);
        }
        self.devices.get(&normalize_device_identifier(mac))
    }

    /// Returns the path to the CSV file used for persistence.
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Returns a JSON-formatted string of all tracked devices.
    #[cfg(feature = "http-api")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let devices: Vec<&DeviceInfo> = self.devices.values().collect();
        serde_json::to_string_pretty(&devices)
    }

    /// Returns a JSON string of all devices, sorted by the `last_seen` timestamp.
    #[cfg(feature = "http-api")]
    pub fn to_json_sorted(&self) -> Result<String, serde_json::Error> {
        let mut devices: Vec<&DeviceInfo> = self.devices.values().collect();
        devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));
        serde_json::to_string_pretty(&devices)
    }
}

impl Drop for DeviceTracker {
    fn drop(&mut self) {
        let _ = self.save_to_db();
    }
}

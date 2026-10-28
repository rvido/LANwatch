// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! Random-MAC merging: one phone, one record.
//!
//! Phones, tablets and laptops use a private (locally administered) MAC per
//! network, and many rotate it every few days or weeks. Discovery is keyed on
//! MAC, so every rotation used to create a fresh device, which lost the
//! person's label and trust and fired a `new` alert for a device that never
//! left.
//!
//! A merge folds the old record into the new one. Getting one wrong joins two
//! people's phones and can hand trust to a stranger, so every rule here is
//! chosen to refuse when in doubt. An old record `O` is merged into a new
//! record `N` only when all of these hold:
//!
//! 1. Both MACs are private. A real, burned-in MAC never rotates.
//! 2. Both carry the same distinctive hostname ([`merge_key`]). Generic
//!    names such as `iPhone` or `android` are shared by unrelated devices.
//! 3. `O` went quiet before `N` appeared ([`MERGE_OVERLAP_GRACE`] allowed).
//!    Two records on the LAN at the same time are two devices.
//! 4. No other record with that hostname overlaps `N` in time, and `O` is
//!    the only candidate. Otherwise the name is not unique right now.
//! 5. Their DHCP signatures (option 55 order, vendor class) do not
//!    contradict each other, which would mean a different operating system.
//!
//! Every merge is logged in `device_merges` and reported as a `merged`
//! presence event, so none happens silently.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, params};

use crate::device::{DeviceInfo, format_timestamp};
use crate::fingerprint::TokenNamespace;
use crate::oui::is_private_mac;
use crate::presence::{PresenceEvent, PresenceKind};
use crate::tracker::DeviceTracker;

/// How long a new random-MAC device without a hostname is kept out of the
/// presence sweep, so its hostname can arrive and a merge can be decided
/// before a `new` event fires.
pub const MERGE_SETTLE: Duration = Duration::from_secs(60);

/// How far the old record's last sighting may run past the new record's
/// first one. A rotating phone is briefly heard under both addresses (a late
/// mDNS answer, an ARP cache), and that is not two devices.
pub const MERGE_OVERLAP_GRACE: Duration = Duration::from_secs(120);

/// Hostnames that many unrelated devices share out of the box.
///
/// Compared after [`merge_key`] has lowercased the name and dropped a
/// numeric suffix, so `iPhone (2)` and `Galaxy-3` are caught too.
const GENERIC_HOSTNAMES: &[&str] = &[
    "amazon",
    "android",
    "apple-watch",
    "chromecast",
    "desktop",
    "echo",
    "esp32",
    "esp8266",
    "espressif",
    "galaxy",
    "huawei",
    "imac",
    "ipad",
    "iphone",
    "ipod",
    "kindle",
    "laptop",
    "localhost",
    "mac",
    "macbook",
    "macbook-air",
    "macbook-pro",
    "none",
    "oneplus",
    "pc",
    "phone",
    "pixel",
    "raspberrypi",
    "redmi",
    "roku",
    "samsung",
    "tablet",
    "unknown",
    "watch",
    "windows",
    "xiaomi",
];

/// The shortest hostname distinctive enough to merge on.
const MIN_HOSTNAME_LEN: usize = 4;

/// The vendor the OUI registry reports for every private MAC.
///
/// It names the address, not a manufacturer, so a merge may replace it.
const PRIVATE_MAC_VENDOR: &str = "Private MAC Address";

/// The form of a hostname that merges compare, or `None` if it is too
/// generic to identify one device.
///
/// Lowercased, with a trailing `.local` and a trailing `.` removed. A
/// numeric suffix (`-2`, ` (2)`) is ignored only for the generic check:
/// `iPhone-2` is still generic, while `Johns-iPhone-2` keeps its suffix.
pub fn merge_key(hostname: &str) -> Option<String> {
    let name = hostname.trim().to_ascii_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let name = name.strip_suffix(".local").unwrap_or(name);
    if name.len() < MIN_HOSTNAME_LEN {
        return None;
    }

    let stem = name
        .trim_end_matches(|c: char| c.is_ascii_digit() || matches!(c, '-' | '_' | ' ' | '(' | ')'));
    if stem.len() < 3 || GENERIC_HOSTNAMES.contains(&stem) {
        return None;
    }
    Some(name.to_string())
}

/// Whether two records were on the LAN at the same time, beyond the grace.
fn overlaps(a: &DeviceInfo, b: &DeviceInfo) -> bool {
    a.first_seen + MERGE_OVERLAP_GRACE < b.last_seen
        && b.first_seen + MERGE_OVERLAP_GRACE < a.last_seen
}

impl DeviceTracker {
    /// Switches random-MAC merging on or off. It is on by default.
    pub fn set_mac_merge(&mut self, enabled: bool) {
        self.mac_merge_enabled = enabled;
    }

    /// Creates the merge log. Safe to run on every startup.
    pub(crate) fn create_merge_schema(conn: &Connection) -> std::io::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS device_merges (
                id      INTEGER PRIMARY KEY,
                old_mac TEXT NOT NULL,
                new_mac TEXT NOT NULL,
                at      TEXT NOT NULL
            );",
            [],
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create merge schema: {}", e)))?;
        Ok(())
    }

    /// Rebuilds each device's `previous_macs` from the merge log.
    ///
    /// Merges chain: if `A` became `B` and then `B` became `C`, `C` was
    /// previously both `A` and `B`. Replaying the log in order gives that.
    pub(crate) fn load_merges_from_db(&mut self) -> std::io::Result<()> {
        let rows: Vec<(String, String)> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT old_mac, new_mac FROM device_merges ORDER BY at, id;")
                .map_err(std::io::Error::other)?;
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(std::io::Error::other)?
                .flatten()
                .collect()
        };

        let mut history: HashMap<String, Vec<String>> = HashMap::new();
        for (old, new) in rows {
            let mut previous = history.remove(&old).unwrap_or_default();
            previous.push(old);
            let entry = history.entry(new).or_default();
            previous.append(entry);
            *entry = previous;
        }
        for (mac, previous) in history {
            if let Some(device) = self.devices.get_mut(&mac) {
                device.previous_macs = previous;
            }
        }
        Ok(())
    }

    /// Finds and performs every merge the rules allow. Returns one `merged`
    /// event per merge, stamped `at`, in the order they were done.
    ///
    /// Each event is built right after its merge: in a chain, the middle
    /// record is itself merged away a moment later.
    ///
    /// One merge at a time, re-evaluated after each, so a chain of rotations
    /// collapses oldest first. The loop is bounded by the device count, since
    /// every merge removes one record.
    pub(crate) fn merge_rotated_macs(&mut self, at: &str) -> std::io::Result<Vec<PresenceEvent>> {
        let mut merged = Vec::new();
        for _ in 0..self.devices.len() {
            let Some((old, new)) = self.find_merge() else {
                break;
            };
            if !self.merge_device(&old, &new)? {
                break;
            }
            if let Some(device) = self.devices.get(&new) {
                merged.push(PresenceEvent::about(
                    device,
                    PresenceKind::Merged,
                    at.to_string(),
                    Some(old),
                ));
            }
        }
        Ok(merged)
    }

    /// The first `(old, new)` pair that passes every rule, oldest first.
    fn find_merge(&self) -> Option<(String, String)> {
        let mut groups: HashMap<String, Vec<&DeviceInfo>> = HashMap::new();
        for (mac, device) in &self.devices {
            if !is_private_mac(mac) {
                continue;
            }
            if let Some(key) = device.hostname.as_deref().and_then(merge_key) {
                groups.entry(key).or_default().push(device);
            }
        }

        let mut found: Vec<(SystemTime, String, String)> = Vec::new();
        for group in groups.values().filter(|group| group.len() >= 2) {
            for new in group {
                let others = group.iter().filter(|d| d.mac_address != new.mac_address);
                if others.clone().any(|other| overlaps(other, new)) {
                    continue;
                }
                let candidates: Vec<&&DeviceInfo> = others
                    .filter(|old| {
                        old.first_seen < new.first_seen
                            && old.last_seen <= new.first_seen + MERGE_OVERLAP_GRACE
                    })
                    .collect();
                let [old] = candidates.as_slice() else {
                    continue;
                };
                if self.dhcp_signatures_conflict(&old.mac_address, &new.mac_address) {
                    continue;
                }
                found.push((
                    old.first_seen,
                    old.mac_address.clone(),
                    new.mac_address.clone(),
                ));
            }
        }
        found.sort();
        found.into_iter().next().map(|(_, old, new)| (old, new))
    }

    /// Whether the two devices' DHCP signatures name different systems.
    ///
    /// Only a namespace both devices have filled can conflict. A phone that
    /// has not renewed its lease yet has no option 55 token, and missing
    /// evidence is not counter-evidence.
    fn dhcp_signatures_conflict(&self, a: &str, b: &str) -> bool {
        let tokens = |mac: &str, namespace: TokenNamespace| -> Vec<String> {
            self.attributes
                .get(mac)
                .map(|log| {
                    log.set()
                        .tokens()
                        .filter(|t| t.starts_with(namespace.prefix()))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        [TokenNamespace::DhcpOptionList, TokenNamespace::VendorClass]
            .into_iter()
            .any(|namespace| {
                let left = tokens(a, namespace);
                let right = tokens(b, namespace);
                !left.is_empty()
                    && !right.is_empty()
                    && !left.iter().any(|token| right.contains(token))
            })
    }

    /// Folds the record of `old` into `new` and removes `old`.
    ///
    /// The surviving record is the newer one, because that is the address
    /// the device answers to now. It keeps its own live data and takes from
    /// `old` what only history can supply: the first sighting, a person's
    /// classification and trust, the attribute tokens if it has none yet, and
    /// the presence history.
    ///
    /// Public so a library user can merge two records by hand. The automatic
    /// rules live in [`DeviceTracker::merge_rotated_macs`], not here. Returns
    /// `false` when either device is not tracked or both are the same.
    pub fn merge_device(&mut self, old: &str, new: &str) -> std::io::Result<bool> {
        if old == new || !self.devices.contains_key(new) {
            return Ok(false);
        }
        let Some(previous) = self.devices.get(old).cloned() else {
            return Ok(false);
        };

        if let Some(device) = self.devices.get_mut(new) {
            device.first_seen = device.first_seen.min(previous.first_seen);
            let vendor_is_placeholder = device
                .vendor
                .as_ref()
                .is_none_or(|v| v.as_str() == PRIVATE_MAC_VENDOR);
            if vendor_is_placeholder
                && let Some(vendor) = previous
                    .vendor
                    .clone()
                    .filter(|v| v.as_str() != PRIVATE_MAC_VENDOR)
            {
                device.vendor = Some(vendor);
            }
            if device.device_type.is_none() {
                device.device_type = previous.device_type.clone();
            }
            if device.hostname.is_none() {
                device.hostname = previous.hostname.clone();
            }
            if device.system_description.is_none() {
                device.system_description = previous.system_description.clone();
            }
            for service in &previous.services {
                device.add_service(service);
            }
            let mut history = previous.previous_macs.clone();
            history.push(old.to_string());
            history.append(&mut device.previous_macs);
            history.dedup();
            device.previous_macs = history;
        }
        self.dirty_devices.lock().unwrap().insert(new.to_string());

        // A person's verdict on the old record is the most valuable thing it
        // holds. The new record's own verdict, if any, is newer and wins.
        if let Some(entry) = self.overrides.remove(old) {
            self.persist_override(old)?;
            if !self.overrides.contains_key(new) {
                self.overrides.insert(new.to_string(), entry);
                self.persist_override(new)?;
            }
        }

        let move_attributes =
            self.attributes.contains_key(old) && !self.attributes.contains_key(new);
        let carry_trust = self.trusted.remove(old);
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction().map_err(|e| {
                std::io::Error::other(format!("Failed to start transaction: {}", e))
            })?;
            let fail =
                |e: rusqlite::Error| std::io::Error::other(format!("Failed to merge: {}", e));
            if move_attributes {
                tx.execute(
                    "UPDATE device_attributes SET mac_address = ? WHERE mac_address = ?;",
                    params![new, old],
                )
                .map_err(fail)?;
            } else {
                tx.execute(
                    "DELETE FROM device_attributes WHERE mac_address = ?;",
                    params![old],
                )
                .map_err(fail)?;
            }
            if carry_trust {
                tx.execute(
                    "DELETE FROM trusted_devices WHERE mac_address = ?;",
                    params![old],
                )
                .map_err(fail)?;
                tx.execute(
                    "INSERT OR IGNORE INTO trusted_devices (mac_address, trusted_at)
                     VALUES (?, ?);",
                    params![new, format_timestamp(SystemTime::now())],
                )
                .map_err(fail)?;
            }
            tx.execute(
                "UPDATE presence_events SET mac_address = ? WHERE mac_address = ?;",
                params![new, old],
            )
            .map_err(fail)?;
            tx.execute(
                "INSERT INTO device_merges (old_mac, new_mac, at) VALUES (?, ?, ?);",
                params![old, new, format_timestamp(SystemTime::now())],
            )
            .map_err(fail)?;
            tx.commit().map_err(fail)?;
        }

        let old_attributes = self.attributes.remove(old);
        let old_dirty = self.dirty_attributes.lock().unwrap().remove(old);
        if move_attributes && let Some(log) = old_attributes {
            self.attributes.insert(new.to_string(), log);
            if let Some(tokens) = old_dirty {
                self.dirty_attributes
                    .lock()
                    .unwrap()
                    .entry(new.to_string())
                    .or_default()
                    .extend(tokens);
            }
        }

        if carry_trust {
            self.trusted.insert(new.to_string());
        }
        #[cfg(feature = "ssdp")]
        self.move_upnp_description(old, new)?;
        if let Some(device) = self.devices.get_mut(new) {
            device.trusted = self.trusted.contains(new);
        }

        // The old address is history now. It stays known, so if it ever
        // comes back it is not news either.
        self.online_state.remove(old);
        self.known_macs.insert(new.to_string());

        self.remove_device(old)?;
        self.refresh_fingerprint(new);
        self.apply_overrides();
        Ok(true)
    }

    /// Drops the merge log entries that name `key`, for `--forget`.
    pub(crate) fn forget_merges(&self, key: &str) -> std::io::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM device_merges WHERE old_mac = ? OR new_mac = ?;",
                params![key, key],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to delete merges: {}", e)))?;
        Ok(rows > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Duration = Duration::from_secs(1800);
    const HOUR: Duration = Duration::from_secs(3600);

    fn tracker(name: &str) -> (String, DeviceTracker) {
        let path = format!("/tmp/lanwatch_test_merge_{}.db", name);
        cleanup(&path);
        (path.clone(), DeviceTracker::new(&path).unwrap())
    }

    fn cleanup(path: &str) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path, suffix));
        }
    }

    /// Adds a device seen from `first` to `last`.
    fn add(
        tracker: &mut DeviceTracker,
        mac: &str,
        hostname: Option<&str>,
        first: SystemTime,
        last: SystemTime,
    ) {
        let mut device = DeviceInfo::new(
            mac.to_string(),
            "192.168.1.60".parse().unwrap(),
            hostname.map(str::to_string),
        );
        device.first_seen = first;
        device.last_seen = last;
        tracker.devices.insert(mac.to_string(), device);
        tracker
            .dirty_devices
            .lock()
            .unwrap()
            .insert(mac.to_string());
    }

    // Both private: second hex digit 2, 6, a or e.
    const OLD: &str = "da:11:22:33:44:01";
    const NEW: &str = "3e:11:22:33:44:02";
    const NAME: Option<&str> = Some("Richards-iPhone");

    #[test]
    fn generic_hostnames_are_refused() {
        for name in [
            "iPhone",
            "iphone (2)",
            "Galaxy-3",
            "android",
            "pc",
            "abc",
            "iPad.local.",
        ] {
            assert_eq!(merge_key(name), None, "{}", name);
        }
        assert_eq!(
            merge_key("Richards-iPhone").as_deref(),
            Some("richards-iphone")
        );
        assert_eq!(
            merge_key("Johns-iPhone-2.local").as_deref(),
            Some("johns-iphone-2")
        );
        assert_eq!(
            merge_key("DESKTOP-4K2J9QX").as_deref(),
            Some("desktop-4k2j9qx")
        );
    }

    #[test]
    fn a_rotated_mac_is_merged_and_keeps_label_trust_and_history() {
        let (path, mut tracker) = tracker("rotate");
        let now = SystemTime::now();
        add(&mut tracker, OLD, NAME, now - 48 * HOUR, now - 24 * HOUR);
        let _ = tracker.sweep_presence(now - 24 * HOUR, LIMIT).unwrap();
        tracker
            .set_classification(OLD, None, None, Some("Richard's phone".to_string()))
            .unwrap();
        tracker.set_trusted(OLD, true).unwrap();

        add(&mut tracker, NEW, NAME, now, now);
        let events = tracker.sweep_presence(now, LIMIT).unwrap();

        assert_eq!(events.len(), 1, "{:?}", events);
        assert_eq!(events[0].event, PresenceKind::Merged);
        assert_eq!(events[0].mac_address, NEW);
        assert_eq!(events[0].previous_mac.as_deref(), Some(OLD));

        assert!(tracker.get_device(OLD).is_none());
        let device = tracker.get_device(NEW).unwrap();
        assert_eq!(device.product_label.as_deref(), Some("Richard's phone"));
        assert!(device.trusted);
        assert_eq!(device.first_seen, now - 48 * HOUR);
        assert_eq!(device.previous_macs, [OLD]);
        assert!(tracker.is_trusted(NEW) && !tracker.is_trusted(OLD));

        let history = tracker.presence_history(Some(NEW), 10).unwrap();
        assert!(history.iter().any(|e| e.event == PresenceKind::New));
        cleanup(&path);
    }

    #[test]
    fn two_devices_with_the_same_name_at_once_are_never_merged() {
        let (path, mut tracker) = tracker("overlap");
        let now = SystemTime::now();
        add(&mut tracker, OLD, NAME, now - HOUR, now);
        add(&mut tracker, NEW, NAME, now - HOUR / 2, now);
        let events = tracker.sweep_presence(now, LIMIT).unwrap();
        assert!(events.iter().all(|e| e.event == PresenceKind::New));
        assert_eq!(tracker.device_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn a_third_record_with_the_name_blocks_the_merge() {
        let (path, mut tracker) = tracker("ambiguous");
        let now = SystemTime::now();
        // Two older records that overlap each other: two phones, one name.
        add(&mut tracker, OLD, NAME, now - 10 * HOUR, now - 5 * HOUR);
        add(
            &mut tracker,
            "aa:11:22:33:44:03",
            NAME,
            now - 9 * HOUR,
            now - 6 * HOUR,
        );
        add(&mut tracker, NEW, NAME, now, now);
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        assert_eq!(tracker.device_count(), 3);
        cleanup(&path);
    }

    #[test]
    fn a_chain_of_rotations_collapses_into_the_newest() {
        let (path, mut tracker) = tracker("chain");
        let now = SystemTime::now();
        let middle = "6a:11:22:33:44:05";
        add(&mut tracker, OLD, NAME, now - 30 * HOUR, now - 20 * HOUR);
        add(&mut tracker, middle, NAME, now - 19 * HOUR, now - 10 * HOUR);
        add(&mut tracker, NEW, NAME, now, now);

        let events = tracker.sweep_presence(now, LIMIT).unwrap();
        let merges: Vec<_> = events
            .iter()
            .filter(|e| e.event == PresenceKind::Merged)
            .collect();
        assert_eq!(merges.len(), 2);
        assert_eq!(tracker.device_count(), 1);
        assert_eq!(
            tracker.get_device(NEW).unwrap().previous_macs,
            [OLD, middle]
        );
        tracker.save_to_db().unwrap();
        drop(tracker);

        // The chain is rebuilt from the log after a restart.
        let tracker = DeviceTracker::new(&path).unwrap();
        assert_eq!(
            tracker.get_device(NEW).unwrap().previous_macs,
            [OLD, middle]
        );
        cleanup(&path);
    }

    #[test]
    fn a_real_mac_or_a_generic_name_is_never_merged() {
        let (path, mut tracker) = tracker("real");
        let now = SystemTime::now();
        add(
            &mut tracker,
            "00:11:22:33:44:01",
            NAME,
            now - 48 * HOUR,
            now - 24 * HOUR,
        );
        add(&mut tracker, NEW, NAME, now, now);
        add(
            &mut tracker,
            "02:00:00:00:00:01",
            Some("iPhone"),
            now - 48 * HOUR,
            now - 24 * HOUR,
        );
        add(&mut tracker, "02:00:00:00:00:02", Some("iPhone"), now, now);
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        assert_eq!(tracker.device_count(), 4);
        cleanup(&path);
    }

    #[test]
    fn conflicting_dhcp_signatures_block_the_merge() {
        let (path, mut tracker) = tracker("dhcp");
        let now = SystemTime::now();
        add(&mut tracker, OLD, NAME, now - 48 * HOUR, now - 24 * HOUR);
        add(&mut tracker, NEW, NAME, now, now);
        tracker
            .attributes
            .entry(OLD.to_string())
            .or_default()
            .record(TokenNamespace::DhcpOptionList, "55=1-3-6-15-119-252", now);
        tracker
            .attributes
            .entry(NEW.to_string())
            .or_default()
            .record(
                TokenNamespace::DhcpOptionList,
                "55=1-33-3-6-15-28-51-58-59",
                now,
            );
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        assert_eq!(tracker.device_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn a_nameless_random_mac_waits_before_it_is_new() {
        let (path, mut tracker) = tracker("settle");
        let now = SystemTime::now();
        add(&mut tracker, NEW, None, now, now);
        assert!(tracker.sweep_presence(now, LIMIT).unwrap().is_empty());

        let later = now + MERGE_SETTLE;
        let events = tracker.sweep_presence(later, LIMIT).unwrap();
        assert_eq!(events[0].event, PresenceKind::New);
        cleanup(&path);
    }

    #[test]
    fn merging_can_be_switched_off() {
        let (path, mut tracker) = tracker("off");
        tracker.set_mac_merge(false);
        let now = SystemTime::now();
        add(&mut tracker, OLD, NAME, now - 48 * HOUR, now - 24 * HOUR);
        add(&mut tracker, NEW, NAME, now, now);
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        assert_eq!(tracker.device_count(), 2);
        cleanup(&path);
    }
}

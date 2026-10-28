// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! Presence tracking, the trusted-device list, and the event hook.
//!
//! A device is *online* while its `last_seen` is younger than a threshold,
//! and *offline* after that. Nothing on the wire says "I left", so going
//! offline is always inferred from silence. [`DeviceTracker::sweep_presence`]
//! compares every device against the threshold on a timer and reports each
//! change once, as a [`PresenceEvent`].
//!
//! The sweep is decoupled from the dozen `update_from_*` paths on purpose:
//! each of them may create a device or refresh `last_seen`, and a check
//! wired into all of them would miss the next one added.

use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, params};
use serde::Serialize;

use crate::device::{format_timestamp, normalize_device_identifier, parse_timestamp};
use crate::tracker::DeviceTracker;

/// How long a device may stay silent before it counts as offline.
///
/// Phones and laptops send ARP or mDNS every few minutes while awake, but
/// many IoT devices speak only at DHCP renewal. Thirty minutes keeps the
/// quiet ones from flapping while still noticing a phone that left the house.
pub const DEFAULT_OFFLINE_AFTER: Duration = Duration::from_secs(30 * 60);

/// How long presence events are kept in the database.
pub const PRESENCE_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// The most hook commands allowed to run at once.
///
/// A burst of new devices (a first run, a guest network coming up) must not
/// fork hundreds of processes. Events past the limit are dropped and counted.
pub const MAX_RUNNING_HOOKS: usize = 8;

/// What changed about a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceKind {
    /// A MAC address LANwatch has never seen before. Implies online.
    New,
    /// A known device that was offline sent traffic again.
    Online,
    /// A device stayed silent longer than the offline threshold.
    Offline,
}

impl PresenceKind {
    /// The stored and displayed name, e.g. `online`.
    pub fn as_str(self) -> &'static str {
        match self {
            PresenceKind::New => "new",
            PresenceKind::Online => "online",
            PresenceKind::Offline => "offline",
        }
    }

    /// Reads a stored name back. Unknown names give `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new" => Some(PresenceKind::New),
            "online" => Some(PresenceKind::Online),
            "offline" => Some(PresenceKind::Offline),
            _ => None,
        }
    }
}

impl fmt::Display for PresenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One presence change, as it is stored, served and handed to the hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PresenceEvent {
    /// The device the event is about.
    pub mac_address: String,
    /// What changed.
    pub event: PresenceKind,
    /// When the change happened, ISO 8601 UTC.
    ///
    /// For `offline` this is the sweep that noticed the silence, not the last
    /// packet; the device's `last_seen` holds that.
    pub at: String,
    /// The device's IP address at the time, if it had one.
    pub ip_address: Option<String>,
    /// The device's hostname at the time, if known.
    pub hostname: Option<String>,
    /// The vendor at the time, if known.
    pub vendor: Option<String>,
    /// The device type at the time, if known.
    pub device_type: Option<String>,
    /// The product name a person gave the device, if any.
    pub label: Option<String>,
    /// Whether the device was on the trusted list.
    pub trusted: bool,
}

impl DeviceTracker {
    /// Creates the presence and trust tables. Safe to run on every startup.
    pub(crate) fn create_presence_schema(conn: &Connection) -> std::io::Result<()> {
        let statements = [
            // Kept apart from `devices`, like the overrides, so trusting a
            // device survives it being removed from the dashboard.
            "CREATE TABLE IF NOT EXISTS trusted_devices (
                mac_address TEXT PRIMARY KEY,
                trusted_at  TEXT NOT NULL
            );",
            "CREATE TABLE IF NOT EXISTS presence_events (
                id          INTEGER PRIMARY KEY,
                mac_address TEXT NOT NULL,
                event       TEXT NOT NULL,
                at          TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_presence_events_mac
                ON presence_events(mac_address, at DESC);",
            "CREATE INDEX IF NOT EXISTS idx_presence_events_at
                ON presence_events(at DESC);",
        ];
        for statement in statements {
            conn.execute(statement, []).map_err(|e| {
                std::io::Error::other(format!("Failed to create presence schema: {}", e))
            })?;
        }
        Ok(())
    }

    /// Reads the trusted list back and marks every loaded device as known.
    ///
    /// Devices already in the database are not news, so the first sweep
    /// after a restart sets their state silently instead of reporting them.
    pub(crate) fn load_presence_from_db(&mut self) -> std::io::Result<()> {
        {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT mac_address FROM trusted_devices;")
                .map_err(std::io::Error::other)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(std::io::Error::other)?;
            for mac in rows.flatten() {
                self.trusted.insert(mac);
            }
        }
        self.known_macs.extend(self.devices.keys().cloned());
        for (mac, device) in self.devices.iter_mut() {
            device.trusted = self.trusted.contains(mac);
        }
        Ok(())
    }

    /// Whether the device is on the trusted list.
    pub fn is_trusted(&self, mac: &str) -> bool {
        self.trusted.contains(&normalize_device_identifier(mac))
    }

    /// Number of devices on the trusted list, tracked or not.
    pub fn trusted_count(&self) -> usize {
        self.trusted.len()
    }

    /// Adds the device to the trusted list, or takes it off.
    ///
    /// Returns `false` when the device is neither tracked nor already on the
    /// list, so a typo in a MAC does not create a silent entry.
    pub fn set_trusted(&mut self, mac: &str, trusted: bool) -> std::io::Result<bool> {
        let key = normalize_device_identifier(mac);
        if !self.devices.contains_key(&key) && !self.trusted.contains(&key) {
            return Ok(false);
        }

        {
            let conn = self.conn.lock().unwrap();
            if trusted {
                conn.execute(
                    "INSERT OR IGNORE INTO trusted_devices (mac_address, trusted_at)
                     VALUES (?, ?);",
                    params![key, format_timestamp(SystemTime::now())],
                )
            } else {
                conn.execute(
                    "DELETE FROM trusted_devices WHERE mac_address = ?;",
                    params![key],
                )
            }
            .map_err(|e| std::io::Error::other(format!("Failed to save trust: {}", e)))?;
        }

        if trusted {
            self.trusted.insert(key.clone());
        } else {
            self.trusted.remove(&key);
        }
        if let Some(device) = self.devices.get_mut(&key) {
            device.trusted = trusted;
        }
        Ok(true)
    }

    /// Trusts every device tracked right now. Returns how many were added.
    ///
    /// Meant for the end of a first run: once LANwatch has seen the household,
    /// one call marks all of it as known, so alerts only fire for strangers.
    pub fn trust_all(&mut self) -> std::io::Result<usize> {
        let new: Vec<String> = self
            .devices
            .keys()
            .filter(|mac| !self.trusted.contains(*mac))
            .cloned()
            .collect();
        if new.is_empty() {
            return Ok(0);
        }

        let now = format_timestamp(SystemTime::now());
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction().map_err(|e| {
                std::io::Error::other(format!("Failed to start transaction: {}", e))
            })?;
            for mac in &new {
                tx.execute(
                    "INSERT OR IGNORE INTO trusted_devices (mac_address, trusted_at)
                     VALUES (?, ?);",
                    params![mac, now],
                )
                .map_err(|e| std::io::Error::other(format!("Failed to save trust: {}", e)))?;
            }
            tx.commit()
                .map_err(|e| std::io::Error::other(format!("Failed to save trust: {}", e)))?;
        }

        for mac in &new {
            self.trusted.insert(mac.clone());
            if let Some(device) = self.devices.get_mut(mac) {
                device.trusted = true;
            }
        }
        Ok(new.len())
    }

    /// Compares every device against the offline threshold and reports changes.
    ///
    /// Each change is reported once and written to `presence_events`. A device
    /// seen for the first time gives `new` only, not `new` and `online`.
    /// Devices loaded from the database get their state set silently on the
    /// first sweep. A database error is returned after the in-memory state is
    /// updated, so a failed write never makes the same event fire twice.
    pub fn sweep_presence(
        &mut self,
        now: SystemTime,
        offline_after: Duration,
    ) -> std::io::Result<Vec<PresenceEvent>> {
        let mut events = Vec::new();
        let at = format_timestamp(now);

        for (mac, device) in self.devices.iter_mut() {
            let age = now.duration_since(device.last_seen).unwrap_or_default();
            let online = age < offline_after;
            device.online = online;
            device.trusted = self.trusted.contains(mac);

            let kind = match self.online_state.insert(mac.clone(), online) {
                None if self.known_macs.insert(mac.clone()) => Some(PresenceKind::New),
                None => None,
                Some(was_online) if was_online != online => Some(if online {
                    PresenceKind::Online
                } else {
                    PresenceKind::Offline
                }),
                Some(_) => None,
            };

            if let Some(event) = kind {
                events.push(PresenceEvent {
                    mac_address: mac.clone(),
                    event,
                    at: at.clone(),
                    ip_address: (!device.ip_address.is_unspecified())
                        .then(|| device.ip_address.to_string())
                        .or_else(|| device.ipv6_address.map(|ip: IpAddr| ip.to_string())),
                    hostname: device.hostname.clone(),
                    vendor: device.vendor.as_ref().map(|v| v.to_string()),
                    device_type: device.device_type.as_ref().map(|t| t.to_string()),
                    label: device.product_label.clone(),
                    trusted: device.trusted,
                });
            }
        }

        // A removed device must start fresh: if it comes back it is online
        // again, which the next sweep reports.
        let devices = &self.devices;
        self.online_state.retain(|mac, _| devices.contains_key(mac));

        if !events.is_empty() {
            self.store_presence_events(&events, now)?;
        }
        Ok(events)
    }

    /// Appends events and drops the ones older than [`PRESENCE_RETENTION`].
    fn store_presence_events(
        &self,
        events: &[PresenceEvent],
        now: SystemTime,
    ) -> std::io::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| std::io::Error::other(format!("Failed to start transaction: {}", e)))?;
        for event in events {
            tx.execute(
                "INSERT INTO presence_events (mac_address, event, at) VALUES (?, ?, ?);",
                params![event.mac_address, event.event.as_str(), event.at],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to save presence: {}", e)))?;
        }
        // The stored format is fixed-width UTC, so string order is time order.
        let cutoff = format_timestamp(now.checked_sub(PRESENCE_RETENTION).unwrap_or(now));
        tx.execute("DELETE FROM presence_events WHERE at < ?;", params![cutoff])
            .map_err(|e| std::io::Error::other(format!("Failed to prune presence: {}", e)))?;
        tx.commit()
            .map_err(|e| std::io::Error::other(format!("Failed to save presence: {}", e)))
    }

    /// The newest stored events, newest first, optionally for one device.
    ///
    /// Only the stored columns come back; the descriptive fields of each
    /// event are filled from the device as it is now, since the table keeps
    /// no copy of them.
    pub fn presence_history(
        &self,
        mac: Option<&str>,
        limit: usize,
    ) -> std::io::Result<Vec<PresenceEvent>> {
        let limit = limit.min(i64::MAX as usize) as i64;
        let rows: Vec<(String, String, String)> = {
            let conn = self.conn.lock().unwrap();
            let map = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            };
            let result = match mac {
                Some(mac) => conn
                    .prepare(
                        "SELECT mac_address, event, at FROM presence_events
                         WHERE mac_address = ? ORDER BY at DESC, id DESC LIMIT ?;",
                    )
                    .and_then(|mut stmt| {
                        stmt.query_map(params![normalize_device_identifier(mac), limit], map)?
                            .collect()
                    }),
                None => conn
                    .prepare(
                        "SELECT mac_address, event, at FROM presence_events
                         ORDER BY at DESC, id DESC LIMIT ?;",
                    )
                    .and_then(|mut stmt| stmt.query_map(params![limit], map)?.collect()),
            };
            result.map_err(|e| std::io::Error::other(format!("Failed to read presence: {}", e)))?
        };

        Ok(rows
            .into_iter()
            .filter_map(|(mac, event, at)| {
                let event = PresenceKind::parse(&event)?;
                // Re-format so a hand-edited row cannot reach the API unchecked.
                let at = format_timestamp(parse_timestamp(&at)?);
                let device = self.devices.get(&mac);
                Some(PresenceEvent {
                    trusted: self.trusted.contains(&mac),
                    ip_address: device
                        .filter(|d| !d.ip_address.is_unspecified())
                        .map(|d| d.ip_address.to_string()),
                    hostname: device.and_then(|d| d.hostname.clone()),
                    vendor: device.and_then(|d| d.vendor.as_ref().map(|v| v.to_string())),
                    device_type: device.and_then(|d| d.device_type.as_ref().map(|t| t.to_string())),
                    label: device.and_then(|d| d.product_label.clone()),
                    mac_address: mac,
                    event,
                    at,
                })
            })
            .collect())
    }

    /// Drops the trust entry and presence history of one device.
    ///
    /// Part of [`DeviceTracker::forget_device`]. Returns whether anything was
    /// there.
    pub(crate) fn forget_presence(&mut self, key: &str) -> std::io::Result<bool> {
        let had_trust = self.trusted.remove(key);
        self.known_macs.remove(key);
        self.online_state.remove(key);

        let conn = self.conn.lock().unwrap();
        let trust_rows = conn
            .execute(
                "DELETE FROM trusted_devices WHERE mac_address = ?;",
                params![key],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to delete trust: {}", e)))?;
        let event_rows = conn
            .execute(
                "DELETE FROM presence_events WHERE mac_address = ?;",
                params![key],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to delete presence: {}", e)))?;
        Ok(had_trust || trust_rows > 0 || event_rows > 0)
    }
}

/// Runs a shell command for each presence event.
///
/// The command gets the event in environment variables (`LANWATCH_EVENT`,
/// `LANWATCH_MAC`, ...) and as one JSON line on stdin, so a script can use
/// whichever is easier. LANwatch does not wait for it: a slow webhook must
/// never hold up the capture.
#[derive(Debug, Clone)]
pub struct EventHook {
    command: String,
    untrusted_only: bool,
    running: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl EventHook {
    /// A hook that runs `command` through `sh -c`.
    ///
    /// With `untrusted_only`, events about trusted devices are skipped.
    pub fn new(command: impl Into<String>, untrusted_only: bool) -> Self {
        Self {
            command: command.into(),
            untrusted_only,
            running: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Whether this hook would run for the event.
    pub fn wants(&self, event: &PresenceEvent) -> bool {
        !(self.untrusted_only && event.trusted)
    }

    /// How many events were dropped because too many hooks were running.
    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Starts the command for one event and returns without waiting.
    ///
    /// Returns `false` when the event was skipped, dropped, or the command
    /// could not be started.
    pub fn dispatch(&self, event: &PresenceEvent) -> bool {
        if !self.wants(event) {
            return false;
        }
        if self.running.fetch_add(1, Ordering::SeqCst) >= MAX_RUNNING_HOOKS {
            self.running.fetch_sub(1, Ordering::SeqCst);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(&self.command)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .env("LANWATCH_EVENT", event.event.as_str())
            .env("LANWATCH_MAC", &event.mac_address)
            .env("LANWATCH_AT", &event.at)
            .env("LANWATCH_TRUSTED", if event.trusted { "1" } else { "0" });
        let optional = [
            ("LANWATCH_IP", &event.ip_address),
            ("LANWATCH_HOSTNAME", &event.hostname),
            ("LANWATCH_VENDOR", &event.vendor),
            ("LANWATCH_DEVICE_TYPE", &event.device_type),
            ("LANWATCH_LABEL", &event.label),
        ];
        for (name, value) in optional {
            command.env(name, value.as_deref().unwrap_or(""));
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.running.fetch_sub(1, Ordering::SeqCst);
                eprintln!("Warning: Failed to start --on-event command: {}", e);
                return false;
            }
        };

        let json = event_json_line(event);
        let running = Arc::clone(&self.running);
        thread::spawn(move || {
            if let Some(mut stdin) = child.stdin.take() {
                // A script that ignores stdin closes the pipe early; that is fine.
                let _ = stdin.write_all(json.as_bytes());
            }
            match child.wait() {
                Ok(status) if !status.success() => {
                    eprintln!("Warning: --on-event command exited with {}", status);
                }
                Err(e) => eprintln!("Warning: --on-event command failed: {}", e),
                Ok(_) => {}
            }
            running.fetch_sub(1, Ordering::SeqCst);
        });
        true
    }
}

/// The event as one line of JSON, built by hand so the hook does not need
/// the `http-api` feature's `serde_json`.
fn event_json_line(event: &PresenceEvent) -> String {
    fn quote(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }
    fn optional(value: &Option<String>) -> String {
        value.as_deref().map_or_else(|| "null".to_string(), quote)
    }

    format!(
        "{{\"event\":{},\"mac_address\":{},\"at\":{},\"ip_address\":{},\"hostname\":{},\
         \"vendor\":{},\"device_type\":{},\"label\":{},\"trusted\":{}}}\n",
        quote(event.event.as_str()),
        quote(&event.mac_address),
        quote(&event.at),
        optional(&event.ip_address),
        optional(&event.hostname),
        optional(&event.vendor),
        optional(&event.device_type),
        optional(&event.label),
        event.trusted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceInfo;

    fn tracker(name: &str) -> (String, DeviceTracker) {
        let path = format!("/tmp/lanwatch_test_presence_{}.db", name);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path, suffix));
        }
        let tracker = DeviceTracker::new(&path).unwrap();
        (path, tracker)
    }

    fn cleanup(path: &str) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path, suffix));
        }
    }

    fn add(tracker: &mut DeviceTracker, mac: &str, last_seen: SystemTime) {
        let mut device = DeviceInfo::new(mac.to_string(), "192.168.1.50".parse().unwrap(), None);
        device.last_seen = last_seen;
        tracker.devices.insert(mac.to_string(), device);
        tracker
            .dirty_devices
            .lock()
            .unwrap()
            .insert(mac.to_string());
    }

    const MAC: &str = "aa:bb:cc:00:00:01";
    const LIMIT: Duration = Duration::from_secs(600);

    #[test]
    fn a_new_device_is_reported_once_then_goes_offline_and_back() {
        let (path, mut tracker) = tracker("cycle");
        let start = SystemTime::now();
        add(&mut tracker, MAC, start);

        let events = tracker.sweep_presence(start, LIMIT).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, PresenceKind::New);
        assert!(tracker.get_device(MAC).unwrap().online);

        assert!(tracker.sweep_presence(start, LIMIT).unwrap().is_empty());

        let later = start + LIMIT + Duration::from_secs(1);
        let events = tracker.sweep_presence(later, LIMIT).unwrap();
        assert_eq!(events[0].event, PresenceKind::Offline);
        assert!(!tracker.get_device(MAC).unwrap().online);

        tracker.devices.get_mut(MAC).unwrap().last_seen = later;
        let events = tracker.sweep_presence(later, LIMIT).unwrap();
        assert_eq!(events[0].event, PresenceKind::Online);

        let history = tracker.presence_history(Some(MAC), 10).unwrap();
        let kinds: Vec<_> = history.iter().map(|e| e.event).collect();
        assert_eq!(
            kinds,
            [
                PresenceKind::Online,
                PresenceKind::Offline,
                PresenceKind::New
            ]
        );
        cleanup(&path);
    }

    #[test]
    fn devices_loaded_from_the_database_are_not_new() {
        let (path, mut tracker) = tracker("reload");
        let now = SystemTime::now();
        add(&mut tracker, MAC, now);
        tracker.save_to_db().unwrap();
        drop(tracker);

        let mut tracker = DeviceTracker::new(&path).unwrap();
        assert!(tracker.sweep_presence(now, LIMIT).unwrap().is_empty());
        cleanup(&path);
    }

    #[test]
    fn trust_survives_a_restart_and_reaches_the_event() {
        let (path, mut tracker) = tracker("trust");
        let now = SystemTime::now();
        add(&mut tracker, MAC, now);
        tracker.save_to_db().unwrap();

        assert!(!tracker.set_trusted("aa:bb:cc:99:99:99", true).unwrap());
        assert!(tracker.set_trusted("AA:BB:CC:00:00:01", true).unwrap());
        assert!(tracker.get_device(MAC).unwrap().trusted);
        drop(tracker);

        let mut tracker = DeviceTracker::new(&path).unwrap();
        assert!(tracker.is_trusted(MAC));
        assert!(tracker.get_device(MAC).unwrap().trusted);

        let later = now + LIMIT;
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        let events = tracker.sweep_presence(later, LIMIT).unwrap();
        assert!(events[0].trusted);

        assert!(tracker.set_trusted(MAC, false).unwrap());
        assert!(!tracker.is_trusted(MAC));
        cleanup(&path);
    }

    #[test]
    fn trust_all_marks_every_tracked_device() {
        let (path, mut tracker) = tracker("trust_all");
        let now = SystemTime::now();
        add(&mut tracker, MAC, now);
        add(&mut tracker, "aa:bb:cc:00:00:02", now);
        assert_eq!(tracker.trust_all().unwrap(), 2);
        assert_eq!(tracker.trust_all().unwrap(), 0);
        assert_eq!(tracker.trusted_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn forgetting_a_device_drops_its_trust_and_history() {
        let (path, mut tracker) = tracker("forget");
        let now = SystemTime::now();
        add(&mut tracker, MAC, now);
        let _ = tracker.sweep_presence(now, LIMIT).unwrap();
        tracker.set_trusted(MAC, true).unwrap();

        assert!(tracker.forget_device(MAC).unwrap());
        assert!(!tracker.is_trusted(MAC));
        assert!(tracker.presence_history(Some(MAC), 10).unwrap().is_empty());

        // Forgotten means forgotten: coming back is news again.
        add(&mut tracker, MAC, now);
        let events = tracker.sweep_presence(now, LIMIT).unwrap();
        assert_eq!(events[0].event, PresenceKind::New);
        cleanup(&path);
    }

    #[test]
    fn the_hook_skips_trusted_devices_when_asked() {
        let event = PresenceEvent {
            mac_address: MAC.to_string(),
            event: PresenceKind::Online,
            at: "2026-01-01T00:00:00Z".to_string(),
            ip_address: None,
            hostname: Some("a \"quoted\"\nname".to_string()),
            vendor: None,
            device_type: None,
            label: None,
            trusted: true,
        };
        assert!(!EventHook::new("true", true).wants(&event));
        assert!(EventHook::new("true", false).wants(&event));

        let line = event_json_line(&event);
        assert!(
            line.contains(r#""hostname":"a \"quoted\"\u000aname""#),
            "{}",
            line
        );
        assert!(line.ends_with("\"trusted\":true}\n"));
    }

    #[test]
    fn the_hook_receives_the_event_in_its_environment() {
        let dir = std::env::temp_dir().join(format!("lanwatch_hook_{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let hook = EventHook::new(
            format!(
                "printf '%s %s' \"$LANWATCH_EVENT\" \"$LANWATCH_MAC\" > '{}'",
                dir.display()
            ),
            false,
        );
        let event = PresenceEvent {
            mac_address: MAC.to_string(),
            event: PresenceKind::New,
            at: "2026-01-01T00:00:00Z".to_string(),
            ip_address: None,
            hostname: None,
            vendor: None,
            device_type: None,
            label: None,
            trusted: false,
        };
        assert!(hook.dispatch(&event));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut output = String::new();
        while std::time::Instant::now() < deadline {
            output = std::fs::read_to_string(&dir).unwrap_or_default();
            if !output.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&dir);
        assert_eq!(output, format!("new {}", MAC));
    }
}

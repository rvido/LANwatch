// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! UPnP device descriptions, fetched once per device (`--upnp-describe`).
//!
//! An SSDP advertisement carries only a `LOCATION` URL. The XML behind it
//! names the device ("Living Room TV"), its manufacturer and its model. That
//! is far better than anything in the headers, but getting it means LANwatch
//! connects to the device, so it is off unless asked for.
//!
//! Every byte of the reply comes from an untrusted device, and the URL comes
//! from an unauthenticated multicast packet. So the fetch is narrow on
//! purpose: plain HTTP to the address that sent the advertisement, and only
//! when that address is on the LAN; a size cap, a time cap, no redirects, and
//! a path made only of URL-safe characters. The XML is not parsed as a tree;
//! a handful of fields are cut out of the root device and sanitized like any
//! other string off the wire.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{Connection, params};

use crate::device::{format_timestamp, sanitize_display_string};
use crate::parser::ssdp::{SsdpPacket, detect_device_type_in, detect_vendor_in};
use crate::tracker::DeviceTracker;

/// Time allowed to open the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Time allowed for the whole reply. Also bounds a device that sends one
/// byte at a time.
const FETCH_DEADLINE: Duration = Duration::from_secs(5);
/// The largest reply read. Real descriptions are a few kilobytes; anything
/// past this is cut off, and the fields near the top still count.
pub const MAX_DESCRIPTION_BYTES: usize = 64 * 1024;
/// The longest `LOCATION` path accepted.
const MAX_PATH_LEN: usize = 512;
/// Devices waiting for a fetch. Past this, new devices wait for the next run.
const MAX_PENDING: usize = 64;
/// Fetches per run. A flood of spoofed advertisements, each with a new MAC,
/// must not turn LANwatch into a scanner.
const MAX_ATTEMPTS: usize = 1024;
/// How often the fetch thread looks for work.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Fetches per poll, done one after the other.
const FETCHES_PER_POLL: usize = 8;

/// What a device says about itself in its UPnP description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpnpDescription {
    /// `friendlyName`, e.g. "Living Room TV".
    pub friendly_name: Option<String>,
    /// `manufacturer`, e.g. "Samsung Electronics".
    pub manufacturer: Option<String>,
    /// `modelName`, e.g. "UE55TU7100".
    pub model_name: Option<String>,
    /// `modelNumber`.
    pub model_number: Option<String>,
    /// `modelDescription`.
    pub model_description: Option<String>,
    /// `deviceType`, e.g. `urn:schemas-upnp-org:device:MediaRenderer:1`.
    pub device_type: Option<String>,
}

impl UpnpDescription {
    /// Manufacturer and model as one line, e.g. "Sonos, Inc. Sonos One S2".
    ///
    /// Leaves out a part the model name already contains, so "Sonos, Inc."
    /// plus "Sonos One" is "Sonos One", not "Sonos, Inc. Sonos One". The
    /// maker is compared by its first word, without "Inc." and the like.
    pub fn model_summary(&self) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        let model = self.model_name.as_deref();
        if let Some(maker) = self.manufacturer.as_deref()
            && !model.is_some_and(|m| {
                let brand = maker
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .next()
                    .unwrap_or(maker);
                contains_ignore_case(m, brand)
            })
        {
            parts.push(maker);
        }
        if let Some(model) = model {
            parts.push(model);
        }
        if let Some(number) = self.model_number.as_deref()
            && !model.is_some_and(|m| contains_ignore_case(m, number))
        {
            parts.push(number);
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Where to fetch one device's description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnpTarget {
    /// The device's MAC key in the tracker.
    pub mac: String,
    /// Address and port to connect to.
    pub addr: SocketAddr,
    /// Request path, already checked to hold only URL-safe characters.
    pub path: String,
}

/// Whether an address is one LANwatch may connect to for a description:
/// private or link-local IPv4, or unique-local IPv6.
///
/// IPv6 link-local is left out because it needs a scope ID that a URL in a
/// packet cannot be trusted to give.
fn is_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Characters allowed in the request path: RFC 3986 unreserved, `/`, and the
/// few query characters real descriptions use. No space, CR or LF, so the
/// path cannot add a header or a second request.
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '/' | '-' | '.' | '_' | '~' | '?' | '=' | '&' | ':' | '%' | '+'
        )
}

/// Checks a `LOCATION` URL and turns it into a target.
///
/// Returns `None` unless the URL is `http`, names an IP literal equal to
/// `source` (the packet's sender), and that address is on the LAN. A device
/// can describe only itself, so a spoofed packet cannot point LANwatch at the
/// router or at a host on the internet.
pub fn description_target(mac: &str, location: &str, source: IpAddr) -> Option<UpnpTarget> {
    check_target(mac, location, source).ok()
}

/// [`description_target`], with the reason for a refusal, for the log.
fn check_target(mac: &str, location: &str, source: IpAddr) -> Result<UpnpTarget, &'static str> {
    const MALFORMED: &str = "malformed URL";
    let location = location.trim();
    // `get` rather than indexing: the URL comes off the wire and may hold a
    // multi-byte character that a fixed byte offset would split.
    let scheme_len = "http://".len();
    if !location
        .get(..scheme_len)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
    {
        return Err("not an http:// URL");
    }
    let rest = &location[scheme_len..];
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    // No user info, which could hide the real host from a reader.
    if authority.contains('@') {
        return Err("user info in URL");
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or(MALFORMED)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(MALFORMED)?),
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let ip: IpAddr = host
        .parse()
        .map_err(|_| "host is a name, not an IP address")?;
    let port: u16 = match port {
        None => 80,
        Some(p) => p.parse().ok().filter(|&p| p != 0).ok_or("bad port")?,
    };

    // Compare after unmapping, so an IPv4 sender matches `::ffff:a.b.c.d`.
    let canonical = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    let ip = canonical(ip);
    if ip != canonical(source) {
        return Err("URL host is not the sender's address");
    }
    if !is_lan_address(ip) {
        return Err("address is not private or link-local");
    }

    if path.is_empty() || path.len() > MAX_PATH_LEN || !path.chars().all(is_path_char) {
        return Err("path has characters that are not allowed");
    }

    Ok(UpnpTarget {
        mac: mac.to_string(),
        addr: SocketAddr::new(ip, port),
        path: path.to_string(),
    })
}

/// Fetches the description at `target` and parses it.
///
/// Errors cover the network, a status other than 200, and a reply with none
/// of the fields.
pub fn fetch_description(target: &UpnpTarget) -> std::io::Result<UpnpDescription> {
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&target.addr, CONNECT_TIMEOUT)?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    let host = match target.addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    };
    // HTTP/1.0 with `Connection: close`: the body ends when the socket does,
    // and most devices then send no chunked encoding.
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: LANwatch/{}\r\nAccept: text/xml, application/xml\r\nConnection: close\r\n\r\n",
        target.path,
        host,
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];
    while response.len() < MAX_DESCRIPTION_BYTES {
        let left = FETCH_DEADLINE
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "reply too slow"))?;
        stream.set_read_timeout(Some(left))?;
        let want = chunk.len().min(MAX_DESCRIPTION_BYTES - response.len());
        match stream.read(&mut chunk[..want])? {
            0 => break,
            n => response.extend_from_slice(&chunk[..n]),
        }
    }

    let body = http_body(&response)?;
    let description = parse_description(&String::from_utf8_lossy(&body));
    if description.is_empty() {
        return Err(std::io::Error::other("no description fields in reply"));
    }
    Ok(description)
}

/// Splits an HTTP reply and returns its body, undoing chunked encoding.
fn http_body(response: &[u8]) -> std::io::Result<Vec<u8>> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no end of HTTP headers"))?;
    let head = String::from_utf8_lossy(&response[..split]);
    let body = &response[split + 4..];

    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code = status.split_whitespace().nth(1);
    if !status.starts_with("HTTP/") || code != Some("200") {
        return Err(std::io::Error::other(format!(
            "HTTP status {}",
            code.unwrap_or("missing")
        )));
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    Ok(if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    })
}

/// Undoes chunked transfer encoding, stopping at the first malformed or cut
/// off chunk and keeping what came before it.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    while let Some(eol) = body.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&body[..eol]);
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        body = &body[eol + 2..];
        if size == 0 {
            break;
        }
        let take = size.min(body.len());
        out.extend_from_slice(&body[..take]);
        if take < size {
            break;
        }
        body = body.get(size + 2..).unwrap_or_default();
    }
    out
}

/// Cuts the root device's fields out of a description document.
///
/// Only the part between the first `<device>` and its `<deviceList>` (the
/// embedded devices) is searched, so a sub-device's name never stands in for
/// the root's. Missing or empty fields stay `None`.
pub fn parse_description(xml: &str) -> UpnpDescription {
    let Some(start) = find_open_tag(xml, "device", 0) else {
        return UpnpDescription::default();
    };
    let end = find_open_tag(xml, "deviceList", start).unwrap_or(xml.len());
    let root = &xml[start..end];
    UpnpDescription {
        friendly_name: tag_text(root, "friendlyName"),
        manufacturer: tag_text(root, "manufacturer"),
        model_name: tag_text(root, "modelName"),
        model_number: tag_text(root, "modelNumber"),
        model_description: tag_text(root, "modelDescription"),
        device_type: tag_text(root, "deviceType"),
    }
}

/// Byte offset just past the first `<name>` or `<name …>` at or after `from`.
fn find_open_tag(xml: &str, name: &str, from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(i) = xml.get(at..)?.find('<') {
        let tag = at + i + 1;
        at = tag;
        let Some(rest) = xml[tag..].strip_prefix(name) else {
            continue;
        };
        match rest.chars().next() {
            Some('>') => return Some(tag + name.len() + 1),
            Some(c) if c.is_ascii_whitespace() => {
                let close = rest.find('>')?;
                return Some(tag + name.len() + close + 1);
            }
            _ => continue,
        }
    }
    None
}

/// The text of the first `<name>…</name>` in `xml`, decoded and sanitized.
fn tag_text(xml: &str, name: &str) -> Option<String> {
    let start = find_open_tag(xml, name, 0)?;
    let close = format!("</{}>", name);
    let len = xml[start..].find(&close)?;
    let raw = xml[start..start + len].trim();
    let raw = raw
        .strip_prefix("<![CDATA[")
        .and_then(|r| r.strip_suffix("]]>"))
        .map(|r| r.to_string())
        .unwrap_or_else(|| decode_entities(raw));
    sanitize_display_string(&raw)
}

/// Decodes the five XML entities and numeric character references. An
/// unknown or invalid reference is kept as written.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.get(1..).and_then(|after| {
            let semi = after.find(';').filter(|&s| s <= 10)?;
            let entity = &after[..semi];
            let c = match entity {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let code = if let Some(hex) = entity
                        .strip_prefix("#x")
                        .or_else(|| entity.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok()?
                    } else {
                        entity.strip_prefix('#')?.parse().ok()?
                    };
                    char::from_u32(code)?
                }
            };
            Some((c, semi + 2))
        });
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &rest[used..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

impl DeviceTracker {
    /// Creates the description table. Safe to run on every startup.
    pub(crate) fn create_upnp_schema(conn: &Connection) -> std::io::Result<()> {
        // Kept apart from `devices`, so a description survives the device
        // being removed from the dashboard and is not fetched again.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS upnp_descriptions (
                mac_address       TEXT PRIMARY KEY,
                friendly_name     TEXT,
                manufacturer      TEXT,
                model_name        TEXT,
                model_number      TEXT,
                model_description TEXT,
                device_type       TEXT,
                fetched_at        TEXT NOT NULL
            );",
            [],
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create UPnP schema: {}", e)))?;
        Ok(())
    }

    /// Reads stored descriptions back and names the loaded devices.
    pub(crate) fn load_upnp_from_db(&mut self) -> std::io::Result<()> {
        {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT mac_address, friendly_name, manufacturer, model_name,
                            model_number, model_description, device_type
                     FROM upnp_descriptions;",
                )
                .map_err(std::io::Error::other)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        UpnpDescription {
                            friendly_name: row.get(1)?,
                            manufacturer: row.get(2)?,
                            model_name: row.get(3)?,
                            model_number: row.get(4)?,
                            model_description: row.get(5)?,
                            device_type: row.get(6)?,
                        },
                    ))
                })
                .map_err(std::io::Error::other)?;
            for (mac, description) in rows.flatten() {
                self.upnp_descriptions.insert(mac, description);
            }
        }
        for (mac, device) in self.devices.iter_mut() {
            if let Some(description) = self.upnp_descriptions.get(mac) {
                device.friendly_name = description.friendly_name.clone();
            }
        }
        Ok(())
    }

    /// Turns description fetching on or off. Off by default.
    pub fn set_upnp_describe(&mut self, enabled: bool) {
        self.upnp_describe_enabled = enabled;
    }

    /// The stored description of a device, if one was fetched.
    pub fn upnp_description(&self, mac: &str) -> Option<&UpnpDescription> {
        self.upnp_descriptions
            .get(&crate::device::normalize_device_identifier(mac))
    }

    /// Called for each SSDP packet: names the device from a stored
    /// description, or queues a fetch if there is none yet.
    pub(crate) fn note_upnp_location(&mut self, mac: &str, packet: &SsdpPacket) {
        if let Some(description) = self.upnp_descriptions.get(mac) {
            if let Some(device) = self.devices.get_mut(mac)
                && device.friendly_name != description.friendly_name
            {
                device.friendly_name = description.friendly_name.clone();
            }
            return;
        }
        if !self.upnp_describe_enabled
            || self.upnp_attempted.contains(mac)
            || self.upnp_attempted.len() >= MAX_ATTEMPTS
            || self.upnp_pending.len() >= MAX_PENDING
        {
            return;
        }
        let Some(location) = packet.header("location") else {
            return;
        };
        // One try per device per run, whether the URL passes or not, so a
        // device that keeps advertising a bad URL is not rechecked forever.
        self.upnp_attempted.insert(mac.to_string());
        match check_target(mac, location, packet.source_ip) {
            Ok(target) => self.upnp_pending.push(target),
            Err(reason) => self.upnp_skipped.push(format!(
                "UPnP: skipped {} (from {}): {}: {}",
                mac,
                packet.source_ip,
                reason,
                crate::device::display_safe(location)
            )),
        }
    }

    /// Takes the log lines for refused `LOCATION` URLs. At most one per
    /// device per run, so the list stays small.
    pub(crate) fn take_upnp_skipped(&mut self) -> Vec<String> {
        std::mem::take(&mut self.upnp_skipped)
    }

    /// Takes up to `max` queued fetches.
    pub fn take_upnp_targets(&mut self, max: usize) -> Vec<UpnpTarget> {
        let n = max.min(self.upnp_pending.len());
        self.upnp_pending.drain(..n).collect()
    }

    /// Stores a fetched description and applies it to the device.
    ///
    /// The friendly name is always shown. The model goes into the system
    /// description only if nothing else filled it. Vendor and type follow the
    /// same replace rules as SSDP headers, and overrides are applied last, so
    /// they still win.
    pub fn store_upnp_description(
        &mut self,
        mac: &str,
        description: UpnpDescription,
    ) -> std::io::Result<()> {
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO upnp_descriptions
                    (mac_address, friendly_name, manufacturer, model_name,
                     model_number, model_description, device_type, fetched_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                params![
                    mac,
                    description.friendly_name,
                    description.manufacturer,
                    description.model_name,
                    description.model_number,
                    description.model_description,
                    description.device_type,
                    format_timestamp(SystemTime::now()),
                ],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to save description: {}", e)))?;
        }

        let oui_vendor = self
            .oui_registry
            .as_ref()
            .and_then(|registry| registry.lookup(mac));
        if let Some(device) = self.devices.get_mut(mac) {
            device.friendly_name = description.friendly_name.clone();

            if device.system_description.is_none() {
                device.system_description = description.model_summary();
            }

            // The friendly name is left out: a person typed it, and "Sony
            // speaker in Bob's room" says nothing about who made this device.
            let texts: Vec<&str> = [
                &description.manufacturer,
                &description.model_name,
                &description.model_description,
                &description.device_type,
            ]
            .into_iter()
            .filter_map(|field| field.as_deref())
            .collect();

            if let Some(v) = detect_vendor_in(&texts)
                && Self::should_replace_vendor(device.vendor.as_ref(), &v, oui_vendor)
                && !(Self::eero_protected(device, oui_vendor, false) && !v.is_eero())
            {
                device.vendor = Some(v);
            }
            if let Some(t) = detect_device_type_in(&texts)
                && Self::should_replace_device_type(device, &t)
                && !Self::eero_protected(device, oui_vendor, false)
            {
                device.device_type = Some(t);
            }
            self.dirty_devices.lock().unwrap().insert(mac.to_string());
        }
        self.upnp_descriptions.insert(mac.to_string(), description);
        self.apply_override_to(mac);

        if self.auto_save {
            self.save_to_db()?;
        }
        Ok(())
    }

    /// Moves a description to the device's new MAC, unless it has its own.
    /// Part of a random-MAC merge.
    pub(crate) fn move_upnp_description(&mut self, old: &str, new: &str) -> std::io::Result<()> {
        let Some(description) = self.upnp_descriptions.remove(old) else {
            return Ok(());
        };
        let conn = self.conn.lock().unwrap();
        let fail = |e: rusqlite::Error| std::io::Error::other(format!("Failed to merge: {}", e));
        if self.upnp_descriptions.contains_key(new) {
            conn.execute(
                "DELETE FROM upnp_descriptions WHERE mac_address = ?;",
                params![old],
            )
            .map_err(fail)?;
        } else {
            conn.execute(
                "UPDATE upnp_descriptions SET mac_address = ? WHERE mac_address = ?;",
                params![new, old],
            )
            .map_err(fail)?;
            if let Some(device) = self.devices.get_mut(new) {
                device.friendly_name = description.friendly_name.clone();
            }
            self.upnp_descriptions.insert(new.to_string(), description);
        }
        Ok(())
    }

    /// Drops a device's description. Part of [`DeviceTracker::forget_device`].
    pub(crate) fn forget_upnp(&mut self, key: &str) -> std::io::Result<bool> {
        let had = self.upnp_descriptions.remove(key).is_some();
        self.upnp_attempted.remove(key);
        self.upnp_pending.retain(|target| target.mac != key);
        let rows = self
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM upnp_descriptions WHERE mac_address = ?;",
                params![key],
            )
            .map_err(|e| std::io::Error::other(format!("Failed to delete description: {}", e)))?;
        Ok(had || rows > 0)
    }
}

/// Starts the thread that fetches queued descriptions.
///
/// The tracker lock is held only to take work and to store results, never
/// during a fetch, so a slow device cannot stall the capture loop.
pub fn start_upnp_describer(tracker: Arc<RwLock<DeviceTracker>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut failed: HashSet<String> = HashSet::new();
        loop {
            thread::sleep(POLL_INTERVAL);
            let (targets, skipped) = match tracker.write() {
                Ok(mut tracker) => (
                    tracker.take_upnp_targets(FETCHES_PER_POLL),
                    tracker.take_upnp_skipped(),
                ),
                Err(_) => return,
            };
            for line in skipped {
                println!("{}", line);
            }
            for target in targets {
                match fetch_description(&target) {
                    Ok(description) => {
                        let name = description
                            .friendly_name
                            .clone()
                            .or_else(|| description.model_summary())
                            .unwrap_or_default();
                        let stored = match tracker.write() {
                            Ok(mut tracker) => {
                                tracker.store_upnp_description(&target.mac, description)
                            }
                            Err(_) => return,
                        };
                        match stored {
                            Ok(()) => println!(
                                "UPnP: {} is \"{}\"",
                                target.mac,
                                crate::device::display_safe(&name)
                            ),
                            Err(e) => eprintln!("Warning: {}", e),
                        }
                    }
                    // One warning per device, not one per retry of the run.
                    Err(e) if failed.insert(target.mac.clone()) => eprintln!(
                        "UPnP: fetch from {} at {} failed: {}",
                        target.mac, target.addr, e
                    ),
                    Err(_) => {}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    const MAC: &str = "aa:bb:cc:dd:ee:ff";
    const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room &amp; Kitchen</friendlyName>
    <manufacturer>Sonos, Inc.</manufacturer>
    <modelName>Sonos One</modelName>
    <modelNumber>S18</modelNumber>
    <modelDescription><![CDATA[Sonos One <speaker>]]></modelDescription>
    <deviceList>
      <device>
        <friendlyName>Embedded Renderer</friendlyName>
        <modelName>Other</modelName>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn parses_only_the_root_device() {
        let d = parse_description(SAMPLE);
        assert_eq!(d.friendly_name.as_deref(), Some("Living Room & Kitchen"));
        assert_eq!(d.manufacturer.as_deref(), Some("Sonos, Inc."));
        assert_eq!(d.model_name.as_deref(), Some("Sonos One"));
        assert_eq!(d.model_number.as_deref(), Some("S18"));
        assert_eq!(d.model_description.as_deref(), Some("Sonos One <speaker>"));
        assert_eq!(
            d.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(d.model_summary().as_deref(), Some("Sonos One S18"));

        let d = UpnpDescription {
            manufacturer: Some("Samsung Electronics".into()),
            model_name: Some("UE55TU7100".into()),
            model_number: Some("UE55TU7100".into()),
            ..Default::default()
        };
        assert_eq!(
            d.model_summary().as_deref(),
            Some("Samsung Electronics UE55TU7100")
        );
    }

    #[test]
    fn hostile_xml_is_sanitized_or_ignored() {
        // Control characters, a bidi override, an unclosed tag, and a bad
        // entity must not panic or leak through.
        let xml = "<device><friendlyName>Evil\u{202E}\r\nName&#0;&bogus;&#x41;</friendlyName><modelName>never closed";
        let d = parse_description(xml);
        assert_eq!(d.friendly_name.as_deref(), Some("EvilName&bogus;A"));
        assert_eq!(d.model_name, None);
        assert!(parse_description("").is_empty());
        assert!(parse_description("<devices><friendlyName>x</friendlyName>").is_empty());
        assert!(parse_description("<device").is_empty());
        assert!(parse_description("&&&<<<>>>&#xFFFFFFFFFF;").is_empty());
    }

    #[test]
    fn long_fields_are_capped() {
        let xml = format!(
            "<device><friendlyName>{}</friendlyName>",
            "a".repeat(10_000)
        );
        let name = parse_description(&xml).friendly_name.unwrap();
        assert_eq!(name.chars().count(), 255);
    }

    #[test]
    fn only_the_sender_on_the_lan_is_a_target() {
        let target = description_target(MAC, "http://192.168.1.20:49152/desc.xml", SOURCE).unwrap();
        assert_eq!(target.addr, "192.168.1.20:49152".parse().unwrap());
        assert_eq!(target.path, "/desc.xml");

        let target = description_target(MAC, "HTTP://192.168.1.20", SOURCE).unwrap();
        assert_eq!(target.addr.port(), 80);
        assert_eq!(target.path, "/");

        let windows = "http://192.168.1.20:2869/upnphost/udhisapi.dll?content=uuid:1234-abcd";
        assert!(description_target(MAC, windows, SOURCE).is_some());

        for bad in [
            // Another host, on the LAN or not.
            "http://192.168.1.1/desc.xml",
            "http://8.8.8.8/desc.xml",
            "http://localhost/desc.xml",
            "http://router.lan/desc.xml",
            // Other schemes and user info.
            "https://192.168.1.20/desc.xml",
            "file:///etc/passwd",
            "http://evil@192.168.1.20/desc.xml",
            // Bad ports.
            "http://192.168.1.20:0/",
            "http://192.168.1.20:99999/",
            "http://192.168.1.20:/",
            // Header injection through the path.
            "http://192.168.1.20/a\r\nX-Evil: 1",
            "http://192.168.1.20/a b",
            // Non-ASCII, including a character across the scheme's end.
            "http:/\u{FFFD}192.168.1.20/",
            "http://192.168.1.20/caf\u{e9}.xml",
            "\u{e9}",
        ] {
            assert_eq!(description_target(MAC, bad, SOURCE), None, "{bad}");
        }

        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(description_target(MAC, "http://8.8.8.8/", public), None);
        let long = format!("http://192.168.1.20/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(description_target(MAC, &long, SOURCE), None);
    }

    #[test]
    fn ipv6_targets_must_be_unique_local() {
        let ula: IpAddr = "fd00::20".parse().unwrap();
        let target = description_target(MAC, "http://[fd00::20]:8080/d.xml", ula).unwrap();
        assert_eq!(target.addr, "[fd00::20]:8080".parse().unwrap());
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(
            description_target(MAC, "http://[fe80::1]/", link_local),
            None
        );
        let global: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            description_target(MAC, "http://[2001:db8::1]/", global),
            None
        );
    }

    #[test]
    fn http_bodies_and_chunks() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<device/>";
        assert_eq!(http_body(ok).unwrap(), b"<device/>");
        assert!(http_body(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
        assert!(http_body(b"HTTP/1.1 301 Moved\r\nLocation: http://x/\r\n\r\n").is_err());
        assert!(http_body(b"garbage").is_err());

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<dev\r\n5;x=y\r\nice/>\r\n0\r\n\r\n";
        assert_eq!(http_body(chunked).unwrap(), b"<device/>");
        // A chunk size larger than what arrived keeps what did arrive.
        assert_eq!(dechunk(b"ffffffff\r\nabc"), b"abc");
        assert_eq!(dechunk(b"zz\r\nabc"), b"");
        assert_eq!(dechunk(b"ffffffffffffffffffffffff\r\nabc"), b"");
    }

    /// Serves `reply` once on a local port, then returns the request seen.
    fn serve_once(reply: Vec<u8>) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            let _ = stream.write_all(&reply);
            String::from_utf8_lossy(&request).into_owned()
        });
        (addr, handle)
    }

    #[test]
    fn fetches_a_description_over_http() {
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n{SAMPLE}");
        let (addr, server) = serve_once(reply.into_bytes());
        let target = UpnpTarget {
            mac: MAC.to_string(),
            addr,
            path: "/desc.xml".to_string(),
        };
        let description = fetch_description(&target).unwrap();
        assert_eq!(description.model_name.as_deref(), Some("Sonos One"));
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /desc.xml HTTP/1.0\r\n"));
        assert!(request.contains(&format!("Host: {}\r\n", addr)));
    }

    #[test]
    fn oversized_replies_are_cut_off() {
        let mut reply = b"HTTP/1.1 200 OK\r\n\r\n<device><friendlyName>Big</friendlyName>".to_vec();
        reply.extend(std::iter::repeat_n(b'x', MAX_DESCRIPTION_BYTES * 2));
        let (addr, server) = serve_once(reply);
        let target = UpnpTarget {
            mac: MAC.to_string(),
            addr,
            path: "/".to_string(),
        };
        let description = fetch_description(&target).unwrap();
        assert_eq!(description.friendly_name.as_deref(), Some("Big"));
        server.join().unwrap();
    }

    fn tracker() -> (DeviceTracker, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "lanwatch_upnp_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        (DeviceTracker::new(&path).unwrap(), path)
    }

    fn ssdp_packet(location: &str) -> SsdpPacket {
        let payload = format!(
            "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: {location}\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: uuid:1234::upnp:rootdevice\r\n\r\n"
        );
        crate::parser::ssdp::parse_ssdp_payload(
            payload.as_bytes(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            SOURCE,
            "239.255.255.250".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn fetching_is_off_by_default_and_tried_once_per_device() {
        let (mut tracker, path) = tracker();
        let packet = ssdp_packet("http://192.168.1.20:1400/xml/device_description.xml");

        tracker.update_from_ssdp(&packet);
        assert!(tracker.take_upnp_targets(8).is_empty());

        tracker.set_upnp_describe(true);
        tracker.update_from_ssdp(&packet);
        tracker.update_from_ssdp(&packet);
        let targets = tracker.take_upnp_targets(8);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].mac, MAC);
        assert_eq!(targets[0].path, "/xml/device_description.xml");

        // Not again in the same run, even though it failed or is pending.
        tracker.update_from_ssdp(&packet);
        assert!(tracker.take_upnp_targets(8).is_empty());
        assert!(tracker.take_upnp_skipped().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_refused_location_is_logged_once_with_the_reason() {
        let (mut tracker, path) = tracker();
        tracker.set_upnp_describe(true);
        let packet = ssdp_packet("http://192.168.1.1:1900/gateway.xml");
        tracker.update_from_ssdp(&packet);
        tracker.update_from_ssdp(&packet);
        assert!(tracker.take_upnp_targets(8).is_empty());
        let skipped = tracker.take_upnp_skipped();
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].starts_with("UPnP: skipped aa:bb:cc:dd:ee:ff"));
        assert!(skipped[0].contains("not the sender's address"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_description_names_the_device_and_survives_a_restart() {
        let (mut tracker, path) = tracker();
        tracker.update_from_ssdp(&ssdp_packet("http://192.168.1.20/d.xml"));
        tracker
            .store_upnp_description(MAC, parse_description(SAMPLE))
            .unwrap();

        let device = tracker.get_device(MAC).unwrap();
        assert_eq!(
            device.friendly_name.as_deref(),
            Some("Living Room & Kitchen")
        );
        assert_eq!(device.system_description.as_deref(), Some("Sonos One S18"));
        assert_eq!(device.vendor, Some(crate::types::Vendor::Sonos));
        drop(tracker);

        let tracker = DeviceTracker::new(&path).unwrap();
        let device = tracker.get_device(MAC).unwrap();
        assert_eq!(
            device.friendly_name.as_deref(),
            Some("Living Room & Kitchen")
        );
        assert!(tracker.upnp_description(MAC).is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn overrides_beat_the_description() {
        let (mut tracker, path) = tracker();
        tracker.update_from_ssdp(&ssdp_packet("http://192.168.1.20/d.xml"));
        tracker.add_override(MAC, Some(crate::types::DeviceType::Nas), None);
        tracker
            .store_upnp_description(MAC, parse_description(SAMPLE))
            .unwrap();
        let device = tracker.get_device(MAC).unwrap();
        assert_eq!(device.device_type, Some(crate::types::DeviceType::Nas));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn forgetting_a_device_drops_its_description() {
        let (mut tracker, path) = tracker();
        tracker.update_from_ssdp(&ssdp_packet("http://192.168.1.20/d.xml"));
        tracker
            .store_upnp_description(MAC, parse_description(SAMPLE))
            .unwrap();
        assert!(tracker.forget_device(MAC).unwrap());
        assert!(tracker.upnp_description(MAC).is_none());
        let _ = std::fs::remove_file(path);
    }
}

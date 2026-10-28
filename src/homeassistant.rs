// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! Home Assistant integration over MQTT.
//!
//! Every tracked device becomes a Home Assistant `device_tracker` entity
//! through MQTT discovery, with state `home` or `not_home` from the presence
//! sweep. Everything is published retained, so a Home Assistant restart
//! needs nothing from LANwatch: the broker hands the last state back.
//!
//! The bridge polls the tracker instead of being fed events. It publishes a
//! message only when its payload changed since the last one, so polling every
//! few seconds costs nothing on the wire, and a reconnect simply clears that
//! memory and sends everything again.
//!
//! The MQTT client is a minimal MQTT 3.1.1 publisher written here, not a
//! dependency: CONNECT with a last will, QoS 0 PUBLISH, PINGREQ. LANwatch
//! never subscribes. There is no TLS, so the broker should be on the same
//! trusted network; the password travels in clear text.

#![cfg(feature = "homeassistant")]

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::device::{DeviceInfo, format_timestamp};
use crate::tracker::DeviceTracker;

/// The broker's default port for plain MQTT.
pub const DEFAULT_MQTT_PORT: u16 = 1883;

/// Home Assistant's default discovery prefix.
pub const DEFAULT_DISCOVERY_PREFIX: &str = "homeassistant";

/// Topic root for LANwatch's own state and attribute topics.
pub const DEFAULT_BASE_TOPIC: &str = "lanwatch";

/// How often the bridge compares the tracker with what it last published.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The keep-alive LANwatch asks the broker for.
const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// Silence after which a PINGREQ is sent, well inside [`KEEP_ALIVE`].
const PING_AFTER: Duration = Duration::from_secs(30);

/// First and longest wait between connection attempts.
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

/// How long a connect or a CONNACK may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The vendor the OUI registry reports for every private MAC. It names the
/// address, not a manufacturer, so it is not sent as one.
const PRIVATE_MAC_VENDOR: &str = "Private MAC Address";

/// Where and how to publish.
#[derive(Debug, Clone)]
pub struct HomeAssistantConfig {
    /// Broker host name or IP address.
    pub host: String,
    /// Broker port.
    pub port: u16,
    /// User name, if the broker needs one.
    pub username: Option<String>,
    /// Password, if the broker needs one.
    pub password: Option<String>,
    /// MQTT client ID. Must be unique on the broker.
    pub client_id: String,
    /// Home Assistant's discovery prefix.
    pub discovery_prefix: String,
    /// Root of LANwatch's own topics.
    pub base_topic: String,
    /// Publish only devices on the trusted list.
    pub trusted_only: bool,
}

impl HomeAssistantConfig {
    /// A config for `host:port` with every other field at its default.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            username: None,
            password: None,
            client_id: "lanwatch".to_string(),
            discovery_prefix: DEFAULT_DISCOVERY_PREFIX.to_string(),
            base_topic: DEFAULT_BASE_TOPIC.to_string(),
            trusted_only: false,
        }
    }

    /// The topic that says whether LANwatch is running.
    fn availability_topic(&self) -> String {
        format!("{}/status", self.base_topic)
    }
}

/// The broker's answer to CONNECT (MQTT 3.1.1, section 3.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectReturnCode {
    Accepted,
    UnacceptableProtocolVersion,
    IdentifierRejected,
    ServerUnavailable,
    BadUsernameOrPassword,
    NotAuthorized,
    Unknown(u8),
}

impl From<u8> for ConnectReturnCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnectReturnCode::Accepted,
            1 => ConnectReturnCode::UnacceptableProtocolVersion,
            2 => ConnectReturnCode::IdentifierRejected,
            3 => ConnectReturnCode::ServerUnavailable,
            4 => ConnectReturnCode::BadUsernameOrPassword,
            5 => ConnectReturnCode::NotAuthorized,
            other => ConnectReturnCode::Unknown(other),
        }
    }
}

impl fmt::Display for ConnectReturnCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectReturnCode::Accepted => f.write_str("accepted"),
            ConnectReturnCode::UnacceptableProtocolVersion => {
                f.write_str("broker does not speak MQTT 3.1.1")
            }
            ConnectReturnCode::IdentifierRejected => f.write_str("client ID rejected"),
            ConnectReturnCode::ServerUnavailable => f.write_str("broker unavailable"),
            ConnectReturnCode::BadUsernameOrPassword => f.write_str("bad user name or password"),
            ConnectReturnCode::NotAuthorized => f.write_str("not authorised"),
            ConnectReturnCode::Unknown(code) => write!(f, "unknown return code {}", code),
        }
    }
}

/// MQTT control packet types used here (section 2.2.1), as the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PacketType {
    Connect = 0x10,
    Connack = 0x20,
    Publish = 0x30,
    Pingreq = 0xC0,
    Disconnect = 0xE0,
}

/// CONNECT flag bits (section 3.1.2.3).
const FLAG_USERNAME: u8 = 0x80;
const FLAG_PASSWORD: u8 = 0x40;
const FLAG_WILL_RETAIN: u8 = 0x20;
const FLAG_WILL: u8 = 0x04;
const FLAG_CLEAN_SESSION: u8 = 0x02;

/// PUBLISH flag bit for a retained message (section 3.3.1.3).
const FLAG_RETAIN: u8 = 0x01;

/// The largest remaining length MQTT can encode (section 2.2.3).
const MAX_REMAINING_LENGTH: usize = 268_435_455;

/// Encodes the variable-length "remaining length" field.
fn encode_remaining_length(mut len: usize, out: &mut Vec<u8>) -> io::Result<()> {
    if len > MAX_REMAINING_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MQTT packet too large",
        ));
    }
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            return Ok(());
        }
    }
}

/// Appends a length-prefixed field (section 1.5.3).
fn encode_field(value: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MQTT field too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Wraps a body in a fixed header.
fn packet(first_byte: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(first_byte);
    encode_remaining_length(body.len(), &mut out)?;
    out.extend_from_slice(body);
    Ok(out)
}

/// A CONNECT packet with a retained last will of `offline` on the
/// availability topic, so Home Assistant marks every entity unavailable when
/// LANwatch dies without saying goodbye.
fn connect_packet(config: &HomeAssistantConfig) -> io::Result<Vec<u8>> {
    let mut flags = FLAG_CLEAN_SESSION | FLAG_WILL | FLAG_WILL_RETAIN;
    if config.username.is_some() {
        flags |= FLAG_USERNAME;
        // MQTT 3.1.1 allows a password only together with a user name.
        if config.password.is_some() {
            flags |= FLAG_PASSWORD;
        }
    }

    let mut body = Vec::new();
    encode_field(b"MQTT", &mut body)?;
    body.push(4); // protocol level 4 = MQTT 3.1.1
    body.push(flags);
    body.extend_from_slice(&(KEEP_ALIVE.as_secs() as u16).to_be_bytes());
    encode_field(config.client_id.as_bytes(), &mut body)?;
    encode_field(config.availability_topic().as_bytes(), &mut body)?;
    encode_field(b"offline", &mut body)?;
    if let Some(username) = &config.username {
        encode_field(username.as_bytes(), &mut body)?;
        if let Some(password) = &config.password {
            encode_field(password.as_bytes(), &mut body)?;
        }
    }
    packet(PacketType::Connect as u8, &body)
}

/// A QoS 0 PUBLISH packet.
fn publish_packet(topic: &str, payload: &[u8], retain: bool) -> io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(topic.len() + payload.len() + 2);
    encode_field(topic.as_bytes(), &mut body)?;
    body.extend_from_slice(payload);
    let flags = if retain { FLAG_RETAIN } else { 0 };
    packet(PacketType::Publish as u8 | flags, &body)
}

/// Reads the CONNACK and turns a refusal into an error.
fn read_connack(stream: &mut impl Read) -> io::Result<()> {
    let mut connack = [0u8; 4];
    stream.read_exact(&mut connack)?;
    if connack[0] != PacketType::Connack as u8 || connack[1] != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker did not answer with CONNACK",
        ));
    }
    match ConnectReturnCode::from(connack[3]) {
        ConnectReturnCode::Accepted => Ok(()),
        refused => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("broker refused the connection: {}", refused),
        )),
    }
}

/// Makes a device identifier safe as one MQTT topic level and an HA ID.
///
/// MACs lose their colons. Anything else (a `duid:` key) keeps only ASCII
/// letters and digits, so no `/`, `+` or `#` can reach a topic.
fn topic_id(identifier: &str) -> String {
    identifier
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .take(64)
        .collect()
}

/// The identifier Home Assistant knows a device by.
///
/// The oldest MAC the device ever used, so a random-MAC merge keeps the same
/// entity instead of creating a new one each time a phone rotates its address.
pub fn entity_key(device: &DeviceInfo) -> String {
    topic_id(device.previous_macs.first().unwrap_or(&device.mac_address))
}

/// The name shown in Home Assistant. The same order the dashboard uses.
fn display_name(device: &DeviceInfo) -> String {
    if let Some(label) = device.product_label.as_deref().filter(|l| !l.is_empty()) {
        return label.to_string();
    }
    if let Some(hostname) = device.hostname.as_deref().filter(|h| !h.is_empty()) {
        return hostname.to_string();
    }
    let vendor = device
        .vendor
        .as_ref()
        .map(|v| v.to_string())
        .filter(|v| v != PRIVATE_MAC_VENDOR);
    vendor
        .or_else(|| device.device_type.as_ref().map(|t| t.to_string()))
        .unwrap_or_else(|| device.mac_address.clone())
}

/// The retained messages that describe one device.
struct DeviceMessages {
    config_topic: String,
    config: String,
    state_topic: String,
    state: &'static str,
    attributes_topic: String,
    attributes: String,
}

fn device_messages(config: &HomeAssistantConfig, device: &DeviceInfo) -> DeviceMessages {
    let key = entity_key(device);
    let unique_id = format!("lanwatch_{}", key);
    let state_topic = format!("{}/{}/state", config.base_topic, key);
    let attributes_topic = format!("{}/{}/attributes", config.base_topic, key);

    let mut ha_device = json!({
        "identifiers": [unique_id],
        "connections": [["mac", device.mac_address]],
        "name": display_name(device),
    });
    if let Some(vendor) = device
        .vendor
        .as_ref()
        .map(|v| v.to_string())
        .filter(|v| v != PRIVATE_MAC_VENDOR)
    {
        ha_device["manufacturer"] = json!(vendor);
    }
    if let Some(device_type) = &device.device_type {
        ha_device["model"] = json!(device_type.to_string());
    }

    let discovery = json!({
        // `null` names the entity after its device, so it reads "Pixel 10
        // Pro", not "Pixel 10 Pro Pixel 10 Pro".
        "name": null,
        "unique_id": unique_id,
        "state_topic": state_topic,
        "json_attributes_topic": attributes_topic,
        "payload_home": "home",
        "payload_not_home": "not_home",
        "source_type": "router",
        "availability_topic": config.availability_topic(),
        "device": ha_device,
        "origin": {
            "name": "LANwatch",
            "sw_version": env!("CARGO_PKG_VERSION"),
            "support_url": env!("CARGO_PKG_REPOSITORY"),
        },
    });

    // `last_seen` is left out: it changes with every packet, and a retained
    // message per packet would flood the broker for no gain.
    let ip = (!device.ip_address.is_unspecified())
        .then(|| device.ip_address.to_string())
        .or_else(|| device.ipv6_address.map(|ip| ip.to_string()));
    let attributes = json!({
        "ip": ip,
        "mac": device.mac_address,
        "host_name": device.hostname,
        "vendor": device.vendor.as_ref().map(|v| v.to_string()),
        "device_type": device.device_type.as_ref().map(|t| t.to_string()),
        "trusted": device.trusted,
        "previous_macs": device.previous_macs,
        "first_seen": format_timestamp(device.first_seen),
    });

    DeviceMessages {
        config_topic: format!(
            "{}/device_tracker/{}/config",
            config.discovery_prefix, unique_id
        ),
        config: discovery.to_string(),
        state_topic,
        state: if device.online { "home" } else { "not_home" },
        attributes_topic,
        attributes: attributes.to_string(),
    }
}

/// One live broker connection, plus what was last sent on it.
struct Session {
    stream: TcpStream,
    /// Topic -> last payload sent, so unchanged messages are skipped.
    sent: HashMap<String, String>,
    /// Entity keys whose discovery config is on the broker.
    published: HashMap<String, String>,
    last_write: Instant,
}

impl Session {
    fn open(config: &HomeAssistantConfig) -> io::Result<Self> {
        let address = (config.host.as_str(), config.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "broker address not found"))?;
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
        stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
        stream.write_all(&connect_packet(config)?)?;
        read_connack(&mut stream)?;
        // From here on the broker only sends PINGRESP, which is drained
        // without waiting.
        stream.set_nonblocking(true)?;
        let mut session = Session {
            stream,
            sent: HashMap::new(),
            published: HashMap::new(),
            last_write: Instant::now(),
        };
        session.publish(&config.availability_topic(), "online")?;
        Ok(session)
    }

    /// Sends a retained message unless the same payload was the last one.
    fn publish(&mut self, topic: &str, payload: &str) -> io::Result<bool> {
        if self.sent.get(topic).is_some_and(|last| last == payload) {
            return Ok(false);
        }
        self.write(&publish_packet(topic, payload.as_bytes(), true)?)?;
        self.sent.insert(topic.to_string(), payload.to_string());
        Ok(true)
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        // A non-blocking socket can take part of a large write; wait out a
        // full send buffer briefly instead of failing the session.
        let mut written = 0;
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        while written < bytes.len() {
            match self.stream.write(&bytes[written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
        self.last_write = Instant::now();
        Ok(())
    }

    /// Discards whatever the broker sent and notices a closed connection.
    fn drain(&mut self) -> io::Result<()> {
        let mut buffer = [0u8; 256];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(io::ErrorKind::ConnectionAborted.into()),
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    fn keep_alive(&mut self) -> io::Result<()> {
        self.drain()?;
        if self.last_write.elapsed() >= PING_AFTER {
            self.write(&[PacketType::Pingreq as u8, 0])?;
        }
        Ok(())
    }

    /// Publishes every changed message for the devices to show, and removes
    /// the entities of devices no longer shown.
    fn sync(&mut self, config: &HomeAssistantConfig, devices: &[DeviceInfo]) -> io::Result<usize> {
        let mut changed = 0;
        let mut shown = HashMap::new();
        for device in devices {
            let messages = device_messages(config, device);
            changed += usize::from(self.publish(&messages.config_topic, &messages.config)?);
            changed += usize::from(self.publish(&messages.state_topic, messages.state)?);
            changed += usize::from(self.publish(&messages.attributes_topic, &messages.attributes)?);
            shown.insert(entity_key(device), messages.config_topic);
        }

        // An empty retained config deletes the entity in Home Assistant, and
        // an empty retained message clears the others on the broker. This
        // covers a device removed from LANwatch or, with `trusted_only`, one
        // no longer trusted. A merge keeps its entity, since the entity key
        // is the oldest MAC. A removed device that comes back is recreated
        // under the same unique ID.
        let gone: Vec<(String, String)> = self
            .published
            .iter()
            .filter(|(key, _)| !shown.contains_key(*key))
            .map(|(key, topic)| (key.clone(), topic.clone()))
            .collect();
        for (key, config_topic) in gone {
            self.publish(&config_topic, "")?;
            self.publish(&format!("{}/{}/state", config.base_topic, key), "")?;
            self.publish(&format!("{}/{}/attributes", config.base_topic, key), "")?;
            changed += 1;
        }
        self.published = shown;
        Ok(changed)
    }

    fn close(mut self) {
        let _ = self.write(&[PacketType::Disconnect as u8, 0]);
    }
}

/// The devices to publish: all of them, or the trusted ones.
fn devices_to_show(
    tracker: &Arc<RwLock<DeviceTracker>>,
    trusted_only: bool,
) -> Option<Vec<DeviceInfo>> {
    let tracker = tracker.read().ok()?;
    Some(
        tracker
            .devices()
            .values()
            .filter(|device| !trusted_only || device.trusted)
            .cloned()
            .collect(),
    )
}

/// Starts the bridge thread. It connects, publishes, and reconnects on its
/// own for as long as the process runs.
///
/// Before the first sync it waits one presence sweep, so `online` is set
/// from real data rather than the default of a freshly loaded device.
pub fn start_home_assistant(
    config: HomeAssistantConfig,
    tracker: Arc<RwLock<DeviceTracker>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(12));
        let mut retry = RETRY_MIN;
        loop {
            match Session::open(&config) {
                Ok(mut session) => {
                    println!(
                        "Home Assistant: connected to MQTT broker {}:{}",
                        config.host, config.port
                    );
                    retry = RETRY_MIN;
                    let result = run_session(&mut session, &config, &tracker);
                    if let Err(e) = result {
                        eprintln!("Warning: Home Assistant connection lost: {}", e);
                    } else {
                        session.close();
                        return;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Home Assistant: cannot connect to {}:{}: {} (retrying in {}s)",
                        config.host,
                        config.port,
                        e,
                        retry.as_secs()
                    );
                }
            }
            thread::sleep(retry);
            retry = (retry * 2).min(RETRY_MAX);
        }
    })
}

/// Publishes until the connection fails. `Ok` only if the tracker is gone.
fn run_session(
    session: &mut Session,
    config: &HomeAssistantConfig,
    tracker: &Arc<RwLock<DeviceTracker>>,
) -> io::Result<()> {
    loop {
        let Some(devices) = devices_to_show(tracker, config.trusted_only) else {
            return Ok(());
        };
        session.sync(config, &devices)?;
        session.keep_alive()?;
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn device(mac: &str, hostname: Option<&str>) -> DeviceInfo {
        DeviceInfo::new(
            mac.to_string(),
            "192.168.1.20".parse().unwrap(),
            hostname.map(str::to_string),
        )
    }

    #[test]
    fn remaining_length_uses_the_spec_examples() {
        for (len, expected) in [
            (0, vec![0x00]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xFF, 0x7F]),
            (16_384, vec![0x80, 0x80, 0x01]),
            (268_435_455, vec![0xFF, 0xFF, 0xFF, 0x7F]),
        ] {
            let mut out = Vec::new();
            encode_remaining_length(len, &mut out).unwrap();
            assert_eq!(out, expected, "{}", len);
        }
        assert!(encode_remaining_length(268_435_456, &mut Vec::new()).is_err());
    }

    #[test]
    fn connect_carries_the_will_and_the_credentials() {
        let mut config = HomeAssistantConfig::new("broker", 1883);
        config.username = Some("ha".to_string());
        config.password = Some("secret".to_string());
        let bytes = connect_packet(&config).unwrap();

        assert_eq!(bytes[0], 0x10);
        // Remaining length, then "MQTT", level 4, flags.
        assert_eq!(&bytes[2..10], b"\x00\x04MQTT\x04\xE6");
        assert_eq!(&bytes[10..12], &60u16.to_be_bytes());
        let tail = String::from_utf8_lossy(&bytes[12..]);
        for part in ["lanwatch", "lanwatch/status", "offline", "ha", "secret"] {
            assert!(tail.contains(part), "{}", part);
        }
    }

    #[test]
    fn a_password_without_a_user_name_is_not_sent() {
        let mut config = HomeAssistantConfig::new("broker", 1883);
        config.password = Some("secret".to_string());
        let bytes = connect_packet(&config).unwrap();
        assert_eq!(bytes[9], FLAG_CLEAN_SESSION | FLAG_WILL | FLAG_WILL_RETAIN);
        assert!(!String::from_utf8_lossy(&bytes).contains("secret"));
    }

    #[test]
    fn publish_is_retained_qos0() {
        let bytes = publish_packet("a/b", b"hi", true).unwrap();
        assert_eq!(bytes, b"\x31\x07\x00\x03a/bhi");
        assert_eq!(publish_packet("a/b", b"", false).unwrap()[0], 0x30);
    }

    #[test]
    fn a_refused_connack_names_the_reason() {
        let ok = read_connack(&mut &b"\x20\x02\x00\x00"[..]);
        assert!(ok.is_ok());
        let refused = read_connack(&mut &b"\x20\x02\x00\x05"[..]).unwrap_err();
        assert!(
            refused.to_string().contains("not authorised"),
            "{}",
            refused
        );
        assert!(read_connack(&mut &b"\x30\x02\x00\x00"[..]).is_err());
    }

    #[test]
    fn the_entity_key_survives_a_mac_merge() {
        let before = device("da:11:22:33:44:01", Some("Richards-iPhone"));
        let mut after = device("3e:11:22:33:44:02", Some("Richards-iPhone"));
        after.previous_macs = vec!["da:11:22:33:44:01".to_string()];
        assert_eq!(entity_key(&before), "da1122334401");
        assert_eq!(entity_key(&after), entity_key(&before));
        assert_eq!(topic_id("duid:00/+#01"), "duid0001");
    }

    #[test]
    fn discovery_names_the_device_and_hides_the_private_vendor() {
        let config = HomeAssistantConfig::new("broker", 1883);
        let mut d = device("3e:11:22:33:44:02", None);
        d.vendor = Some(PRIVATE_MAC_VENDOR.into());
        d.product_label = Some("Richard's phone".to_string());
        d.online = false;
        let messages = device_messages(&config, &d);

        assert_eq!(
            messages.config_topic,
            "homeassistant/device_tracker/lanwatch_3e1122334402/config"
        );
        assert_eq!(messages.state, "not_home");
        let parsed: serde_json::Value = serde_json::from_str(&messages.config).unwrap();
        assert_eq!(parsed["device"]["name"], "Richard's phone");
        assert!(parsed["device"].get("manufacturer").is_none());
        assert!(parsed["name"].is_null());
        assert_eq!(parsed["state_topic"], "lanwatch/3e1122334402/state");
    }

    /// Reads one MQTT packet off a socket: (first byte, body).
    fn read_packet(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).unwrap();
        let (mut len, mut shift) = (0usize, 0);
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            len |= ((byte[0] & 0x7F) as usize) << shift;
            shift += 7;
            if byte[0] & 0x80 == 0 {
                break;
            }
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        (first[0], body)
    }

    fn topic_and_payload(body: &[u8]) -> (String, String) {
        let len = u16::from_be_bytes([body[0], body[1]]) as usize;
        (
            String::from_utf8_lossy(&body[2..2 + len]).to_string(),
            String::from_utf8_lossy(&body[2 + len..]).to_string(),
        )
    }

    #[test]
    fn a_session_publishes_once_then_only_changes_and_removals() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (first, _) = read_packet(&mut stream);
            assert_eq!(first, 0x10);
            stream.write_all(b"\x20\x02\x00\x00").unwrap();
            let mut seen = Vec::new();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            while seen.len() < 8 {
                let (first, body) = read_packet(&mut stream);
                assert_eq!(first, 0x31, "retained QoS 0 publish");
                seen.push(topic_and_payload(&body));
            }
            seen
        });

        let config = HomeAssistantConfig::new("127.0.0.1", port);
        let mut session = Session::open(&config).unwrap();
        let mut phone = device("3e:11:22:33:44:02", Some("Richards-iPhone"));
        assert_eq!(
            session.sync(&config, std::slice::from_ref(&phone)).unwrap(),
            3
        );
        assert_eq!(
            session.sync(&config, std::slice::from_ref(&phone)).unwrap(),
            0
        );
        phone.online = false;
        assert_eq!(
            session.sync(&config, std::slice::from_ref(&phone)).unwrap(),
            1
        );
        assert_eq!(session.sync(&config, &[]).unwrap(), 1);

        let seen = broker.join().unwrap();
        assert_eq!(
            seen[0],
            ("lanwatch/status".to_string(), "online".to_string())
        );
        assert_eq!(seen[2].0, "lanwatch/3e1122334402/state");
        assert_eq!(seen[2].1, "home");
        assert_eq!(seen[4].1, "not_home");
        assert_eq!(
            seen[5],
            (
                "homeassistant/device_tracker/lanwatch_3e1122334402/config".to_string(),
                String::new()
            )
        );
    }
}

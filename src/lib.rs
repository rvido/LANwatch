//! LANwatch is a library for network device discovery and tracking using DHCP, mDNS, SSDP, and other discovery protocols.

// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

/// Kernel-side capture filter for the sniffers.
pub mod capture_filter;
/// Device classifier logic.
pub mod classifier;
/// Device information, parsing and serialization logic.
pub mod device;
/// Device attribute fingerprinting.
pub mod fingerprint;
/// Random-MAC merging: folds a rotated private MAC into its old record.
pub mod mac_merge;
/// IEEE OUI database parsing and querying.
pub mod oui;
/// Packet parsing implementations.
pub mod parser;
/// Presence history, trusted devices and the event hook.
pub mod presence;
/// Packet sniffing and network listeners.
pub mod sniffer;
/// Central device tracker registry.
pub mod tracker;
/// Shared data types, enums and structures.
pub mod types;

/// Registry for advertising and monitoring mDNS services.
#[cfg(feature = "mdns")]
pub mod mdns_registry;

/// Home Assistant integration over MQTT discovery.
#[cfg(feature = "homeassistant")]
pub mod homeassistant;

/// HTTP API server implementation.
#[cfg(feature = "http-api")]
pub mod api;

// Re-export public interface
pub use classifier::*;
pub use device::{DeviceInfo, DisplaySafe, display_safe, format_timestamp, parse_timestamp};
pub use fingerprint::{
    CatalogueSkips, Fingerprint, FingerprintCatalogue, FingerprintMatch, FingerprintProfile,
    TokenNamespace, TokenSet, fnv1a64, is_ripe,
};
pub use mac_merge::{MERGE_OVERLAP_GRACE, MERGE_SETTLE, merge_key};
pub use oui::{IEEE_OUI_URL, OuiRegistry, download_ieee_oui};
pub use parser::*;
pub use presence::{
    DEFAULT_OFFLINE_AFTER, EventHook, MAX_RUNNING_HOOKS, PRESENCE_RETENTION, PresenceEvent,
    PresenceKind,
};
pub use sniffer::*;
pub use tracker::*;
pub use types::*;

#[cfg(feature = "mdns")]
pub use mdns_registry::{MdnsServiceInfo, MdnsServiceRegistry};

#[cfg(feature = "homeassistant")]
pub use homeassistant::{
    ConnectReturnCode, DEFAULT_BASE_TOPIC, DEFAULT_DISCOVERY_PREFIX, DEFAULT_MQTT_PORT,
    HomeAssistantConfig, entity_key, start_home_assistant,
};

#[cfg(feature = "http-api")]
pub use api::{
    ApiServer, start_api_server, start_api_server_with_hosts, start_api_server_with_options,
};

// Include the unit tests
#[cfg(test)]
include!("tests.rs");

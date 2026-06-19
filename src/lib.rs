//! LANwatch is a library for network device discovery and tracking using DHCP, mDNS, SSDP, and other discovery protocols.

// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking

/// Device classifier logic.
pub mod classifier;
/// Device information, parsing and serialization logic.
pub mod device;
/// IEEE OUI database parsing and querying.
pub mod oui;
/// Packet parsing implementations.
pub mod parser;
/// Packet sniffing and network listeners.
pub mod sniffer;
/// Central device tracker registry.
pub mod tracker;
/// Shared data types, enums and structures.
pub mod types;

/// Registry for advertising and monitoring mDNS services.
#[cfg(feature = "mdns")]
pub mod mdns_registry;

/// HTTP API server implementation.
#[cfg(feature = "http-api")]
pub mod api;

// Re-export public interface
pub use classifier::*;
pub use device::{DeviceInfo, format_timestamp, parse_timestamp};
pub use oui::{IEEE_OUI_URL, OuiRegistry, download_ieee_oui};
pub use parser::*;
pub use sniffer::*;
pub use tracker::*;
pub use types::*;

#[cfg(feature = "mdns")]
pub use mdns_registry::{MdnsServiceInfo, MdnsServiceRegistry};

#[cfg(feature = "http-api")]
pub use api::{ApiServer, start_api_server};

// Include the unit tests
#[cfg(test)]
include!("tests.rs");

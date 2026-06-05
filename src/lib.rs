// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking

pub mod classifier;
pub mod device;
pub mod oui;
pub mod parser;
pub mod sniffer;
pub mod tracker;
pub mod types;

#[cfg(feature = "mdns")]
pub mod mdns_registry;

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

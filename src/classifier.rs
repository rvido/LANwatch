// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

use crate::types::{DeviceType, Vendor};

/// Detect vendor from hostname patterns
pub fn detect_vendor_from_hostname(hostname: Option<&str>) -> Option<Vendor> {
    let hostname_val = hostname?;
    let owned_holder;
    let hostname = if hostname_val.bytes().any(|b| b.is_ascii_uppercase()) {
        owned_holder = hostname_val.to_ascii_lowercase();
        owned_holder.as_str()
    } else {
        hostname_val
    };

    if hostname.contains("roborock") {
        return Some(Vendor::Roborock);
    }

    if hostname.contains("rachio") {
        return Some(Vendor::Rachio);
    }

    if hostname.contains("eero") {
        return Some(Vendor::Eero);
    }

    if hostname.contains("lenovo")
        || hostname.contains("legion")
        || hostname.contains("thinkpad")
        || hostname.contains("ideapad")
        || hostname.contains("yoga")
    {
        return Some(Vendor::Lenovo);
    }

    if hostname.contains("dell")
        || hostname.contains("inspiron")
        || hostname.contains("latitude")
        || hostname.contains("xps")
        || hostname.contains("precision")
        || hostname.contains("alienware")
    {
        return Some(Vendor::Dell);
    }

    if hostname.contains("asus") || hostname.contains("zenbook") || hostname.contains("vivobook") {
        return Some(Vendor::Asus);
    }

    if hostname.contains("acer")
        || hostname.contains("aspire")
        || hostname.contains("predator")
        || hostname.contains("swift")
    {
        return Some(Vendor::Acer);
    }

    if hostname.contains("surface") {
        return Some(Vendor::Microsoft);
    }

    // Google/Nest devices often use WICED platform
    if hostname.starts_with("wiced-hap") || hostname.contains("nest") {
        return Some(Vendor::Google);
    }

    // Google Pixel phones
    if hostname.contains("pixel") {
        return Some(Vendor::Google);
    }

    // Apple devices
    if hostname.contains("iphone")
        || hostname.contains("ipad")
        || hostname.contains("macbook")
        || hostname.contains("imac")
        || hostname.contains("mac-mini")
        || hostname.contains("apple")
    {
        return Some(Vendor::Apple);
    }

    // Samsung devices
    if hostname.contains("samsung") || hostname.contains("galaxy") {
        return Some(Vendor::Samsung);
    }

    // Motorola devices
    if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola") {
        return Some(Vendor::Motorola);
    }

    // Android devices
    if hostname.starts_with("android") || hostname.starts_with("android_") {
        return Some(Vendor::Google);
    }

    // HP printers (NPI prefix)
    if hostname.starts_with("npi") {
        return Some(Vendor::Hp);
    }

    // Newly added signatures
    if hostname.contains("sonos") {
        return Some(Vendor::Sonos);
    }
    if hostname.contains("roku") {
        return Some(Vendor::Roku);
    }
    if hostname.contains("appletv") || hostname.contains("apple-tv") {
        return Some(Vendor::Apple);
    }
    if hostname.starts_with("esp32-")
        || hostname.starts_with("esp-")
        || hostname.starts_with("espressif-")
        || hostname.contains("_esp32")
    {
        return Some(Vendor::Espressif);
    }
    if hostname.starts_with("raspberrypi")
        || hostname.starts_with("raspberry-pi")
        || hostname.starts_with("pi-")
    {
        return Some(Vendor::RaspberryPi);
    }
    if hostname.starts_with("synology-")
        || hostname.contains("synology")
        || hostname.starts_with("nas-")
    {
        return Some(Vendor::Synology);
    }
    if hostname.starts_with("kindle-") {
        return Some(Vendor::Amazon);
    }
    if hostname.starts_with("nintendo-") {
        return Some(Vendor::Nintendo);
    }
    if hostname.starts_with("playstation-")
        || hostname.starts_with("ps4-")
        || hostname.starts_with("ps5-")
    {
        return Some(Vendor::Sony);
    }
    if hostname.starts_with("xbox-") {
        return Some(Vendor::Microsoft);
    }
    if hostname.starts_with("hp-")
        || hostname.starts_with("hp_")
        || hostname.contains("hewlett-packard")
        || hostname.contains("jetdirect")
    {
        return Some(Vendor::Hp);
    }
    if hostname.starts_with("canon-") || hostname.contains("canon") {
        return Some(Vendor::Canon);
    }
    if hostname.starts_with("brother-") || hostname.contains("brother") {
        return Some(Vendor::Brother);
    }
    if hostname.starts_with("epson-") || hostname.contains("epson") {
        return Some(Vendor::Epson);
    }
    if hostname.starts_with("ring-") || hostname.contains("ring-doorbell") {
        return Some(Vendor::Ring);
    }
    if hostname.starts_with("wemo-") {
        return Some(Vendor::Belkin);
    }
    if hostname.starts_with("philips-hue") || hostname.starts_with("hue-") {
        return Some(Vendor::Philips);
    }

    None
}

/// Detect device type from hostname patterns
pub fn detect_device_type_from_hostname(hostname: Option<&str>) -> Option<DeviceType> {
    let hostname_val = hostname?;
    let owned_holder;
    let hostname = if hostname_val.bytes().any(|b| b.is_ascii_uppercase()) {
        owned_holder = hostname_val.to_ascii_lowercase();
        owned_holder.as_str()
    } else {
        hostname_val
    };

    if hostname.contains("roborock") {
        return Some(DeviceType::SmartCleaningDevice);
    }

    if hostname.contains("rachio") {
        return Some(DeviceType::SmartWateringDevice);
    }

    if hostname.contains("eero") {
        return Some(DeviceType::Router);
    }

    if hostname.contains("lenovo")
        || hostname.contains("legion")
        || hostname.contains("thinkpad")
        || hostname.contains("ideapad")
        || hostname.contains("yoga")
        || hostname.contains("inspiron")
        || hostname.contains("latitude")
        || hostname.contains("xps")
        || hostname.contains("precision")
        || hostname.contains("alienware")
        || hostname.contains("zenbook")
        || hostname.contains("vivobook")
        || hostname.contains("spectre")
        || hostname.contains("envy")
        || hostname.contains("elitebook")
        || hostname.contains("probook")
        || hostname.contains("surface")
    {
        return Some(DeviceType::Laptop);
    }

    // Google Pixel phones - check before other patterns
    if hostname.contains("pixel") {
        return Some(DeviceType::PixelPhone);
    }

    // Google/Nest thermostats use WICED-hap prefix
    if hostname.starts_with("wiced-hap") {
        return Some(DeviceType::Thermostat);
    }

    // Nest devices
    if hostname.contains("nest") {
        if hostname.contains("thermostat") {
            return Some(DeviceType::Thermostat);
        }
        if hostname.contains("cam") || hostname.contains("doorbell") {
            return Some(DeviceType::SecurityCamera);
        }
        return Some(DeviceType::SmartHomeDevice);
    }

    // iPhones/iPads
    if hostname.contains("iphone") {
        return Some(DeviceType::AppleIPhone);
    }
    if hostname.contains("ipad") {
        return Some(DeviceType::AppleIPad);
    }

    // Macs
    if hostname.contains("macbook")
        || hostname.contains("imac")
        || hostname.contains("mac-mini")
        || hostname.contains("mac-pro")
    {
        return Some(DeviceType::Mac);
    }

    // HP printers (NPI prefix = Network Peripheral Interface)
    if hostname.starts_with("npi") {
        return Some(DeviceType::Printer);
    }

    // Motorola devices
    if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola") {
        return Some(DeviceType::AndroidPhone);
    }

    // Android phones
    if hostname.starts_with("android") || hostname.starts_with("android_") {
        return Some(DeviceType::AndroidPhone);
    }

    // Newly added signatures
    if hostname.contains("sonos") {
        return Some(DeviceType::SmartSpeaker);
    }
    if hostname.contains("roku") {
        return Some(DeviceType::MediaPlayer);
    }
    if hostname.contains("chromecast") {
        return Some(DeviceType::MediaPlayer);
    }
    if hostname.contains("appletv") || hostname.contains("apple-tv") {
        return Some(DeviceType::AppleTv);
    }
    if hostname.starts_with("google-home") || hostname.contains("googlehome") {
        return Some(DeviceType::SmartSpeaker);
    }
    if hostname.starts_with("ring-") || hostname.contains("ring-doorbell") {
        return Some(DeviceType::SmartDoorbell);
    }
    if hostname.starts_with("wemo-") {
        return Some(DeviceType::SmartPlug);
    }
    if hostname.starts_with("philips-hue") || hostname.starts_with("hue-") {
        return Some(DeviceType::SmartLight);
    }
    if hostname.starts_with("esp32-")
        || hostname.starts_with("esp-")
        || hostname.starts_with("espressif-")
        || hostname.contains("_esp32")
    {
        return Some(DeviceType::IotDevice);
    }
    if hostname.starts_with("raspberrypi")
        || hostname.starts_with("raspberry-pi")
        || hostname.starts_with("pi-")
    {
        return Some(DeviceType::SingleBoardComputer);
    }
    if hostname.starts_with("synology-")
        || hostname.contains("synology")
        || hostname.starts_with("nas-")
    {
        return Some(DeviceType::StorageNas);
    }
    if hostname.starts_with("kindle-") {
        return Some(DeviceType::EReader);
    }
    if hostname.starts_with("nintendo-") {
        return Some(DeviceType::GameConsole);
    }
    if hostname.starts_with("playstation-")
        || hostname.starts_with("ps4-")
        || hostname.starts_with("ps5-")
    {
        return Some(DeviceType::GameConsole);
    }
    if hostname.starts_with("xbox-") {
        return Some(DeviceType::GameConsole);
    }
    if hostname.starts_with("hp-")
        || hostname.starts_with("hp_")
        || hostname.contains("hewlett-packard")
        || hostname.contains("jetdirect")
        || hostname.contains("canon")
        || hostname.contains("brother")
        || hostname.contains("epson")
    {
        return Some(DeviceType::Printer);
    }

    None
}

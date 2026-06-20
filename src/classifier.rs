// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

/// Detect vendor from hostname patterns
pub fn detect_vendor_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
    let hostname = hostname?.to_lowercase();

    if hostname.contains("roborock") {
        return Some("Roborock");
    }

    if hostname.contains("rachio") {
        return Some("Rachio");
    }

    if hostname.contains("lenovo")
        || hostname.contains("legion")
        || hostname.contains("thinkpad")
        || hostname.contains("ideapad")
        || hostname.contains("yoga")
    {
        return Some("Lenovo");
    }

    // Google/Nest devices often use WICED platform
    if hostname.starts_with("wiced-hap") || hostname.contains("nest") {
        return Some("Google");
    }

    // Google Pixel phones
    if hostname.contains("pixel") {
        return Some("Google");
    }

    // Apple devices
    if hostname.contains("iphone")
        || hostname.contains("ipad")
        || hostname.contains("macbook")
        || hostname.contains("imac")
        || hostname.contains("mac-mini")
        || hostname.contains("apple")
    {
        return Some("Apple");
    }

    // Samsung devices
    if hostname.contains("samsung") || hostname.contains("galaxy") {
        return Some("Samsung");
    }

    // Motorola devices
    if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola") {
        return Some("Motorola");
    }

    // Android devices
    if hostname.starts_with("android") || hostname.starts_with("android_") {
        return Some("Google");
    }

    // HP printers (NPI prefix)
    if hostname.starts_with("npi") {
        return Some("HP");
    }

    // Newly added signatures
    if hostname.contains("sonos") {
        return Some("Sonos");
    }
    if hostname.contains("roku") {
        return Some("Roku");
    }
    if hostname.contains("appletv") || hostname.contains("apple-tv") {
        return Some("Apple");
    }
    if hostname.starts_with("esp32-")
        || hostname.starts_with("esp-")
        || hostname.starts_with("espressif-")
        || hostname.contains("_esp32")
    {
        return Some("Espressif");
    }
    if hostname.starts_with("raspberrypi")
        || hostname.starts_with("raspberry-pi")
        || hostname.starts_with("pi-")
    {
        return Some("Raspberry Pi");
    }
    if hostname.starts_with("synology-")
        || hostname.contains("synology")
        || hostname.starts_with("nas-")
    {
        return Some("Synology");
    }
    if hostname.starts_with("kindle-") {
        return Some("Amazon");
    }
    if hostname.starts_with("nintendo-") {
        return Some("Nintendo");
    }
    if hostname.starts_with("playstation-")
        || hostname.starts_with("ps4-")
        || hostname.starts_with("ps5-")
    {
        return Some("Sony");
    }
    if hostname.starts_with("xbox-") {
        return Some("Microsoft");
    }
    if hostname.starts_with("hp-")
        || hostname.starts_with("hp_")
        || hostname.contains("hewlett-packard")
        || hostname.contains("jetdirect")
    {
        return Some("HP");
    }
    if hostname.starts_with("canon-") || hostname.contains("canon") {
        return Some("Canon");
    }
    if hostname.starts_with("brother-") || hostname.contains("brother") {
        return Some("Brother");
    }
    if hostname.starts_with("epson-") || hostname.contains("epson") {
        return Some("Epson");
    }
    if hostname.starts_with("ring-") || hostname.contains("ring-doorbell") {
        return Some("Ring");
    }
    if hostname.starts_with("wemo-") {
        return Some("Belkin");
    }
    if hostname.starts_with("philips-hue") || hostname.starts_with("hue-") {
        return Some("Philips");
    }

    None
}

/// Detect device type from hostname patterns
pub fn detect_device_type_from_hostname(hostname: Option<&str>) -> Option<&'static str> {
    let hostname = hostname?.to_lowercase();

    if hostname.contains("roborock") {
        return Some("Smart Cleaning Device");
    }

    if hostname.contains("rachio") {
        return Some("Smart Watering Device");
    }

    if hostname.contains("lenovo")
        || hostname.contains("legion")
        || hostname.contains("thinkpad")
        || hostname.contains("ideapad")
        || hostname.contains("yoga")
    {
        return Some("Laptop");
    }

    // Google Pixel phones - check before other patterns
    if hostname.contains("pixel") {
        return Some("Pixel Phone");
    }

    // Google/Nest thermostats use WICED-hap prefix
    if hostname.starts_with("wiced-hap") {
        return Some("Thermostat");
    }

    // Nest devices
    if hostname.contains("nest") {
        if hostname.contains("thermostat") {
            return Some("Thermostat");
        }
        if hostname.contains("cam") || hostname.contains("doorbell") {
            return Some("Security Camera");
        }
        return Some("Smart Home Device");
    }

    // iPhones/iPads
    if hostname.contains("iphone") {
        return Some("Apple iPhone");
    }
    if hostname.contains("ipad") {
        return Some("Apple iPad");
    }

    // Macs
    if hostname.contains("macbook")
        || hostname.contains("imac")
        || hostname.contains("mac-mini")
        || hostname.contains("mac-pro")
    {
        return Some("Mac");
    }

    // HP printers (NPI prefix = Network Peripheral Interface)
    if hostname.starts_with("npi") {
        return Some("Printer");
    }

    // Motorola devices
    if hostname.contains("moto") || hostname.contains("stylus") || hostname.contains("motorola") {
        return Some("Android Phone");
    }

    // Android phones
    if hostname.starts_with("android") || hostname.starts_with("android_") {
        return Some("Android Phone");
    }

    // Newly added signatures
    if hostname.contains("sonos") {
        return Some("Smart Speaker");
    }
    if hostname.contains("roku") {
        return Some("Media Player");
    }
    if hostname.contains("chromecast") {
        return Some("Media Player");
    }
    if hostname.contains("appletv") || hostname.contains("apple-tv") {
        return Some("Apple TV");
    }
    if hostname.starts_with("google-home") || hostname.contains("googlehome") {
        return Some("Smart Speaker");
    }
    if hostname.starts_with("ring-") || hostname.contains("ring-doorbell") {
        return Some("Smart Doorbell");
    }
    if hostname.starts_with("wemo-") {
        return Some("Smart Plug");
    }
    if hostname.starts_with("philips-hue") || hostname.starts_with("hue-") {
        return Some("Smart Light");
    }
    if hostname.starts_with("esp32-")
        || hostname.starts_with("esp-")
        || hostname.starts_with("espressif-")
        || hostname.contains("_esp32")
    {
        return Some("IoT Device");
    }
    if hostname.starts_with("raspberrypi")
        || hostname.starts_with("raspberry-pi")
        || hostname.starts_with("pi-")
    {
        return Some("Single-board Computer");
    }
    if hostname.starts_with("synology-")
        || hostname.contains("synology")
        || hostname.starts_with("nas-")
    {
        return Some("Storage (NAS)");
    }
    if hostname.starts_with("kindle-") {
        return Some("e-Reader");
    }
    if hostname.starts_with("nintendo-") {
        return Some("Game Console");
    }
    if hostname.starts_with("playstation-")
        || hostname.starts_with("ps4-")
        || hostname.starts_with("ps5-")
    {
        return Some("Game Console");
    }
    if hostname.starts_with("xbox-") {
        return Some("Game Console");
    }
    if hostname.starts_with("hp-")
        || hostname.starts_with("hp_")
        || hostname.contains("hewlett-packard")
        || hostname.contains("jetdirect")
        || hostname.contains("canon")
        || hostname.contains("brother")
        || hostname.contains("epson")
    {
        return Some("Printer");
    }

    None
}

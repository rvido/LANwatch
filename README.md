# lanwatch

A Rust library and CLI tool for network device discovery and tracking via DHCP, mDNS, and IEEE-OUI identification.

## Features

- **DHCPv4 Support**: Capture and parse DHCP DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, and INFORM messages
- **DHCPv6 Support**: Capture and parse SOLICIT, ADVERTISE, REQUEST, CONFIRM, RENEW, REBIND, REPLY, RELEASE, DECLINE, RECONFIGURE, and INFO-REQUEST messages
- **mDNS Support** (optional): Passive and active mDNS discovery for enhanced device identification
- **Device Classification**: Automatic identification of device types (phones, printers, thermostats, etc.) from hostnames, services, and vendor data
- **IEEE OUI Database**: Built-in vendor identification from MAC addresses using IEEE OUI (Organizationally Unique Identifier) prefixes
- **Device Tracking**: Automatically track detected devices and save to CSV file
- **CSV Export**: Export device information with timestamps, MAC addresses, IP addresses, and hostnames
- **HTTP API** (optional): Built-in REST API server to query devices as JSON
- **Library API**: Use as a library in your own Rust projects
- **CLI Tool**: Run as a standalone command-line tool
- **Type-Safe**: Strongly typed enums for message types, operations, and options
- **Cross-Platform**: Works on macOS, Linux, and other Unix-like systems

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lanwatch = "0.1.0"
```

Or without the HTTP API feature (smaller binary):

```toml
[dependencies]
lanwatch = { version = "0.1.0", default-features = false }
```

Or clone and build from source:

```bash
git clone <repository-url>
cd lanwatch
cargo build --release

# Or build without HTTP API
cargo build --release --no-default-features
```

## Usage

### Command Line

```bash
# List available interfaces
sudo cargo run

# Sniff DHCP traffic on a specific interface (saves to dhcp_devices.csv by default)
sudo cargo run -- en0        # macOS
sudo cargo run -- eth0       # Linux

# Specify a custom output CSV file
sudo cargo run -- en0 -o /path/to/devices.csv
sudo cargo run -- en0 --output devices.csv

# Load additional OUI database entries
sudo cargo run -- en0 --oui /path/to/oui.txt
sudo cargo run -- en0 -u ieee-oui.txt

# Start with HTTP API server
sudo cargo run -- en0 --api 0.0.0.0:8080

# Start with API on default address (127.0.0.1:8080)
sudo cargo run -- en0 --api-default

# Enable mDNS sniffing for enhanced device discovery (requires mdns feature)
sudo cargo run --features mdns -- en0 --mdns

# Enable mDNS with active querying (sends discovery probes)
sudo cargo run --features mdns -- en0 --mdns-query

# Combine all options
sudo cargo run --all-features -- en0 -o devices.csv --api 0.0.0.0:8080 --mdns-query -u oui.txt

# Show help
cargo run -- --help
```

**Note:** Root/sudo privileges are typically required for packet capture.

### CSV Output Format

The tool saves detected devices to a CSV file with the following columns:

```csv
first_seen,last_seen,mac_address,ip_address,ipv6_address,hostname,device_type,vendor,services
2026-01-16T10:25:00Z,2026-01-16T10:30:45Z,AA:BB:CC:DD:EE:FF,192.168.1.100,"fe80::1","mydevice","Chromecast","Google","_googlecast._tcp"
2026-01-16T10:28:30Z,2026-01-16T10:28:30Z,11:22:33:44:55:66,192.168.1.101,"","","AirPlay Device","Apple","_airplay._tcp"
```

- **first_seen**: ISO 8601 timestamp of first detection
- **last_seen**: ISO 8601 timestamp of last DHCP/mDNS activity
- **mac_address**: Device MAC address (or DUID for DHCPv6)
- **ip_address**: IPv4 address (requested or assigned)
- **ipv6_address**: IPv6 address if available (from mDNS AAAA records)
- **hostname**: Device hostname if available (empty if not)
- **device_type**: Device type inferred from mDNS services (e.g., "Chromecast", "Apple TV", "Printer", "NAS")
- **vendor**: Detected vendor based on mDNS services (e.g., "Apple", "Google", "Amazon")
- **services**: Semicolon-separated list of mDNS services (requires `mdns` feature)

The CSV file is updated in real-time as new devices are detected or existing devices change.

### mDNS Service Identification

When mDNS sniffing is enabled, the tool can identify devices based on the services they advertise.
You can provide a custom services file to enhance identification:

```bash
# Use a custom services file
sudo cargo run --features mdns -- en0 --mdns -s mdns-services.txt
```

**Services file format:**
```
# Comment lines start with #
_service._tcp.local    # Description of the service
_http._tcp.local       # Web Server
_airplay._tcp.local    # AirPlay, Apple
_googlecast._tcp.local # Google Chromecast streaming protocol, Google
```

The tool includes built-in detection for:
- **Vendors**: Apple, Google, Amazon, Spotify, NVIDIA, Microsoft, Sony, Samsung, etc.
- **Device Types**: Chromecast, Apple TV, Fire TV, AirPlay Device, Printer, Scanner, NAS, Smart Home Device, Android TV, NVIDIA Shield, etc.

Loading a services file allows for more comprehensive identification. Device types are inferred from
service descriptions (e.g., "_googlecast._tcp" → "Chromecast").

### IEEE OUI Database

The tool uses the `oui-data` crate which provides the complete IEEE OUI (Organizationally Unique Identifier) 
database with **40,000+ vendor entries**. This allows automatic identification of device manufacturers based 
on the first 3 bytes of their MAC address.

**Benefits of the oui-data crate:**
- Complete IEEE OUI registry (40,000+ entries)
- Regularly updated as new vendors are registered
- No manual maintenance of vendor lists required

**Built-in coverage includes:**
- All major manufacturers: Apple, Google, Samsung, Microsoft, Sony, Intel, etc.
- Network equipment: Cisco, Netgear, TP-Link, Ubiquiti, etc.
- IoT/Smart home: Philips, Sonos, Ring, Nest, etc.
- Industrial and enterprise vendors
- Consumer electronics brands
- And thousands more...

**Loading additional OUI entries:**

You can load custom OUI entries to supplement or override the built-in database:

```bash
# Load additional OUI entries
sudo cargo run -- en0 --oui custom-oui.txt

# Default locations checked automatically:
# - ./oui.txt (current directory)
```

**Supported OUI file formats:**

```
# IEEE OUI format (from IEEE registry downloads)
00-1A-2B   (hex)    Vendor Name, Inc.

# Simple colon format
00:1A:2B    Vendor Name

# Simple dash format  
00-1A-2B    Vendor Name

# Compact format (no separators)
001A2B Vendor Name

# Comments start with #
# This is a comment line
```

The IEEE maintains the official OUI registry at:
https://standards-oui.ieee.org/oui/oui.txt

**Vendor priority:** mDNS-detected vendors take precedence over OUI lookups, as mDNS provides
more specific identification (e.g., "Google Chromecast" vs just "Google" from OUI).

### HTTP API

> **Note:** The HTTP API requires the `http-api` feature, which is enabled by default.
> Build with `--no-default-features` to disable it.

When started with `--api` or `--api-default`, the tool exposes a REST API for querying devices:

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info and available endpoints |
| `/devices` | GET | List all devices as JSON (sorted by last_seen) |
| `/devices/count` | GET | Get device count |
| `/health` | GET | Health check endpoint |

**Example Requests:**

```bash
# Get all devices
curl http://localhost:3000/devices

# Get device count
curl http://localhost:3000/devices/count

# Health check
curl http://localhost:3000/health
```

**Example Response (`/devices`):**

```json
{
  "success": true,
  "count": 1,
  "data": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "ip_address": "192.168.1.100",
      "ipv6_address": "fe80::1",
      "hostname": "mydevice",
      "services": ["_http._tcp", "_airplay._tcp"],
      "vendor": "Apple",
      "device_type": "AirPlay Device",
      "first_seen": "2026-01-16T10:25:00Z",
      "last_seen": "2026-01-16T10:30:45Z"
    }
  ]
}
```

### Library Usage

```rust
use lanwatch::{DhcpSniffer, DhcpEvent, DeviceTracker, Dhcpv6Option};

fn main() {
    let mut sniffer = DhcpSniffer::new("en0").expect("Failed to create sniffer");
    let mut tracker = DeviceTracker::new("devices.csv").expect("Failed to create tracker");

    sniffer.run(|event| {
        match &event {
            DhcpEvent::V4(packet) => {
                let is_new = tracker.update_from_dhcpv4(packet);
                println!("DHCPv4: {} -> {}", packet.source_ip, packet.dest_ip);
                println!("  Type: {:?}", packet.message_type);
                println!("  Client MAC: {}", packet.client_mac_string());
                if is_new {
                    println!("  [New or updated device]");
                }
            }
            DhcpEvent::V6(packet) => {
                let is_new = tracker.update_from_dhcpv6(packet);
                println!("DHCPv6: {} -> {}", packet.source_ip, packet.dest_ip);
                println!("  Type: {}", packet.message_type);
            }
        }
        true // Continue sniffing
    });
}
```

### Parsing Raw Payloads

```rust
use lanwatch::{parse_dhcpv4_payload, parse_dhcpv6_payload};
use std::net::{Ipv4Addr, Ipv6Addr};

// Parse a DHCPv4 payload
if let Some(packet) = parse_dhcpv4_payload(
    &payload_bytes,
    Ipv4Addr::new(0, 0, 0, 0),
    Ipv4Addr::new(255, 255, 255, 255),
    68, 67,
) {
    println!("Message type: {:?}", packet.message_type);
}

// Parse a DHCPv6 payload
if let Some(packet) = parse_dhcpv6_payload(
    &payload_bytes,
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2),
    546, 547,
) {
    println!("Message type: {}", packet.message_type);
    println!("Transaction ID: {}", packet.transaction_id_string());
    println!("Options: {:?}", packet.options);
}
```

## Examples

Run the included examples:

```bash
# Basic sniffer with packet counter
sudo cargo run --example basic_sniffer en0

# Parse sample payloads (no root required)
cargo run --example parse_payload
```

## API Reference

### Main Types

- `DhcpSniffer` - Main sniffer struct for capturing DHCP packets
- `NetworkSniffer` - Extended sniffer for DHCP + mDNS (requires `mdns` feature)
- `DhcpEvent` - Enum containing either `V4(Dhcpv4Packet)` or `V6(Dhcpv6Packet)`
- `NetworkEvent` - Enum for DHCP or mDNS events (requires `mdns` feature)
- `Dhcpv4Packet` - Parsed DHCPv4 packet with all fields
- `Dhcpv6Packet` - Parsed DHCPv6 packet with all fields
- `MdnsPacket` - Parsed mDNS packet (requires `mdns` feature)
- `MdnsRecord` - DNS resource record from mDNS
- `MdnsQuerier` - Active mDNS query sender (requires `mdns` feature)
- `DeviceTracker` - Track detected devices and save to CSV
- `DeviceInfo` - Information about a detected device
- `OuiRegistry` - IEEE OUI database for MAC-to-vendor lookups
- `DhcpError` - Error types for sniffer operations
- `ApiServer` - HTTP API server for querying devices

### Message Types

**DHCPv4:**
- `Dhcpv4MessageType`: Discover, Offer, Request, Decline, Ack, Nak, Release, Inform
- `Dhcpv4Operation`: BootRequest, BootReply

**DHCPv6:**
- `Dhcpv6MessageType`: Solicit, Advertise, Request, Confirm, Renew, Rebind, Reply, Release, Decline, Reconfigure, InfoRequest
- `Dhcpv6Option`: ClientId, ServerId, IaNa, ClientFqdn, Other

### Constants

- `DHCPV4_SERVER_PORT` (67)
- `DHCPV4_CLIENT_PORT` (68)
- `DHCPV6_CLIENT_PORT` (546)
- `DHCPV6_SERVER_PORT` (547)
- `MDNS_PORT` (5353) - requires `mdns` feature
- `MDNS_IPV4_MULTICAST` (224.0.0.251) - requires `mdns` feature
- `MDNS_IPV6_MULTICAST` (ff02::fb) - requires `mdns` feature

### Helper Functions

- `list_interfaces()` - List available network interfaces
- `find_interface(name)` - Find interface by name
- `is_dhcpv4_ports(src, dest)` - Check if ports indicate DHCPv4
- `is_dhcpv6_ports(src, dest)` - Check if ports indicate DHCPv6
- `is_mdns_ports(src, dest)` - Check if ports indicate mDNS (requires `mdns` feature)
- `parse_dhcpv4_payload(payload, src, dst, src_port, dst_port)` - Parse DHCPv4 from raw bytes
- `parse_dhcpv6_payload(payload, src, dst, src_port, dst_port)` - Parse DHCPv6 from raw bytes
- `parse_mdns_payload(payload, src, dst)` - Parse mDNS from raw bytes (requires `mdns` feature)
- `build_mdns_query(name, record_type)` - Build an mDNS query packet (requires `mdns` feature)
- `start_api_server(addr, tracker)` - Start HTTP API server in background thread (requires `http-api` feature)
- `to_json()` / `to_json_sorted()` - Export devices as JSON (requires `http-api` feature)

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `http-api` | ✓ | Enables the HTTP REST API server, JSON export, and serde serialization |
| `mdns` | ✗ | Enables mDNS (Multicast DNS) sniffing for enhanced device discovery |

```bash
# Build with default features (http-api)
cargo build --release

# Build with mDNS support
cargo build --release --features mdns

# Build with all features
cargo build --release --all-features

# Build without any optional features (smallest binary)
cargo build --release --no-default-features
```

### mDNS Discovery

When the `mdns` feature is enabled, the tool can capture mDNS traffic to discover:

- Device hostnames (`.local` names)
- Service types (HTTP, AirPlay, Chromecast, printers, etc.)
- IP address to hostname mappings

**Passive mode** (`--mdns`): Captures mDNS announcements as devices broadcast them.

**Active mode** (`--mdns-query`): Also sends multicast queries for common services:
- `_http._tcp.local` - Web servers
- `_airplay._tcp.local` - Apple AirPlay devices
- `_googlecast._tcp.local` - Chromecast devices
- `_printer._tcp.local` - Network printers
- `_smb._tcp.local` - SMB file shares
- And more...

## Testing

```bash
cargo test
```

## Dependencies

- [pnet](https://crates.io/crates/pnet) - Low-level networking library for packet capture and parsing
- [oui-data](https://crates.io/crates/oui-data) - IEEE OUI database for MAC address vendor identification (40,000+ entries)
- [serde](https://crates.io/crates/serde) - Serialization framework for JSON support (optional, `http-api` feature)
- [serde_json](https://crates.io/crates/serde_json) - JSON serialization/deserialization (optional, `http-api` feature)
- [tiny_http](https://crates.io/crates/tiny_http) - Lightweight HTTP server for the REST API (optional, `http-api` feature)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Richard Vidal-Dorsch

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

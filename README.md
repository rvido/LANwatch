# dhcpsniff

A Rust library and CLI tool for sniffing and parsing DHCP (v4 & v6) network traffic.

## Features

- **DHCPv4 Support**: Capture and parse DHCP DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, and INFORM messages
- **DHCPv6 Support**: Capture and parse SOLICIT, ADVERTISE, REQUEST, CONFIRM, RENEW, REBIND, REPLY, RELEASE, DECLINE, RECONFIGURE, and INFO-REQUEST messages
- **Device Tracking**: Automatically track detected devices and save to CSV file
- **CSV Export**: Export device information with timestamps, MAC addresses, IP addresses, and hostnames
- **HTTP API**: Built-in REST API server to query devices as JSON
- **Library API**: Use as a library in your own Rust projects
- **CLI Tool**: Run as a standalone command-line sniffer
- **Type-Safe**: Strongly typed enums for message types, operations, and options
- **Cross-Platform**: Works on macOS, Linux, and other Unix-like systems

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
dhcpsniff = "0.1.0"
```

Or clone and build from source:

```bash
git clone <repository-url>
cd dhcpsniff
cargo build --release
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

# Start with HTTP API server
sudo cargo run -- en0 --api 0.0.0.0:8080

# Start with API on default address (127.0.0.1:3000)
sudo cargo run -- en0 --api-default

# Combine options
sudo cargo run -- en0 -o devices.csv --api 0.0.0.0:8080

# Show help
cargo run -- --help
```

**Note:** Root/sudo privileges are typically required for packet capture.

### CSV Output Format

The tool saves detected devices to a CSV file with the following columns:

```csv
last_seen,mac_address,ip_address,hostname,first_seen
2026-01-16T10:30:45Z,AA:BB:CC:DD:EE:FF,192.168.1.100,"mydevice",2026-01-16T10:25:00Z
2026-01-16T10:28:30Z,11:22:33:44:55:66,192.168.1.101,"",2026-01-16T10:28:30Z
```

- **last_seen**: ISO 8601 timestamp of last DHCP activity
- **mac_address**: Device MAC address (or DUID for DHCPv6)
- **ip_address**: IP address (requested or assigned)
- **hostname**: Device hostname if available (empty if not)
- **first_seen**: ISO 8601 timestamp of first detection

The CSV file is updated in real-time as new devices are detected or existing devices change.

### HTTP API

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
      "hostname": "mydevice",
      "first_seen": "2026-01-16T10:25:00Z",
      "last_seen": "2026-01-16T10:30:45Z"
    }
  ]
}
```

### Library Usage

```rust
use dhcpsniff::{DhcpSniffer, DhcpEvent, DeviceTracker, Dhcpv6Option};

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
use dhcpsniff::{parse_dhcpv4_payload, parse_dhcpv6_payload};
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

- `DhcpSniffer` - Main sniffer struct for capturing packets
- `DhcpEvent` - Enum containing either `V4(Dhcpv4Packet)` or `V6(Dhcpv6Packet)`
- `Dhcpv4Packet` - Parsed DHCPv4 packet with all fields
- `Dhcpv6Packet` - Parsed DHCPv6 packet with all fields
- `DeviceTracker` - Track detected devices and save to CSV
- `DeviceInfo` - Information about a detected device
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

### Helper Functions

- `list_interfaces()` - List available network interfaces
- `find_interface(name)` - Find interface by name
- `is_dhcpv4_ports(src, dest)` - Check if ports indicate DHCPv4
- `is_dhcpv6_ports(src, dest)` - Check if ports indicate DHCPv6
- `parse_dhcpv4_payload(payload, src, dst, src_port, dst_port)` - Parse DHCPv4 from raw bytes
- `parse_dhcpv6_payload(payload, src, dst, src_port, dst_port)` - Parse DHCPv6 from raw bytes
- `start_api_server(addr, tracker)` - Start HTTP API server in background thread

## Testing

```bash
cargo test
```

## Dependencies

- [pnet](https://crates.io/crates/pnet) - Low-level networking library for packet capture and parsing
- [serde](https://crates.io/crates/serde) - Serialization framework for JSON support
- [serde_json](https://crates.io/crates/serde_json) - JSON serialization/deserialization
- [tiny_http](https://crates.io/crates/tiny_http) - Lightweight HTTP server for the REST API

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Richard Vidal-Dorsch

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

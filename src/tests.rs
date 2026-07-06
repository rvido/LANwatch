mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;
    use std::time::SystemTime;
    use std::fs::File;

    #[cfg(feature = "ssdp")]
    use std::collections::HashMap;

    use crate::device::{is_leap_year, sanitize_hostname};
    use crate::parser::dhcp::extract_mac_from_duid;

    #[cfg(feature = "mdns")]
    use crate::parser::mdns::{parse_dns_name, is_mdns_ports};

    #[cfg(feature = "http-api")]
    use crate::api::{ApiResponse, ApiError};

    #[test]
    fn test_dhcpv4_message_type_from_u8() {
        assert_eq!(Dhcpv4MessageType::from(1), Dhcpv4MessageType::Discover);
        assert_eq!(Dhcpv4MessageType::from(2), Dhcpv4MessageType::Offer);
        assert_eq!(Dhcpv4MessageType::from(3), Dhcpv4MessageType::Request);
        assert_eq!(Dhcpv4MessageType::from(5), Dhcpv4MessageType::Ack);
        assert_eq!(Dhcpv4MessageType::from(6), Dhcpv4MessageType::Nak);
        assert_eq!(Dhcpv4MessageType::from(7), Dhcpv4MessageType::Release);
        assert_eq!(Dhcpv4MessageType::from(99), Dhcpv4MessageType::Unknown(99));
    }

    #[test]
    fn test_dhcpv4_message_type_display() {
        assert_eq!(format!("{}", Dhcpv4MessageType::Discover), "DISCOVER");
        assert_eq!(format!("{}", Dhcpv4MessageType::Offer), "OFFER");
        assert_eq!(format!("{}", Dhcpv4MessageType::Unknown(42)), "UNKNOWN(42)");
    }

    #[test]
    fn test_dhcpv4_operation_from_u8() {
        assert_eq!(Dhcpv4Operation::from(1), Dhcpv4Operation::BootRequest);
        assert_eq!(Dhcpv4Operation::from(2), Dhcpv4Operation::BootReply);
        assert_eq!(Dhcpv4Operation::from(99), Dhcpv4Operation::Unknown(99));
    }

    #[test]
    fn test_dhcpv6_message_type_from_u8() {
        assert_eq!(Dhcpv6MessageType::from(1), Dhcpv6MessageType::Solicit);
        assert_eq!(Dhcpv6MessageType::from(2), Dhcpv6MessageType::Advertise);
        assert_eq!(Dhcpv6MessageType::from(7), Dhcpv6MessageType::Reply);
        assert_eq!(Dhcpv6MessageType::from(11), Dhcpv6MessageType::InfoRequest);
        assert_eq!(Dhcpv6MessageType::from(99), Dhcpv6MessageType::Unknown(99));
    }

    #[test]
    fn test_dhcpv6_message_type_display() {
        assert_eq!(format!("{}", Dhcpv6MessageType::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcpv6MessageType::Reply), "REPLY");
        assert_eq!(
            format!("{}", Dhcpv6MessageType::InfoRequest),
            "INFO-REQUEST"
        );
    }

    #[test]
    fn test_is_dhcpv4_ports() {
        assert!(is_dhcpv4_ports(67, 1234));
        assert!(is_dhcpv4_ports(68, 1234));
        assert!(is_dhcpv4_ports(1234, 67));
        assert!(is_dhcpv4_ports(1234, 68));
        assert!(!is_dhcpv4_ports(80, 443));
    }

    #[test]
    fn test_is_dhcpv6_ports() {
        assert!(is_dhcpv6_ports(546, 1234));
        assert!(is_dhcpv6_ports(547, 1234));
        assert!(is_dhcpv6_ports(1234, 546));
        assert!(is_dhcpv6_ports(1234, 547));
        assert!(!is_dhcpv6_ports(80, 443));
    }

    #[test]
    fn test_parse_dhcpv4_payload_too_short() {
        let payload = vec![0u8; 100];
        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dhcpv4_payload_basic() {
        // Create a minimal valid DHCPv4 packet
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Set client MAC at offset 28-33
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0xFF;
        // Add DHCP magic cookie would be at 236-239
        // Add message type option at 240
        payload[240] = 53; // Option: DHCP Message Type
        payload[241] = 1; // Length: 1
        payload[242] = 1; // DISCOVER
        payload[243] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.operation, Dhcpv4Operation::BootRequest);
        assert_eq!(packet.client_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(packet.client_mac_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(packet.message_type, Some(Dhcpv4MessageType::Discover));
        assert_eq!(packet.source_port, 68);
        assert_eq!(packet.dest_port, 67);
    }

    #[test]
    fn test_parse_dhcpv4_with_hostname() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Add hostname option at 240
        payload[240] = 12; // Option: Hostname
        payload[241] = 4; // Length: 4
        payload[242] = b't';
        payload[243] = b'e';
        payload[244] = b's';
        payload[245] = b't';
        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.hostname, Some("test".to_string()));
    }

    #[test]
    fn test_parse_dhcpv4_with_requested_ip() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        // Add requested IP option at 240
        payload[240] = 50; // Option: Requested IP
        payload[241] = 4; // Length: 4
        payload[242] = 192;
        payload[243] = 168;
        payload[244] = 1;
        payload[245] = 100;
        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.requested_ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_parse_dhcpv4_fallback_to_yiaddr() {
        // Minimal DHCPv4 packet where yiaddr is populated by server reply.
        let mut payload = vec![0u8; 300];
        payload[0] = 2; // BootReply
        // yiaddr (bytes 16..20)
        payload[16] = 192;
        payload[17] = 168;
        payload[18] = 4;
        payload[19] = 81;
        // Client MAC
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0xFF;
        // End options
        payload[240] = 255;

        let packet = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 4, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            67,
            68,
        )
        .unwrap();

        assert_eq!(packet.requested_ip, Some(Ipv4Addr::new(192, 168, 4, 81)));
    }

    #[test]
    fn test_parse_dhcpv6_payload_too_short() {
        let payload = vec![0u8; 2];
        let result = parse_dhcpv6_payload(
            &payload,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            546,
            547,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dhcpv6_payload_basic() {
        // Create a minimal DHCPv6 packet
        let mut payload = vec![0u8; 10];
        payload[0] = 1; // SOLICIT
        payload[1] = 0x12; // Transaction ID byte 1
        payload[2] = 0x34; // Transaction ID byte 2
        payload[3] = 0x56; // Transaction ID byte 3

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Solicit);
        assert_eq!(packet.transaction_id, [0x12, 0x34, 0x56]);
        assert_eq!(packet.transaction_id_string(), "0x123456");
    }

    #[test]
    fn test_parse_dhcpv6_with_client_id() {
        // Exactly 12 bytes: 4 header + 8 option (4 header + 4 data)
        let payload = vec![
            0x01, // Message type: SOLICIT
            0xAB, 0xCD, 0xEF, // Transaction ID
            0x00, 0x01, // Option code: 1 (Client ID)
            0x00, 0x04, // Length: 4
            0xDE, 0xAD, 0xBE, 0xEF, // Client ID data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientId(data) => {
                assert_eq!(data, &vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("Expected ClientId option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_client_fqdn_dns_wire_format() {
        // SOLICIT + option 39 (Client FQDN)
        // value: [flags=0x00][len=8]['CircleV2'][root=0]
        let payload = vec![
            0x01, // Message type: SOLICIT
            0x11, 0x22, 0x33, // Transaction ID
            0x00, 0x27, // Option code: 39 (Client FQDN)
            0x00, 0x0B, // Length: 11
            0x00, // Flags
            0x08, b'C', b'i', b'r', b'c', b'l', b'e', b'V', b'2', 0x00, // Root label
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientFqdn(name) => assert_eq!(name, "CircleV2"),
            _ => panic!("Expected ClientFqdn option"),
        }
    }

    #[test]
    fn test_dhcp_error_display() {
        let err = DhcpError::InterfaceNotFound("eth0".to_string());
        assert_eq!(format!("{}", err), "Interface not found: eth0");

        let err = DhcpError::UnsupportedChannelType;
        assert_eq!(format!("{}", err), "Unsupported channel type");
    }

    #[test]
    fn test_list_interfaces() {
        // Just verify it doesn't panic and returns a valid list
        let interfaces = list_interfaces();
        // Verify it's a valid Vec (this will always pass, but ensures the function works)
        let _ = interfaces;
    }

    #[test]
    fn test_device_info_creation() {
        let device = DeviceInfo::new(
            "aa:bb:cc:dd:ee:ff".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Some("testhost".to_string()),
        );

        assert_eq!(device.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(device.ip_address.to_string(), "192.168.1.100");
        assert_eq!(device.hostname, Some("testhost".to_string()));
        assert_eq!(device.first_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_csv_roundtrip() {
        let device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: Some("fe80::1".parse().unwrap()),
            ipv6_addresses: vec!["fe80::1".parse().unwrap()],
            hostname: Some("testhost".to_string()),
            system_description: Some("My LLDP Device Description".to_string()),
            services: vec!["_http._tcp".to_string(), "_ssh._tcp".to_string()],
            vendor: Some("TestVendor".to_string()),
            device_type: Some("Server".to_string()),
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.ipv6_address, device.ipv6_address);
        assert_eq!(parsed.hostname, device.hostname);
        assert_eq!(parsed.system_description, device.system_description);
        assert_eq!(parsed.services, device.services);
        assert_eq!(parsed.vendor, device.vendor);
        assert_eq!(parsed.device_type, device.device_type);
        assert_eq!(parsed.first_seen, device.first_seen);
        assert_eq!(parsed.last_seen, device.last_seen);
    }

    #[test]
    fn test_device_info_from_csv_normalizes_legacy_dhcpv6_duid_identifier() {
        let line = "2026-04-07T02:41:49Z,2026-04-07T03:12:39Z,00:03:00:01:8c:e2:da:bc:78:7a,fe80::8ee2:daff:febc:787a,\"\",\"\0\x08CircleV2\0\",\"\",\"Barracuda Networks, Inc.\",\"\"";
        let parsed = DeviceInfo::from_csv_line(line).unwrap();

        assert_eq!(parsed.mac_address, "8c:e2:da:bc:78:7a");
        assert_eq!(parsed.hostname.as_deref(), Some("CircleV2"));
    }

    #[test]
    fn test_device_info_csv_no_hostname() {
        let device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: None,
            ipv6_addresses: Vec::new(),
            hostname: None,
            system_description: None,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        let csv_line = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv_line).unwrap();

        assert_eq!(parsed.hostname, None);
    }

    #[test]
    fn test_device_info_update() {
        let mut device = DeviceInfo {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: None,
            ipv6_addresses: Vec::new(),
            hostname: None,
            system_description: None,
            services: Vec::new(),
            vendor: None,
            device_type: None,
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
        };

        // Update with new IP - should return true
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), None);
        assert!(changed);
        assert_eq!(device.ip_address.to_string(), "192.168.1.200");

        // Update with same IP - should return false
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), None);
        assert!(!changed);

        // Update with hostname - should return true
        let changed = device.update(Ipv4Addr::new(192, 168, 1, 200).into(), Some("newhost"));
        assert!(changed);
        assert_eq!(device.hostname, Some("newhost".to_string()));
    }

    #[test]
    fn test_format_timestamp() {
        // Test epoch
        let epoch = SystemTime::UNIX_EPOCH;
        let ts = format_timestamp(epoch);
        assert_eq!(ts, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(!is_leap_year(1900)); // Not leap (divisible by 100 but not 400)
        assert!(is_leap_year(2000)); // Leap (divisible by 400)
        assert!(is_leap_year(2024)); // Leap (divisible by 4)
        assert!(!is_leap_year(2023)); // Not leap
    }

    #[test]
    fn test_device_tracker_new_device() {
        let temp_path = "/tmp/lanwatch_test_devices.csv";
        let _ = std::fs::remove_file(temp_path); // Clean up any existing file
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Create a test packet
        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("testhost".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        let is_new = tracker.update_from_dhcpv4(&packet);
        assert!(is_new);
        assert_eq!(tracker.device_count(), 1);

        // Same device should not be "new"
        let is_new = tracker.update_from_dhcpv4(&packet);
        assert!(!is_new);
        assert_eq!(tracker.device_count(), 1);

        // Clean up
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_device_tracker_dhcpv4_does_not_use_server_source_ip() {
        let temp_path = "/tmp/lanwatch_test_dhcpv4_server_ip.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Simulate DHCPv4 server reply without requested_ip/yiaddr fallback data.
        // The server source IP (router) must not be attributed to client MAC.
        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 1),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 67,
            dest_port: 68,
            operation: Dhcpv4Operation::BootReply,
            client_mac: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            message_type: Some(Dhcpv4MessageType::Offer),
            hostname: None,
            requested_ip: None,
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);
        let device = tracker.devices().get("10:20:30:40:50:60").unwrap();
        assert_eq!(device.ip_address.to_string(), "0.0.0.0");

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_update_from_dhcpv6() {
        let temp_path = "/tmp/lanwatch_test_v6_devices.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Create a DHCPv6 packet with ClientId
        let packet = Dhcpv6Packet {
            source_ip: "fe80::1".parse().unwrap(),
            dest_ip: "ff02::1:2".parse().unwrap(),
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x12, 0x34, 0x56],
            options: vec![
                // DUID-LL (type 3), hw type Ethernet (1), MAC aa:bb:cc:dd:ee:ff
                Dhcpv6Option::ClientId(vec![
                    0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                ]),
                Dhcpv6Option::ClientFqdn("myhost.local".to_string()),
            ],
        };

        let is_new = tracker.update_from_dhcpv6(&packet);
        assert!(is_new);
        assert_eq!(tracker.device_count(), 1);

        // Verify the device was stored with extracted Ethernet MAC
        let devices = tracker.devices();
        assert!(devices.contains_key("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            devices
                .get("aa:bb:cc:dd:ee:ff")
                .and_then(|d| d.hostname.as_deref()),
            Some("myhost.local")
        );

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_dhcpv6_no_client_id() {
        let temp_path = "/tmp/lanwatch_test_v6_no_id.csv";
        let _ = std::fs::remove_file(temp_path);
        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // DHCPv6 packet without ClientId should not be tracked
        let packet = Dhcpv6Packet {
            source_ip: "fe80::1".parse().unwrap(),
            dest_ip: "ff02::1:2".parse().unwrap(),
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x12, 0x34, 0x56],
            options: vec![], // No ClientId
        };

        let is_new = tracker.update_from_dhcpv6(&packet);
        assert!(!is_new); // Should return false - can't track without DUID
        assert_eq!(tracker.device_count(), 0);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_prefers_hostname_over_oui_vendor() {
        let temp_path = "/tmp/lanwatch_test_lenovo_fingerprint.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        tracker.set_oui_registry(OuiRegistry::new());

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 112),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x48, 0x45, 0xE6, 0x48, 0x4C, 0x85],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("RVD_Legion".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 4, 112)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("48:45:e6:48:4c:85").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Lenovo"));
        assert_eq!(device.device_type.as_deref(), Some("Laptop"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_rachio_from_loaded_csv() {
        let temp_path = "/tmp/lanwatch_test_rachio_reclassify.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut device = DeviceInfo::new(
            "9c:50:d1:18:8d:cc".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 4, 36)),
            Some("rachio-188dcc".to_string()),
        );
        device.device_type = Some("Security Camera".to_string());
        device.vendor = Some("Murata Manufacturing Co., Ltd.".to_string());
        tracker.devices.insert(device.mac_address.clone(), device);

        let mut registry = OuiRegistry::new();
        registry.add("9c:50:d1", "Murata Manufacturing Co., Ltd.");
        tracker.set_oui_registry(registry);

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 36),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x9C, 0x50, 0xD1, 0x18, 0x8D, 0xCC],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("rachio-188dcc".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 4, 36)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("9c:50:d1:18:8d:cc").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Rachio"));
        assert_eq!(device.device_type.as_deref(), Some("Smart Watering Device"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_rachio_from_google_thermostat() {
        let temp_path = "/tmp/lanwatch_test_rachio_google_reclassify.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut device = DeviceInfo::new(
            "9c:50:d1:18:8d:cc".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 4, 36)),
            Some("rachio-188dcc".to_string()),
        );
        device.device_type = Some("Thermostat".to_string());
        device.vendor = Some("Google".to_string());
        device.services.push("_hap._tcp".to_string());
        tracker.devices.insert(device.mac_address.clone(), device);

        let mut registry = OuiRegistry::new();
        registry.add("9c:50:d1", "Murata Manufacturing Co., Ltd.");
        tracker.set_oui_registry(registry);

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 4, 36),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x9C, 0x50, 0xD1, 0x18, 0x8D, 0xCC],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("rachio-188dcc".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 4, 36)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("9c:50:d1:18:8d:cc").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Rachio"));
        assert_eq!(device.device_type.as_deref(), Some("Smart Watering Device"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_roborock_from_loaded_csv() {
        let temp_path = "/tmp/lanwatch_test_roborock_reclassify.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut device = DeviceInfo::new(
            "b0:4a:39:e3:3f:da".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 7, 193)),
            Some("roborock-vacuum-a75".to_string()),
        );
        device.device_type = Some("Security Camera".to_string());
        device.vendor = Some("Beijing Roborock Technology Co., Ltd.".to_string());
        tracker.devices.insert(device.mac_address.clone(), device);

        let mut registry = OuiRegistry::new();
        registry.add("b0:4a:39", "Beijing Roborock Technology Co., Ltd.");
        tracker.set_oui_registry(registry);

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 7, 193),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xB0, 0x4A, 0x39, 0xE3, 0x3F, 0xDA],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("roborock-vacuum-a75".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 7, 193)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("b0:4a:39:e3:3f:da").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Roborock"));
        assert_eq!(device.device_type.as_deref(), Some("Smart Cleaning Device"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_uses_oui_for_eero_when_no_hostname_present() {
        let temp_path = "/tmp/lanwatch_test_eero_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut registry = OuiRegistry::new();
        registry.add("dc:69:b5", "eero inc.");
        tracker.set_oui_registry(registry);

        let packet = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(192, 168, 7, 1),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xDC, 0x69, 0xB5, 0x95, 0x58, 0xB2],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 7, 1)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };

        tracker.update_from_dhcpv4(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));
        assert_eq!(device.device_type.as_deref(), Some("Router"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_device_tracker_uses_oui_for_eero_in_mdns_when_no_vendor_present() {
        let temp_path = "/tmp/lanwatch_test_eero_mdns_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut registry = OuiRegistry::new();
        registry.add("dc:69:b5", "eero inc.");
        tracker.set_oui_registry(registry);

        let packet = MdnsPacket {
            source_mac: "dc:69:b5:95:58:b2".to_string(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 7, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 1234,
            is_response: true,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        tracker.update_from_mdns(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_device_tracker_mdns_proxy_reflector_no_pollution() {
        let temp_path = "/tmp/lanwatch_test_eero_mdns_reflector.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut registry = OuiRegistry::new();
        registry.add("dc:69:b5", "eero inc.");
        tracker.set_oui_registry(registry);

        // Pre-populate router (Eero) and a tracked device (HP printer)
        let router_mac = "dc:69:b5:95:58:b2";
        let router_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1));
        let mut router_device = DeviceInfo::new(router_mac.to_string(), router_ip, Some("eero-02j6".to_string()));
        router_device.vendor = Some("eero inc.".to_string());
        router_device.device_type = Some("Router".to_string());
        tracker.devices.insert(router_mac.to_string(), router_device);

        let printer_mac = "00:11:22:33:44:55";
        let printer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 7, 50));
        let printer_device = DeviceInfo::new(printer_mac.to_string(), printer_ip, None);
        tracker.devices.insert(printer_mac.to_string(), printer_device);

        // Create an mDNS packet representing a proxied advertisement for the HP printer
        // sent from the Eero router's MAC/IP, but with target IPs in the records
        let packet = MdnsPacket {
            source_mac: router_mac.to_string(),
            source_ip: router_ip,
            dest_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 42,
            is_response: true,
            questions: vec![],
            answers: vec![
                MdnsRecord {
                    name: "HP-Printer.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 7, 50)),
                },
                MdnsRecord {
                    name: "_printer._tcp.local".to_string(),
                    record_type: MdnsRecordType::Ptr,
                    ttl: 120,
                    data: MdnsRecordData::Ptr("HP-Printer.local".to_string()),
                },
                MdnsRecord {
                    name: "HP-Printer.local".to_string(),
                    record_type: MdnsRecordType::Txt,
                    ttl: 120,
                    data: MdnsRecordData::Txt(vec!["model=HP OfficeJet".to_string()]),
                },
            ],
            authority: vec![],
            additional: vec![],
        };

        // Update should succeed and return some changes
        let changes = tracker.update_from_mdns(&packet);
        assert!(changes > 0, "mDNS update should successfully process proxied info");

        // Verify the printer device was updated
        let printer = tracker.devices().get(printer_mac).unwrap();
        assert_eq!(printer.hostname.as_deref(), Some("HP-Printer"));
        assert_eq!(printer.vendor.as_deref(), Some("HP"));
        assert_eq!(printer.device_type.as_deref(), Some("Printer"));

        // Verify the Eero router was NOT polluted or updated by the printer's mDNS records
        let router = tracker.devices().get(router_mac).unwrap();
        assert_eq!(router.hostname.as_deref(), Some("eero-02j6"));
        assert_eq!(router.vendor.as_deref(), Some("eero inc."));
        assert_eq!(router.device_type.as_deref(), Some("Router"));
        assert!(!router.services.iter().any(|s| s == "_printer._tcp"));

        // Test a proxied packet for an UNTRACKED IP - should be ignored to avoid pollution
        let untracked_packet = MdnsPacket {
            source_mac: router_mac.to_string(),
            source_ip: router_ip,
            dest_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 43,
            is_response: true,
            questions: vec![],
            answers: vec![
                MdnsRecord {
                    name: "Rachio-188DCC.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 7, 99)),
                },
                MdnsRecord {
                    name: "Rachio-188DCC.local".to_string(),
                    record_type: MdnsRecordType::Txt,
                    ttl: 120,
                    data: MdnsRecordData::Txt(vec!["model=Rachio-188DCC".to_string()]),
                },
            ],
            authority: vec![],
            additional: vec![],
        };

        let changes_untracked = tracker.update_from_mdns(&untracked_packet);
        assert_eq!(changes_untracked, 0, "untracked proxy packets should be ignored");

        // Verify again that the Eero router has not been polluted
        let router_after = tracker.devices().get(router_mac).unwrap();
        assert_eq!(router_after.vendor.as_deref(), Some("eero inc."));
        assert_eq!(router_after.device_type.as_deref(), Some("Router"));
        assert_ne!(router_after.system_description.as_deref(), Some("Rachio-188DCC"));

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_uses_oui_for_eero_in_ssdp_when_no_vendor_present() {
        let temp_path = "/tmp/lanwatch_test_eero_ssdp_oui.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut registry = OuiRegistry::new();
        registry.add("dc:69:b5", "eero inc.");
        tracker.set_oui_registry(registry);

        let packet = SsdpPacket {
            source_mac: "dc:69:b5:95:58:b2".to_string(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 7, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
            message_type: SsdpMessageType::Response,
            start_line: "HTTP/1.1 200 OK".to_string(),
            headers: HashMap::new(),
        };

        tracker.update_from_ssdp(&packet);

        let device = tracker.devices().get("dc:69:b5:95:58:b2").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("eero inc."));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_device_tracker_reclassifies_motorola_from_chromecast() {
        let temp_path = "/tmp/lanwatch_test_motorola.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let mut registry = OuiRegistry::new();
        registry.add("dc:69:b5", "eero inc.");
        tracker.set_oui_registry(registry);

        // 1. Initially seen as Chromecast with an OUI-derived vendor (eero inc.)
        let mut device = DeviceInfo::new(
            "dc:69:b5:33:44:55".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            None,
        );
        device.device_type = Some("Chromecast".to_string());
        device.vendor = Some("eero inc.".to_string());
        tracker.devices.insert(device.mac_address.clone(), device);

        // 2. Updated with Motorola hostname - should override Chromecast type and eero vendor!
        tracker.update_device(
            "dc:69:b5:33:44:55",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            Some("Moto-G-Stylus-2025"),
        );

        let device = tracker.devices().get("dc:69:b5:33:44:55").unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Motorola"));
        assert_eq!(device.device_type.as_deref(), Some("Android Phone"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_extract_mac_from_duid_llt() {
        // DUID-LLT type 1, hw type 1 (Ethernet), time 0x12345678, MAC 8c:e2:da:bc:78:7a
        let duid = vec![
            0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x8C, 0xE2, 0xDA, 0xBC, 0x78, 0x7A,
        ];
        assert_eq!(
            extract_mac_from_duid(&duid).as_deref(),
            Some("8c:e2:da:bc:78:7a")
        );
    }

    #[test]
    fn test_sanitize_hostname_removes_control_bytes() {
        assert_eq!(
            sanitize_hostname("\0\u{0008}CircleV2\0").as_deref(),
            Some("CircleV2")
        );
        assert_eq!(sanitize_hostname("....").as_deref(), None);
    }

    #[test]
    fn test_device_tracker_persistence() {
        let temp_path = "/tmp/lanwatch_test_persistence.csv";
        let _ = std::fs::remove_file(temp_path);

        // Create tracker and add a device
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = Dhcpv4Packet {
                source_ip: Ipv4Addr::new(192, 168, 1, 100),
                dest_ip: Ipv4Addr::new(255, 255, 255, 255),
                source_port: 68,
                dest_port: 67,
                operation: Dhcpv4Operation::BootRequest,
                client_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                message_type: Some(Dhcpv4MessageType::Request),
                hostname: Some("persistent-host".to_string()),
                requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
                parameter_request_list: None,
                vendor_class_id: None,
                vendor_specific_info: None,
            };
            tracker.update_from_dhcpv4(&packet);
            assert_eq!(tracker.device_count(), 1);
        }

        // Create new tracker and verify data was loaded
        {
            let tracker = DeviceTracker::new(temp_path).unwrap();
            assert_eq!(tracker.device_count(), 1);

            let devices = tracker.devices();
            let device = devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.ip_address.to_string(), "192.168.1.100");
            assert_eq!(device.hostname, Some("persistent-host".to_string()));
        }

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_device_info_json_serialization() {
        let device = DeviceInfo {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 100).into(),
            ipv6_address: Some("fe80::abcd:1234".parse().unwrap()),
            ipv6_addresses: vec!["fe80::abcd:1234".parse().unwrap()],
            hostname: Some("jsonhost".to_string()),
            system_description: None,
            services: vec!["_airplay._tcp".to_string()],
            vendor: Some("Apple".to_string()),
            device_type: Some("AirPlay Device".to_string()),
            first_seen: parse_timestamp("2026-01-15T10:00:00Z").unwrap(),
            last_seen: parse_timestamp("2026-01-15T12:00:00Z").unwrap(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("AA:BB:CC:DD:EE:FF"));
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("fe80::abcd:1234"));
        assert!(json.contains("jsonhost"));

        // Deserialize back
        let parsed: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.hostname, device.hostname);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_device_tracker_to_json() {
        let temp_path = "/tmp/lanwatch_test_json.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // Add two devices
        let packet1 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: Some("device1".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet1);

        let packet2 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 2)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet2);

        let json = tracker.to_json().unwrap();
        assert!(json.contains("device1"));
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("192.168.1.2"));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_parse_dhcpv6_with_server_id() {
        let payload = vec![
            0x02, // Message type: ADVERTISE
            0x12, 0x34, 0x56, // Transaction ID
            0x00, 0x02, // Option code: 2 (Server ID)
            0x00, 0x04, // Length: 4
            0x01, 0x02, 0x03, 0x04, // Server ID data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 547, 546);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Advertise);
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ServerId(data) => {
                assert_eq!(data, &vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected ServerId option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_client_fqdn() {
        let fqdn = "myhost.example.com";
        let mut payload = vec![
            0x01, // Message type: SOLICIT
            0xAB, 0xCD, 0xEF, // Transaction ID
            0x00, 0x27, // Option code: 39 (Client FQDN)
        ];

        // RFC 4704 encoding: flags + DNS wire-format labels
        let fqdn_data = vec![
            0x00, // Flags
            0x06, b'm', b'y', b'h', b'o', b's', b't', // myhost
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // root
        ];

        // Add length (2 bytes big-endian)
        payload.push(0x00);
        payload.push(fqdn_data.len() as u8);
        // Add FQDN data
        payload.extend_from_slice(&fqdn_data);

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 1);
        match &packet.options[0] {
            Dhcpv6Option::ClientFqdn(name) => {
                assert_eq!(name, fqdn);
            }
            _ => panic!("Expected ClientFqdn option"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_with_ia_na() {
        let payload = vec![
            0x03, // Message type: REQUEST
            0x11, 0x22, 0x33, // Transaction ID
            0x00, 0x03, // Option code: 3 (IA_NA)
            0x00, 0x00, // Length: 0 (minimal)
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.message_type, Dhcpv6MessageType::Request);
        assert_eq!(packet.options.len(), 1);
        assert!(matches!(packet.options[0], Dhcpv6Option::IaNa));
    }

    #[test]
    fn test_parse_dhcpv6_multiple_options() {
        let payload = vec![
            0x01, // Message type: SOLICIT
            0x00, 0x00, 0x01, // Transaction ID
            // Option 1: ClientId
            0x00, 0x01, // Option code: 1
            0x00, 0x02, // Length: 2
            0xAA, 0xBB, // Data
            // Option 2: IA_NA
            0x00, 0x03, // Option code: 3
            0x00, 0x00, // Length: 0
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 2);
    }

    #[test]
    fn test_parse_dhcpv4_truncated_option() {
        // Payload with option that claims longer length than available
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        payload[240] = 12; // Option: Hostname
        payload[241] = 100; // Length: 100 (but only a few bytes available)
        payload[242] = b't';
        payload[243] = 255; // End option prematurely

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        // Should still parse but might not have hostname
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_dhcpv6_truncated_option() {
        // Option claims 100 bytes but only 2 available
        let payload = vec![
            0x01, // Message type
            0x00, 0x00, 0x01, // Transaction ID
            0x00, 0x01, // Option code
            0x00, 0x64, // Length: 100 (but not enough data)
            0xAA, 0xBB, // Only 2 bytes of data
        ];

        let result =
            parse_dhcpv6_payload(&payload, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 546, 547);

        // Should parse but truncated option won't be included
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.options.len(), 0); // Option was skipped due to truncation
    }

    #[test]
    fn test_dhcpv4_packet_fields() {
        let mut payload = vec![0u8; 300];
        payload[0] = 2; // BootReply
        // Set client MAC
        for i in 0..6 {
            payload[28 + i] = (i + 1) as u8;
        }
        // Set yiaddr (your IP address) at offset 16
        payload[16] = 10;
        payload[17] = 0;
        payload[18] = 0;
        payload[19] = 100;

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            67,
            68,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.operation, Dhcpv4Operation::BootReply);
        assert_eq!(packet.source_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(packet.dest_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(packet.client_mac, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_dhcpv6_packet_transaction_id_string() {
        let packet = Dhcpv6Packet {
            source_ip: Ipv6Addr::LOCALHOST,
            dest_ip: Ipv6Addr::LOCALHOST,
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0x00, 0x00, 0x00],
            options: vec![],
        };
        assert_eq!(packet.transaction_id_string(), "0x000000");

        let packet2 = Dhcpv6Packet {
            source_ip: Ipv6Addr::LOCALHOST,
            dest_ip: Ipv6Addr::LOCALHOST,
            source_port: 546,
            dest_port: 547,
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: [0xFF, 0xFF, 0xFF],
            options: vec![],
        };
        // The format uses uppercase hex
        assert_eq!(packet2.transaction_id_string(), "0xFFFFFF");
    }

    #[test]
    fn test_device_tracker_mac_address_update() {
        let temp_path = "/tmp/lanwatch_test_mac_update.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // First packet with one IP
        let packet1 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet1);
        assert_eq!(tracker.device_count(), 1);

        // Same MAC, different IP (simulating DHCP renewal with new IP)
        let packet2 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            message_type: Some(Dhcpv4MessageType::Request),
            hostname: Some("newname".to_string()),
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 200)),
            parameter_request_list: None,
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        let changed = tracker.update_from_dhcpv4(&packet2);
        assert!(changed);
        assert_eq!(tracker.device_count(), 1); // Still only 1 device

        // Verify IP was updated (MAC is lowercase)
        let device = tracker.devices().get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(device.ip_address.to_string(), "192.168.1.200");
        assert_eq!(device.hostname, Some("newname".to_string()));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_api_response_serialization() {
        let response: ApiResponse<Vec<String>> = ApiResponse {
            success: true,
            data: vec!["test".to_string()],
            count: 1,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"count\":1"));
    }

    #[test]
    #[cfg(feature = "http-api")]
    fn test_api_error_serialization() {
        let error = ApiError {
            success: false,
            error: "Not found".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("Not found"));
    }

    // =========================================================================
    // mDNS Tests
    // =========================================================================

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_record_type_from_u16() {
        assert_eq!(MdnsRecordType::from(1), MdnsRecordType::A);
        assert_eq!(MdnsRecordType::from(28), MdnsRecordType::Aaaa);
        assert_eq!(MdnsRecordType::from(12), MdnsRecordType::Ptr);
        assert_eq!(MdnsRecordType::from(33), MdnsRecordType::Srv);
        assert_eq!(MdnsRecordType::from(16), MdnsRecordType::Txt);
        assert_eq!(MdnsRecordType::from(255), MdnsRecordType::Any);
        assert_eq!(MdnsRecordType::from(99), MdnsRecordType::Unknown(99));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_record_type_display() {
        assert_eq!(format!("{}", MdnsRecordType::A), "A");
        assert_eq!(format!("{}", MdnsRecordType::Aaaa), "AAAA");
        assert_eq!(format!("{}", MdnsRecordType::Ptr), "PTR");
        assert_eq!(format!("{}", MdnsRecordType::Srv), "SRV");
        assert_eq!(format!("{}", MdnsRecordType::Txt), "TXT");
        assert_eq!(format!("{}", MdnsRecordType::Unknown(42)), "UNKNOWN(42)");
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_is_mdns_ports() {
        assert!(is_mdns_ports(5353, 1234));
        assert!(is_mdns_ports(1234, 5353));
        assert!(is_mdns_ports(5353, 5353));
        assert!(!is_mdns_ports(80, 443));
        assert!(!is_mdns_ports(67, 68));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_payload_too_short() {
        let payload = vec![0u8; 10];
        let result = parse_mdns_payload(
            &payload,
            "00:11:22:33:44:55".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );
        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_query() {
        // Build a simple mDNS query for _http._tcp.local
        let mut payload = Vec::new();
        // Transaction ID
        payload.extend_from_slice(&[0x00, 0x00]);
        // Flags (standard query)
        payload.extend_from_slice(&[0x00, 0x00]);
        // Questions: 1
        payload.extend_from_slice(&[0x00, 0x01]);
        // Answer/Authority/Additional: 0
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Question: _http._tcp.local
        payload.push(5);
        payload.extend_from_slice(b"_http");
        payload.push(4);
        payload.extend_from_slice(b"_tcp");
        payload.push(5);
        payload.extend_from_slice(b"local");
        payload.push(0);
        // QTYPE: PTR (12)
        payload.extend_from_slice(&[0x00, 0x0C]);
        // QCLASS: IN (1)
        payload.extend_from_slice(&[0x00, 0x01]);

        let result = parse_mdns_payload(
            &payload,
            "aa:bb:cc:dd:ee:ff".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "aa:bb:cc:dd:ee:ff");
        assert!(!packet.is_response);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "_http._tcp.local");
        assert_eq!(packet.questions[0].record_type, MdnsRecordType::Ptr);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_dns_name_rejects_pointer_cycle() {
        let payload = vec![0xC0, 0x02, 0xC0, 0x00];

        assert!(parse_dns_name(&payload, 0).is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_payload_rejects_large_header_counts() {
        let mut payload = vec![0u8; 12];
        payload[4..6].copy_from_slice(&u16::MAX.to_be_bytes());

        let result = parse_mdns_payload(
            &payload,
            "aa:bb:cc:dd:ee:ff".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns_response_with_a_record() {
        let mut payload = Vec::new();
        // Transaction ID
        payload.extend_from_slice(&[0x00, 0x00]);
        // Flags (response)
        payload.extend_from_slice(&[0x84, 0x00]);
        // Questions: 0, Answers: 1, Authority: 0, Additional: 0
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Answer: mydevice.local A 192.168.1.50
        payload.push(8);
        payload.extend_from_slice(b"mydevice");
        payload.push(5);
        payload.extend_from_slice(b"local");
        payload.push(0);
        // TYPE: A (1)
        payload.extend_from_slice(&[0x00, 0x01]);
        // CLASS: IN with cache-flush
        payload.extend_from_slice(&[0x80, 0x01]);
        // TTL: 120
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        // RDLENGTH: 4
        payload.extend_from_slice(&[0x00, 0x04]);
        // RDATA: 192.168.1.50
        payload.extend_from_slice(&[192, 168, 1, 50]);

        let result = parse_mdns_payload(
            &payload,
            "11:22:33:44:55:66".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "11:22:33:44:55:66");
        assert!(packet.is_response);
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.answers[0].name, "mydevice.local");
        assert_eq!(packet.answers[0].record_type, MdnsRecordType::A);
        assert_eq!(packet.answers[0].ttl, 120);
        if let MdnsRecordData::A(addr) = &packet.answers[0].data {
            assert_eq!(*addr, Ipv4Addr::new(192, 168, 1, 50));
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_build_mdns_query() {
        let query = build_mdns_query("_http._tcp.local", MdnsRecordType::Ptr);

        // Should be a valid DNS query packet
        assert!(query.len() >= 12);

        // Check header
        assert_eq!(query[0..2], [0x00, 0x00]); // Transaction ID
        assert_eq!(query[2..4], [0x00, 0x00]); // Flags (query)
        assert_eq!(query[4..6], [0x00, 0x01]); // 1 question
        assert_eq!(query[6..8], [0x00, 0x00]); // 0 answers

        // Parse it back
        let parsed = parse_mdns_payload(
            &query,
            "de:ad:be:ef:00:01".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
        );
        assert!(parsed.is_some());
        let packet = parsed.unwrap();
        assert!(!packet.is_response);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "_http._tcp.local");
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_packet_get_ipv4_addresses() {
        let packet = MdnsPacket {
            source_mac: "00:11:22:33:44:55".to_string(),
            source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_ip: std::net::IpAddr::V4(MDNS_IPV4_MULTICAST),
            transaction_id: 0,
            is_response: true,
            questions: vec![],
            answers: vec![
                MdnsRecord {
                    name: "device1.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 1, 10)),
                },
                MdnsRecord {
                    name: "device2.local".to_string(),
                    record_type: MdnsRecordType::A,
                    ttl: 120,
                    data: MdnsRecordData::A(Ipv4Addr::new(192, 168, 1, 20)),
                },
            ],
            authority: vec![],
            additional: vec![],
        };

        let addresses = packet.get_ipv4_addresses();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&("device1.local".to_string(), Ipv4Addr::new(192, 168, 1, 10))));
        assert!(addresses.contains(&("device2.local".to_string(), Ipv4Addr::new(192, 168, 1, 20))));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_constants() {
        assert_eq!(MDNS_PORT, 5353);
        assert_eq!(MDNS_IPV4_MULTICAST, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(
            MDNS_IPV6_MULTICAST,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)
        );
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_defaults() {
        let registry = MdnsServiceRegistry::with_defaults();

        // Should have some default services
        assert!(!registry.is_empty());

        // Test Apple service lookup
        let airplay = registry.lookup("_airplay._tcp");
        assert!(airplay.is_some());
        let airplay = airplay.unwrap();
        assert_eq!(airplay.vendor, Some("Apple".to_string()));

        // Test Google service lookup
        assert_eq!(registry.get_vendor("_googlecast._tcp"), Some("Google"));

        // Test service without vendor
        let http = registry.lookup("_http._tcp");
        assert!(http.is_some());
        assert!(http.unwrap().vendor.is_none());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_add() {
        let mut registry = MdnsServiceRegistry::new();

        registry.add("_custom._tcp", "Custom Service", Some("MyVendor"));

        let service = registry.lookup("_custom._tcp");
        assert!(service.is_some());
        assert_eq!(service.unwrap().description, "Custom Service");
        assert_eq!(registry.get_vendor("_custom._tcp"), Some("MyVendor"));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_service_registry_normalize() {
        let mut registry = MdnsServiceRegistry::new();

        // Add with .local suffix
        registry.add("_test._tcp.local", "Test Service", None);

        // Should be found with or without .local
        assert!(registry.lookup("_test._tcp").is_some());
        assert!(registry.lookup("_test._tcp.local").is_some());

        // Case insensitive
        assert!(registry.lookup("_TEST._TCP").is_some());
    }

    #[test]
    fn test_device_info_add_service() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Adding a new service should return true
        assert!(device.add_service("_http._tcp"));
        assert_eq!(device.services, vec!["_http._tcp"]);

        // Adding the same service should return false
        assert!(!device.add_service("_http._tcp"));

        // Adding with .local suffix should normalize
        assert!(device.add_service("_ssh._tcp.local"));
        assert!(device.services.contains(&"_ssh._tcp".to_string()));

        // Services should be sorted
        assert_eq!(device.services, vec!["_http._tcp", "_ssh._tcp"]);
    }

    #[test]
    fn test_device_info_set_vendor() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Setting vendor first time should return true
        assert!(device.set_vendor("Apple"));
        assert_eq!(device.vendor, Some("Apple".to_string()));

        // Setting vendor again should return false (first wins)
        assert!(!device.set_vendor("Google"));
        assert_eq!(device.vendor, Some("Apple".to_string()));
    }

    #[test]
    fn test_device_info_set_device_type() {
        let mut device = DeviceInfo::new(
            "AA:BB:CC:DD:EE:FF".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Setting device type first time should return true
        assert!(device.set_device_type("Chromecast"));
        assert_eq!(device.device_type, Some("Chromecast".to_string()));

        // Setting device type again should return false (first wins)
        assert!(!device.set_device_type("Apple TV"));
        assert_eq!(device.device_type, Some("Chromecast".to_string()));
    }

    #[test]
    fn test_device_info_csv_roundtrip_with_device_type() {
        let mut device = DeviceInfo::new(
            "aa:bb:cc:dd:ee:ff".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Some("mydevice".to_string()),
        );
        device.add_service("_googlecast._tcp");
        device.set_vendor("Google");
        device.set_device_type("Chromecast");

        let csv = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv).unwrap();

        assert_eq!(parsed.mac_address, device.mac_address);
        assert_eq!(parsed.ip_address, device.ip_address);
        assert_eq!(parsed.hostname, device.hostname);
        assert_eq!(parsed.services, device.services);
        assert_eq!(parsed.vendor, device.vendor);
        assert_eq!(parsed.device_type, device.device_type);
    }

    // ========================================================================
    // OUI Registry Tests
    // ========================================================================

    #[test]
    fn test_oui_registry_new() {
        let registry = OuiRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.custom_count(), 0);
        assert_eq!(OuiRegistry::builtin_count(), 0);
    }

    #[test]
    fn test_oui_registry_with_defaults() {
        let registry = OuiRegistry::with_defaults();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_oui_registry_lookup_known_vendor() {
        let mut registry = OuiRegistry::new();
        registry.add("00:1B:63", "Apple");
        registry.add("00:1B:21", "Intel");

        // Apple's OUI (well-known)
        let vendor = registry.lookup("00:1B:63:00:00:00");
        assert_eq!(vendor, Some("Apple"));

        // Intel's OUI (well-known)
        let vendor = registry.lookup("00:1B:21:00:00:00");
        assert_eq!(vendor, Some("Intel"));
    }

    #[test]
    fn test_oui_registry_normalize_mac() {
        let mut registry = OuiRegistry::new();
        registry.add("00:1B:63", "Apple");

        // All these formats should normalize to the same OUI lookup
        let mac_formats = [
            "00:1B:63:AA:BB:CC", // colon separated full
            "00-1B-63-AA-BB-CC", // dash separated full
            "001B63AABBCC",      // no separator
            "00:1B:63",          // OUI only
            "001B63",            // OUI only no separator
        ];

        // They should all find the same vendor (or none)
        let first_result = registry.lookup(mac_formats[0]);
        for mac in &mac_formats[1..] {
            assert_eq!(
                registry.lookup(mac),
                first_result,
                "All MAC formats should resolve to same vendor: {}",
                mac
            );
        }
    }

    #[test]
    fn test_oui_registry_custom_override() {
        let mut registry = OuiRegistry::new();

        // Add a custom override
        registry.add("AA:BB:CC", "My Custom Vendor");

        // Custom override should take priority
        let vendor = registry.lookup("AA:BB:CC:DD:EE:FF");
        assert_eq!(vendor, Some("My Custom Vendor"));

        // Custom count should increase
        assert_eq!(registry.custom_count(), 1);
    }

    #[test]
    fn test_oui_registry_custom_overrides_builtin() {
        let mut registry = OuiRegistry::new();
        registry.add("00:1B:63", "Apple");

        // Apple's OUI - check if it exists and remember if we found one
        let has_original = registry.lookup("00:1B:63:00:00:00").is_some();
        assert!(has_original);

        // Override Apple's OUI with custom vendor
        registry.add("00:1B:63", "Fake Vendor Override");

        // Custom should now take priority
        let vendor = registry.lookup("00:1B:63:AA:BB:CC");
        assert_eq!(vendor, Some("Fake Vendor Override"));
    }

    #[test]
    fn test_oui_registry_lookup_unknown() {
        let registry = OuiRegistry::new();

        // This OUI is unlikely to exist (private range)
        let vendor = registry.lookup("FE:FF:FF:00:00:00");
        // May or may not be found - just ensure no panic
        let _ = vendor;
    }

    #[test]
    fn test_oui_registry_private_mac() {
        let registry = OuiRegistry::new();

        // Test various private/randomized MAC formats
        // 2, 6, A, E as second hexadecimal digit
        assert_eq!(registry.lookup("02:00:00:00:00:00"), Some("Private MAC Address"));
        assert_eq!(registry.lookup("16:11:22:33:44:55"), Some("Private MAC Address"));
        assert_eq!(registry.lookup("AA:BB:CC:DD:EE:FF"), Some("Private MAC Address"));
        assert_eq!(registry.lookup("fe:ff:ff:00:00:00"), Some("Private MAC Address"));

        // A non-private MAC should still be None in an empty registry
        assert_eq!(registry.lookup("00:11:22:33:44:55"), None);
        assert_eq!(registry.lookup("01:23:45:67:89:AB"), None);
    }

    #[test]
    fn test_is_private_mac() {
        use crate::oui::is_private_mac;

        // Valid private/randomized MACs (second digit is 2, 6, a/A, e/E)
        assert!(is_private_mac("02:00:00:00:00:00"));
        assert!(is_private_mac("36-12-34-56-78-90"));
        assert!(is_private_mac("5A1122334455"));
        assert!(is_private_mac("FE:FF:FF:00:00:00"));

        // Valid non-private/randomized MACs
        assert!(!is_private_mac("00:11:22:33:44:55"));
        assert!(!is_private_mac("01-23-45-67-89-AB"));
        assert!(!is_private_mac("13579BDF0246"));

        // Invalid MAC formats
        assert!(!is_private_mac(""));
        assert!(!is_private_mac("G"));
        assert!(!is_private_mac("0"));
    }

    #[test]
    fn test_oui_registry_load_from_file() {
        use std::io::Write;

        let mut registry = OuiRegistry::new();

        // Create a temporary file with OUI entries
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_oui.txt");
        {
            let mut file = File::create(&temp_file).unwrap();
            writeln!(file, "# Comment line").unwrap();
            writeln!(file).unwrap(); // Empty line
            writeln!(file, "AA:BB:CC\tTest Vendor 1").unwrap();
            writeln!(file, "DD:EE:FF  Test Vendor 2").unwrap();
            writeln!(file, "11-22-33  Test Vendor 3").unwrap();
        }

        // Load the file
        let count = registry.load_from_file(&temp_file).unwrap();
        assert_eq!(count, 3);
        assert_eq!(registry.custom_count(), 3);

        // Check lookups
        assert_eq!(registry.lookup("AA:BB:CC:00:00:00"), Some("Test Vendor 1"));
        assert_eq!(registry.lookup("DD:EE:FF:00:00:00"), Some("Test Vendor 2"));
        assert_eq!(registry.lookup("11:22:33:00:00:00"), Some("Test Vendor 3"));

        // Clean up
        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn test_oui_registry_len() {
        let mut registry = OuiRegistry::new();
        let initial_len = registry.len();

        // Add custom entries
        registry.add("AA:BB:CC", "Vendor 1");
        registry.add("DD:EE:FF", "Vendor 2");

        // Length should increase
        assert_eq!(registry.len(), initial_len + 2);
    }

    #[test]
    fn test_oui_registry_load_from_ieee_file() {
        use std::io::Write;

        let mut registry = OuiRegistry::new();

        // Create a temporary file with IEEE OUI format entries
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_ieee_oui.txt");
        {
            let mut file = File::create(&temp_file).unwrap();
            // IEEE format: "XX-XX-XX   (hex)\t\tVendor Name"
            writeln!(file, "OUI/MA-L			Organization").unwrap();
            writeln!(file, "company_id			Organization Address").unwrap();
            writeln!(file).unwrap();
            writeln!(file, "00-00-00   (hex)\t\tXerox Corporation").unwrap();
            writeln!(file, "000000     (base 16)\t\tXerox Corporation").unwrap();
            writeln!(file, "\t\t\t\t26600 SW Parkway").unwrap();
            writeln!(file).unwrap();
            writeln!(file, "00-00-01   (hex)\t\tXerox Corporation").unwrap();
            writeln!(file, "00-00-0C   (hex)\t\tCisco Systems, Inc").unwrap();
            writeln!(file, "00-17-F2   (hex)\t\tApple, Inc.").unwrap();
        }

        // Load the file
        let count = registry.load_from_ieee_file(&temp_file).unwrap();
        assert_eq!(count, 4); // Only (hex) lines are parsed

        // Check lookups
        assert_eq!(
            registry.lookup("00:00:00:11:22:33"),
            Some("Xerox Corporation")
        );
        assert_eq!(
            registry.lookup("00:00:0C:AA:BB:CC"),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(registry.lookup("00:17:F2:12:34:56"), Some("Apple, Inc."));

        // Clean up
        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn test_parse_ieee_oui_line() {
        // Test valid IEEE format lines
        let result = OuiRegistry::parse_ieee_oui_line("00-00-00   (hex)\t\tXerox Corporation");
        assert!(result.is_some());
        let (mac, vendor) = result.unwrap();
        assert_eq!(mac, "00-00-00");
        assert_eq!(vendor, "Xerox Corporation");

        // Test line without (hex) marker - should return None
        let result = OuiRegistry::parse_ieee_oui_line("000000     (base 16)\t\tXerox Corporation");
        assert!(result.is_none());

        // Test empty/whitespace lines
        let result = OuiRegistry::parse_ieee_oui_line("");
        assert!(result.is_none());
        let result = OuiRegistry::parse_ieee_oui_line("   ");
        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_all() {
        let request = build_ssdp_search_request("ssdp:all");
        let request_str = String::from_utf8_lossy(&request);

        // Verify M-SEARCH format
        assert!(request_str.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(request_str.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(request_str.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(request_str.contains("MX: 2\r\n"));
        assert!(request_str.contains("ST: ssdp:all\r\n"));
        assert!(request_str.ends_with("\r\n\r\n"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_upnp_root() {
        let request = build_ssdp_search_request("upnp:rootdevice");
        let request_str = String::from_utf8_lossy(&request);

        // Verify format with different search target
        assert!(request_str.contains("ST: upnp:rootdevice\r\n"));
        assert!(request_str.starts_with("M-SEARCH * HTTP/1.1\r\n"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_build_ssdp_search_request_media_renderer() {
        let request = build_ssdp_search_request("urn:schemas-upnp-org:device:MediaRenderer:1");
        let request_str = String::from_utf8_lossy(&request);

        // Verify format with URN
        assert!(request_str.contains("urn:schemas-upnp-org:device:MediaRenderer:1"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_querier_new() {
        // Test that SsdpQuerier can be created
        let result = SsdpQuerier::new(None);
        assert!(result.is_ok(), "SsdpQuerier::new() should succeed");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_notify() {
        let msg_type = SsdpMessageType::Notify;
        assert_eq!(format!("{}", msg_type), "NOTIFY");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_search() {
        let msg_type = SsdpMessageType::Search;
        assert_eq!(format!("{}", msg_type), "M-SEARCH");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_ssdp_message_type_response() {
        let msg_type = SsdpMessageType::Response;
        assert_eq!(format!("{}", msg_type), "RESPONSE");
    }

    #[test]
    fn test_dhcpv4_option55_parsing() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest

        // Option 55 (Parameter Request List)
        // Code 55, Length 4, Values [1, 3, 6, 42]
        payload[240] = 55;
        payload[241] = 4;
        payload[242] = 1;
        payload[243] = 3;
        payload[244] = 6;
        payload[245] = 42;

        payload[246] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.parameter_request_list, Some(vec![1, 3, 6, 42]));
    }

    #[test]
    fn test_dhcpv4_option60_parsing() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest

        // Option 60 (Vendor Class Identifier)
        // Code 60, Length 8, Value "MSFT 5.0"
        payload[240] = 60;
        payload[241] = 8;
        payload[242..250].copy_from_slice(b"MSFT 5.0");

        payload[250] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.vendor_class_id.as_deref(), Some("MSFT 5.0"));
    }

    #[test]
    fn test_device_tracker_fingerprint_matching() {
        let temp_path = "/tmp/lanwatch_test_fingerprint.csv";
        let _ = std::fs::remove_file(temp_path);

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // 1. Windows Option 55 Fingerprint: contains 249 (MS Classless Route)
        let packet_win = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 101)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249]),
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet_win);
        {
            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Microsoft"));
            assert_eq!(device.device_type.as_deref(), Some("PC/Windows"));
        }

        // 2. Apple Option 55 Fingerprint: contains 95 (LDAP) and lacks 26/28
        let packet_apple = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 102)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 95, 119]),
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet_apple);
        {
            let device = tracker.devices.get("22:33:44:55:66:77").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Apple"));
            assert_eq!(device.device_type.as_deref(), Some("Apple Device"));
        }

        // 3. Android Option 55 Fingerprint: contains 26 and 28
        let packet_android = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 103)),
            parameter_request_list: Some(vec![1, 3, 6, 15, 26, 28, 121]),
            vendor_class_id: None,
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet_android);
        {
            let device = tracker.devices.get("33:44:55:66:77:88").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Google"));
            assert_eq!(device.device_type.as_deref(), Some("Android Phone"));
        }

        // 4. Windows Option 60 Fingerprint
        let packet_win60 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 104)),
            parameter_request_list: None,
            vendor_class_id: Some("MSFT 5.0".to_string()),
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet_win60);
        {
            let device = tracker.devices.get("44:55:66:77:88:99").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Microsoft"));
            assert_eq!(device.device_type.as_deref(), Some("PC/Windows"));
        }

        // 5. HP Option 60 Fingerprint
        let packet_hp60 = Dhcpv4Packet {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(255, 255, 255, 255),
            source_port: 68,
            dest_port: 67,
            operation: Dhcpv4Operation::BootRequest,
            client_mac: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
            message_type: Some(Dhcpv4MessageType::Discover),
            hostname: None,
            requested_ip: Some(Ipv4Addr::new(192, 168, 1, 105)),
            parameter_request_list: None,
            vendor_class_id: Some("Hewlett-Packard JetDirect".to_string()),
            vendor_specific_info: None,
        };
        tracker.update_from_dhcpv4(&packet_hp60);
        {
            let device = tracker.devices.get("55:66:77:88:99:aa").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("HP"));
            assert_eq!(device.device_type.as_deref(), Some("Printer"));
        }

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn test_parse_arp_packet() {
        let mut frame = vec![0u8; 42];
        // Ethernet Header
        // Destination MAC (Broadcast)
        frame[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC (00:11:22:33:44:55)
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType ARP (0x0806)
        frame[12..14].copy_from_slice(&[0x08, 0x06]);

        // ARP Packet
        // Hardware type: Ethernet (0x0001)
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        // Protocol type: IPv4 (0x0800)
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        // Hardware size (6)
        frame[18] = 6;
        // Protocol size (4)
        frame[19] = 4;
        // Opcode: Request (0x0001)
        frame[20..22].copy_from_slice(&[0x00, 0x01]);
        // Sender MAC: 00:11:22:33:44:55
        frame[22..28].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender IP: 192.168.1.50
        frame[28..32].copy_from_slice(&[192, 168, 1, 50]);
        // Target MAC: 00:00:00:00:00:00
        frame[32..38].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Target IP: 192.168.1.1
        frame[38..42].copy_from_slice(&[192, 168, 1, 1]);

        let result = process_ethernet_frame_extended(&frame);
        assert!(result.is_some());
        match result.unwrap() {
            NetworkEvent::Arp {
                source_mac,
                source_ip,
            } => {
                assert_eq!(source_mac, "00:11:22:33:44:55");
                assert_eq!(
                    source_ip,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50))
                );
            }
            _ => panic!("Expected NetworkEvent::Arp"),
        }
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_llmnr_packet() {
        let mut payload = vec![0u8; 30];
        payload[0..2].copy_from_slice(&[0x12, 0x34]); // Transaction ID
        payload[2..4].copy_from_slice(&[0x80, 0x00]); // Response flag
        payload[4..6].copy_from_slice(&[0x00, 0x00]); // Questions: 0
        payload[6..8].copy_from_slice(&[0x00, 0x01]); // Answer RRs: 1
        payload[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Answer Section: Name "myhost", Type A, Class IN, TTL 30, Data 192.168.1.100
        payload[12] = 6;
        payload[13..19].copy_from_slice(b"myhost");
        payload[19] = 0;
        payload[20..22].copy_from_slice(&[0x00, 0x01]); // Type A (1)
        payload[22..24].copy_from_slice(&[0x00, 0x01]); // Class IN (1)
        payload[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL 30
        payload[28..30].copy_from_slice(&[0x00, 0x04]); // RDLength 4
        let mut full_payload = payload;
        full_payload.extend_from_slice(&[192, 168, 1, 100]); // RData: IP 192.168.1.100

        let result = parse_mdns_payload(
            &full_payload,
            "00:11:22:33:44:55".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252)),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "00:11:22:33:44:55");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.answers[0].name, "myhost");

        // Test update_from_llmnr
        let temp_path = "/tmp/lanwatch_test_llmnr.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        let mut tracker = DeviceTracker::new(temp_path).unwrap();
        let updated = tracker.update_from_llmnr(&packet);
        assert_eq!(updated, 2);
        let dev = tracker.devices.get("00:11:22:33:44:55").unwrap();
        assert_eq!(dev.hostname.as_deref(), Some("myhost"));
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_dhcpv4_option43_parsing() {
        let mut payload = vec![0u8; 300];
        payload[0] = 1; // BootRequest
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0x11;

        // Option 43 (Vendor Specific Info)
        payload[240] = 43;
        payload[241] = 10; // Length
        payload[242..252].copy_from_slice(b"\x01\x08UniFi-AP");

        payload[252] = 255; // End option

        let result = parse_dhcpv4_payload(
            &payload,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            68,
            67,
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.vendor_specific_info, Some("UniFi-AP".to_string()));

        // Also test how DeviceTracker updates vendor/type from option 43
        let temp_path = "/tmp/lanwatch_test_opt43_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            tracker.update_from_dhcpv4(&packet);
            let device = tracker.devices.get("aa:bb:cc:dd:ee:11").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Ubiquiti"));
            assert_eq!(device.device_type.as_deref(), Some("Network Device"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_hostname_classifier() {
        // Test Sonos mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("sonos-living")),
            Some("Sonos")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("sonos-living")),
            Some("Smart Speaker")
        );

        // Test ESP32 mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("esp32-weather")),
            Some("Espressif")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("esp32-weather")),
            Some("IoT Device")
        );

        // Test HP printer mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("hp-printer-12")),
            Some("HP")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("hp-printer-12")),
            Some("Printer")
        );

        // Test Kindle mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("kindle-reader")),
            Some("Amazon")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("kindle-reader")),
            Some("e-Reader")
        );

        // Test Synology mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("synology-nas")),
            Some("Synology")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("synology-nas")),
            Some("Storage (NAS)")
        );

        // Test PlayStation mapping
        assert_eq!(
            DeviceTracker::detect_vendor_from_hostname(Some("playstation-5")),
            Some("Sony")
        );
        assert_eq!(
            DeviceTracker::detect_device_type_from_hostname(Some("playstation-5")),
            Some("Game Console")
        );
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_mdns_txt_record_parsing() {
        let temp_path = "/tmp/lanwatch_test_mdns_txt.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        let mut tracker = DeviceTracker::new(temp_path).unwrap();

        // 1. Apple TV TXT record (key: model)
        let packet_appletv = MdnsPacket {
            source_mac: "00:11:22:33:44:55".to_string(),
            source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            dest_ip: std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 1,
            is_response: true,
            questions: vec![],
            answers: vec![MdnsRecord {
                name: "Living Room Apple TV.local".to_string(),
                record_type: MdnsRecordType::Txt,
                ttl: 120,
                data: MdnsRecordData::Txt(vec!["model=AppleTV14,1".to_string()]),
            }],
            authority: vec![],
            additional: vec![],
        };
        tracker.update_from_mdns(&packet_appletv);
        {
            let device = tracker.devices.get("00:11:22:33:44:55").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Apple"));
            assert_eq!(device.device_type.as_deref(), Some("Apple TV"));
        }

        // 2. Sonos TXT record (key: md)
        let packet_sonos = MdnsPacket {
            source_mac: "00:11:22:33:44:66".to_string(),
            source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 51)),
            dest_ip: std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 2,
            is_response: true,
            questions: vec![],
            answers: vec![MdnsRecord {
                name: "Sonos Play.local".to_string(),
                record_type: MdnsRecordType::Txt,
                ttl: 120,
                data: MdnsRecordData::Txt(vec!["md=Sonos Play:1".to_string()]),
            }],
            authority: vec![],
            additional: vec![],
        };
        tracker.update_from_mdns(&packet_sonos);
        {
            let device = tracker.devices.get("00:11:22:33:44:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Sonos"));
            assert_eq!(device.device_type.as_deref(), Some("Smart Speaker"));
        }

        // 3. Printer TXT record (key: ty)
        let packet_printer = MdnsPacket {
            source_mac: "00:11:22:33:44:77".to_string(),
            source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 52)),
            dest_ip: std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            transaction_id: 3,
            is_response: true,
            questions: vec![],
            answers: vec![MdnsRecord {
                name: "HP Laserjet.local".to_string(),
                record_type: MdnsRecordType::Txt,
                ttl: 120,
                data: MdnsRecordData::Txt(vec!["ty=HP LaserJet Pro".to_string()]),
            }],
            authority: vec![],
            additional: vec![],
        };
        tracker.update_from_mdns(&packet_printer);
        {
            let device = tracker.devices.get("00:11:22:33:44:77").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("HP"));
            assert_eq!(device.device_type.as_deref(), Some("Printer"));
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_nbns_packet() {
        let mut payload = vec![0u8; 12];
        // Transaction ID
        payload[0..2].copy_from_slice(&[0x12, 0x34]);
        // Flags (Query, Opcode 0, not response)
        payload[2..4].copy_from_slice(&[0x00, 0x00]);
        // QDCount = 1
        payload[4..6].copy_from_slice(&[0x00, 0x01]);

        // Encoded name: "SAMBA" with suffix 0x20
        let encoded_name = b"FDEBENECEBCACACACACACACACACACACA";
        payload.push(32); // length byte
        payload.extend_from_slice(encoded_name);
        payload.push(0); // null terminator

        let result = parse_nbns_payload(
            &payload,
            "aa:bb:cc:dd:ee:ff".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.name, "SAMBA");
        assert_eq!(packet.suffix, 0x20);

        // Also test how DeviceTracker handles the update
        let temp_path = "/tmp/lanwatch_test_nbns_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            tracker.update_from_nbns(&packet);
            let device = tracker.devices.get("aa:bb:cc:dd:ee:ff").unwrap();
            assert_eq!(device.hostname.as_deref(), Some("SAMBA"));
            assert_eq!(device.vendor.as_deref(), Some("Linux"));
            assert_eq!(device.device_type.as_deref(), Some("File Server"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_wsd_packet() {
        let xml_payload = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
  <soap:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsd:Types>wsd:Device NetworkVideoTransmitter</wsd:Types>
        <pub:ModelName>Canon IP Camera</pub:ModelName>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </soap:Body>
</soap:Envelope>"#;

        let result = parse_wsd_payload(
            xml_payload.as_bytes(),
            "00:11:22:33:44:55".to_string(),
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        );

        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.device_type, Some("IP Camera".to_string()));
        assert_eq!(packet.vendor, Some("Canon".to_string()));

        // Also test how DeviceTracker updates from WS-Discovery
        let temp_path = "/tmp/lanwatch_test_wsd_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            tracker.update_from_wsd(&packet);
            let device = tracker.devices.get("00:11:22:33:44:55").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Canon"));
            assert_eq!(device.device_type.as_deref(), Some("IP Camera"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn test_parse_ndp_packet() {
        // NDP solicitation or advertisement is captured over ICMPv6.
        // We will construct a raw Ethernet + IPv6 + ICMPv6 packet and run process_ethernet_frame_extended.
        let mut frame = vec![0u8; 14 + 40 + 8]; // Ethernet (14) + IPv6 (40) + ICMPv6 header (8)
        // Set EtherType: 0x86DD (IPv6)
        frame[12] = 0x86;
        frame[13] = 0xDD;
        // Source MAC: 00:11:22:33:44:55
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // IPv6 Header fields
        frame[14] = 0x60; // Version = 6
        // Payload Length = 8
        frame[18] = 0x00;
        frame[19] = 0x08;

        // IPv6 Source Address: fe80::1
        let source_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        frame[14 + 8..14 + 24].copy_from_slice(&source_ip.octets());
        // Next header: ICMPv6 (58)
        frame[14 + 6] = 58;

        // ICMPv6 type: 136 (Neighbor Advertisement)
        frame[14 + 40] = 136;

        let event = process_ethernet_frame_extended(&frame);
        assert!(event.is_some());
        match event.unwrap() {
            NetworkEvent::Ndp {
                source_mac,
                source_ip: ip,
            } => {
                assert_eq!(source_mac, "00:11:22:33:44:55");
                assert_eq!(ip, IpAddr::V6(source_ip));
            }
            _ => panic!("Expected NetworkEvent::Ndp"),
        }

        // Test updating DeviceTracker from NDP
        let temp_path = "/tmp/lanwatch_test_ndp_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let is_new = tracker.update_device("00:11:22:33:44:55", IpAddr::V6(source_ip), None);
            assert!(is_new);
            let device = tracker.devices.get("00:11:22:33:44:55").unwrap();
            assert_eq!(device.ipv6_address, Some(IpAddr::V6(source_ip)));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_lldp_packet() {
        // Construct a mock LLDP payload
        let mut payload = Vec::new();
        // TLV 1: Chassis ID (subtype 4 = MAC)
        payload.extend_from_slice(&[0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // TLV 2: Port ID (subtype 5 = Interface name) (type 2 << 9 | 5 = 1029 = 0x0405)
        payload.extend_from_slice(&[0x04, 0x05, 0x05, b'e', b't', b'h', b'0']);
        // TLV 5: System Name (type 5 << 9 | 12 = 2572 = 0x0a0c)
        payload.extend_from_slice(&[
            0x0a, 0x0c, b'M', b'y', b'S', b'w', b'i', b't', b'c', b'h', b'.', b'n', b'e', b't',
        ]);
        // TLV 6: System Description (type 6 << 9 | 19 = 3091 = 0x0c13)
        payload.extend_from_slice(&[
            0x0c, 0x13, b'C', b'i', b's', b'c', b'o', b' ', b'S', b'g', b'3', b'5', b'0', b' ',
            b'2', b'4', b'-', b'P', b'o', b'r', b't',
        ]);
        // TLV 8: Management Address (Address length 5, Subtype 1 = IPv4, IP: 192.168.1.254, Interface Subtype 1, Number 1, OID length 0)
        payload.extend_from_slice(&[
            0x10, 0x0c, 0x05, 0x01, 192, 168, 1, 254, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
        ]);
        // TLV 0: End
        payload.extend_from_slice(&[0x00, 0x00]);

        let packet = parse_lldp_payload(&payload, "00:11:22:33:44:55".to_string()).unwrap();
        assert_eq!(packet.system_name.as_deref(), Some("MySwitch.net"));
        assert_eq!(packet.port_id.as_deref(), Some("eth0"));
        assert_eq!(
            packet.management_address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)))
        );

        // Update DeviceTracker
        let temp_path = "/tmp/lanwatch_test_lldp_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let is_new = tracker.update_from_lldp(&packet);
            assert!(is_new);
            let device = tracker.devices.get("00:11:22:33:44:55").unwrap();
            assert_eq!(device.hostname.as_deref(), Some("MySwitch.net"));
            assert_eq!(device.vendor.as_deref(), Some("Cisco"));
            assert_eq!(device.device_type.as_deref(), Some("Network Device"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_cdp_packet() {
        // Construct a mock CDP payload (LLC/SNAP already stripped, so payload starts with CDP version/TTL/checksum)
        let mut payload = vec![
            0x02, // Version 2
            180,  // TTL
            0x00, 0x00, // Checksum placeholder
        ];

        // TLV 1: Device ID
        let dev_id = b"Cisco-Switch-3560";
        payload.extend_from_slice(&[0x00, 0x01]); // Type
        payload.extend_from_slice(&((dev_id.len() + 4) as u16).to_be_bytes()); // Length
        payload.extend_from_slice(dev_id);

        // TLV 2: Address
        // Number of addresses = 1
        // Protocol type length = 1, type = 0xcc (IPv4 NLPID)
        // Address length = 4, address = 10.0.0.1
        let addr_value = vec![
            0x00, 0x00, 0x00, 0x01, // Num addresses
            0x01, // Proto type len
            0xcc, // Proto (NLPID IPv4)
            0x00, 0x04, // Address len
            10, 0, 0, 1, // Address
        ];
        payload.extend_from_slice(&[0x00, 0x02]);
        payload.extend_from_slice(&((addr_value.len() + 4) as u16).to_be_bytes());
        payload.extend_from_slice(&addr_value);

        // TLV 3: Port ID
        let port_id = b"GigabitEthernet0/1";
        payload.extend_from_slice(&[0x00, 0x03]);
        payload.extend_from_slice(&((port_id.len() + 4) as u16).to_be_bytes());
        payload.extend_from_slice(port_id);

        // TLV 6: Platform
        let platform = b"cisco WS-C3560G-24TS";
        payload.extend_from_slice(&[0x00, 0x06]);
        payload.extend_from_slice(&((platform.len() + 4) as u16).to_be_bytes());
        payload.extend_from_slice(platform);

        let packet = parse_cdp_payload(&payload, "00:aa:bb:cc:dd:ee".to_string()).unwrap();
        assert_eq!(packet.device_id.as_deref(), Some("Cisco-Switch-3560"));
        assert_eq!(packet.port_id.as_deref(), Some("GigabitEthernet0/1"));
        assert_eq!(packet.platform.as_deref(), Some("cisco WS-C3560G-24TS"));
        assert_eq!(
            packet.management_address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );

        // Update DeviceTracker
        let temp_path = "/tmp/lanwatch_test_cdp_device.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let is_new = tracker.update_from_cdp(&packet);
            assert!(is_new);
            let device = tracker.devices.get("00:aa:bb:cc:dd:ee").unwrap();
            assert_eq!(device.hostname.as_deref(), Some("Cisco-Switch-3560"));
            assert_eq!(device.vendor.as_deref(), Some("Cisco"));
            assert_eq!(device.device_type.as_deref(), Some("Switch"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_dhcpv6_fingerprinting() {
        // Test Option 15: User Class ("Android")
        let mut user_class_payload = vec![
            0x00, 0x07, // Length of Android user class (7)
        ];
        user_class_payload.extend_from_slice(b"Android");

        let mut opt15_data = vec![
            0x01, // Message type: SOLICIT
            0x12,
            0x34,
            0x56, // Transaction ID
            0x00,
            0x0f, // Option code: 15 (User Class)
            0x00,
            (user_class_payload.len()) as u8, // Option len
        ];
        opt15_data.extend_from_slice(&user_class_payload);

        let result = parse_dhcpv6_payload(
            &opt15_data,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            546,
            547,
        )
        .unwrap();
        assert_eq!(result.options.len(), 1);
        match &result.options[0] {
            Dhcpv6Option::UserClass(classes) => {
                assert_eq!(classes.len(), 1);
                assert_eq!(classes[0], "Android");
            }
            _ => panic!("Expected UserClass option"),
        }

        // Test Option 16: Vendor Class (Enterprise 311 for MSFT)
        let mut vendor_class_payload = vec![
            0x00, 0x00, 0x01, 0x37, // Enterprise Number 311
            0x00, 0x04, // Sub-option length 4
        ];
        vendor_class_payload.extend_from_slice(b"MSFT");

        let mut opt16_data = vec![
            0x01, // Message type
            0x12,
            0x34,
            0x56, // Transaction ID
            0x00,
            0x10, // Option 16
            0x00,
            (vendor_class_payload.len()) as u8, // Option len
        ];
        opt16_data.extend_from_slice(&vendor_class_payload);

        let result2 = parse_dhcpv6_payload(
            &opt16_data,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            546,
            547,
        )
        .unwrap();
        assert_eq!(result2.options.len(), 1);
        match &result2.options[0] {
            Dhcpv6Option::VendorClass {
                enterprise_number,
                data,
            } => {
                assert_eq!(*enterprise_number, 311);
                assert_eq!(data.len(), 1);
                assert_eq!(data[0], "MSFT");
            }
            _ => panic!("Expected VendorClass option"),
        }

        // Test device tracker fingerprinting updates
        let temp_path = "/tmp/lanwatch_test_dhcpv6_fingerprint.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();

            // Setup a fake Dhcpv6Packet with client ID and VendorClass
            let packet = Dhcpv6Packet {
                source_ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dest_ip: Ipv6Addr::LOCALHOST,
                source_port: 546,
                dest_port: 547,
                message_type: Dhcpv6MessageType::Solicit,
                transaction_id: [1, 2, 3],
                options: vec![
                    Dhcpv6Option::ClientId(vec![
                        0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                    ]), // MAC: 00:11:22:33:44:55
                    Dhcpv6Option::VendorClass {
                        enterprise_number: 311,
                        data: vec!["MSFT".to_string()],
                    },
                ],
            };

            let is_new = tracker.update_from_dhcpv6(&packet);
            assert!(is_new);
            let device = tracker.devices.get("00:11:22:33:44:55").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Microsoft"));
        }
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_device_tracker_flush_and_compaction() {
        let temp_path = "/tmp/lanwatch_test_flush_compaction.csv";
        let _ = std::fs::remove_file(temp_path);

        // Scope 1: Create tracker, save once to create the main file, then write an update with auto_save = false.
        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();

            // Insert initial device and save so the file exists
            tracker.update_device(
                "00:11:22:33:44:55",
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                None,
            );
            tracker.save_to_csv().unwrap();
            assert!(Path::new(temp_path).exists());

            // Disable auto_save to test flush logic
            tracker.set_auto_save(false);

            // Update the device (IP changes)
            tracker.update_device(
                "00:11:22:33:44:55",
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                None,
            );

            // Read the main file to verify the old IP is still there in the saved file (since we haven't flushed yet)
            {
                let conn = rusqlite::Connection::open(temp_path).unwrap();
                let mut stmt = conn.prepare("SELECT ip_address FROM devices WHERE mac_address = '00:11:22:33:44:55'").unwrap();
                let saved_ip: String = stmt.query_row([], |row| row.get(0)).unwrap();
                assert_eq!(saved_ip, "192.168.1.100");
            }

            // Flush to save the updated state
            tracker.flush_to_csv().unwrap();

            // Verify that after flushing, the file has the updated IP
            {
                let conn = rusqlite::Connection::open(temp_path).unwrap();
                let mut stmt = conn.prepare("SELECT ip_address FROM devices WHERE mac_address = '00:11:22:33:44:55'").unwrap();
                let saved_ip2: String = stmt.query_row([], |row| row.get(0)).unwrap();
                assert_eq!(saved_ip2, "192.168.1.101");
            }
        }

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_lldp_system_description_and_eero_classification() {
        let temp_path = "/tmp/lanwatch_test_lldp_desc.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = LldpPacket {
                source_mac: "dc:69:b5:a5:8c:a0".to_string(),
                system_name: Some("eero".to_string()),
                system_description: Some("eero Pro 6E GGB1UD22435506MW".to_string()),
                port_id: Some("2".to_string()),
                management_address: Some("fe80::de69:b5ff:fea5:8cb2".parse().unwrap()),
            };

            let is_new = tracker.update_from_lldp(&packet);
            assert!(is_new);

            let device = tracker.devices.get("dc:69:b5:a5:8c:a0").unwrap();
            assert_eq!(
                device.system_description.as_deref(),
                Some("eero Pro 6E GGB1UD22435506MW")
            );
            assert_eq!(device.vendor.as_deref(), Some("eero inc."));
            assert_eq!(device.device_type.as_deref(), Some("Router"));
            assert_eq!(device.hostname.as_deref(), Some("eero"));
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    fn test_device_info_multiple_ipv6_addresses() {
        let mut device = DeviceInfo::new(
            "aa:bb:cc:dd:ee:ff".to_string(),
            Ipv4Addr::new(192, 168, 1, 100).into(),
            None,
        );

        // Add a link-local address
        let lla: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(device.set_ipv6_address(lla));
        assert_eq!(device.ipv6_address, Some(IpAddr::V6(lla)));
        assert_eq!(device.ipv6_addresses, vec![lla]);

        // Add a unique local address (should override link-local)
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(device.set_ipv6_address(ula));
        assert_eq!(device.ipv6_address, Some(IpAddr::V6(ula)));
        assert_eq!(device.ipv6_addresses, vec![lla, ula]);

        // Add a global unicast address (should override unique local)
        let gua: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(device.set_ipv6_address(gua));
        assert_eq!(device.ipv6_address, Some(IpAddr::V6(gua)));
        assert_eq!(device.ipv6_addresses, vec![lla, ula, gua]);

        // Add the link-local address again (should do nothing, return false)
        assert!(!device.set_ipv6_address(lla));
        assert_eq!(device.ipv6_address, Some(IpAddr::V6(gua)));
        assert_eq!(device.ipv6_addresses, vec![lla, ula, gua]);

        // Test CSV roundtrip with multiple IPv6 addresses
        let csv = device.to_csv_line();
        let parsed = DeviceInfo::from_csv_line(&csv).unwrap();
        assert_eq!(parsed.ipv6_address, Some(IpAddr::V6(gua)));
        assert_eq!(parsed.ipv6_addresses, vec![lla, ula, gua]);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_is_lifx_port() {
        use crate::parser::iot::is_lifx_port;
        assert!(is_lifx_port(56700));
        assert!(!is_lifx_port(80));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_lifx_payload() {
        use crate::parser::iot::parse_lifx_payload;
        
        let mut payload = vec![0u8; 36];
        payload[0] = 36;
        payload[2] = 0;
        payload[3] = 4; // protocol = 1024
        payload[8] = 0xAA;
        payload[9] = 0xBB;
        payload[10] = 0xCC;
        payload[11] = 0xDD;
        payload[12] = 0xEE;
        payload[13] = 0xFF;
        payload[32] = 3; // msg_type = 3

        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let result = parse_lifx_payload(&payload, "11:22:33:44:55:66".to_string(), source_ip);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "11:22:33:44:55:66");
        assert_eq!(packet.target_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(packet.msg_type, 3);
        assert_eq!(packet.size, 36);
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_extract_iot_metadata_matter() {
        use crate::parser::iot::extract_iot_metadata;
        use std::collections::HashMap;

        let services = vec!["_matter._tcp", "_services._dns-sd._udp"];
        let mut txt = HashMap::new();
        txt.insert("vid".to_string(), "0x10B1");
        txt.insert("pid".to_string(), "0x0001");

        let meta = extract_iot_metadata(&services, &txt);
        assert_eq!(meta.vendor.as_deref(), Some("Google"));
        assert_eq!(meta.device_type.as_deref(), Some("Matter Smart Device"));
        assert_eq!(meta.model.as_deref(), Some("Matter Device (VID: 0x10B1, PID: 0x0001)"));
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_extract_iot_metadata_hap() {
        use crate::parser::iot::extract_iot_metadata;
        use std::collections::HashMap;

        let services = vec!["_hap._tcp"];
        let mut txt = HashMap::new();
        txt.insert("md".to_string(), "Eve Energy");
        txt.insert("ci".to_string(), "7"); // Outlet category
        txt.insert("sf".to_string(), "1"); // Unpaired flag

        let meta = extract_iot_metadata(&services, &txt);
        assert_eq!(meta.vendor.as_deref(), Some("Eve Systems"));
        assert_eq!(meta.device_type.as_deref(), Some("Outlet"));
        assert_eq!(meta.model.as_deref(), Some("Eve Energy"));
        assert_eq!(meta.status.as_deref(), Some("Unpaired / Pairing Mode"));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_lifx() {
        let temp_path = "/tmp/lanwatch_test_lifx.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::iot::LifxPacket {
                source_mac: "11:22:33:44:55:66".to_string(),
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)),
                target_mac: "00:00:00:00:00:00".to_string(),
                msg_type: 3,
                size: 36,
            };

            let updates = tracker.update_from_lifx(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("LIFX"));
            assert_eq!(device.device_type.as_deref(), Some("Lightbulb"));
            assert_eq!(device.ip_address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)));
            assert_eq!(device.system_description.as_deref(), Some("LIFX device (msg_type: 3)"));
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_is_coap_port() {
        use crate::parser::iot::is_coap_port;
        assert!(is_coap_port(5683));
        assert!(!is_coap_port(80));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_is_knx_port() {
        use crate::parser::iot::is_knx_port;
        assert!(is_knx_port(3671));
        assert!(!is_knx_port(80));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_coap_payload() {
        use crate::parser::iot::parse_coap_payload;

        // CoAP header is 4 bytes minimum
        // Ver=1, Type=0, TKL=0 => Byte 0 = 0x40
        // Code=1 (GET) => Byte 1 = 0x01
        // MessageID=0x1234 => Bytes 2-3 = [0x12, 0x34]
        // Payload marker = 0xFF
        // Payload = "temp"
        let mut payload = vec![0x40, 0x01, 0x12, 0x34, 0xFF];
        payload.extend_from_slice(b"temp");

        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let result = parse_coap_payload(&payload, "11:22:33:44:55:66".to_string(), source_ip);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "11:22:33:44:55:66");
        assert_eq!(packet.code, 1);
        assert_eq!(packet.message_id, 0x1234);
        assert_eq!(packet.payload.as_deref(), Some("temp"));
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_knx_payload() {
        use crate::parser::iot::parse_knx_payload;

        // KNXnet/IP Search Response (0x0202)
        // Header length = 6 => payload[0] = 6
        // Version = 0x10 => payload[1] = 0x10
        // Service type = 0x0202 => payload[2-3] = [0x02, 0x02]
        // Total length = 6 + 54 = 60 => payload[4-5] = [0, 60]
        let mut payload = vec![6, 0x10, 0x02, 0x02, 0, 60];

        // Device Info DIB (DIB structure starting at byte index 6)
        // DIB length = 54 => DIB[0] = 54
        // DIB type = 0x01 (Device Info) => DIB[1] = 0x01
        let mut dib = vec![0u8; 54];
        dib[0] = 54;
        dib[1] = 0x01;
        // Serial number (6 bytes starting at index 12 in DIB, i.e., indices 12-17)
        dib[12] = 0x00; dib[13] = 0x11; dib[14] = 0x22;
        dib[15] = 0x33; dib[16] = 0x44; dib[17] = 0x55;
        // Friendly name (30 bytes starting at index 22 in DIB, i.e., indices 22-51)
        let name_bytes = b"KNX Thermostat";
        for (i, &b) in name_bytes.iter().enumerate() {
            dib[22 + i] = b;
        }

        payload.extend_from_slice(&dib);

        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let result = parse_knx_payload(&payload, "11:22:33:44:55:66".to_string(), source_ip);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "11:22:33:44:55:66");
        assert_eq!(packet.service_type, 0x0202);
        assert_eq!(packet.friendly_name.as_deref(), Some("KNX Thermostat"));
        assert_eq!(packet.serial_number.as_deref(), Some("001122334455"));
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_coap() {
        let temp_path = "/tmp/lanwatch_test_coap.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::iot::CoapPacket {
                source_mac: "11:22:33:44:55:66".to_string(),
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)),
                code: 69,
                message_id: 1234,
                payload: Some("temp sensor".to_string()),
            };

            let updates = tracker.update_from_coap(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.device_type.as_deref(), Some("Sensor"));
            assert_eq!(device.ip_address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)));
            assert_eq!(device.system_description.as_deref(), Some("temp sensor"));
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_knx() {
        let temp_path = "/tmp/lanwatch_test_knx.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::iot::KnxPacket {
                source_mac: "11:22:33:44:55:66".to_string(),
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)),
                service_type: 0x0202,
                friendly_name: Some("KNX Light".to_string()),
                serial_number: Some("001122334455".to_string()),
            };

            let updates = tracker.update_from_knx(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("KNX"));
            assert_eq!(device.device_type.as_deref(), Some("Home Automation"));
            assert_eq!(device.hostname.as_deref(), Some("KNX Light"));
            assert_eq!(
                device.system_description.as_deref(),
                Some("KNX Device (KNX Light Serial: 001122334455)")
            );
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_cctv_ports() {
        assert!(crate::parser::cctv::is_cctv_port(9999));
        assert!(crate::parser::cctv::is_cctv_port(37020));
        assert!(crate::parser::cctv::is_cctv_port(37810));
        assert!(crate::parser::cctv::is_cctv_port(554));
        assert!(!crate::parser::cctv::is_cctv_port(80));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_sadp_payload() {
        let payload = r#"<?xml version="1.0" encoding="utf-8"?><Response><DeviceType>DS-2CD2132F-I</DeviceType><DeviceDescription>IP Camera</DeviceDescription><DeviceSN>DS-2CD2132F-I20140922AAWR481234567</DeviceSN><IPv4Address>192.168.1.64</IPv4Address><MAC>70:3d:15:ab:cd:ef</MAC></Response>"#.as_bytes();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 64));
        let result = crate::parser::cctv::parse_sadp_payload(payload, "00:11:22:33:44:55".to_string(), source_ip);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "70:3d:15:ab:cd:ef");
        assert_eq!(packet.vendor, "Hikvision");
        assert_eq!(packet.model.as_deref(), Some("DS-2CD2132F-I"));
        assert_eq!(packet.serial_number.as_deref(), Some("DS-2CD2132F-I20140922AAWR481234567"));
        assert_eq!(packet.protocol, "SADP");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_dahua_payload() {
        let payload = r#"{ "method": "client.notifyDeviceIP", "params": { "mac": "00:1a:2b:3c:4d:5e", "ip": "192.168.1.108", "deviceType": "IPC-HFW4431R-ZS", "serial": "XYZ98765" } }"#.as_bytes();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 108));
        let result = crate::parser::cctv::parse_dahua_payload(payload, "00:11:22:33:44:55".to_string(), source_ip);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.source_mac, "00:1a:2b:3c:4d:5e");
        assert_eq!(packet.vendor, "Dahua");
        assert_eq!(packet.model.as_deref(), Some("IPC-HFW4431R-ZS"));
        assert_eq!(packet.serial_number.as_deref(), Some("XYZ98765"));
        assert_eq!(packet.protocol, "Dahua Discovery");
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_cctv() {
        let temp_path = "/tmp/lanwatch_test_cctv.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::cctv::CctvPacket {
                source_mac: "11:22:33:44:55:66".to_string(),
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)),
                vendor: "Hikvision".to_string(),
                model: Some("DS-ABC1234".to_string()),
                serial_number: Some("SN987654".to_string()),
                protocol: "SADP".to_string(),
            };

            let updates = tracker.update_from_cctv(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Hikvision"));
            assert_eq!(device.device_type.as_deref(), Some("IP Camera"));
            assert_eq!(device.hostname.as_deref(), Some("DS-ABC1234"));
            assert_eq!(
                device.system_description.as_deref(),
                Some("IP Camera (DS-ABC1234 Serial: SN987654) via SADP")
            );
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_mqtt_connect() {
        let payload = vec![
            0x10, // Connect packet type
            0x11, // Remaining length (17)
            0x00, 0x04, // Protocol name length (4)
            b'M', b'Q', b'T', b'T', // Protocol name
            0x04, // Proto level
            0x02, // Connect flags
            0x00, 0x3c, // Keep alive (60)
            0x00, 0x05, // Client ID length (5)
            b'm', b'y', b'c', b'l', b'i', // Client ID
        ];
        let source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
        let result = crate::parser::mqtt_gdm::parse_mqtt_connect(
            &payload,
            "00:11:22:33:44:55".to_string(),
            source_ip,
        );
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.client_id, "mycli");
        assert_eq!(packet.protocol, "MQTT");
        assert_eq!(packet.source_mac, "00:11:22:33:44:55");
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_mqtt_sn_connect() {
        let payload = vec![
            13, // Length
            0x04, // MsgType: CONNECT
            0x04, // Flags
            0x01, // ProtocolId
            0x00, 0x3c, // Duration
            b'm', b'y', b's', b'n', b'c', b'l', b'i', // Client ID
        ];
        let source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 101));
        let result = crate::parser::mqtt_gdm::parse_mqtt_sn_connect(
            &payload,
            "00:11:22:33:44:66".to_string(),
            source_ip,
        );
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.client_id, "mysncli");
        assert_eq!(packet.protocol, "MQTT-SN");
        assert_eq!(packet.source_mac, "00:11:22:33:44:66");
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_parse_gdm_payload() {
        let payload = b"Content-Type: plex/media-server\r\nName: MyPlexServer\r\nPort: 32400\r\nProduct: Plex Media Server\r\nResource-Identifier: 12345678-abcd-ef01-2345-6789abcdef01\r\n";
        let source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 102));
        let result = crate::parser::mqtt_gdm::parse_gdm_payload(
            payload,
            "00:11:22:33:44:77".to_string(),
            source_ip,
        );
        assert!(result.is_some());
        let packet = result.unwrap();
        assert_eq!(packet.name.as_deref(), Some("MyPlexServer"));
        assert_eq!(packet.port, Some(32400));
        assert_eq!(packet.product.as_deref(), Some("Plex Media Server"));
        assert_eq!(packet.resource_id.as_deref(), Some("12345678-abcd-ef01-2345-6789abcdef01"));
        assert_eq!(packet.source_mac, "00:11:22:33:44:77");
        assert_eq!(packet.source_ip, source_ip);
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_mqtt() {
        let temp_path = "/tmp/lanwatch_test_mqtt.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::mqtt_gdm::MqttPacket {
                source_mac: "11:22:33:44:55:66".to_string(),
                source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 55)),
                client_id: "test-client".to_string(),
                protocol: "MQTT".to_string(),
            };

            let updates = tracker.update_from_mqtt(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("11:22:33:44:55:66").unwrap();
            assert_eq!(device.device_type.as_deref(), Some("IoT Device"));
            assert_eq!(
                device.system_description.as_deref(),
                Some("MQTT Client ID: test-client via MQTT")
            );
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(feature = "ssdp")]
    fn test_device_tracker_update_from_gdm() {
        let temp_path = "/tmp/lanwatch_test_gdm.csv";
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));

        {
            let mut tracker = DeviceTracker::new(temp_path).unwrap();
            let packet = crate::parser::mqtt_gdm::GdmPacket {
                source_mac: "22:33:44:55:66:77".to_string(),
                source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 56)),
                name: Some("PlexServer".to_string()),
                product: Some("Plex Media Server".to_string()),
                resource_id: Some("uuid-12345".to_string()),
                port: Some(32400),
            };

            let updates = tracker.update_from_gdm(&packet);
            assert!(updates > 0);

            let device = tracker.devices.get("22:33:44:55:66:77").unwrap();
            assert_eq!(device.vendor.as_deref(), Some("Plex"));
            assert_eq!(device.device_type.as_deref(), Some("Media Server"));
            assert_eq!(device.hostname.as_deref(), Some("PlexServer"));
            assert_eq!(
                device.system_description.as_deref(),
                Some("Plex device: Plex Media Server (uuid-12345)")
            );
        }

        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_file(format!("{}.journal", temp_path));
    }

    #[test]
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn test_direct_parse_arp_packet() {
        use crate::parser::network::parse_arp_packet;
        let mut arp_payload = vec![0u8; 28];
        // Hardware type: Ethernet (1)
        arp_payload[0..2].copy_from_slice(&[0x00, 0x01]);
        // Protocol type: IPv4 (0x0800)
        arp_payload[2..4].copy_from_slice(&[0x08, 0x00]);
        // Hardware size (6), Protocol size (4)
        arp_payload[4] = 6;
        arp_payload[5] = 4;
        // Opcode: Reply (2)
        arp_payload[6..8].copy_from_slice(&[0x00, 0x02]);
        // Sender MAC: 00:11:22:33:44:55
        arp_payload[8..14].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender IP: 192.168.1.10
        arp_payload[14..18].copy_from_slice(&[192, 168, 1, 10]);

        let result = parse_arp_packet(&arp_payload);
        assert!(result.is_some());
        let (mac, ip) = result.unwrap();
        assert_eq!(mac, "00:11:22:33:44:55");
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10)));

        // Test invalid packet
        let invalid = vec![0u8; 5];
        assert!(parse_arp_packet(&invalid).is_none());
        
        // Test invalid operation opcode (e.g. 0)
        arp_payload[7] = 0;
        assert!(parse_arp_packet(&arp_payload).is_none());
    }

    #[test]
    #[cfg(any(feature = "mdns", feature = "ssdp"))]
    fn test_direct_parse_ndp_packet() {
        use crate::parser::network::parse_ndp_packet;
        let ndp_payload = vec![135, 0, 0, 0, 0, 0, 0, 0]; // type 135 (solicitation)
        let source_ip = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let result = parse_ndp_packet(&ndp_payload, source_ip, "00:11:22:33:44:55".to_string());
        assert!(result.is_some());
        let (mac, ip) = result.unwrap();
        assert_eq!(mac, "00:11:22:33:44:55");
        assert_eq!(ip, std::net::IpAddr::V6(source_ip));

        // Test invalid payload size
        let invalid = vec![135, 0];
        assert!(parse_ndp_packet(&invalid, source_ip, "00:11:22:33:44:55".to_string()).is_none());

        // Test invalid ICMPv6 type (e.g. 1)
        let invalid_type = vec![1, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_ndp_packet(&invalid_type, source_ip, "00:11:22:33:44:55".to_string()).is_none());

        // Test unspecified source IP
        let unspecified = std::net::Ipv6Addr::UNSPECIFIED;
        assert!(parse_ndp_packet(&ndp_payload, unspecified, "00:11:22:33:44:55".to_string()).is_none());
    }
}

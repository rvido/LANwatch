// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

//! Kernel-side capture filter for the discovery sniffers.
//!
//! An unfiltered `AF_PACKET` socket copies *every* frame on the segment into
//! user space, and the sniffer then discards all but the handful of discovery
//! protocols it parses. On a link carrying real traffic that copy dominates
//! LANwatch's cost: a flamegraph taken on a Raspberry Pi CM4 router attributed
//! 28% of all process CPU to the `recvfrom` inside `NetworkSniffer::run`,
//! before a single byte had been parsed.
//!
//! A classic BPF program attached with `SO_ATTACH_FILTER` moves that decision
//! into the kernel, which already holds the packet: a non-matching frame is
//! never queued, never copied and never woken up for. What survives the filter
//! is a superset of what the parsers accept, so discovery behaviour does not
//! change -- only the volume of work needed to reach it.
//!
//! The filter is Linux-only, because `SO_ATTACH_FILTER` is. Elsewhere, and if
//! the socket cannot be prepared, capture falls back to pnet's own unfiltered
//! socket: a filter is an optimisation, and losing it must not stop discovery.
//!
//! # Keeping this in step with the parsers
//!
//! [`FILTER_EXPRESSION`] is the source of truth. After editing it, regenerate
//! [`FILTER`] with:
//!
//! ```text
//! tcpdump -dd -y EN10MB '<FILTER_EXPRESSION>'
//! ```
//!
//! The `filter_accepts_every_parsed_port` test drives the program over a
//! crafted frame for every port constant the parsers match, so adding a
//! protocol without regenerating the filter fails the test suite instead of
//! silently going undiscovered.
//!
//! VLAN-tagged frames are not matched, which costs nothing today:
//! `process_ethernet_frame_extended` does not look past an 802.1Q tag either.

/// The capture filter in tcpdump syntax -- the source of truth for [`FILTER`].
///
/// It keeps, in order: ARP; LLDP (ethertype 0x88cc); LLC/SNAP frames, which
/// carry CDP (an ethertype below 1500 is a length, not a protocol); every
/// ICMPv6 message, for the NDP neighbour advertisements; the discovery UDP
/// ports; and the two TCP ports whose responders identify a device (RTSP 554,
/// MQTT 1883).
///
/// Bulk traffic -- TCP 80/443 and QUIC on UDP 443 -- matches nothing here, and
/// that is the traffic this filter exists to stop copying.
pub const FILTER_EXPRESSION: &str = "arp or ether proto 0x88cc or ether[12:2] < 1500 or icmp6 \
     or (udp and (port 67 or port 68 or port 546 or port 547 or port 5353 or port 5355 \
     or port 137 or port 1900 or port 3702 or port 56700 or port 5683 or port 3671 \
     or port 9999 or port 37020 or port 37810 or port 1883 or portrange 32410-32414)) \
     or (tcp and (port 554 or port 1883))";

#[cfg(target_os = "linux")]
const fn i(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// [`FILTER_EXPRESSION`] compiled to classic BPF by `tcpdump -dd -y EN10MB`.
///
/// Hand-editing this is a mistake: change the expression and regenerate.
#[cfg(target_os = "linux")]
static FILTER: [libc::sock_filter; 114] = [
    i(0x28, 0, 0, 0x0000000c),
    i(0x15, 111, 0, 0x00000806),
    i(0x15, 110, 0, 0x000088cc),
    i(0x35, 0, 109, 0x000005dc),
    i(0x15, 0, 51, 0x000086dd),
    i(0x30, 0, 0, 0x00000014),
    i(0x15, 106, 0, 0x0000003a),
    i(0x15, 0, 2, 0x0000002c),
    i(0x30, 0, 0, 0x00000036),
    i(0x15, 103, 102, 0x0000003a),
    i(0x15, 0, 39, 0x00000011),
    i(0x28, 0, 0, 0x00000036),
    i(0x15, 100, 0, 0x00000043),
    i(0x15, 99, 0, 0x00000044),
    i(0x15, 98, 0, 0x00000222),
    i(0x15, 97, 0, 0x00000223),
    i(0x15, 96, 0, 0x000014e9),
    i(0x15, 95, 0, 0x000014eb),
    i(0x15, 94, 0, 0x00000089),
    i(0x15, 93, 0, 0x0000076c),
    i(0x15, 92, 0, 0x00000e76),
    i(0x15, 91, 0, 0x0000dd7c),
    i(0x15, 90, 0, 0x00001633),
    i(0x15, 89, 0, 0x00000e57),
    i(0x15, 88, 0, 0x0000270f),
    i(0x15, 87, 0, 0x0000909c),
    i(0x15, 86, 0, 0x000093b2),
    i(0x15, 85, 0, 0x0000075b),
    i(0x28, 0, 0, 0x00000038),
    i(0x15, 83, 0, 0x00000043),
    i(0x15, 82, 0, 0x00000044),
    i(0x15, 81, 0, 0x00000222),
    i(0x15, 80, 0, 0x00000223),
    i(0x15, 79, 0, 0x000014e9),
    i(0x15, 78, 0, 0x000014eb),
    i(0x15, 77, 0, 0x00000089),
    i(0x15, 76, 0, 0x0000076c),
    i(0x15, 75, 0, 0x00000e76),
    i(0x15, 74, 0, 0x0000dd7c),
    i(0x15, 73, 0, 0x00001633),
    i(0x15, 72, 0, 0x00000e57),
    i(0x15, 71, 0, 0x0000270f),
    i(0x15, 70, 0, 0x0000909c),
    i(0x15, 69, 0, 0x000093b2),
    i(0x15, 68, 0, 0x0000075b),
    i(0x28, 0, 0, 0x00000036),
    i(0x35, 0, 1, 0x00007e9a),
    i(0x25, 0, 65, 0x00007e9e),
    i(0x28, 0, 0, 0x00000038),
    i(0x35, 51, 62, 0x00007e9a),
    i(0x15, 0, 61, 0x00000006),
    i(0x28, 0, 0, 0x00000036),
    i(0x15, 60, 0, 0x0000022a),
    i(0x15, 59, 0, 0x0000075b),
    i(0x28, 0, 0, 0x00000038),
    i(0x15, 57, 55, 0x0000022a),
    i(0x15, 0, 55, 0x00000800),
    i(0x30, 0, 0, 0x00000017),
    i(0x15, 0, 43, 0x00000011),
    i(0x28, 0, 0, 0x00000014),
    i(0x45, 51, 0, 0x00001fff),
    i(0xb1, 0, 0, 0x0000000e),
    i(0x48, 0, 0, 0x0000000e),
    i(0x15, 49, 0, 0x00000043),
    i(0x15, 48, 0, 0x00000044),
    i(0x15, 47, 0, 0x00000222),
    i(0x15, 46, 0, 0x00000223),
    i(0x15, 45, 0, 0x000014e9),
    i(0x15, 44, 0, 0x000014eb),
    i(0x15, 43, 0, 0x00000089),
    i(0x15, 42, 0, 0x0000076c),
    i(0x15, 41, 0, 0x00000e76),
    i(0x15, 40, 0, 0x0000dd7c),
    i(0x15, 39, 0, 0x00001633),
    i(0x15, 38, 0, 0x00000e57),
    i(0x15, 37, 0, 0x0000270f),
    i(0x15, 36, 0, 0x0000909c),
    i(0x15, 35, 0, 0x000093b2),
    i(0x15, 34, 0, 0x0000075b),
    i(0x48, 0, 0, 0x00000010),
    i(0x15, 32, 0, 0x00000043),
    i(0x15, 31, 0, 0x00000044),
    i(0x15, 30, 0, 0x00000222),
    i(0x15, 29, 0, 0x00000223),
    i(0x15, 28, 0, 0x000014e9),
    i(0x15, 27, 0, 0x000014eb),
    i(0x15, 26, 0, 0x00000089),
    i(0x15, 25, 0, 0x0000076c),
    i(0x15, 24, 0, 0x00000e76),
    i(0x15, 23, 0, 0x0000dd7c),
    i(0x15, 22, 0, 0x00001633),
    i(0x15, 21, 0, 0x00000e57),
    i(0x15, 20, 0, 0x0000270f),
    i(0x15, 19, 0, 0x0000909c),
    i(0x15, 18, 0, 0x000093b2),
    i(0x15, 17, 0, 0x0000075b),
    i(0x48, 0, 0, 0x0000000e),
    i(0x35, 0, 1, 0x00007e9a),
    i(0x25, 0, 14, 0x00007e9e),
    i(0x48, 0, 0, 0x00000010),
    i(0x35, 0, 11, 0x00007e9a),
    i(0x25, 10, 11, 0x00007e9e),
    i(0x15, 0, 9, 0x00000006),
    i(0x28, 0, 0, 0x00000014),
    i(0x45, 7, 0, 0x00001fff),
    i(0xb1, 0, 0, 0x0000000e),
    i(0x48, 0, 0, 0x0000000e),
    i(0x15, 5, 0, 0x0000022a),
    i(0x15, 4, 0, 0x0000075b),
    i(0x48, 0, 0, 0x00000010),
    i(0x15, 2, 0, 0x0000022a),
    i(0x15, 1, 0, 0x0000075b),
    i(0x6, 0, 0, 0x00000000),
    i(0x6, 0, 0, 0x00040000),
];

/// Open an `AF_PACKET` socket with [`FILTER`] already attached, for
/// [`pnet_datalink::Config::socket_fd`].
///
/// The socket is created exactly as pnet would create it, so that pnet's own
/// bind, promiscuous-mode and non-blocking setup behave identically; the only
/// difference is the filter, attached here *before* the caller binds to an
/// interface so no unfiltered frame is ever queued.
///
/// pnet closes the descriptor on every one of its own failure paths, and this
/// function closes it on its own, so the caller never owns a stray socket.
#[cfg(target_os = "linux")]
pub fn filtered_socket() -> std::io::Result<i32> {
    // SAFETY: a plain socket(2) call; the result is checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as libc::c_int).to_be(),
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // The kernel copies the program, so a local copy is enough -- and it keeps
    // the pointer handed over from casting away the static's constness.
    let mut program = FILTER;
    let fprog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };

    // SAFETY: `fprog` points at `program`, which outlives the call, and the
    // length matches the array it describes.
    let attached = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&fprog as *const libc::sock_fprog).cast(),
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if attached == -1 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` is a socket this function opened and no longer uses.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

/// Channel configuration for the discovery sniffers: pnet's defaults, plus the
/// kernel-side capture filter where the platform supports one.
pub fn channel_config() -> pnet_datalink::Config {
    let mut config = pnet_datalink::Config::default();

    #[cfg(target_os = "linux")]
    match filtered_socket() {
        Ok(fd) => config.socket_fd = Some(fd),
        Err(e) => {
            eprintln!("Warning: capture filter unavailable ({e}); capturing every frame instead")
        }
    }

    config
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Verdict for a frame the filter drops.
    const DROP: u32 = 0;

    /// A minimal classic-BPF interpreter covering only the instructions
    /// `tcpdump` emits for [`FILTER_EXPRESSION`].
    ///
    /// This exists so the compiled program can be exercised in a unit test:
    /// the alternative is a privileged socket, which no test should need. An
    /// out-of-range load returns `DROP`, as the kernel's interpreter does.
    fn verdict(packet: &[u8]) -> u32 {
        let load16 = |at: u32| -> Option<u32> {
            let at = at as usize;
            let bytes = packet.get(at..at + 2)?;
            Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u32)
        };

        let mut pc = 0usize;
        let mut a = 0u32;
        let mut x = 0u32;
        loop {
            let op = FILTER[pc];
            pc += 1;
            let jump = |taken: bool, pc: usize| {
                if taken {
                    pc + op.jt as usize
                } else {
                    pc + op.jf as usize
                }
            };
            match op.code {
                // ldh [k] / ldb [k]
                0x28 => match load16(op.k) {
                    Some(value) => a = value,
                    None => return DROP,
                },
                0x30 => match packet.get(op.k as usize) {
                    Some(byte) => a = *byte as u32,
                    None => return DROP,
                },
                // ldx 4*([k] & 0xf) -- the IPv4 header length
                0xb1 => match packet.get(op.k as usize) {
                    Some(byte) => x = 4 * (*byte & 0x0f) as u32,
                    None => return DROP,
                },
                // ldh [x + k]
                0x48 => match load16(x + op.k) {
                    Some(value) => a = value,
                    None => return DROP,
                },
                0x15 => pc = jump(a == op.k, pc),
                0x35 => pc = jump(a >= op.k, pc),
                0x25 => pc = jump(a > op.k, pc),
                0x45 => pc = jump(a & op.k != 0, pc),
                0x06 => return op.k,
                other => panic!("unhandled BPF opcode {other:#x} at {pc}"),
            }
        }
    }

    fn ether(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x11; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0x45, 0x00];
        header.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        header.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, protocol, 0x00, 0x00]);
        header.extend_from_slice(&[192, 168, 1, 10]);
        header.extend_from_slice(&[192, 168, 1, 1]);
        header.extend_from_slice(payload);
        ether(0x0800, &header)
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0x60, 0x00, 0x00, 0x00];
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        header.push(next_header);
        header.push(64);
        header.extend_from_slice(&[0x20; 16]);
        header.extend_from_slice(&[0x30; 16]);
        header.extend_from_slice(payload);
        ether(0x86dd, &header)
    }

    fn udp(source: u16, destination: u16) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&source.to_be_bytes());
        segment.extend_from_slice(&destination.to_be_bytes());
        segment.extend_from_slice(&16u16.to_be_bytes());
        segment.extend_from_slice(&[0x00, 0x00]);
        segment.extend_from_slice(&[0xAA; 8]);
        segment
    }

    fn tcp(source: u16, destination: u16) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&source.to_be_bytes());
        segment.extend_from_slice(&destination.to_be_bytes());
        segment.extend_from_slice(&[0x00; 8]); // sequence + ack
        segment.extend_from_slice(&[0x50, 0x18]); // data offset 5, PSH|ACK
        segment.extend_from_slice(&[0x00; 6]); // window, checksum, urgent
        segment.extend_from_slice(&[0xAA; 8]);
        segment
    }

    /// Every UDP port the parsers dispatch on must survive the filter, on both
    /// IPv4 and IPv6 and in either direction. The list is built from the
    /// parsers' own constants, so a new protocol whose port is missing from
    /// [`FILTER_EXPRESSION`] fails here.
    #[test]
    fn filter_accepts_every_parsed_port() {
        // Only the mdns and ssdp blocks below extend the list.
        #[cfg_attr(not(any(feature = "mdns", feature = "ssdp")), allow(unused_mut))]
        let mut udp_ports = vec![
            crate::types::DHCPV4_SERVER_PORT,
            crate::types::DHCPV4_CLIENT_PORT,
            crate::types::DHCPV6_CLIENT_PORT,
            crate::types::DHCPV6_SERVER_PORT,
        ];
        #[cfg(feature = "mdns")]
        udp_ports.extend_from_slice(&[
            crate::parser::mdns::MDNS_PORT,
            crate::parser::mdns::LLMNR_PORT,
            crate::parser::mdns::NBNS_PORT,
        ]);
        #[cfg(feature = "ssdp")]
        {
            udp_ports.extend_from_slice(&[
                crate::parser::ssdp::SSDP_PORT,
                crate::parser::ssdp::WSD_PORT,
                crate::parser::iot::LIFX_PORT,
                crate::parser::iot::COAP_PORT,
                crate::parser::iot::KNX_PORT,
                crate::parser::cctv::SADP_PORT,
                crate::parser::cctv::SADP_ALT_PORT,
                crate::parser::cctv::DAHUA_PORT,
                crate::parser::mqtt_gdm::MQTT_PORT,
            ]);
            udp_ports.extend_from_slice(crate::parser::mqtt_gdm::GDM_PORTS);
        }

        for port in udp_ports {
            for (source, destination) in [(port, 40000), (40000, port)] {
                assert_ne!(
                    verdict(&ipv4(17, &udp(source, destination))),
                    DROP,
                    "IPv4 UDP {source}->{destination} was filtered out"
                );
                assert_ne!(
                    verdict(&ipv6(17, &udp(source, destination))),
                    DROP,
                    "IPv6 UDP {source}->{destination} was filtered out"
                );
            }
        }

        #[cfg(feature = "ssdp")]
        {
            // Only the RTSP responder identifies a camera, but the filter is
            // deliberately symmetric: the parser, not the kernel, decides.
            for (source, destination) in [
                (crate::parser::cctv::RTSP_PORT, 40000),
                (40000, crate::parser::mqtt_gdm::MQTT_PORT),
            ] {
                assert_ne!(
                    verdict(&ipv4(6, &tcp(source, destination))),
                    DROP,
                    "IPv4 TCP {source}->{destination} was filtered out"
                );
            }
        }
    }

    #[test]
    fn filter_accepts_link_layer_discovery() {
        assert_ne!(verdict(&ether(0x0806, &[0xAA; 28])), DROP, "ARP");
        assert_ne!(verdict(&ether(0x88cc, &[0xAA; 28])), DROP, "LLDP");
        // An ethertype below 1500 is an 802.3 length: LLC/SNAP, which carries CDP.
        assert_ne!(verdict(&ether(0x0026, &[0xAA; 28])), DROP, "LLC/SNAP");
        // ICMPv6 type 136 is a neighbour advertisement (NDP).
        let mut ndp = vec![136, 0, 0, 0, 0, 0, 0, 0];
        ndp.extend_from_slice(&[0x00; 16]);
        assert_ne!(verdict(&ipv6(58, &ndp)), DROP, "ICMPv6 NDP");
    }

    /// The traffic this filter exists to stop copying.
    #[test]
    fn filter_drops_bulk_traffic() {
        assert_eq!(verdict(&ipv4(17, &udp(50000, 443))), DROP, "QUIC");
        assert_eq!(verdict(&ipv4(17, &udp(443, 50000))), DROP, "QUIC reply");
        assert_eq!(verdict(&ipv4(6, &tcp(50000, 443))), DROP, "HTTPS");
        assert_eq!(verdict(&ipv4(6, &tcp(80, 50000))), DROP, "HTTP reply");
        assert_eq!(verdict(&ipv6(6, &tcp(50000, 443))), DROP, "HTTPS over IPv6");
        // Plain DNS is the engine's business, not the device tracker's.
        assert_eq!(verdict(&ipv4(17, &udp(53, 40000))), DROP, "DNS");
    }
}

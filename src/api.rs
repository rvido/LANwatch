// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LANwatch - Network device discovery and tracking

#![cfg(feature = "http-api")]

use serde::Serialize;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Response, Server};

use crate::device::DeviceInfo;
use crate::tracker::DeviceTracker;

/// Cache representation for sorted device lists to reduce database locking under high traffic.
struct SortedDevicesCache {
    devices: Arc<Vec<DeviceInfo>>,
    cached_at: Instant,
}

/// HTTP API server for exposing device data
#[derive(Clone)]
pub struct ApiServer {
    server: Arc<Server>,
    tracker: Arc<RwLock<DeviceTracker>>,
    cache: Arc<Mutex<Option<SortedDevicesCache>>>,
}

/// API response structure
#[derive(Serialize)]
pub(crate) struct ApiResponse<T> {
    pub(crate) success: bool,
    pub(crate) count: usize,
    pub(crate) data: T,
}

/// Error response structure
#[derive(Serialize)]
pub(crate) struct ApiError {
    pub(crate) success: bool,
    pub(crate) error: String,
}

impl ApiServer {
    /// Creates a new HTTP API server instance.
    ///
    /// # Arguments
    /// * `addr` - The socket address to listen on (e.g., "127.0.0.1:8080").
    /// * `tracker` - An `Arc<RwLock<DeviceTracker>>` for safe sharing of device data.
    pub fn new(addr: &str, tracker: Arc<RwLock<DeviceTracker>>) -> std::io::Result<Self> {
        let server = Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self {
            server: Arc::new(server),
            tracker,
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Starts the API server request handling loop using a thread pool.
    pub fn run(&self) {
        println!(
            "API server listening on http://{}",
            self.server.server_addr()
        );
        println!("Endpoints:");
        println!(
            "  GET /devices     - List all devices (JSON, pagination supported: ?limit=50&offset=0)"
        );
        println!("  GET /devices/count - Get device count");
        println!("  DELETE /devices/{{mac}} - Remove a single device");
        println!("  DELETE /devices - Remove all devices");
        println!("  GET /health      - Health check");
        println!();

        // Dynamically determine optimal thread count based on hardware or environment override
        let thread_count = std::env::var("LANWATCH_API_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| std::thread::available_parallelism().map(|n| n.get()).ok())
            .unwrap_or(4);

        println!(
            "Starting API server with {} worker threads...",
            thread_count
        );

        let mut workers = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let server = Arc::clone(&self.server);
            let self_clone = self.clone();

            let handle = thread::spawn(move || {
                for request in server.incoming_requests() {
                    let response = self_clone.handle_request(&request);
                    let _ = request.respond(response);
                }
            });
            workers.push(handle);
        }

        for worker in workers {
            let _ = worker.join();
        }
    }

    /// Handle incoming HTTP requests
    fn handle_request(&self, request: &tiny_http::Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let path = request.url();
        let method = request.method();

        match (method.as_str(), path) {
            ("GET", "/devices/count") | ("GET", "/device/count") => self.handle_device_count(),
            ("GET", "/health") => self.handle_health(),
            ("GET", "/") => self.handle_root(),
            ("GET", "/logo.png") => self.handle_logo(),
            ("GET", p)
                if p == "/devices"
                    || p.starts_with("/devices?")
                    || p == "/device"
                    || p.starts_with("/device?") =>
            {
                let (limit, offset) = Self::parse_query_params(p);
                self.handle_devices_paginated(limit, offset)
            }
            ("GET", p) if p.starts_with("/devices/") || p.starts_with("/device/") => {
                let prefix_len = if p.starts_with("/devices/") { 9 } else { 8 };
                let mac = &p[prefix_len..];
                let mac_clean = if let Some(pos) = mac.find('?') {
                    &mac[..pos]
                } else {
                    mac
                };
                self.handle_device_by_mac(&Self::percent_decode(mac_clean))
            }
            ("DELETE", "/devices") | ("DELETE", "/device") => self.handle_flush_devices(),
            ("DELETE", p) if p.starts_with("/devices/") || p.starts_with("/device/") => {
                let prefix_len = if p.starts_with("/devices/") { 9 } else { 8 };
                let mac = &p[prefix_len..];
                self.handle_delete_device(&Self::percent_decode(mac))
            }
            _ => self.handle_not_found(),
        }
    }

    /// Decodes `%XX` percent-escapes in a URL path segment (e.g. `%3A` -> `:`).
    ///
    /// `tiny_http` hands back the raw, undecoded request path, but well-behaved
    /// HTTP clients (including this crate's own dashboard) percent-encode path
    /// segments per RFC 3986 -- colons in a MAC address are valid unencoded in a
    /// path segment, but a client is not required to know that. Malformed `%`
    /// sequences are passed through unchanged.
    fn percent_decode(input: &str) -> String {
        fn hex_val(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }

        // Operate on raw bytes throughout (never slicing `input` as a `&str`)
        // so a stray `%` adjacent to a multi-byte UTF-8 character can't panic
        // on a non-char-boundary index.
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Helper to extract limit & offset from URL query params
    fn parse_query_params(path: &str) -> (Option<usize>, usize) {
        let mut limit = None;
        let mut offset = 0;
        if let Some(pos) = path.find('?') {
            let query = &path[pos + 1..];
            for part in query.split('&') {
                let mut kv = part.split('=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    match k {
                        "limit" => limit = v.parse::<usize>().ok(),
                        "offset" => offset = v.parse::<usize>().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }
        (limit, offset)
    }

    /// Retrieves devices from cache if valid (<= 500ms), otherwise updates cache from tracker
    fn get_or_update_cache(&self) -> Result<Arc<Vec<DeviceInfo>>, &'static str> {
        let now = Instant::now();

        // 1. Try reading with cache lock first
        if let Ok(guard) = self.cache.lock() {
            let entry = guard.as_ref().filter(|cache_entry| {
                now.duration_since(cache_entry.cached_at) < Duration::from_millis(500)
            });
            if let Some(cache_entry) = entry {
                return Ok(Arc::clone(&cache_entry.devices));
            }
        }

        // 2. Cache is expired or uninitialized: acquire lock to update
        if let Ok(mut guard) = self.cache.lock() {
            // Double-check pattern
            let entry = guard.as_ref().filter(|cache_entry| {
                now.duration_since(cache_entry.cached_at) < Duration::from_millis(500)
            });
            if let Some(cache_entry) = entry {
                return Ok(Arc::clone(&cache_entry.devices));
            }

            // Rebuild sorted device list from the tracker using SQL indexed query
            if let Ok(tracker) = self.tracker.read() {
                let devices = tracker.get_devices_sorted();
                let devices_arc = Arc::new(devices);
                *guard = Some(SortedDevicesCache {
                    devices: Arc::clone(&devices_arc),
                    cached_at: now,
                });
                Ok(devices_arc)
            } else {
                Err("Failed to read device data")
            }
        } else {
            Err("Lock acquisition failed")
        }
    }

    fn handle_devices_paginated(
        &self,
        limit: Option<usize>,
        offset: usize,
    ) -> Response<std::io::Cursor<Vec<u8>>> {
        let devices_arc = match self.get_or_update_cache() {
            Ok(arc) => arc,
            Err(e) => return self.handle_error(e),
        };
        let total_count = devices_arc.len();

        let slice = if offset >= total_count {
            &[]
        } else {
            let end = if let Some(l) = limit {
                std::cmp::min(offset + l, total_count)
            } else {
                total_count
            };
            &devices_arc[offset..end]
        };

        let response = ApiResponse {
            success: true,
            count: total_count,
            data: slice,
        };

        let json = serde_json::to_string(&response).unwrap_or_default();
        Response::from_string(json)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_device_by_mac(&self, mac: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        // Look up in cache first to avoid locking tracker
        let cache_val = {
            if let Ok(guard) = self.cache.lock() {
                let entry = guard.as_ref().filter(|cache_entry| {
                    Instant::now().duration_since(cache_entry.cached_at)
                        < Duration::from_millis(500)
                });
                entry.and_then(|cache_entry| {
                    cache_entry
                        .devices
                        .iter()
                        .find(|d| d.mac_address == mac)
                        .cloned()
                })
            } else {
                None
            }
        };

        let device = match cache_val {
            Some(d) => Some(d),
            None => match self.tracker.read() {
                Ok(tracker) => tracker.get_device(mac).cloned(),
                Err(_) => None,
            },
        };

        if let Some(dev) = device {
            let response = ApiResponse {
                success: true,
                count: 1,
                data: dev,
            };

            let json = serde_json::to_string(&response).unwrap_or_default();
            Response::from_string(json).with_header(
                tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
            )
        } else {
            self.handle_not_found()
        }
    }

    /// Deletes a single device by MAC address.
    ///
    /// This only removes current state: since discovery is passive, a device
    /// still active on the LAN will reappear the next time it's observed.
    fn handle_delete_device(&self, mac: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let removed = match self.tracker.write() {
            Ok(mut tracker) => tracker.remove_device(mac),
            Err(_) => return self.handle_error("Failed to acquire device lock"),
        };

        match removed {
            Ok(true) => {
                *self.cache.lock().unwrap() = None;
                let json = serde_json::json!({ "success": true, "removed": mac });
                Response::from_string(json.to_string()).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Ok(false) => self.handle_not_found(),
            Err(_) => self.handle_error("Failed to remove device"),
        }
    }

    /// Deletes every tracked device.
    ///
    /// Same caveat as [`ApiServer::handle_delete_device`]: devices still active
    /// on the LAN will simply reappear as new entries the next time they're seen.
    fn handle_flush_devices(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let cleared = match self.tracker.write() {
            Ok(mut tracker) => tracker.clear_all_devices(),
            Err(_) => return self.handle_error("Failed to acquire device lock"),
        };

        match cleared {
            Ok(count) => {
                *self.cache.lock().unwrap() = None;
                let json = serde_json::json!({ "success": true, "removed": count });
                Response::from_string(json.to_string()).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Err(_) => self.handle_error("Failed to flush devices"),
        }
    }

    fn handle_device_count(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let count = {
            if let Ok(guard) = self.cache.lock() {
                let entry = guard.as_ref().filter(|cache_entry| {
                    Instant::now().duration_since(cache_entry.cached_at)
                        < Duration::from_millis(500)
                });
                entry.map(|cache_entry| cache_entry.devices.len())
            } else {
                None
            }
        };

        let final_count = match count {
            Some(c) => c,
            None => match self.tracker.read() {
                Ok(tracker) => tracker.device_count(),
                Err(_) => 0,
            },
        };

        let json = serde_json::json!({
            "success": true,
            "count": final_count
        });
        Response::from_string(json.to_string())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_health(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "status": "ok",
            "service": "lanwatch"
        });
        Response::from_string(json.to_string())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    /// Serves the LANwatch logo, compiled into the binary so the dashboard is
    /// fully self-contained with no external asset dependencies.
    fn handle_logo(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let bytes = include_bytes!("../assets/lanwatch_logo_icon.png").to_vec();
        Response::from_data(bytes)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "image/png").unwrap())
            .with_header(
                tiny_http::Header::from_bytes("Cache-Control", "public, max-age=86400").unwrap(),
            )
    }

    fn handle_root(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let html = include_str!("dashboard.html").replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));
        Response::from_string(html).with_header(
            tiny_http::Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap(),
        )
    }

    fn handle_not_found(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let error = ApiError {
            success: false,
            error: "Not found".to_string(),
        };
        Response::from_string(serde_json::to_string(&error).unwrap_or_default())
            .with_status_code(404)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }

    fn handle_error(&self, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let error = ApiError {
            success: false,
            error: message.to_string(),
        };
        Response::from_string(serde_json::to_string(&error).unwrap_or_default())
            .with_status_code(500)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    }
}

/// Starts the HTTP API server in a dedicated background thread.
///
/// # Arguments
/// * `addr` - The address to bind to.
/// * `tracker` - The shared device tracker.
pub fn start_api_server(
    addr: &str,
    tracker: Arc<RwLock<DeviceTracker>>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let server = ApiServer::new(addr, tracker)?;
    Ok(thread::spawn(move || {
        server.run();
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceInfo;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn get_http_body(response: &str) -> &str {
        if let Some(pos) = response.find("\r\n\r\n") {
            &response[pos + 4..]
        } else {
            response
        }
    }

    #[test]
    fn test_api_server_endpoints() {
        let temp_db = "/tmp/lanwatch_test_api.db";
        let _ = std::fs::remove_file(temp_db);
        let _ = std::fs::remove_file(format!("{}-journal", temp_db));
        let _ = std::fs::remove_file(format!("{}-wal", temp_db));
        let _ = std::fs::remove_file(format!("{}-shm", temp_db));

        let tracker = Arc::new(RwLock::new(DeviceTracker::new(temp_db).unwrap()));

        // Insert a dummy device
        {
            let mut guard = tracker.write().unwrap();
            let mut device = DeviceInfo::new(
                "aa:bb:cc:dd:ee:ff".to_string(),
                "192.168.1.100".parse().unwrap(),
                Some("test-device".to_string()),
            );
            device.device_type = Some(crate::types::DeviceType::Laptop);
            device.vendor = Some(crate::types::Vendor::Dell);
            let mac = device.mac_address.clone();
            guard.devices.insert(mac.clone(), device);
            guard.dirty_devices.lock().unwrap().insert(mac);
            guard.save_to_db().unwrap();
        }

        // Bind to a free port dynamically allocated by the OS
        let api_server = ApiServer::new("127.0.0.1:0", Arc::clone(&tracker)).unwrap();
        let bound_addr = api_server.server.server_addr().to_string();

        // Run the server loop in a separate thread so it doesn't block the test
        let server_clone = api_server.clone();
        let _server_handle = std::thread::spawn(move || {
            for request in server_clone.server.incoming_requests() {
                let response = server_clone.handle_request(&request);
                let _ = request.respond(response);
            }
        });

        // 1. Test /health
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"status\":\"ok\""));
        }

        // 2. Test /devices/count
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"GET /devices/count HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"count\":1"));
        }

        // 3. Test /devices
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(b"GET /devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            println!("BODY: {:?}", body);
            assert!(body.contains("\"mac_address\":\"aa:bb:cc:dd:ee:ff\""));
            assert!(body.contains("\"hostname\":\"test-device\""));
        }

        // 4. Test /devices/aa:bb:cc:dd:ee:ff
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream.write_all(b"GET /devices/aa:bb:cc:dd:ee:ff HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"mac_address\":\"aa:bb:cc:dd:ee:ff\""));
        }

        // 5. Test /devices/unknown (404)
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream.write_all(b"GET /devices/11:22:33:44:55:66 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"success\":false"));
        }

        // 6. Test /invalid-path (404)
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"GET /invalid-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("404 Not Found"));
        }

        // 7. Test / (Root serves dashboard)
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("<!DOCTYPE html>"));
            // Release version is injected into the dashboard and the placeholder is gone.
            assert!(body.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
            assert!(!body.contains("{{VERSION}}"));
            // The dashboard references the embedded logo endpoint.
            assert!(body.contains("/logo.png"));
        }

        // 7b. Test /logo.png (embedded binary asset)
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"GET /logo.png HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();

            let sep = b"\r\n\r\n";
            let header_end = response
                .windows(sep.len())
                .position(|w| w == sep)
                .expect("response must have a header/body separator");
            let headers = String::from_utf8_lossy(&response[..header_end]);
            assert!(headers.contains("200 OK"));
            assert!(headers.contains("Content-Type: image/png"));

            // Body may be chunk-framed; confirm the PNG magic number is present.
            let body = &response[header_end + sep.len()..];
            let png_magic = b"\x89PNG\r\n\x1a\n";
            assert!(
                body.windows(png_magic.len()).any(|w| w == png_magic),
                "logo response body must contain PNG data"
            );
        }

        // 8. Test parse_query_params
        let (limit, offset) = ApiServer::parse_query_params("/devices?limit=10&offset=5");
        assert_eq!(limit, Some(10));
        assert_eq!(offset, 5);

        // 9. Test DELETE /devices/{mac} for an unknown MAC (404)
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream.write_all(b"DELETE /devices/11:22:33:44:55:66 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"success\":false"));
        }

        // 10. Test DELETE /devices/{mac} for a known MAC, then confirm it's gone
        {
            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream.write_all(b"DELETE /devices/aa:bb:cc:dd:ee:ff HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"success\":true"));

            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"GET /devices/count HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(
                body.contains("\"count\":0"),
                "device should be removed immediately (cache must be invalidated): {:?}",
                body
            );
        }

        // 10b. Test DELETE /devices/{mac} where the MAC's colons are percent-encoded
        // (e.g. `encodeURIComponent` in the bundled dashboard's JS), as opposed to
        // sent literally like test 10 above.
        {
            let mut guard = tracker.write().unwrap();
            let device = DeviceInfo::new(
                "cc:dd:ee:ff:00:11".to_string(),
                "192.168.1.102".parse().unwrap(),
                Some("percent-encoded-device".to_string()),
            );
            let mac = device.mac_address.clone();
            guard.devices.insert(mac.clone(), device);
            guard.dirty_devices.lock().unwrap().insert(mac);
            guard.save_to_db().unwrap();
            drop(guard);

            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream.write_all(b"DELETE /devices/cc%3Add%3Aee%3Aff%3A00%3A11 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(
                body.contains("\"success\":true"),
                "percent-encoded MAC delete should succeed: {:?}",
                body
            );
            assert!(
                !tracker
                    .read()
                    .unwrap()
                    .devices
                    .contains_key("cc:dd:ee:ff:00:11")
            );
        }

        // 11. Test DELETE /devices (flush all)
        {
            let mut device = DeviceInfo::new(
                "11:22:33:44:55:66".to_string(),
                "192.168.1.101".parse().unwrap(),
                Some("second-device".to_string()),
            );
            device.device_type = Some(crate::types::DeviceType::Laptop);
            let mac = device.mac_address.clone();
            let mut guard = tracker.write().unwrap();
            guard.devices.insert(mac.clone(), device);
            guard.dirty_devices.lock().unwrap().insert(mac);
            guard.save_to_db().unwrap();
            drop(guard);

            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"DELETE /devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"success\":true"));
            assert!(body.contains("\"removed\":1"));

            let mut stream = TcpStream::connect(&bound_addr).unwrap();
            stream
                .write_all(
                    b"GET /devices/count HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let body = get_http_body(&response);
            assert!(body.contains("\"count\":0"));
        }

        // Terminate the server to stop the thread loop
        drop(api_server);

        let _ = std::fs::remove_file(temp_db);
        let _ = std::fs::remove_file(format!("{}-journal", temp_db));
        let _ = std::fs::remove_file(format!("{}-wal", temp_db));
        let _ = std::fs::remove_file(format!("{}-shm", temp_db));
    }
}

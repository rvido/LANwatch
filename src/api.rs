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
                self.handle_device_by_mac(mac_clean)
            }
            _ => self.handle_not_found(),
        }
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

            // Rebuild sorted device list from the tracker
            if let Ok(tracker) = self.tracker.read() {
                let mut devices: Vec<DeviceInfo> = tracker.devices().values().cloned().collect();
                devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));
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

    fn handle_root(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let json = serde_json::json!({
            "service": "lanwatch",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": {
                "/devices": "GET - List detected devices (supports: ?limit=50&offset=0)",
                "/devices/{mac}": "GET - Get a specific device by MAC address",
                "/devices/count": "GET - Get device count",
                "/health": "GET - Health check"
            }
        });
        Response::from_string(serde_json::to_string(&json).unwrap_or_default())
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
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

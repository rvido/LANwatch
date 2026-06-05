// Copyright (c) 2026 Richard Vidal-Dorsch
// SPDX-License-Identifier: MIT
//
// LANwatch - Network device discovery and tracking

#![cfg(feature = "http-api")]

use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::thread;
use tiny_http::{Response, Server};

use crate::device::DeviceInfo;
use crate::tracker::DeviceTracker;

/// HTTP API server for exposing device data
pub struct ApiServer {
    server: Server,
    tracker: Arc<RwLock<DeviceTracker>>,
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
        Ok(Self { server, tracker })
    }

    /// Starts the API server request handling loop (blocks the current thread).
    pub fn run(&self) {
        println!(
            "API server listening on http://{}",
            self.server.server_addr()
        );
        println!("Endpoints:");
        println!("  GET /devices     - List all devices (JSON)");
        println!("  GET /devices/count - Get device count");
        println!("  GET /health      - Health check");
        println!();

        for request in self.server.incoming_requests() {
            let response = self.handle_request(&request);
            let _ = request.respond(response);
        }
    }

    /// Handle incoming HTTP requests
    fn handle_request(&self, request: &tiny_http::Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let path = request.url();
        let method = request.method();

        match (method.as_str(), path) {
            ("GET", "/devices") => self.handle_devices(),
            ("GET", "/devices/count") => self.handle_device_count(),
            ("GET", "/health") => self.handle_health(),
            ("GET", "/") => self.handle_root(),
            ("GET", p) if p.starts_with("/devices/") => {
                let mac = &p[9..];
                self.handle_device_by_mac(mac)
            }
            _ => self.handle_not_found(),
        }
    }

    fn handle_devices(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                let mut devices: Vec<&DeviceInfo> = tracker.devices().values().collect();
                devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));

                let response = ApiResponse {
                    success: true,
                    count: devices.len(),
                    data: devices,
                };

                let json = serde_json::to_string(&response).unwrap_or_default();
                Response::from_string(json).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Err(_) => self.handle_error("Failed to read device data"),
        }
    }

    fn handle_device_by_mac(&self, mac: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                if let Some(device) = tracker.get_device(mac) {
                    let response = ApiResponse {
                        success: true,
                        count: 1,
                        data: device,
                    };

                    let json = serde_json::to_string(&response).unwrap_or_default();
                    Response::from_string(json).with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    )
                } else {
                    self.handle_not_found()
                }
            }
            Err(_) => self.handle_error("Failed to read device data"),
        }
    }

    fn handle_device_count(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.tracker.read() {
            Ok(tracker) => {
                let json = serde_json::json!({
                    "success": true,
                    "count": tracker.device_count()
                });
                Response::from_string(json.to_string()).with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                )
            }
            Err(_) => self.handle_error("Failed to read device count"),
        }
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
                "/devices": "GET - List all detected devices",
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

use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::accept_async;
use futures_util::{StreamExt, SinkExt};
use serde_json;
use tauri::Emitter;
use crate::state::{WinState, get_state_path, save_state, LicenseTier};
// use crate::x7y9z2; // Removed - not needed
use rust_embed::RustEmbed;
// Minimal percent-decoder to avoid extra crates
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < bytes.len() => {
                let h1 = bytes[i+1];
                let h2 = bytes[i+2];
                fn hex(x: u8) -> Option<u8> {
                    match x {
                        b'0'..=b'9' => Some(x - b'0'),
                        b'a'..=b'f' => Some(10 + (x - b'a')),
                        b'A'..=b'F' => Some(10 + (x - b'A')),
                        _ => None,
                    }
                }
                if let (Some(a), Some(b)) = (hex(h1), hex(h2)) { out.push((a << 4) | b); i += 3; }
                else { out.push(bytes[i]); i += 1; }
            }
            _ => { out.push(bytes[i]); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// Embed static folder (overlay.html and assets/*)
#[derive(RustEmbed)]
#[folder = "../static"]
struct StaticAssets;

pub fn start_http_server(shared_state: Arc<Mutex<WinState>>, broadcast_tx: broadcast::Sender<WinState>, app_handle: tauri::AppHandle) {
    println!("🌐 Starting HTTP server...");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            // Shared challenge message store (in-memory)
            let challenge_msg: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
            // Serve static overlay assets on 777 to meet TikTok Studio requirement
            let addr = "127.0.0.1:777";
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
        println!("🌐 HTTP server running on {}", addr);
                listener
            },
            Err(e) => {
                println!("❌ Failed to bind HTTP server to {}: {}", addr, e);
                return;
            }
        };

        // Start minimal challenge server on 7777 (must start BEFORE the blocking accept loop)
        tokio::spawn(async move {
                // Try IPv4 127.0.0.1:7777 and IPv6 ::1:7777
                let listener_v4 = tokio::net::TcpListener::bind("127.0.0.1:7777").await.ok();
                let listener_v6 = tokio::net::TcpListener::bind("[::1]:7777").await.ok();

                async fn serve_once(mut stream: tokio::net::TcpStream) {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 { return; }
                        let req = String::from_utf8_lossy(&buffer[..n]);
                        let mut path = "/".to_string();
                        if let Some(line) = req.lines().next() {
                            let mut parts = line.split_whitespace();
                            let _method = parts.next().unwrap_or("");
                            path = parts.next().unwrap_or("/").to_string();
                        }
                        if path.contains("/challange.html") {
                            if let Some(file) = StaticAssets::get("challange.html") {
                                let body = file.data;
                                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\n";
                                let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                return;
                            }
                        }
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                    }
                }

                if let Some(listener) = listener_v4 {
                    println!("🌐 Minimal HTTP server (challenge) on 127.0.0.1:7777");
                    tokio::spawn(async move {
                        loop {
                            if let Ok((stream, _)) = listener.accept().await {
                                tokio::spawn(serve_once(stream));
                            }
                        }
                    });
                }
                if let Some(listener) = listener_v6 {
                    println!("🌐 Minimal HTTP server (challenge) on [::1]:7777");
                    tokio::spawn(async move {
                        loop {
                            if let Ok((stream, _)) = listener.accept().await {
                                tokio::spawn(serve_once(stream));
                            }
                        }
                    });
                }
        });

        // Start a dedicated minimal HTTP server for timer.html on port 888
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            async fn serve_timer_once(mut stream: tokio::net::TcpStream) {
                let mut buffer = [0u8; 4096];
                if let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 { return; }
                    let req = String::from_utf8_lossy(&buffer[..n]);
                    if req.contains("GET /timer.html") {
                        if let Some(file) = StaticAssets::get("timer.html") {
                            let body = file.data;
                            let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\n";
                            let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.write_all(&body).await;
                            return;
                        }
                    } else if let Some(start) = req.find("GET /assets/") {
                        // Serve /assets/* on port 888 as well
                        let rest = &req[start + 4..];
                        let mut parts = rest.split_whitespace();
                        if let Some(path) = parts.next() {
                            let rel_in_assets = path.trim_start_matches('/');
                            let static_key = rel_in_assets;
                            if let Some(file) = StaticAssets::get(static_key) {
                                let rel = rel_in_assets.trim_start_matches("assets/");
                                let content_type = if rel.ends_with(".png") { "image/png" }
                                    else if rel.ends_with(".jpg") || rel.ends_with(".jpeg") { "image/jpeg" }
                                    else if rel.ends_with(".gif") { "image/gif" }
                                    else if rel.ends_with(".svg") { "image/svg+xml" }
                                    else if rel.ends_with(".ttf") { "font/ttf" }
                                    else if rel.ends_with(".css") { "text/css" }
                                    else if rel.ends_with(".mp3") { "audio/mpeg" }
                                    else { "application/octet-stream" };
                                let body = file.data;
                                let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nCache-Control: no-cache\r\n", content_type);
                                let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                return;
                            }
                        }
                    }
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                }
            }

            let listener_v4 = tokio::net::TcpListener::bind("127.0.0.1:888").await.ok();
            let listener_v6 = tokio::net::TcpListener::bind("[::1]:888").await.ok();
            if let Some(listener) = listener_v4 {
                println!("🌐 Timer server on 127.0.0.1:888");
                tokio::spawn(async move {
                    loop {
                        if let Ok((stream, _)) = listener.accept().await {
                            tokio::spawn(serve_timer_once(stream));
                        }
                    }
                });
            }
            if let Some(listener) = listener_v6 {
                println!("🌐 Timer server on [::1]:888");
                tokio::spawn(async move {
                    loop {
                        if let Ok((stream, _)) = listener.accept().await {
                            tokio::spawn(serve_timer_once(stream));
                        }
                    }
                });
            }
        });

        while let Ok((stream, _)) = listener.accept().await {
            let shared_state_clone = shared_state.clone();
            let broadcast_tx_clone = broadcast_tx.clone();
            let app_handle_clone = app_handle.clone();
            let challenge_msg_clone = challenge_msg.clone();
            let rt = tokio::runtime::Handle::current();
            rt.spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                let mut stream = tokio::net::TcpStream::from(stream);
                
                // Read HTTP request robustly: read headers fully, then read body by Content-Length (up to 64KB)
                let mut req_bytes: Vec<u8> = Vec::with_capacity(4096);
                let mut tmp = [0u8; 2048];
                let mut content_length: usize = 0;
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            req_bytes.extend_from_slice(&tmp[..n]);
                            if let Some(idx) = req_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                // Parse Content-Length if present
                                let headers_str = String::from_utf8_lossy(&req_bytes[..idx + 4]);
                                for line in headers_str.lines() {
                                    if line.to_ascii_lowercase().starts_with("content-length:") {
                                        if let Some(v) = line.split(':').nth(1) { content_length = v.trim().parse::<usize>().unwrap_or(0); }
                                    }
                                }
                                // If there is a body, ensure we have all of it
                                let have_body = req_bytes.len().saturating_sub(idx + 4);
                                if content_length > have_body {
                                    let to_read = (content_length - have_body).min(64 * 1024);
                                    let mut remaining = to_read;
                                    while remaining > 0 {
                                        match stream.read(&mut tmp).await {
                                            Ok(0) => break,
                                            Ok(m) => { req_bytes.extend_from_slice(&tmp[..m]); remaining = remaining.saturating_sub(m); }
                                            Err(_) => break,
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                
                if !req_bytes.is_empty() {
                        let request = String::from_utf8_lossy(&req_bytes);
                        // Parse method and path from first line robustly
                        let mut method = String::new();
                        let mut path_full = String::new();
                        if let Some(line) = request.lines().next() {
                            let mut parts = line.split_whitespace();
                            method = parts.next().unwrap_or("").to_string();
                            path_full = parts.next().unwrap_or("").to_string();
                        }
                        println!("🌐 HTTP {} {}", method, path_full);
                        
                        // [DEBUG] Log detailed request info for debugging CORS issues
                        if path_full.contains("/api/license/expiry") {
                            println!("🔍 [DEBUG] License expiry API call detected!");
                            println!("🔍 [DEBUG] Method: {}", method);
                            println!("🔍 [DEBUG] Path: {}", path_full);
                            println!("🔍 [DEBUG] Request headers:");
                            for line in request.lines().skip(1) {
                                if line.trim().is_empty() { break; }
                                println!("🔍 [DEBUG]   {}", line);
                            }
                        }
                        
                        if request.contains("Upgrade: websocket") {
                            // Upgrade WebSocket on this same port (777)
                            // Handshake will be handled by tokio-tungstenite accept_async below
                            // We fall through; the acceptor is managed in start_ws_server
                            let response = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                            println!("⚠️ Received WS upgrade on HTTP path; WS is served by separate listener on 9777");
                        } else if path_full.starts_with("/api/license/expiry") && (method == "GET" || method == "OPTIONS") {
                            // Handle license expiry API endpoint with CORS support
                            if method == "OPTIONS" {
                                // CORS preflight response
                                let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 2\r\n\r\nOK";
                                let _ = stream.write_all(response.as_bytes()).await;
                                println!("✅ [DEBUG] CORS preflight response sent for license expiry");
                                return;
                            }
                            
                            // Handle GET request for license expiry
                            println!("🔍 [DEBUG] Processing license expiry API request...");
                            
                            // TODO: Connect to Superdatabase to get real expiry date
                            // For now, return a mock response with proper CORS headers
                            let mock_expiry_date = "2025-12-31T23:59:59Z"; // Mock expiry date
                            
                            let body = format!(
                                "{{\"success\":true,\"expiry_date\":\"{}\",\"source\":\"mock\"}}",
                                mock_expiry_date
                            );
                            
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nCache-Control: no-cache\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(), body
                            );
                            
                            let _ = stream.write_all(response.as_bytes()).await;
                            println!("✅ [DEBUG] License expiry API response sent: {}", body);
                        } else if path_full == "/state" && method == "GET" {
                            // Return current state as JSON
                            let state = {
                                let shared_state = shared_state_clone.lock().unwrap();
                                serde_json::to_string(&*shared_state).unwrap()
                            };
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                                state.len(),
                                state
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        } else if path_full.starts_with("/webhook/gift") && (method == "GET" || method == "POST" || method == "OPTIONS") {
                            // Enforce license tier: only Premium can use gift webhook
                            let tier_is_premium = {
                                let s = shared_state_clone.lock().unwrap();
                                matches!(s.license_tier, LicenseTier::Premium) || matches!(s.license_tier, LicenseTier::Kiraeve)
                            };
                            if !tier_is_premium {
                                let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                                return;
                            }
                            // Basic CORS preflight
                            if method == "OPTIONS" {
                                let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 2\r\n\r\nOK";
                                let _ = stream.write_all(response.as_bytes()).await;
                                return;
                            }
                            // Parse query string for value and op
                            let path = path_full.clone();
                            let mut delta: i32 = 0;
                            if let Some(q_idx) = path.find('?') {
                                let qs = &path[q_idx + 1..];
                                let mut value_param: Option<i32> = None;
                                let mut op_param: Option<String> = None;
                                for pair in qs.split('&') {
                                    let mut it = pair.splitn(2, '=');
                                    let k = it.next().unwrap_or("");
                                    let v = it.next().unwrap_or("");
                                    if k.eq_ignore_ascii_case("value") || k.eq_ignore_ascii_case("step") {
                                        if let Ok(parsed) = v.parse::<i32>() { value_param = Some(parsed); }
                                    } else if k.eq_ignore_ascii_case("op") || k.eq_ignore_ascii_case("operation") {
                                        op_param = Some(v.to_lowercase());
                                    }
                                }
                                let mut step = value_param.unwrap_or(1).abs().min(100000);
                                let mut is_sub = op_param.as_deref() == Some("subtract") || op_param.as_deref() == Some("sub");

                                // Also try to parse small POST body if present in the first buffer (form-encoded or JSON)
                                if method == "POST" {
                                    if let Some(bi) = request.find("\r\n\r\n") {
                                        let body = &request[bi+4..];
                                        if body.contains('=') && body.len() < 800 {
                                            // form like value=10&op=add
                                            for pair in body.split('&') {
                                                let mut it = pair.splitn(2, '=');
                                                let k = it.next().unwrap_or("");
                                                let v = it.next().unwrap_or("");
                                                if k.eq_ignore_ascii_case("value") || k.eq_ignore_ascii_case("step") {
                                                    if let Ok(parsed) = v.parse::<i32>() { step = parsed.abs().min(100000); }
                                                } else if k.eq_ignore_ascii_case("op") || k.eq_ignore_ascii_case("operation") {
                                                    is_sub = v.eq_ignore_ascii_case("subtract") || v.eq_ignore_ascii_case("sub");
                                                }
                                            }
                                        } else if body.trim_start().starts_with('{') && body.len() < 800 {
                                            // naive JSON parsing
                                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                                                if let Some(v) = json.get("value").and_then(|v| v.as_i64()) { step = (v as i32).abs().min(100000); }
                                                if let Some(opv) = json.get("op").and_then(|v| v.as_str()) { is_sub = opv.eq_ignore_ascii_case("subtract") || opv.eq_ignore_ascii_case("sub"); }
                                            }
                                        }
                                    }
                                }

                                delta = if is_sub { -step } else { step };
                            }

                            // Apply delta to win with animation support
                            let new_state_json = {
                                let (from_value, to_value) = {
                                    let mut s = shared_state_clone.lock().unwrap();
                                    let from = s.win;
                                    let new_win = (s.win + delta).max(-100000).min(100000);
                                    s.win = new_win;
                                    // Persist state to disk
                                    let p = get_state_path();
                                    save_state(&p, &s);
                                    let cloned = s.clone();
                                    drop(s);
                                    // Broadcast to websocket clients
                                    let _ = broadcast_tx_clone.send(cloned.clone());
                                    // Emit to frontend UI with only changed values
                                    let _ = app_handle_clone.emit("state-updated", cloned.clone());
                                    (from, new_win)
                                };
                                
                                // Send animation command to overlay if value changed
                                if from_value != to_value {
                                    let animation_state = WinState {
                                        overlay_data: Some(serde_json::json!({
                                            "type": "animate_win",
                                            "from": from_value,
                                            "to": to_value,
                                            "stepDelayMs": 150
                                        })),
                                        ..WinState::default()
                                    };
                                    let _ = broadcast_tx_clone.send(animation_state);
                                    println!("🎁 Webhook triggered animation: {} → {}", from_value, to_value);
                                }
                                
                                // Return the final state
                                let s = shared_state_clone.lock().unwrap();
                                serde_json::to_string(&*s).unwrap_or_else(|_| "{}".to_string())
                            };

                            let body = format!("{{\"ok\":true,\"delta\":{},\"state\":{}}}", delta, new_state_json);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(), body
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        } else if path_full.starts_with("/webhook/timer") && (method == "GET" || method == "POST" || method == "OPTIONS") {
                            debug_println!("⏰ Timer webhook endpoint called - method: {}", method);
                            // Basic CORS preflight
                            if method == "OPTIONS" {
                                let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 2\r\n\r\nOK";
                                let _ = stream.write_all(response.as_bytes()).await;
                                return;
                            }
                            // Parse query string for value and op (similar to gift webhook)
                            let path = path_full.clone();
                            let mut delta_seconds: i32 = 0;
                            if let Some(q_idx) = path.find('?') {
                                let qs = &path[q_idx + 1..];
                                let mut value_param: Option<i32> = None;
                                let mut op_param: Option<String> = None;
                                for pair in qs.split('&') {
                                    let mut it = pair.splitn(2, '=');
                                    let k = it.next().unwrap_or("");
                                    let v = it.next().unwrap_or("");
                                    if k.eq_ignore_ascii_case("value") || k.eq_ignore_ascii_case("step") {
                                        if let Ok(parsed) = v.parse::<i32>() { value_param = Some(parsed); }
                                    } else if k.eq_ignore_ascii_case("op") || k.eq_ignore_ascii_case("operation") {
                                        op_param = Some(v.to_lowercase());
                                    }
                                }
                                let mut step = value_param.unwrap_or(30).abs().min(100000); // Default 30 seconds
                                let mut is_sub = op_param.as_deref() == Some("subtract") || op_param.as_deref() == Some("sub");

                                // Also try to parse POST body if present
                                if method == "POST" {
                                    if let Some(bi) = request.find("\r\n\r\n") {
                                        let body = &request[bi+4..];
                                        if body.contains('=') && body.len() < 800 {
                                            // form like value=3600&op=add
                                            for pair in body.split('&') {
                                                let mut it = pair.splitn(2, '=');
                                                let k = it.next().unwrap_or("");
                                                let v = it.next().unwrap_or("");
                                                if k.eq_ignore_ascii_case("value") || k.eq_ignore_ascii_case("step") {
                                                    if let Ok(parsed) = v.parse::<i32>() { step = parsed.abs().min(100000); }
                                                } else if k.eq_ignore_ascii_case("op") || k.eq_ignore_ascii_case("operation") {
                                                    is_sub = v.eq_ignore_ascii_case("subtract") || v.eq_ignore_ascii_case("sub");
                                                }
                                            }
                                        } else if body.trim_start().starts_with('{') && body.len() < 800 {
                                            // naive JSON parsing
                                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                                                if let Some(v) = json.get("value").and_then(|v| v.as_i64()) { step = (v as i32).abs().min(100000); }
                                                if let Some(opv) = json.get("op").and_then(|v| v.as_str()) { is_sub = opv.eq_ignore_ascii_case("subtract") || opv.eq_ignore_ascii_case("sub"); }
                                            }
                                        }
                                    }
                                }

                                delta_seconds = if is_sub { -step } else { step };
                            }

                            debug_println!("⏰ Timer webhook - Parsed delta_seconds: {}", delta_seconds);

                            // Send timer data via broadcast to timer overlay
                            let timer_data = serde_json::json!({
                                "type": "timer_webhook",
                                "delta_seconds": delta_seconds,
                                "operation": if delta_seconds >= 0 { "add" } else { "subtract" },
                                "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                            });

                            // Create a timer-only state without affecting win/goal values
                            // ใช้ค่า win/goal จาก state ปัจจุบันแทนการสร้างใหม่
                            let current_state = {
                                let s = shared_state_clone.lock().unwrap();
                                s.clone()
                            };
                            
                            debug_println!("⏰ Timer webhook - Current state: win={}, goal={}", current_state.win, current_state.goal);
                            
                            let mut timer_state = current_state;
                            timer_state.timer_data = Some(timer_data.clone());
                            
                            debug_println!("⏰ Timer webhook - Broadcasting timer state: win={}, goal={}, has_timer_data={}", 
                                timer_state.win, timer_state.goal, timer_state.timer_data.is_some());

                            // Broadcast to WebSocket clients (including timer.html)
                            let _ = broadcast_tx_clone.send(timer_state);

                            // Also emit to frontend for timer modal updates
                            let _ = app_handle_clone.emit("timer-webhook-received", timer_data);

                            let body = format!("{{\"ok\":true,\"delta_seconds\":{},\"type\":\"timer\"}}", delta_seconds);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(), body
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        } else if request.contains("GET /overlay.html") {
                            if let Some(file) = StaticAssets::get("overlay.html") {
                                let body = file.data;
                                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\n";
                                let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                            } else {
                                let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                        } else if request.contains("GET /challange.html") {
                            if let Some(file) = StaticAssets::get("challange.html") {
                                let body = file.data;
                                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\n";
                                let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                            } else {
                                let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                        } else if path_full.starts_with("/challenge/get") && method == "GET" {
                            // Prefer state.challenge_message
                            let msg = {
                                let s = shared_state_clone.lock().unwrap();
                                if !s.challenge_message.is_empty() { s.challenge_message.clone() } else { challenge_msg_clone.lock().unwrap().clone() }
                            };
                            let body = format!("{{\"message\":{}}}", serde_json::to_string(&msg).unwrap_or_else(|_| "\"\"".to_string()));
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(), body
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        } else if (path_full.starts_with("/challenge/set") && (method == "GET" || method == "POST")) || (method == "OPTIONS" && path_full.starts_with("/challenge/")) {
                            if method == "OPTIONS" {
                                let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 2\r\n\r\nOK";
                                let _ = stream.write_all(response.as_bytes()).await; return; }
                            let mut new_msg: Option<String> = None;
                            if let Some(qi) = path_full.find('?') {
                                let qs = &path_full[qi+1..];
                                for pair in qs.split('&') { let mut it = pair.splitn(2,'='); let k = it.next().unwrap_or(""); let v = it.next().unwrap_or(""); if k.eq_ignore_ascii_case("text") || k.eq_ignore_ascii_case("message") { new_msg = Some(percent_decode(v)); } }
                            }
                            if new_msg.is_none() && method == "POST" {
                                if let Some(bi) = request.find("\r\n\r\n") { let body = &request[bi+4..]; if body.contains('=') { let params: Vec<&str> = body.split('&').collect(); for p in params { let mut it = p.splitn(2,'='); let k = it.next().unwrap_or(""); let v = it.next().unwrap_or(""); if k.eq_ignore_ascii_case("text") || k.eq_ignore_ascii_case("message") { new_msg = Some(percent_decode(v)); } } } else if body.trim_start().starts_with('{') { if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) { if let Some(t) = json.get("text").and_then(|v| v.as_str()).or_else(|| json.get("message").and_then(|v| v.as_str())) { new_msg = Some(t.to_string()); } } } }
                            }
                            if let Some(m) = new_msg { 
                                // Save to state so it persists and broadcasts
                                let cloned_state = {
                                    let mut s = shared_state_clone.lock().unwrap();
                                    s.challenge_message = m.clone();
                                    let p = get_state_path();
                                    save_state(&p, &s);
                                    s.clone()
                                };
                                *challenge_msg_clone.lock().unwrap() = m.clone();
                                let _ = app_handle_clone.emit("challenge-updated", m.clone());
                                // Broadcast to WS clients so challange.html updates instantly
                                let _ = broadcast_tx_clone.send(cloned_state);
                            }
                            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: 15\r\n\r\n{\"ok\":true}"; let _ = stream.write_all(response.as_bytes()).await;
                        } else if request.contains("GET /message.html") {
                            // Simple message box overlay (for challenge messages)
                            let html = r#"<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><title>Message</title><style>html,body{background:transparent;margin:0;padding:0;overflow:hidden} .box{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);padding:24px 32px;border-radius:16px;border:3px solid rgba(0,255,255,.7);box-shadow:0 0 24px rgba(0,255,255,.25);color:#fff;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:rgba(5,10,25,.65);}</style></head><body><div class=\"box\" id=\"msg\">Ready</div><script>const ws=new WebSocket('ws://localhost:9777');ws.onmessage=(e)=>{try{const d=JSON.parse(e.data);if(d.message){document.getElementById('msg').textContent=d.message;}}catch{}}</script></body></html>"#;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                                html.len(), html
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        } else if request.contains("GET /assets/") {
                            // Serve /assets/* from static/assets/*
                            if let Some(start) = request.find("GET /assets/") {
                                let rest = &request[start + 4..]; // after "GET "
                                let mut parts = rest.split_whitespace();
                                if let Some(path) = parts.next() {
                                    let rel_in_assets = path.trim_start_matches('/');
                                    let static_key = rel_in_assets; // e.g., assets/ui/crown.png
                                    if let Some(file) = StaticAssets::get(static_key) {
                                        let rel = rel_in_assets.trim_start_matches("assets/");
                                        let content_type = if rel.ends_with(".png") { "image/png" }
                                            else if rel.ends_with(".jpg") || rel.ends_with(".jpeg") { "image/jpeg" }
                                            else if rel.ends_with(".gif") { "image/gif" }
                                            else if rel.ends_with(".svg") { "image/svg+xml" }
                                            else if rel.ends_with(".ttf") { "font/ttf" }
                                            else if rel.ends_with(".css") { "text/css" }
                                            else if rel.ends_with(".mp3") { "audio/mpeg" }
                                            else { "application/octet-stream" };
                                        let body = file.data;
                                        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nCache-Control: no-cache\r\n", content_type);
                                        let response = format!("{}Content-Length: {}\r\n\r\n", headers, body.len());
                                        let _ = stream.write_all(response.as_bytes()).await;
                                        let _ = stream.write_all(&body).await;
                                    } else {
                                        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                                        let _ = stream.write_all(response.as_bytes()).await;
                                    }
                                }
                            }
                        } else if request.contains("GET /favicon.png") {
                            let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            } else {
                            let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            }
                        }
            });
        }

        // In parallel, start a minimal HTTP server on port 7777 for challange.html
        // (Already started above before the accept loop)
        });
    });
}

pub fn start_ws_server(shared_state: Arc<Mutex<WinState>>, broadcast_tx: broadcast::Sender<WinState>, app_handle: tauri::AppHandle) {
    println!("🚀 Starting WebSocket server on 127.0.0.1:9777...");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
        let addr = "127.0.0.1:9777";
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                println!("🔌 WebSocket server listening on {}", addr);
                l
            },
            Err(e) => {
                println!("❌ Failed to bind WebSocket server to {}: {}", addr, e);
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let shared_state_clone = shared_state.clone();
                    let broadcast_tx_clone = broadcast_tx.clone();
                    let mut rx = broadcast_tx.subscribe();
                    let app_handle_clone = app_handle.clone();
                    tokio::spawn(async move {
                        // Complete WebSocket handshake using tokio-tungstenite
                        let ws_stream = match accept_async(stream).await {
                            Ok(ws) => ws,
                            Err(e) => {
                                println!("❌ WS handshake failed: {}", e);
                                return;
                            }
                        };

                        println!("✅ WebSocket client connected");
                        let (mut writer, mut reader) = ws_stream.split();

                        // Create channel for sending messages to writer
                        let (tx, mut rx_send) = tokio::sync::mpsc::channel::<String>(100);

                        // Send initial state immediately
                        let initial_json = {
                            let guard = shared_state_clone.lock().unwrap();
                            serde_json::to_string(&*guard).unwrap_or_else(|_| "{}".to_string())
                        };
                        if let Err(e) = writer.send(Message::Text(initial_json)).await { 
                            println!("❌ WS initial send failed: {}", e); 
                        }

                        // Forward broadcast updates to this client
                        let tx_clone = tx.clone();
                        let forward_task = tokio::spawn(async move {
                            while let Ok(state) = rx.recv().await {
                                // Only log in debug mode to reduce spam
                                #[cfg(debug_assertions)]
                                {
                                    println!("🎨 Broadcasting state - win: {}, goal: {}, icon_path: {}, has_timer_data: {}", 
                                        state.win, state.goal, state.icon_path, state.timer_data.is_some());
                                }
                                if let Ok(text) = serde_json::to_string(&state) {
                                    if let Err(e) = tx_clone.send(text).await {
                                        // Only log in debug mode to reduce spam
                                        #[cfg(debug_assertions)]
                                        {
                                            println!("⚠️ WS channel send error: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                        });

                        // Handle incoming messages from client
                        let tx_clone2 = tx.clone();
                        let read_task = tokio::spawn(async move {
                            while let Some(msg) = reader.next().await {
                                match msg {
                                    Ok(Message::Close(_)) => break,
                                    Ok(Message::Text(text)) => {
                                        // Handle client messages
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                            if let Some(msg_type) = json.get("type").and_then(|v| v.as_str()) {
                                                match msg_type {
                                                    "request_state" => {
                                                        // Send current state to client
                                                        let current_state = {
                                                            let guard = shared_state_clone.lock().unwrap();
                                                            serde_json::to_string(&*guard).unwrap_or_else(|_| "{}".to_string())
                                                        };
                                                        if let Err(e) = tx_clone2.send(current_state).await {
                                                            println!("❌ WS state response failed: {}", e);
                                                        }
                                                    }
                                                    "play_sound" => {
                                                        // Handle sound trigger from overlay
                                                        if let Some(direction) = json.get("direction").and_then(|v| v.as_str()) {
                                                                                                                    let event_name = match direction {
                                                            "increase" => "play-increase-sound",
                                                            "decrease" => "play-decrease-sound",
                                                            _ => return,
                                                        };
                                                        let _ = app_handle_clone.emit(event_name, ());
                                                        }
                                                    }
                                                    "reset_state" => {
                                                        // Reset state to defaults
                                                        if let Some(reset_data) = json.get("data") {
                                                            let mut guard = shared_state_clone.lock().unwrap();
                                                            if let Ok(reset_state) = serde_json::from_value::<crate::state::WinState>(reset_data.clone()) {
                                                                *guard = reset_state;
                                                                println!("🔄 State reset to defaults");
                                                                
                                                                // Broadcast the reset state
                                                                let _ = broadcast_tx_clone.send(guard.clone());
                                                            }
                                                        }
                                                    }
                                                    _ => { /* ignore other message types */ }
                                                }
                                            }
                                        }
                                    }
                                    Ok(_) => { /* ignore other message types */ }
                                    Err(e) => { println!("⚠️ WS read error: {}", e); break; }
                                }
                            }
                        });

                        // Writer task - sends messages from channel to WebSocket
                        let writer_task = tokio::spawn(async move {
                            while let Some(text) = rx_send.recv().await {
                                if let Err(e) = writer.send(Message::Text(text)).await {
                                    // Only log in debug mode to reduce spam
                                    #[cfg(debug_assertions)]
                                    {
                                        println!("⚠️ WS send error (client likely disconnected): {}", e);
                                    }
                                    break;
                                }
                            }
                        });

                        let _ = tokio::join!(forward_task, read_task, writer_task);
                        // Only log in debug mode to reduce spam
                        #[cfg(debug_assertions)]
                        {
                            println!("🔌 WebSocket client disconnected");
                        }
                    });
                },
                Err(e) => {
                    println!("❌ Failed to accept WS connection: {}", e);
                }
            }
        }
        });
    });
    println!("✅ WebSocket server setup complete");
}



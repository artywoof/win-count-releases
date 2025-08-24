// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unused_imports, dead_code, unused_variables, unreachable_code, static_mut_refs)]

// Macro to conditionally print only in debug mode
macro_rules! debug_println {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}

// Module declarations
mod server;
mod state;
mod hotkeys;
mod storage;
mod security_protection;

// Anti-Debugging: Block debug builds in production
// Debug build protection disabled for development
// #[cfg(debug_assertions)]
// compile_error!("Debug builds not allowed for production - use release build only");

use serde::{Deserialize, Serialize};
use rust_embed::RustEmbed;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tauri::{State, Emitter, Manager, LogicalSize, Size, menu::{MenuBuilder, MenuItemBuilder}};
use tauri_plugin_global_shortcut::GlobalShortcutExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::broadcast;
use futures_util::{StreamExt, SinkExt};
use tokio::runtime::Runtime;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::accept_async;
use serde_json;
use std::env;
use dotenv::dotenv;
use sha2::{Digest, Sha256 as Sha256Hasher};
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, generic_array::GenericArray, generic_array::typenum::U12}};
use chrono::{Utc, DateTime, TimeZone, FixedOffset};
use std::fs::File;
use std::io::{Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::atomic::AtomicBool;

// Use the new modules
use state::{WinState, SharedWinState, KeyTrackerMap, KeyEventTracker, PresetData, HotkeyConfig, UpdateInfo, LicenseTier, get_state_path, save_state, load_state};
use security_protection::{SecurityManager, secure_license_validation};
use server::{start_http_server, start_ws_server};
use hotkeys::{update_hotkey, reload_hotkeys_command, reload_hotkeys, register_hotkeys_dynamically, 
              convert_hotkey_format, load_custom_hotkeys, save_custom_hotkeys, clear_hotkeys, 
              save_default_hotkeys, check_hotkey_file};
use storage::{save_preset, load_presets, load_preset, delete_preset, rename_preset,
              save_custom_sound, get_custom_sound_path, delete_custom_sound, read_sound_file, 
              get_custom_sound_filename, list_custom_sounds, set_active_custom_sound, delete_specific_custom_sound, clear_active_custom_sound,
              set_custom_icon, get_custom_icon, clear_custom_icon,
              add_custom_icon, get_custom_icons, get_custom_icon_by_id, delete_custom_icon, CustomIcon};
// Updater commands are now handled by tauri-plugin-updater
use tauri::AppHandle as _;
use winreg::enums::*;
use winreg::RegKey;

// Embedded static assets (overlay.html, /assets/*) compiled into the binary
#[derive(RustEmbed)]
#[folder = "../static"]
struct EmbeddedAssets;

// PromptPay module removed - using promptpay.io instead

// Notification function
#[tauri::command]
async fn send_notification(title: String, message: String, app: tauri::AppHandle) -> Result<(), String> {
    match app.notification()
        .builder()
        .title(&title)
        .body(&message)
        .show() {
        Ok(_) => {
            #[cfg(debug_assertions)]
            debug_println!("🔔 Notification sent: {} - {}", title, message);
            Ok(())
        },
        Err(e) => {
            #[cfg(debug_assertions)]
            debug_println!("❌ Failed to send notification: {}", e);
            Err(format!("Failed to send notification: {}", e))
        }
    }
}

// License system removed

// ===== Timezone Conversion Functions =====
#[tauri::command]
fn convert_utc_to_bangkok(utc_timestamp: i64) -> Result<String, String> {
    // Bangkok timezone is UTC+7
    let bangkok_offset = FixedOffset::east_opt(7 * 3600).unwrap();
    
    // Convert UTC timestamp to Bangkok time
    let utc_datetime = Utc.timestamp_opt(utc_timestamp, 0)
        .single()
        .ok_or("Invalid timestamp")?;
    
    let bangkok_datetime = utc_datetime.with_timezone(&bangkok_offset);
    
    // Format as readable string
    let formatted = bangkok_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    
    #[cfg(debug_assertions)]
    debug_println!("🕐 UTC {} -> Bangkok {}", utc_timestamp, formatted);
    
    Ok(formatted)
}

#[tauri::command]
fn get_current_bangkok_time() -> Result<String, String> {
    let bangkok_offset = FixedOffset::east_opt(7 * 3600).unwrap();
    let bangkok_now = Utc::now().with_timezone(&bangkok_offset);
    
    let formatted = bangkok_now.format("%Y-%m-%d %H:%M:%S").to_string();
    
    #[cfg(debug_assertions)]
    debug_println!("🕐 Current Bangkok time: {}", formatted);
    
    Ok(formatted)
}

// ===== Auto-Backup System =====
#[tauri::command]
async fn auto_backup_license() -> Result<String, String> {
    // Auto-backup by copying the current license file
    if let Ok(app_data_dir) = get_app_data_dir() {
        let license_file = app_data_dir.join("win_count_license.json");
        let backup_file = app_data_dir.join("win_count_license.backup.json");
        let backup_file2 = app_data_dir.join("license_backup.json");
        
        if license_file.exists() {
            // Copy to backup locations
            if let Ok(contents) = fs::read_to_string(&license_file) {
                let _ = fs::write(&backup_file, &contents);
                let _ = fs::write(&backup_file2, &contents);
                debug_println!("✅ Auto-backup created successfully");
                return Ok("Auto-backup created".to_string());
            }
        }
    }
    
    Err("Failed to create auto-backup".to_string())
}

#[tauri::command]
async fn create_directory(path: String) -> Result<(), String> {
    // Create directory recursively
    std::fs::create_dir_all(&path).map_err(|e| format!("Failed to create directory: {}", e))?;
    Ok(())
}

#[tauri::command]
async fn open_devtools(app: tauri::AppHandle) -> Result<(), String> {
    // Open DevTools for the main window
    if let Some(window) = app.webview_windows().values().next() {
        // In Tauri v2, DevTools are controlled by the devtools flag in tauri.conf.json
        // The window will automatically show DevTools when devtools: true is set
        debug_println!("✅ DevTools should be available (F12 or Ctrl+Shift+I)");
        Ok(())
    } else {
        Err("No window found".to_string())
    }
}



// ===== Secure storage helpers (AES-GCM with machine-bound key) =====
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
const _DUMMY_VAR_1: u32 = 0xdeadbeef;
const _DUMMY_VAR_2: u32 = 0xcafebabe;
const _DUMMY_VAR_3: u32 = 0x12345678;
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
fn crypto_secret() -> String {
    std::env::var("LICENSE_CRYPTO_SECRET").unwrap_or_else(|_| "WINCOUNT_DEFAULT_SECRET".to_string())
}

fn derive_aes_key(machine_id: &str) -> [u8; 32] {
    let secret = crypto_secret();
    let mut hasher: Sha256Hasher = Default::default();
    hasher.update(machine_id.as_bytes());
    hasher.update(":".as_bytes());
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn encrypt_for_machine(plaintext: &str, machine_id: &str) -> Result<String, String> {
    let key_bytes = derive_aes_key(machine_id);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("cipher init error: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce error: {}", e))?;
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|e| format!("encrypt error: {}", e))?;
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(combined))
}

fn decrypt_for_machine(b64: &str, machine_id: &str) -> Result<String, String> {
    let data = general_purpose::STANDARD.decode(b64).map_err(|e| format!("base64 error: {}", e))?;
    if data.len() < 13 { return Err("cipher too short".into()); }
    let (nonce_bytes, ct) = data.split_at(12);
    let key_bytes = derive_aes_key(machine_id);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("cipher init error: {}", e))?;
    let nonce = GenericArray::<u8, U12>::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ct).map_err(|e| format!("decrypt error: {}", e))?;
    String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {}", e))
}

#[cfg(windows)]
use winapi::um::winuser::{GetAsyncKeyState, VK_MENU, VK_OEM_PLUS, VK_OEM_MINUS, VK_SHIFT, VK_ADD, VK_SUBTRACT};

// Function to get safe app data directory
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security constants for obfuscation
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security constants for obfuscation
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security obfuscation layer active
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security constants removed for compilation
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security constants removed for compilation
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security constants removed for compilation
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Security obfuscation active
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Dummy variable removed
// Dummy variable removed
// Dummy variable removed
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification
// Dummy variable removed
// Dummy variable removed
// Dummy variable removed
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification

// Dummy variable removed
// Dummy variable removed
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification


// Dummy variable removed
// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification



// Obfuscated code - do not modify
// Security layer 1
// Anti-tamper protection
// License validation system
// Heartbeat monitoring
// Machine ID verification



fn get_app_data_dir() -> Result<PathBuf, String> {
    // Unified to %APPDATA%\WinCount on Windows (and platform equivalents)
    #[cfg(target_os = "windows")]
    {
        let roaming = std::env::var("APPDATA").map_err(|_| "APPDATA not found".to_string())?;
        let unified = PathBuf::from(roaming).join("WinCount");
        if !unified.exists() { fs::create_dir_all(&unified).map_err(|e| format!("Failed to create app data directory: {}", e))?; }

        // One-time migration from older path: LocalAppData\Win Count by ArtYWoof
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let old = PathBuf::from(local).join("Win Count by ArtYWoof");
            if old.exists() {
                // Move known subfolders/files
                let items = [
                    ("win_state.json", unified.join("win_state.json")),
                    ("win_count_state.json", unified.join("win_count_state.json")),
                    ("win_count_presets.json", unified.join("win_count_presets.json")),
                    ("presets", unified.join("presets")),
                    ("sounds", unified.join("sounds")),
                    ("custom_hotkeys.json", unified.join("custom_hotkeys.json")),
                    ("win_count_license.json", unified.join("win_count_license.json")),
                ];
                for (name, dst) in items.iter() {
                    let src = old.join(name);
                    if src.exists() && !dst.exists() {
                        let _ = fs::create_dir_all(dst.parent().unwrap_or(&unified));
                        let _ = fs::rename(&src, &dst);
                    }
                }
            }
        }
        return Ok(unified);
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not found".to_string())?;
        let unified = PathBuf::from(home).join("Library/Application Support/WinCount");
        if !unified.exists() { fs::create_dir_all(&unified).map_err(|e| format!("Failed to create app data directory: {}", e))?; }
        return Ok(unified);
    }

    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not found".to_string())?;
        let unified = PathBuf::from(home).join(".config/WinCount");
        if !unified.exists() { fs::create_dir_all(&unified).map_err(|e| format!("Failed to create app data directory: {}", e))?; }
        return Ok(unified);
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported operating system".to_string())
    }
}

// Function to get file path in app data directory
fn get_app_data_file(filename: &str) -> Result<PathBuf, String> {
    let app_data_dir = get_app_data_dir()?;
    Ok(app_data_dir.join(filename))
}

// Function to clear license cache
fn clear_license_cache() {
    unsafe {
        LAST_LICENSE_CHECK = None;
        CACHED_LICENSE_VALID = None;
    }
    debug_println!("[CACHE] License cache cleared");
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> Result<String, String> {
    // Temporarily bypass license gate during development
    Ok(format!("Hello, {}! You've been greeted from Rust!", name))
}

#[tauri::command]
fn get_app_version() -> Result<String, String> {
    // Temporarily bypass license gate during development
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

#[tauri::command]
async fn get_license_tier(state: State<'_, SharedWinState>) -> Result<String, String> {
    // เพียงแค่คืนค่า tier ปัจจุบันจาก state
    // การตรวจสอบจริงจะทำใน a1b2c3d4 และ h3a2r1t
    let s = state.lock().map_err(|e| e.to_string())?;
    let tier = match s.license_tier {
        LicenseTier::Premium => "premium",
        LicenseTier::Kiraeve => "kiraeve",
        LicenseTier::Pro => "pro",
        LicenseTier::Test => "test",
        LicenseTier::Free => "free",
    };
    #[cfg(debug_assertions)]
    debug_println!("📊 Current license tier: {}", tier);
    Ok(tier.to_string())
}

#[tauri::command]
fn get_license_expiry() -> Result<String, String> {
    // ดึงวันหมดอายุจาก license key ที่บันทึกไว้
    // ใช้เป็น fallback เมื่อ API ไม่ทำงาน
    if let Ok(app_data_dir) = get_app_data_dir() {
        let license_file = app_data_dir.join("win_count_license.json");
        if let Ok(contents) = fs::read_to_string(&license_file) {
            if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(expiry) = license_data.get("expires_at") {
                    if let Some(expiry_str) = expiry.as_str() {
                        return Ok(expiry_str.to_string());
                    }
                }
            }
        }
    }
    
    // ถ้าไม่มีข้อมูล ให้คืนค่าว่าง
    Ok("".to_string())
}

// Auto-backup system - manual backup functions removed

#[tauri::command]
async fn check_and_update_license_tier(state: State<'_, SharedWinState>) -> Result<String, String> {
    // ตรวจสอบ license และอัพเดท tier พร้อม grace period
    #[cfg(debug_assertions)]
    debug_println!("🔄 ตรวจสอบและอัพเดท License Tier...");
    
    // ตรวจสอบ tier ปัจจุบันก่อน
    let current_tier = {
        let s = state.lock().map_err(|e| e.to_string())?;
        match s.license_tier {
            LicenseTier::Premium => "premium",
            LicenseTier::Kiraeve => "kiraeve",
            LicenseTier::Pro => "pro",
            LicenseTier::Test => "test",
            LicenseTier::Free => "free",
        }
    };
    
    // ถ้าเป็น free อยู่แล้ว แต่ยังต้องเช็คว่ามี license file อยู่หรือไม่
    if current_tier == "free" {
        #[cfg(debug_assertions)]
        debug_println!("📊 Currently free tier, but checking for license file...");
        // ยังต้องเรียก h3a2r1t() เพื่อเช็ค license file
    }
    
    // 🔧 ลองอัพเดท Machine ID ก่อนตรวจสอบ license (ถ้าเป็น Temporary)
    // ต้องอ่าน license file ก่อนเพื่อดู license key
    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
        if std::path::Path::new(&license_path).exists() {
            if let Ok(file_content) = fs::read_to_string(&license_path) {
                if let Ok(machine_id) = m4c5h6n() {
                    let json_text = if file_content.trim_start().starts_with('{') {
                        file_content
                    } else {
                        decrypt_for_machine(&file_content, &machine_id).unwrap_or_default()
                    };
                    
                    if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                        if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                            #[cfg(debug_assertions)]
                            debug_println!("🔧 Attempting to update machine ID for license: {}", license_key);
                            match update_machine_id_from_temporary(license_key.to_string()).await {
                                Ok(updated_id) => {
                                    #[cfg(debug_assertions)]
                                    debug_println!("✅ Machine ID update successful: {}", updated_id);
                                },
                                Err(e) => {
                                    #[cfg(debug_assertions)]
                                    debug_println!("⚠️ Machine ID update failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // เรียก h3a2r1t เพื่อตรวจสอบ license
    #[cfg(debug_assertions)]
    debug_println!("[DEBUG] Calling h3a2r1t() from check_and_update_license_tier");
    match h3a2r1t().await {
        Ok(is_valid) => {
            if !is_valid {
                // License หมดอายุ ให้เปลี่ยนเป็น Free
                #[cfg(debug_assertions)]
                debug_println!("⏰ License expired, updating tier to free");
                let mut s = state.lock().map_err(|e| e.to_string())?;
                s.license_tier = LicenseTier::Free;
                Ok("free".to_string())
            } else {
                // License valid - ตรวจสอบ package type และอัพเดท tier ตามนั้น
                if current_tier == "free" {
                    // ตรวจสอบ license key prefix เพื่อกำหนด tier
                    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
                        if let Ok(license_content) = fs::read_to_string(&license_path) {
                            let json_text = if license_content.trim_start().starts_with('{') {
                                license_content
                            } else {
                                match decrypt_for_machine(&license_content, &m4c5h6n().unwrap_or_default()) {
                                    Ok(txt) => txt,
                                    Err(_) => return Ok("free".to_string()),
                                }
                            };
                            
                            if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                                if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                                    let key = license_key.trim().to_uppercase();
                                    
                                    // กำหนด tier ตาม package type
                                    let new_tier = if key.starts_with("TEST-") {
                                        #[cfg(debug_assertions)]
                                        debug_println!("✅ TEST license detected, updating tier to test");
                                        LicenseTier::Test
                                    } else if key.starts_with("PRO-") {
                                        #[cfg(debug_assertions)]
                                        debug_println!("✅ PRO license detected, updating tier to pro");
                                        LicenseTier::Pro
                                    } else if key.starts_with("PREMIUM-") {
                                        #[cfg(debug_assertions)]
                                        debug_println!("✅ PREMIUM license detected, updating tier to premium");
                                        LicenseTier::Premium
                                    } else if key.starts_with("KIRAEVE-") {
                                        #[cfg(debug_assertions)]
                                        debug_println!("✅ KIRAEVE license detected, updating tier to kiraeve");
                                        LicenseTier::Kiraeve
                                    } else {
                                        #[cfg(debug_assertions)]
                                        debug_println!("✅ Unknown license type, defaulting to premium");
                                        LicenseTier::Premium
                                    };
                                    
                                    let mut s = state.lock().map_err(|e| e.to_string())?;
                                    s.license_tier = new_tier.clone();
                                    
                                    let tier_string = match new_tier {
                                        LicenseTier::Test => "test",
                                        LicenseTier::Pro => "pro",
                                        LicenseTier::Premium => "premium",
                                        LicenseTier::Kiraeve => "kiraeve",
                                        _ => "free",
                                    };
                                    
                                    Ok(tier_string.to_string())
                                } else {
                                    #[cfg(debug_assertions)]
                                    debug_println!("✅ License valid but no key found, defaulting to premium");
                                    let mut s = state.lock().map_err(|e| e.to_string())?;
                                    s.license_tier = LicenseTier::Premium;
                                    Ok("premium".to_string())
                                }
                            } else {
                                #[cfg(debug_assertions)]
                                debug_println!("✅ License valid but JSON parse failed, defaulting to premium");
                                let mut s = state.lock().map_err(|e| e.to_string())?;
                                s.license_tier = LicenseTier::Premium;
                                Ok("premium".to_string())
                            }
                        } else {
                            #[cfg(debug_assertions)]
                            debug_println!("✅ License valid but file read failed, defaulting to premium");
                            let mut s = state.lock().map_err(|e| e.to_string())?;
                            s.license_tier = LicenseTier::Premium;
                            Ok("premium".to_string())
                        }
                    } else {
                        #[cfg(debug_assertions)]
                        debug_println!("✅ License valid but no license file, defaulting to premium");
                        let mut s = state.lock().map_err(|e| e.to_string())?;
                        s.license_tier = LicenseTier::Premium;
                        Ok("premium".to_string())
                    }
                } else {
                    #[cfg(debug_assertions)]
                    debug_println!("✅ License still valid, tier: {}", current_tier);
                    Ok(current_tier.to_string())
                }
            }
        },
        Err(e) => {
            #[cfg(debug_assertions)]
            debug_println!("❌ License check failed: {}, but keeping current tier for now", e);
            // ไม่เปลี่ยน tier ทันที ให้ grace period
            Ok(current_tier.to_string())
        }
    }
}



#[tauri::command]
fn set_license_tier(state: State<'_, SharedWinState>, tier: String) -> Result<(), String> {
    // Internal/admin/testing helper to set tier; in production tie to license payload
    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.license_tier = match tier.as_str() {
        "premium" => LicenseTier::Premium,
        "kiraeve" => LicenseTier::Kiraeve,
        "pro" => LicenseTier::Pro,
        "test" => LicenseTier::Test,
        _ => LicenseTier::Free,
    };
    Ok(())
}

// Enhanced License Key Validation Function
#[tauri::command]
async fn a1b2c3d4(
    license_key: String,
    state: State<'_, SharedWinState>,
) -> Result<bool, String> {
    #[cfg(debug_assertions)]
    debug_println!("🔑 Validating license key: {}", license_key);

    // 1) Enhanced format validation
    let key = license_key.trim().to_uppercase();
    
    // Check basic format (FREE ไม่ต้องใช้ License Key)
    let valid_formats = regex::Regex::new(r"^(PRO|PREMIUM|KIRAEVE|TEST)-[A-Z0-9]+-[A-Z0-9]+$")
        .map_err(|_| "Regex compilation failed".to_string())?;
    
    if !valid_formats.is_match(&key) {
        #[cfg(debug_assertions)]
        debug_println!("[LICENSE] Invalid format (expecting PRO-XXXX-XXXX, PREMIUM-XXXX-XXXX, KIRAEVE-XXXX-XXXX, or TEST-XXXX-XXXX)");
        return Ok(false);
    }
    
    // Check length constraints (PRO = 13, TEST = 14, PREMIUM/KIRAEVE = 17)
    if key.len() < 13 || key.len() > 17 {
        #[cfg(debug_assertions)]
        debug_println!("[LICENSE] Invalid length: {} (expected 13-17)", key.len());
        return Ok(false);
    }
    
    // Check for obviously invalid patterns
    if key.contains("TEST-TEST") || key.contains("SAMPLE") || key.contains("DEMO") {
        #[cfg(debug_assertions)]
        debug_println!("[LICENSE] Demo/test pattern detected");
        return Ok(false);
    }

    // 2) Remote validation with enhanced error handling
    let machine_id = m4c5h6n()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Win-Count-License-Validator/1.0")
        .build()
        .map_err(|e| format!("HTTP client creation failed: {}", e))?;
    
    let url = format!("{}/verify-license", license_server_url());
    
    let verify_data = serde_json::json!({
        "license_key": key,
        "machine_id": machine_id,
        "timestamp": chrono::Utc::now().timestamp(),
        "app_version": env!("CARGO_PKG_VERSION")
    });
    
    #[cfg(debug_assertions)]
    debug_println!("[LICENSE] Sending verification request to: {}", url);
    
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&verify_data)
        .send()
        .await
        .map_err(|e| {
            #[cfg(debug_assertions)]
            debug_println!("❌ Network error during license verification: {}", e);
            format!("Network error - please check your internet connection: {}", e)
        })?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    
    #[cfg(debug_assertions)]
    debug_println!("[LICENSE] Server response: {} - {}", status, body);
    
    if status.is_success() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(success) = json.get("success").and_then(|v| v.as_bool()) {
                if success {
                    // อัปเดท tier จาก API response
                    if let Some(tier) = json.get("tier").and_then(|v| v.as_str()) {
                        let mut s = state.lock().map_err(|e| e.to_string())?;
                        s.license_tier = match tier.to_lowercase().as_str() {
                            "premium" => LicenseTier::Premium,
                            "pro" => LicenseTier::Pro,
                            "test" => LicenseTier::Test,
                            "kiraeve" => LicenseTier::Kiraeve,
                            _ => LicenseTier::Free,
                        };
                        #[cfg(debug_assertions)]
                        debug_println!("✅ License validation successful, tier updated to: {}", tier);
                    } else {
                        #[cfg(debug_assertions)]
                        debug_println!("✅ License validation successful, but no tier info");
                    }
                    return Ok(true);
                } else {
                    let reason = json.get("reason").and_then(|v| v.as_str()).unwrap_or("unknown");
                    #[cfg(debug_assertions)]
                    debug_println!("❌ License validation failed: {}", reason);
                    return Ok(false);
                }
            }
        }
    }
    
    #[cfg(debug_assertions)]
    debug_println!("❌ License validation failed: Invalid server response");
    Ok(false)
}

// License management functions
// License Server URLs - รองรับ Multiple Fallback Servers 🚀
fn get_license_server_urls() -> Vec<String> {
    let primary_url = std::env::var("L1C3NS3_S3RV3R")
        .unwrap_or_else(|_| "https://win-count-by-artywoof.vercel.app/api".to_string());

    // 🛡️ Production Servers - ไม่ต้องรัน server เอง!
    let backup_servers = vec![
        "https://win-count-by-artywoof.vercel.app/api".to_string(),  // Vercel (Primary) - ใช้งานจริง
        "https://win-count-license.vercel.app".to_string(),      // Vercel (Backup)
        "https://license.win-count.app".to_string(),             // Custom Domain (Future)
    ];

    // ใช้ Vercel API ทั้งใน development และ production
    let mut servers = vec![primary_url];
    servers.extend(backup_servers);
    servers.into_iter().filter(|url| url.starts_with("https://")).collect()
}

// เก็บไว้เพื่อ backward compatibility
fn license_server_url() -> String {
    get_license_server_urls().into_iter().next()
        .unwrap_or_else(|| "https://win-count-license.vercel.app".to_string())
}

// License validation function - DISABLED (Free for everyone)
fn x7y9z2() -> bool {
    // Always return true - no license validation needed
    return true;
    
    // OLD CODE DISABLED:
    /*
    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
        if let Ok(file_content) = fs::read_to_string(&license_path) {
            // decrypt if needed
            let machine_id_for_dec = m4c5h6n().ok();
            let json_text = if file_content.trim_start().starts_with('{') {
                file_content
            } else if let Some(mid) = machine_id_for_dec {
                match decrypt_for_machine(&file_content, &mid) {
                    Ok(txt) => txt,
                    Err(e) => { debug_println!("[SECURITY] decrypt failed: {}", e); return false; }
                }
            } else {
                return false;
            };
            if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                    // Enhanced validation - check with server
                    if let Ok(machine_id) = m4c5h6n() {
                        // Create a blocking runtime for synchronous validation
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        let result = rt.block_on(async {
                            let client = reqwest::Client::new();
                            let url = format!("{}/verify-license", license_server_url());
                            if !url.starts_with("https://") {
                                #[cfg(not(debug_assertions))]
                                {
                                    debug_println!("[SECURITY] License server URL is not HTTPS!");
                                    return false;
                                }
                                #[cfg(debug_assertions)]
                                {
                                    debug_println!("[SECURITY] License server URL is not HTTPS (dev allowed)");
                                }
                            }
                            let response = client
                                .post(&url)
                                .header("Content-Type", "application/json")
                                .json(&serde_json::json!({
                                    "license_key": license_key,
                                    "machine_id": machine_id,
                                }))
                                .send()
                                .await;
                            match response {
                                Ok(resp) => {
                                    let status = resp.status();
                                    let body = resp.text().await.unwrap_or_default();
                                    debug_println!("[SECURITY] License server response: {} - {}", status, body);
                                    if status.is_success() {
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                            if let Some(success) = json.get("success").and_then(|v| v.as_bool()) {
                                                return success;
                                            }
                                        }
                                    }
                                                                    // ถ้า response ไม่ success
                                debug_println!("[SECURITY] License server returned error status: {}", status);
                                // Activate Grace Period สำหรับ offline users
                                GR4C3_P3R10D.store(true, Ordering::SeqCst);
                                unsafe { GRACE_PERIOD_START = Some(Utc::now()); }
                                return false;
                                }
                                Err(e) => {
                                    debug_println!("[SECURITY] Network error: {}", e);
                                    // Activate Grace Period สำหรับ offline users
                                    GR4C3_P3R10D.store(true, Ordering::SeqCst);
                                    unsafe { GRACE_PERIOD_START = Some(Utc::now()); }
                                    return false;
                                }
                            }
                        });
                        return result;
                    }
                }
            }
        }
    }
    false
    */
}

#[tauri::command]
fn get_license_key() -> Result<Option<String>, String> {
    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
        if let Ok(file_content) = fs::read_to_string(&license_path) {
            if let Ok(mid) = m4c5h6n() {
                let json_text = if file_content.trim_start().starts_with('{') {
                    file_content
                } else {
                    match decrypt_for_machine(&file_content, &mid) {
                        Ok(txt) => txt,
                        Err(_) => return Ok(None),
                    }
                };
                if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                    if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                        return Ok(Some(license_key.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

#[tauri::command]
fn remove_license_key() -> Result<(), String> {
    let license_path = get_app_data_file("win_count_license.json")?;
    if std::path::Path::new(&license_path).exists() {
        fs::remove_file(&license_path).map_err(|e| format!("Failed to remove license file: {}", e))?;
    }
    // Clear cache when license is removed
    clear_license_cache();
    Ok(())
}

#[tauri::command]
fn clear_license_cache_command() -> Result<(), String> {
    clear_license_cache();
    Ok(())
}

#[tauri::command]
fn is_license_valid() -> Result<bool, String> {
    Ok(x7y9z2())
}



#[tauri::command]
async fn s4v3k3y(key: String) -> Result<(), String> {
    // ไม่ต้องตรวจสอบ License สำหรับการบันทึก License Key เพราะเป็นฟังก์ชันการตั้งค่า License
    #[cfg(debug_assertions)]
    debug_println!("💾 Saving license key: {}", key);
    
    // Save to app data directory (encrypted)
    let license_path = get_app_data_file("win_count_license.json")?;
    let machine_id = m4c5h6n()?;
    let license_data = serde_json::json!({
        "license_key": key.clone(),
        "saved_at": chrono::Utc::now().to_rfc3339(),
        "machine_id": machine_id
    });

    let license_json = serde_json::to_string(&license_data)
        .map_err(|e| format!("Failed to serialize license data: {}", e))?;

    let encrypted = encrypt_for_machine(&license_json, &machine_id)?;
    fs::write(license_path, encrypted)
        .map_err(|e| format!("Failed to save license key: {}", e))?;
    
    #[cfg(debug_assertions)]
    debug_println!("✅ License key saved successfully");
    
    // 🔒 Auto-backup license after saving
    let _ = auto_backup_license().await;
    
    // 🔧 ตรวจสอบและอัพเดท Machine ID หากเป็น Temporary
    #[cfg(debug_assertions)]
    debug_println!("🔧 Checking if machine ID update is needed...");
    match update_machine_id_from_temporary(key.clone()).await {
        Ok(updated_machine_id) => {
            debug_println!("✅ Machine ID update completed: {}", updated_machine_id);
        },
        Err(e) => {
            debug_println!("⚠️ Machine ID update failed (will retry later): {}", e);
            // ไม่ return error เพราะ license key ถูกบันทึกแล้ว
            // จะลองอัพเดทใหม่ในการตรวจสอบ license ครั้งต่อไป
        }
    }
    
    Ok(())
}

#[tauri::command]
async fn update_machine_id_from_temporary(license_key: String) -> Result<String, String> {
    // ฟังก์ชันสำหรับอัพเดท Machine ID จาก Temporary เป็นจริง
    debug_println!("🔧 Updating machine ID from temporary for license: {}", license_key);
    
    // ตรวจสอบว่ามี license file อยู่หรือไม่
    let license_path = get_app_data_file("win_count_license.json")?;
    if !std::path::Path::new(&license_path).exists() {
        return Err("License file not found".to_string());
    }
    
    // อ่าน license file
    let file_content = fs::read_to_string(&license_path)
        .map_err(|e| format!("Failed to read license file: {}", e))?;
    
    // ถอดรหัส license file
    let current_machine_id = m4c5h6n()?;
    let json_text = if file_content.trim_start().starts_with('{') {
        file_content
    } else {
        match decrypt_for_machine(&file_content, &current_machine_id) {
            Ok(txt) => txt,
            Err(_) => return Err("Failed to decrypt license file".to_string()),
        }
    };
    
    // Parse JSON
    let mut license_data: serde_json::Value = serde_json::from_str(&json_text)
        .map_err(|e| format!("Failed to parse license data: {}", e))?;
    
    // ตรวจสอบว่า license key ตรงกันหรือไม่
    let stored_license_key = license_data.get("license_key")
        .and_then(|v| v.as_str())
        .ok_or("License key not found in file")?;
    
    if stored_license_key != license_key {
        return Err("License key mismatch".to_string());
    }
    
    // ตรวจสอบว่า machine_id ปัจจุบันเป็น Temporary หรือไม่
    let stored_machine_id = license_data.get("machine_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(); // Clone เพื่อหลีกเลี่ยง borrow conflict
    
    if !stored_machine_id.starts_with("TEMP-") {
        debug_println!("ℹ️ Machine ID is already updated: {}", stored_machine_id);
        return Ok(stored_machine_id);
    }
    
    debug_println!("🔄 Found temporary machine ID: {}", stored_machine_id);
    debug_println!("🔄 Real machine ID: {}", current_machine_id);
    
    // เรียก API เพื่ออัพเดท Machine ID ใน server
    let client = reqwest::Client::new();
    let api_url = format!("{}/update-machine-id", license_server_url());
    
    let response = client
        .post(&api_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "license_key": license_key,
            "old_machine_id": stored_machine_id,
            "new_machine_id": current_machine_id
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to update machine ID on server: {}", e))?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!("Server error: {}", error_text));
    }
    
    let response_data: serde_json::Value = response.json().await
        .map_err(|e| format!("Failed to parse server response: {}", e))?;
    
    if !response_data.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        let error_msg = response_data.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown server error");
        return Err(format!("Server rejected update: {}", error_msg));
    }
    
    // อัพเดท license file ด้วย machine ID จริง
    license_data["machine_id"] = serde_json::Value::String(current_machine_id.clone());
    license_data["updated_at"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
    
    let updated_json = serde_json::to_string(&license_data)
        .map_err(|e| format!("Failed to serialize updated license data: {}", e))?;
    
    let encrypted = encrypt_for_machine(&updated_json, &current_machine_id)?;
    fs::write(&license_path, encrypted)
        .map_err(|e| format!("Failed to save updated license file: {}", e))?;
    
    debug_println!("✅ Machine ID updated successfully: {} -> {}", stored_machine_id, current_machine_id);
    Ok(current_machine_id)
}

// Debug updater functions
#[tauri::command]
async fn check_for_updates_debug() -> Result<serde_json::Value, String> {
    #[cfg(debug_assertions)]
    debug_println!("🔄 Checking for updates (debug mode)...");
    
    // ทดสอบเรียก API endpoint โดยตรง
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Win-Count-Debug/1.0")
        .build()
        .map_err(|e| format!("HTTP client creation failed: {}", e))?;
    
    let url = "https://win-count-by-artywoof.vercel.app/api/tauri-updater";
    
    #[cfg(debug_assertions)]
    debug_println!("🌐 Fetching update info from: {}", url);
    
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;
    
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    
    #[cfg(debug_assertions)]
    debug_println!("📡 Server response: {} - {}", status, body);
    
    if status.is_success() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            #[cfg(debug_assertions)]
            debug_println!("✅ Successfully parsed update info: {:?}", json);
            Ok(json)
        } else {
            Err(format!("Failed to parse JSON response: {}", body))
        }
    } else {
        Err(format!("Server returned error: {} - {}", status, body))
    }
}

#[tauri::command]
fn debug_updater_config() -> Result<serde_json::Value, String> {
    #[cfg(debug_assertions)]
    debug_println!("🔧 Debugging updater configuration...");
    
    let config = serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
                        "product_name": "Win Count by ArtYWoof",
        "update_endpoint": "https://win-count-by-artywoof.vercel.app/api/tauri-updater",
        "public_key": "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDVGRkYwOUFFNjBCNzlERUEKUldUcW5iZGdyZ24vWC9jWEhIUER3b09HTlJDZERJMjFCa1pZSUtGelcxVm5sTmJabmtNZ2tOU2sK"
    });
    
    #[cfg(debug_assertions)]
    debug_println!("🔧 Updater config: {:?}", config);
    
    Ok(config)
}

// Static cache for machine ID
use std::sync::OnceLock;
static MACHINE_ID_CACHE: OnceLock<String> = OnceLock::new();

#[tauri::command]
fn m4c5h6n() -> Result<String, String> {
    // Check cache first
    if let Some(cached_id) = MACHINE_ID_CACHE.get() {
        debug_println!("🔄 Using cached machine ID: {}", cached_id);
        return Ok(cached_id.clone());
    }
    
    // Try to load from file first
    if let Ok(app_data_dir) = get_app_data_dir() {
        let machine_id_file = app_data_dir.join("machine_id.txt");
        if let Ok(contents) = fs::read_to_string(&machine_id_file) {
            let machine_id = contents.trim().to_string();
            if machine_id.len() >= 8 {
                let _ = MACHINE_ID_CACHE.set(machine_id.clone());
                debug_println!("📁 Loaded machine ID from file: {}", machine_id);
                return Ok(machine_id);
            }
        }
    }
    
    // ไม่ต้องตรวจสอบ License สำหรับการสร้าง Machine ID เพราะเป็นฟังก์ชันพื้นฐาน
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::env;
    use std::time::Duration;
    
    // Create a unique machine identifier based on system information
    let mut hasher = DefaultHasher::new();
    
    // Use computer name and username as base with fallbacks
    let computer_name = env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .or_else(|_| env::var("NAME"))
        .unwrap_or_else(|_| {
            debug_println!("⚠️ Could not get computer name, using fallback");
            format!("machine-{}", std::process::id())
        });
    
    let user_name = env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            debug_println!("⚠️ Could not get username, using fallback");
            "user".to_string()
        });
    
    computer_name.hash(&mut hasher);
    user_name.hash(&mut hasher);
    
    // Add process ID for additional uniqueness (but use consistent value)
    // Use a hash of the process ID to make it more stable
    let process_id_hash = format!("{:x}", {
        let mut pid_hasher = DefaultHasher::new();
        std::process::id().hash(&mut pid_hasher);
        pid_hasher.finish()
    });
    process_id_hash.hash(&mut hasher);
    
    // Add system-specific information with timeout and error handling
    #[cfg(windows)]
    {
        use std::process::Command;
        
        // Try multiple methods to get unique system info
        let mut system_info_added = false;
        
        // Method 1: Try WMIC with timeout
        match std::thread::spawn(|| {
            Command::new("wmic")
                .args(&["csproduct", "get", "UUID"])
                .output()
        }).join() {
            Ok(Ok(output)) => {
                if let Ok(uuid) = String::from_utf8(output.stdout) {
                    let clean_uuid = uuid.replace("UUID", "").trim().to_string();
                    if !clean_uuid.is_empty() && clean_uuid != "UUID" {
                        clean_uuid.hash(&mut hasher);
                        system_info_added = true;
                        debug_println!("✅ Added system UUID to machine ID");
                    }
                }
            },
            Ok(Err(e)) => debug_println!("⚠️ WMIC command failed: {}", e),
            Err(_) => debug_println!("⚠️ WMIC command timed out"),
        }
        
        // Method 2: Try getting system info from registry (fallback)
        if !system_info_added {
            if let Ok(reg_key) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                .open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
                if let Ok(system_serial) = reg_key.get_value::<String, _>("SystemSerialNumber") {
                    system_serial.hash(&mut hasher);
                    system_info_added = true;
                    debug_println!("✅ Added system serial from registry to machine ID");
                }
            }
        }
        
        // Method 3: Use MAC address as final fallback
        if !system_info_added {
            if let Ok(output) = Command::new("getmac").args(&["/fo", "csv"]).output() {
                if let Ok(mac_info) = String::from_utf8(output.stdout) {
                    let first_mac = mac_info.lines()
                        .nth(1) // Skip header
                        .and_then(|line| line.split(',').next())
                        .map(|s| s.trim_matches('"'))
                        .unwrap_or("");
                    if !first_mac.is_empty() {
                        first_mac.hash(&mut hasher);
                        debug_println!("✅ Added MAC address to machine ID as fallback");
                    }
                }
            }
        }
    }
    
    // Add system boot time for additional uniqueness (more stable than current time)
    let boot_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() / 86400; // Day-based component for stability
    boot_time.hash(&mut hasher);
    
    let machine_id = format!("{:x}", hasher.finish());
    
    // Validate machine ID length and format
    if machine_id.len() < 8 {
        return Err("Machine ID generation failed - insufficient entropy".to_string());
    }
    
    // Cache the machine ID
    let _ = MACHINE_ID_CACHE.set(machine_id.clone());
    
    // Save to file for persistence
    if let Ok(app_data_dir) = get_app_data_dir() {
        let machine_id_file = app_data_dir.join("machine_id.txt");
        if let Err(e) = fs::write(&machine_id_file, &machine_id) {
            debug_println!("⚠️ Failed to save machine ID to file: {}", e);
        } else {
            debug_println!("💾 Saved machine ID to file: {}", machine_id_file.display());
        }
    }
    
    debug_println!("🖥️ Generated and cached machine ID: {} (length: {})", machine_id, machine_id.len());
    Ok(machine_id)
}

// Payment system functions - now using the promptpay module
#[tauri::command]
async fn create_promptpay_qr(amount: f64, phone: String) -> Result<String, String> {
    // ไม่ต้องตรวจสอบ License สำหรับการสร้าง QR Code เพราะเป็นฟังก์ชันการชำระเงิน
    // Use promptpay.io directly
    let qr_url = format!("https://promptpay.io/{}/{}", phone, amount);
    Ok(qr_url)
}

// Payment status check removed - using promptpay.io instead

// Functions moved to hotkeys module










// License system removed

// Types are now defined in the state module

// Add global shortcut manager state
type GlobalShortcutManager = Arc<Mutex<Option<tauri::AppHandle>>>;



#[tauri::command]
fn get_win_state(state: State<'_, SharedWinState>) -> Result<WinState, String> {
    // Temporarily bypass license gate during development
    state::get_win_state(state)
}

#[tauri::command]
fn set_win_state(new_state: WinState, state: State<'_, SharedWinState>) -> Result<(), String> {
    // Temporarily bypass license gate during development
    state::set_win_state(new_state, state)
}

#[tauri::command]
fn minimize_app(window: tauri::Window) -> Result<(), String> {
    // Temporarily bypass license gate during development
    
    let _ = window.minimize();
    Ok(())
}

#[tauri::command]
fn hide_to_tray(window: tauri::Window) -> Result<(), String> {
    debug_println!("🔒 hide_to_tray command called");
    
    // ให้แอปยังแสดงใน taskbar เพื่อให้คลิกได้
    if let Err(e) = window.set_skip_taskbar(false) {
        debug_println!("⚠️ Failed to show in taskbar: {:?}", e);
    }
    
    match window.hide() {
        Ok(_) => {
            debug_println!("✅ Window hidden to tray (still in taskbar)");

            // Play hide sound and notify frontend
            let app_handle = window.app_handle();
            let _ = app_handle.emit("minimized-to-tray", "hidden");
            let _ = app_handle.emit("play-sound", "hide");

            // ไม่แสดง notification เพื่อลดความรำคาญ
            debug_println!("✅ Window hidden to tray successfully");

            // Update tray tooltip if available
            if let Some(tray) = app_handle.tray_by_id("main") {
                let _ = tray.set_tooltip(Some("Win Count by ArtYWoof — Hidden".to_string()));
            }

            Ok(())
        },
        Err(e) => {
            debug_println!("❌ Failed to hide window via command: {:?}", e);
            // Try minimizing as fallback
            match window.minimize() {
                Ok(_) => {
                    debug_println!("✅ Window minimized as fallback via command");
                    let app_handle = window.app_handle();
                    let _ = app_handle.emit("minimized-to-tray", "minimized");
                    let _ = app_handle.emit("play-sound", "hide");
                    debug_println!("🔔 Window minimized to tray (notification skipped)");
                    if let Some(tray) = app_handle.tray_by_id("main") {
                        let _ = tray.set_tooltip(Some("Win Count by ArtYWoof — Minimized".to_string()));
                    }
                    Ok(())
                },
                Err(e2) => {
                    let error_msg = format!("Failed to hide or minimize window: {:?}", e2);
                    debug_println!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
    }
}

#[tauri::command]
fn set_always_on_top(window: tauri::Window, enabled: bool) -> Result<(), String> {
    if let Err(e) = window.set_always_on_top(enabled) {
        return Err(format!("Failed to set always on top: {:?}", e));
    }
    Ok(())
}

#[tauri::command]
fn get_always_on_top(window: tauri::Window) -> Result<bool, String> {
    // Tauri v2 does not expose a direct getter; track via window.is_visible/on top is not available.
    // Best effort: return true if config had it set; allow frontend to persist user choice.
    Ok(true)
}



#[tauri::command]
fn set_run_at_startup(enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::path::PathBuf;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let (key, _disp) = hkcu
            .create_subkey(path)
            .map_err(|e| format!("Failed to open HKCU Run: {}", e))?;
        let app_name = "Win Count by ArtYWoof";
        if enabled {
            let exe = std::env::current_exe().map_err(|e| format!("current_exe error: {}", e))?;
            let exe_str: String = exe.as_os_str().to_string_lossy().into_owned();
            key.set_value(app_name, &exe_str)
                .map_err(|e| format!("Failed to set Run registry value: {}", e))?;
        } else {
            let _ = key.delete_value(app_name);
        }
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Run at startup not implemented for this OS".into())
    }
}

#[tauri::command]
fn show_from_tray(window: tauri::Window) -> Result<(), String> {
    // Temporarily bypass license gate during development
    
    let _ = window.show();
    let _ = window.set_focus();
    Ok(())
}

// KeyEventTracker moved to state module

// Windows-specific key state checking
#[cfg(windows)]
unsafe fn is_key_physically_pressed(vk_code: i32) -> bool {
    // GetAsyncKeyState returns the key state
    // The most significant bit indicates if the key is currently pressed
    (GetAsyncKeyState(vk_code) as u16 & 0x8000) != 0
}

#[cfg(not(windows))]
fn is_key_physically_pressed(_vk_code: i32) -> bool {
    false // Fallback for non-Windows platforms
}

// Check if Alt and Equal keys are physically pressed (supports main row and numpad +)
fn are_hotkeys_alt_equal_pressed() -> (bool, bool) {
    #[cfg(windows)]
    unsafe {
        let alt_pressed = is_key_physically_pressed(VK_MENU);
        // Treat either '=' (OEM_PLUS) or Numpad '+' (VK_ADD) as equal/increment
        let equal_pressed = is_key_physically_pressed(VK_OEM_PLUS) || is_key_physically_pressed(VK_ADD);
        (alt_pressed, equal_pressed)
    }
    #[cfg(not(windows))]
    {
        (false, false)
    }
}

// Check if Alt and Minus keys are physically pressed (supports main row and numpad -)
fn are_hotkeys_alt_minus_pressed() -> (bool, bool) {
    #[cfg(windows)]
    unsafe {
        let alt_pressed = is_key_physically_pressed(VK_MENU);
        // Treat either '-' (OEM_MINUS) or Numpad '-' (VK_SUBTRACT) as minus/decrement
        let minus_pressed = is_key_physically_pressed(VK_OEM_MINUS) || is_key_physically_pressed(VK_SUBTRACT);
        (alt_pressed, minus_pressed)
    }
    #[cfg(not(windows))]
    {
        (false, false)
    }
}

// Calculate dynamic step based on press frequency
fn calculate_dynamic_step(tracker: &KeyEventTracker) -> i32 {
    let time_since_last = tracker.last_press_time.elapsed();
    
    // If pressed rapidly (within 300ms), increase step size
    if time_since_last < Duration::from_millis(300) {
        match tracker.press_count {
            1 => 1,          // First press: always step 1
            2..=3 => 1,      // Still slow: normal step
            4..=6 => 2,      // Medium: double step
            7..=10 => 3,     // Fast: 3x step
            11..=15 => 5,    // Very fast: 5x step
            _ => 8,          // Extremely fast: 8x step
        }
    } else {
        // Reset to normal speed if paused
        1
    }
}

// Helper function for win state mutation and event emitting
fn change_win_with_step(app: &tauri::AppHandle, state: &SharedWinState, broadcast_tx: &tokio::sync::broadcast::Sender<WinState>, delta: i32, step: i32) {
    let mut s = state.lock().unwrap();
    let new_win = (s.win + (delta * step)).max(-100000).min(100000);  // Support negative values, match set_win range
    s.win = new_win;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    
    // Auto-save to current preset (same as set_win)
    let current_preset_name = s.current_preset.clone();
    let current_state = s.clone();
    drop(s); // Release lock before calling save_preset
    
    if let Ok(mut presets) = load_presets() {
        if let Some(preset) = presets.iter_mut().find(|p| p.name == current_preset_name) {
            preset.win = current_state.win;
            preset.goal = current_state.goal;
            preset.show_goal = current_state.show_goal;
            preset.show_crown = current_state.show_crown;
            
            // Save updated presets
            let presets_path = get_app_data_file("win_count_presets.json").unwrap_or_else(|_| {
                debug_println!("❌ Failed to get presets file path, using temp directory");
                std::env::temp_dir().join("win_count_presets.json")
            });
            if let Ok(json) = serde_json::to_string_pretty(&presets) {
                let _ = fs::write(&presets_path, json);
                debug_println!("💾 Auto-saved hotkey change to preset: {}", current_preset_name);
            }
        } else {
            debug_println!("⚠️ Preset '{}' not found for auto-save, hotkey change saved to state only", current_preset_name);
            // Try to create the preset if it doesn't exist
            let new_preset = PresetData {
                name: current_preset_name.clone(),
                win: current_state.win,
                goal: current_state.goal,
                show_goal: current_state.show_goal,
                show_crown: current_state.show_crown,
                hotkeys: HotkeyConfig::default(),
            };
            presets.push(new_preset);
            
            // Save updated presets
            let presets_path = get_app_data_file("win_count_presets.json").unwrap_or_else(|_| {
                debug_println!("❌ Failed to get presets file path, using temp directory");
                std::env::temp_dir().join("win_count_presets.json")
            });
            if let Ok(json) = serde_json::to_string_pretty(&presets) {
                let _ = fs::write(&presets_path, json);
                debug_println!("💾 Created and auto-saved to new preset: {}", current_preset_name);
            }
        }
    }
    
    // Emit sound event
    if delta > 0 {
        let _ = app.emit("play-increase-sound", ());
    } else {
        let _ = app.emit("play-decrease-sound", ());
    }
    
    debug_println!("🔥 Win changed by {} (step: {}), new value: {}", delta * step, step, new_win);
}

// Helper function for win state mutation and event emitting
fn change_win(app: &tauri::AppHandle, state: &SharedWinState, broadcast_tx: &tokio::sync::broadcast::Sender<WinState>, delta: i32) {
    change_win_with_step(app, state, broadcast_tx, delta, 1);
}

#[tauri::command]
fn increase_win(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Temporarily bypass license gate during development
    change_win(&app, &state, &*broadcast_tx, 1);
    Ok(())
}

#[tauri::command]
fn decrease_win(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Temporarily bypass license gate during development
    change_win(&app, &state, &*broadcast_tx, -1);
    Ok(())
}

#[tauri::command]
fn increase_win_by_step(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, step: i32) -> Result<(), String> {
    // Temporarily bypass license gate during development
    change_win_with_step(&app, &state, &*broadcast_tx, 1, step);
    Ok(())
}

#[tauri::command]
fn decrease_win_by_step(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, step: i32) -> Result<(), String> {
    // Temporarily bypass license gate during development
    change_win_with_step(&app, &state, &*broadcast_tx, -1, step);
    Ok(())
}

#[tauri::command]
fn select_preset(
    name: String,
    app: tauri::AppHandle,
    state: State<'_, SharedWinState>,
    broadcast_tx: State<'_, broadcast::Sender<WinState>>,
) -> Result<PresetData, String> {
    // Load preset data from storage
    let preset = storage::load_preset(name.clone())?;

    // Apply to in-memory state atomically
    {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.win = preset.win.max(-100000).min(100000);
        s.goal = preset.goal.max(-100000).min(100000);
        s.show_goal = preset.show_goal;
        s.show_crown = preset.show_crown;
        s.current_preset = name.clone();
        // Persist global state
        let path = get_state_path();
        save_state(&path, &s);
        // Emit and broadcast
        let _ = app.emit("state-updated", s.clone());
        let _ = broadcast_tx.send(s.clone());
    }

    Ok(preset)
}

#[tauri::command]
fn list_system_fonts() -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        // Gather font names from multiple sources: HKLM registry, HKCU registry (per-user installs),
        // and as a last resort, file names in the Windows Fonts folder.
        let mut names: Vec<String> = Vec::new();

        let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts";

        // Helper to process registry key values
        let mut process_key = |key: &RegKey| {
            for item in key.enum_values().filter_map(Result::ok) {
                let (name, _value) = item;
                let mut n = name.trim().to_string();
                // Strip common suffixes and styles to get family name
                for suffix in [" (TrueType)", " (OpenType)", " (All Fonts)"] { if n.ends_with(suffix) { n.truncate(n.len() - suffix.len()); } }
                for style in [" Bold", " Italic", " Bold Italic", " Regular", " Light", " Medium", " SemiBold", " Black", " ExtraBold"] {
                    if let Some(idx) = n.rfind(style) { if idx + style.len() == n.len() { n.truncate(idx); } }
                }
                n = n.trim().to_string();
                if !n.is_empty() { names.push(n); }
            }
        };

        // HKLM (machine-wide installed fonts)
        if let Ok(hklm) = std::panic::catch_unwind(|| RegKey::predef(HKEY_LOCAL_MACHINE)) {
            if let Ok(key) = hklm.open_subkey(path) {
                process_key(&key);
            }
        }

        // HKCU (per-user installed fonts)
        if let Ok(hkcu) = std::panic::catch_unwind(|| RegKey::predef(HKEY_CURRENT_USER)) {
            if let Ok(key) = hkcu.open_subkey(path) {
                process_key(&key);
            }
        }

        // Fallback: scan %WINDIR%/Fonts file names (useful when registry misses entries)
        if let Ok(windir) = std::env::var("WINDIR") {
            let fonts_path = std::path::Path::new(&windir).join("Fonts");
            if fonts_path.exists() {
                if let Ok(iter) = std::fs::read_dir(&fonts_path) {
                    for entry in iter.filter_map(Result::ok) {
                        if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                            let mut s = stem.trim().to_string();
                            // replace underscores and dashes with space to look nicer
                            s = s.replace('_', " ").replace('-', " ");
                            if !s.is_empty() { names.push(s); }
                        }
                    }
                }
            }
        }

        // Deduplicate and sort (case-insensitive)
        names.sort_by(|a,b| a.to_lowercase().cmp(&b.to_lowercase()));
        names.dedup_by(|a,b| a.eq_ignore_ascii_case(b));
        return Ok(names);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![
            "Inter".into(), "Roboto".into(), "Arial".into(), "Helvetica".into(), "Courier New".into(),
        ])
    }
}

#[tauri::command]
fn set_win(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, value: i32, expected_preset: Option<String>) -> Result<(), String> {
    // Temporarily bypass license gate during development
    
    let mut s = state.lock().unwrap();
    // If caller expects a certain preset, drop update when preset already changed
    if let Some(expected) = expected_preset {
        if s.current_preset != expected {
            debug_println!("⏭️ Ignoring set_win due to preset switch (expected: {}, current: {})", expected, s.current_preset);
            return Ok(());
        }
    }
    // Clamp value between -100000 and 100000
    let new_win = value.max(-100000).min(100000);
    s.win = new_win;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    
    // Auto-save to current preset (write the actual preset file)
    let current_preset_name = s.current_preset.clone();
    let current_state = s.clone();
    drop(s);
    if let Ok(presets) = load_presets() {
        // Find current preset or create one
        let target: Option<PresetData> = presets
            .into_iter()
            .find(|p| p.name == current_preset_name)
            .or_else(|| None);
        let mut preset = target.unwrap_or(PresetData {
            name: current_preset_name.clone(),
            win: current_state.win,
            goal: current_state.goal,
            show_goal: current_state.show_goal,
            show_crown: current_state.show_crown,
            hotkeys: HotkeyConfig::default(),
        });
        preset.win = current_state.win;
        preset.goal = current_state.goal;
        preset.show_goal = current_state.show_goal;
        preset.show_crown = current_state.show_crown;
        // Persist using storage module (writes to APPDATA/WinCount/presets/<name>.json)
        if let Err(e) = storage::save_preset(preset, state) {
            debug_println!("❌ Failed to auto-save preset '{}': {}", current_preset_name, e);
        } else {
            debug_println!("💾 Auto-saved goal to preset: {}", current_preset_name);
        }
    }
    
    debug_println!("🎯 Win set to: {}", new_win);
    Ok(())
}

#[tauri::command]
fn set_goal(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, value: i32, expected_preset: Option<String>) -> Result<(), String> {
    // Temporarily bypass license gate during development
    
    let mut s = state.lock().unwrap();
    // Drop update if preset changed during input commit
    if let Some(expected) = expected_preset {
        if s.current_preset != expected {
            debug_println!("⏭️ Ignoring set_goal due to preset switch (expected: {}, current: {})", expected, s.current_preset);
            return Ok(());
        }
    }
    // Clamp value between -100000 and 100000  
    let new_goal = value.max(-100000).min(100000);
    s.goal = new_goal;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    
    // Auto-save to current preset (write the actual preset file)
    let current_preset_name = s.current_preset.clone();
    let current_state = s.clone();
    drop(s);
    if let Ok(presets) = load_presets() {
        let target: Option<PresetData> = presets
            .into_iter()
            .find(|p| p.name == current_preset_name)
            .or_else(|| None);
        let mut preset = target.unwrap_or(PresetData {
            name: current_preset_name.clone(),
            win: current_state.win,
            goal: current_state.goal,
            show_goal: current_state.show_goal,
            show_crown: current_state.show_crown,
            hotkeys: HotkeyConfig::default(),
        });
        preset.win = current_state.win;
        preset.goal = current_state.goal;
        preset.show_goal = current_state.show_goal;
        preset.show_crown = current_state.show_crown;
        if let Err(e) = storage::save_preset(preset, state) {
            debug_println!("❌ Failed to auto-save preset '{}': {}", current_preset_name, e);
        } else {
            debug_println!("💾 Auto-saved win to preset: {}", current_preset_name);
        }
    }
    
    debug_println!("🎯 Goal set to: {}", new_goal);
    Ok(())
}

#[tauri::command]
fn toggle_goal_visibility(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Enforce tier: Free cannot toggle goal visibility (always enforce by tier)
    {
        let s = state.lock().unwrap();
        if matches!(s.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }
    }

    let mut s = state.lock().unwrap();
    s.show_goal = !s.show_goal;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    debug_println!("🎯 Goal visibility toggled to: {}", s.show_goal);
    Ok(())
}

#[tauri::command]
fn toggle_crown_visibility(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Enforce tier: Free cannot toggle crown visibility (overlay icon forced)
    {
        let s = state.lock().unwrap();
        if matches!(s.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }
    }

    let mut s = state.lock().unwrap();
    s.show_crown = !s.show_crown;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    debug_println!("👑 Crown visibility toggled to: {}", s.show_crown);
    Ok(())
}

#[tauri::command]
fn toggle_overlay_border(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Enforce tier: Free cannot toggle border
    {
        let s = state.lock().unwrap();
        if matches!(s.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }
    }
    let mut s = state.lock().unwrap();
    // If background is off, always force border off
    if !s.show_background {
        s.show_border = false;
    } else {
        s.show_border = !s.show_border;
    }
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    debug_println!("🟦 Border visibility toggled to: {}", s.show_border);
    Ok(())
}

#[tauri::command]
fn toggle_overlay_background(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>) -> Result<(), String> {
    // Enforce tier: Free cannot toggle background
    {
        let s = state.lock().unwrap();
        if matches!(s.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }
    }
    let mut s = state.lock().unwrap();
    s.show_background = !s.show_background;
    // If background is turned off, force border off as well
    if !s.show_background {
        s.show_border = false;
    }
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    debug_println!("🖼️ Background visibility toggled to: {}", s.show_background);
    Ok(())
}

#[tauri::command]
fn set_theme(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, theme_id: String) -> Result<(), String> {
    // Enforce tier: Free only 'app-neon', Pro allow 'pro-*', Premium all (always enforce by tier)
    {
        let s = state.lock().unwrap();
        let allowed =         match s.license_tier {
            LicenseTier::Free => theme_id == "app-neon",
            LicenseTier::Test => theme_id == "app-neon" || theme_id.starts_with("pro-"),
            LicenseTier::Pro => theme_id == "app-neon" || theme_id.starts_with("pro-"),
            LicenseTier::Premium => true,
            LicenseTier::Kiraeve => true,
        };
        if !allowed { return Err("FEATURE_LOCKED_TIER".into()); }
    }
    let mut s = state.lock().unwrap();
    s.theme_id = theme_id;
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct OverlayStylePayload {
    win_font_size: i32,
    goal_font_size: i32,
    slash_font_size: i32,
    #[serde(default)] win_font_family: Option<String>,
    #[serde(default)] goal_font_family: Option<String>,
    #[serde(default)] slash_font_family: Option<String>,
    crown_size: i32,
    border_thickness: i32,
    background_blur: i32,
    #[serde(default)] win_color: Option<String>,
    #[serde(default)] goal_color: Option<String>,
    #[serde(default)] slash_c1: Option<String>,
    #[serde(default)] slash_c2: Option<String>,
    #[serde(default)] icon_path: Option<String>,
    #[serde(default)] bg_color: Option<String>,
    #[serde(default)] pill_height: Option<i32>,
    #[serde(default)] pill_padding_x: Option<i32>,
    #[serde(default)] pill_padding_y: Option<i32>,
    #[serde(default)] pill_expand: Option<i32>,
    #[serde(default)] border_color: Option<String>,
    #[serde(default)] border_gradient_c1: Option<String>,
    #[serde(default)] border_gradient_c2: Option<String>,
    #[serde(default)] use_gradient_border: Option<bool>,
}

#[tauri::command]
fn set_overlay_style(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, payload: OverlayStylePayload) -> Result<(), String> {
    debug_println!("🎨 Received overlay style - win_font_size: {}, goal_font_size: {}, slash_font_size: {}, crown_size: {}, border_thickness: {}, background_blur: {}", 
        payload.win_font_size, payload.goal_font_size, payload.slash_font_size, payload.crown_size, payload.border_thickness, payload.background_blur);
    let mut s = state.lock().unwrap();
    s.win_font_size = payload.win_font_size.max(10).min(300);
    s.goal_font_size = payload.goal_font_size.max(10).min(300);
    s.slash_font_size = payload.slash_font_size.max(10).min(300);
    s.crown_size = payload.crown_size.max(10).min(300);
    s.border_thickness = payload.border_thickness.max(0).min(32);
    s.background_blur = payload.background_blur.max(0).min(64);
    if let Some(p) = payload.icon_path { s.icon_path = p; }
    if let Some(c) = payload.win_color { s.win_color = c; }
    if let Some(c) = payload.goal_color { s.goal_color = c; }
    if let Some(c) = payload.slash_c1 { s.slash_c1 = c; }
    if let Some(c) = payload.slash_c2 { s.slash_c2 = c; }
    if let Some(ff) = payload.win_font_family { s.win_font_family = ff; }
    if let Some(ff) = payload.goal_font_family { s.goal_font_family = ff; }
    if let Some(ff) = payload.slash_font_family { s.slash_font_family = ff; }
    if let Some(c) = payload.bg_color { s.bg_color = c; }
    if let Some(c) = payload.border_color {
        if c.is_empty() { s.border_color.clear(); } else { s.border_color = c; }
    }
    if let Some(c) = payload.border_gradient_c1 { s.border_gradient_c1 = c; }
    if let Some(c) = payload.border_gradient_c2 { s.border_gradient_c2 = c; }
    if let Some(use_gradient) = payload.use_gradient_border { s.use_gradient_border = use_gradient; }
    if let Some(v) = payload.pill_height { s.pill_height = v.max(20).min(400); }
    if let Some(v) = payload.pill_padding_x { s.pill_padding_x = v.max(0).min(120); }
    if let Some(v) = payload.pill_padding_y { s.pill_padding_y = v.max(0).min(120); }
    if let Some(v) = payload.pill_expand { s.pill_expand = v.max(-100).min(200); }
    let _ = app.emit("state-updated", s.clone());
    let path = get_state_path();
    save_state(&path, &s);
    let _ = broadcast_tx.send(s.clone());
    Ok(())
}
#[tauri::command]
async fn copy_overlay_link() -> Result<String, String> {
    // Temporarily bypass license gate during development
    
    use std::process::Command;
    let overlay_url = "http://localhost:777/overlay.html";
    
    // Use Windows clipboard command  
    #[cfg(windows)]
    {
        let output = Command::new("cmd")
            .args(&["/C", &format!("echo {} | clip", overlay_url)])
            .output()
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;
            
        if output.status.success() {
            debug_println!("📋 Copied overlay link to clipboard: {}", overlay_url);
            Ok(overlay_url.to_string())
        } else {
            Err("Failed to copy overlay link to clipboard".to_string())
        }
    }
    
    #[cfg(not(windows))]
    {
        // For non-Windows systems, just return the URL
        debug_println!("📋 Overlay link: {}", overlay_url);
        Ok(overlay_url.to_string())
    }    
}

#[tauri::command]
fn send_timer_data(app: tauri::AppHandle, state: State<'_, SharedWinState>, broadcast_tx: State<'_, broadcast::Sender<WinState>>, timer_data: serde_json::Value) -> Result<(), String> {
    // Send timer data through the existing WebSocket broadcast system
    // Use current state values to preserve win/goal
    let current_state = state.lock().unwrap().clone();
    let mut timer_state = current_state;
    timer_state.timer_data = Some(timer_data);
    debug_println!("⏰ send_timer_data - Broadcasting timer state: win={}, goal={}, has_timer_data={}", 
        timer_state.win, timer_state.goal, timer_state.timer_data.is_some());
    let _ = broadcast_tx.send(timer_state);
    Ok(())
}

#[tauri::command]
fn send_to_overlay(broadcast_tx: State<'_, broadcast::Sender<WinState>>, data: serde_json::Value) -> Result<(), String> {
    // Send custom data to overlay through WebSocket broadcast
    let mut overlay_state = WinState::default();
    overlay_state.overlay_data = Some(data);
    let _ = broadcast_tx.send(overlay_state);
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TimerStylePayload {
    #[serde(default)] timer_font_size: Option<i32>,
    #[serde(default)] border_thickness: Option<i32>,
    #[serde(default)] pill_width: Option<i32>,
    #[serde(default)] pill_height: Option<i32>,
    #[serde(default)] pill_padding_x: Option<i32>,
    #[serde(default)] pill_padding_y: Option<i32>,
    #[serde(default)] colon_offset: Option<i32>,
    #[serde(default)] bg_color: Option<String>,
}

#[tauri::command]
fn set_timer_overlay_style(
    _app: tauri::AppHandle,
    broadcast_tx: State<'_, broadcast::Sender<WinState>>,
    payload: TimerStylePayload,
) -> Result<(), String> {
    // Broadcast a WinState carrying timer style data
    let style_json = serde_json::json!({
        "type": "timer_style",
        "style": payload,
    });
    let mut s = WinState::default();
    s.timer_data = Some(style_json);
    let _ = broadcast_tx.send(s);
    Ok(())
}

#[tauri::command]
fn set_timer_theme(
    _app: tauri::AppHandle,
    broadcast_tx: State<'_, broadcast::Sender<WinState>>,
    theme_id: String,
) -> Result<(), String> {
    // Broadcast timer theme selection; timer.html will map theme id to visuals
    let theme_json = serde_json::json!({
        "type": "timer_theme",
        "themeId": theme_id,
    });
    let mut s = WinState::default();
    s.timer_data = Some(theme_json);
    let _ = broadcast_tx.send(s);
    Ok(())
}

#[tauri::command]
// Function moved to storage module





// test_hotkeys function moved to hotkeys module





// Auto-Update Commands moved to updater module

// License system removed

// HTTP server function moved to server module

// WebSocket server function moved to server module

fn main() {
    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!("✅ dotenv loaded successfully");
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("❌ dotenv failed to load: {}", e);
        }
    }
    
    // Debug: Print environment variables
    #[cfg(debug_assertions)]
    {
        println!("🔐 DEBUG: Using Tauri Plugin v2 updater");
        println!("🔐 DEBUG: Environment variables loaded from .env");
    }
    
    run()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize security manager
    let security_manager = SecurityManager::new();
    if let Err(e) = security_manager.initialize_security() {
        debug_println!("Security initialization failed: {} (continuing anyway)", e);
        // std::process::exit(1); // DISABLED - Don't exit on security init failure
    }
    
    let path = get_state_path();
    let mut initial = load_state(&path);
    
    // Check license on startup - moved to after tauri app creation
    
    // Validate current_preset exists in presets, fallback to Default if not
    if let Ok(presets) = load_presets() {
        if !presets.iter().any(|p| p.name == initial.current_preset) {
            debug_println!("⚠️ Current preset '{}' not found in presets, falling back to 'Default'", initial.current_preset);
            initial.current_preset = "Default".to_string();
            
            // Update the state file with the corrected preset
            save_state(&path, &initial);
        }
    }
    
    // Set default license tier to Free for everyone
    initial.license_tier = LicenseTier::Free;
    
    let shared_state = Arc::new(Mutex::new(initial));
    let (broadcast_tx, _broadcast_rx) = broadcast::channel::<WinState>(32);
    let key_tracker: KeyTrackerMap = Arc::new(Mutex::new(HashMap::new()));
    
            // Start HTTP server for overlay.html
        debug_println!("🌐 Starting HTTP server...");
        // Pass broadcast sender and app handle to allow webhook to broadcast and emit
        // We'll start HTTP inside setup where we have an AppHandle
    
    // WebSocket server will be started in setup with app_handle
    
    // Start Heartbeat monitoring (will be started in setup)
    
    tauri::Builder::default()
        .manage(shared_state.clone())
        .manage(broadcast_tx.clone())
        .manage(key_tracker.clone())
        .manage(security_manager.clone())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())

        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            debug_println!("🔄 Another instance detected - bringing existing window to focus");
            debug_println!("   Args: {:?}", argv);
            debug_println!("   CWD: {:?}", cwd);
            
            // Find the main window and bring it to focus
            if let Some(window) = app.webview_windows().values().next() {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.set_always_on_top(true);
                
                // Send notification to existing instance
                let _ = app.notification()
                    .builder()
                    .title("Win Count by ArtYWoof")
                    .body("แอปพลิเคชันกำลังทำงานอยู่แล้ว")
                    .show();
                    
                debug_println!("✅ Successfully brought window to focus");
            } else {
                debug_println!("❌ No window found to focus");
            }
        }))

        // จัดการ invoke_handler ให้ถูกต้อง (แก้ไข syntax และ format เพื่อความอ่านง่าย)
        .invoke_handler(tauri::generate_handler![
            greet,
            get_app_version,
            is_license_valid,
            a1b2c3d4,
            s4v3k3y,
            m4c5h6n,
            update_machine_id_from_temporary,
            get_license_tier,
            check_and_update_license_tier,
            set_license_tier,
            hotkeys::update_hotkey,
            hotkeys::reload_hotkeys_command,
            hotkeys::test_hotkeys,
            hotkeys::disable_global_hotkeys,
            get_win_state,
            set_win_state,
            minimize_app,
            hide_to_tray,
            show_from_tray,
            set_always_on_top,
            get_always_on_top,
            set_run_at_startup,
            increase_win,
            decrease_win,
            increase_win_by_step,
            decrease_win_by_step,
            set_win,
            set_goal,
            toggle_goal_visibility,
            toggle_crown_visibility,
            toggle_overlay_border,
            toggle_overlay_background,
            set_theme,
            set_overlay_style,
            copy_overlay_link,
            send_timer_data,
            send_to_overlay,
            set_timer_overlay_style,
            set_timer_theme,
            storage::save_preset,
            storage::load_presets,
            storage::load_preset,
            storage::delete_preset,
            storage::rename_preset,
            hotkeys::play_test_sounds,
            hotkeys::clear_hotkeys,
            hotkeys::save_default_hotkeys,
            hotkeys::check_hotkey_file,
            storage::save_custom_sound,
            storage::get_custom_sound_path,
            storage::delete_custom_sound,
            storage::read_sound_file,
            storage::get_custom_sound_filename,
            storage::list_custom_sounds,
            storage::set_active_custom_sound,
            storage::delete_specific_custom_sound,
            storage::clear_active_custom_sound,
            storage::clear_win_goal_data,
            storage::set_custom_icon,
            storage::get_custom_icon,
            storage::clear_custom_icon,
            storage::add_custom_icon,
            storage::get_custom_icons,
            storage::get_custom_icon_by_id,
            storage::delete_custom_icon,
            create_promptpay_qr,
            get_license_key,
            remove_license_key,
            clear_license_cache_command,
            select_preset,
            list_system_fonts,
            send_notification,
            check_for_updates_debug,
            debug_updater_config,
            auto_backup_license,
            create_directory,
            open_devtools,
            convert_utc_to_bangkok,
            get_current_bangkok_time
        ])
        .setup({
            let shared_state = Arc::clone(&shared_state);
            let broadcast_tx = broadcast_tx.clone();
            let _key_tracker = key_tracker.clone();
            
            move |app| {
                // Start HTTP server (overlay + webhook) with ability to emit/broadcast
                start_http_server(shared_state.clone(), broadcast_tx.clone(), app.handle().clone());
                
                // Start WebSocket server with app_handle for sound events
                start_ws_server(shared_state.clone(), broadcast_tx.clone(), app.handle().clone());

                let app_handle: tauri::AppHandle = app.handle().clone();
                let state: SharedWinState = Arc::clone(&shared_state);
                let gs = app_handle.global_shortcut();
                let gs_manager_state: GlobalShortcutManager = Arc::new(Mutex::new(Some(app.handle().clone())));
                
                // Register the global shortcut manager with the app
                app.manage(gs_manager_state.clone());
                
                debug_println!("🎮 Registering dynamic global shortcuts...");

                


                // Use polling-based hotkeys instead of global shortcuts for better compatibility
                debug_println!("🎮 Using polling-based hotkeys for better compatibility");
                
                // Use the dynamic registration function as fallback
                match register_hotkeys_dynamically(&app_handle, &state, &broadcast_tx) {
                    Ok(()) => {
                        debug_println!("✅ Dynamic hotkeys registered successfully in setup");
                    },
                    Err(e) => {
                        debug_println!("❌ Failed to register dynamic hotkeys in setup: {}", e);
                        debug_println!("⚠️ Using global shortcuts as primary method");
                    }
                }
                // Keep lightweight polling fallback on Windows to ensure hotkeys work even if plugin callback is unavailable
                #[cfg(windows)]
                {
                    let app_clone = app_handle.clone();
                    let state_clone = state.clone();
                    let tx_clone = broadcast_tx.clone();
                    std::thread::spawn(move || {
                        start_hotkey_polling(app_clone, state_clone, tx_clone);
                    });
                }
                
                // Start Heartbeat monitoring
                m0n1t0r(app.handle().clone(), shared_state.clone());
                
                // Start Enhanced Security Monitor
                start_security_monitor(app.handle().clone());
                
                // Setup System Tray with enhanced menu
                debug_println!("🎯 Setting up system tray...");
                
                // สร้าง tray menu items
                let show_menu_item = MenuItemBuilder::with_id("show", "👑 Show Win Counter").build(app)?;
                let current_win_item = MenuItemBuilder::with_id("current_win", "📊 Current Win: 0").build(app)?;
                let current_goal_item = MenuItemBuilder::with_id("current_goal", "🎯 Current Goal: 10").build(app)?;
                let quit_menu_item = MenuItemBuilder::with_id("quit", "❌ Quit Win Count").build(app)?;
                
                let tray_menu = MenuBuilder::new(app)
                    .items(&[&show_menu_item, &current_win_item, &current_goal_item, &quit_menu_item])
                    .build()?;
                
                // สร้าง tray icon ด้วย TrayIconBuilder
                use tauri::tray::{TrayIconBuilder};
                
                // ตั้งค่า tray icon ให้ใช้ไอคอนที่กำหนด
                debug_println!("🎯 Setting up custom tray icon...");
                
                let tray = TrayIconBuilder::with_id("main")
                    .tooltip("Win Count by ArtYWoof")
                    .icon(app.default_window_icon().unwrap().clone())
                    .build(app)?;
                
                debug_println!("✅ Tray icon created with custom icon");
                
                // ตั้งค่า tray tooltip
                if let Err(e) = tray.set_tooltip(Some("Win Count by ArtYWoof".to_string())) {
                    debug_println!("⚠️ Failed to set tray tooltip: {:?}", e);
                } else {
                    debug_println!("✅ Tray tooltip set successfully");
                }
                
                // ตั้งค่า tray menu
                tray.set_menu(Some(tray_menu))?;
                // Handle tray menu clicks
                tray.on_menu_event({
                    let app_handle = app_handle.clone();
                    let state = state.clone();
                    move |app, event| {
                        match event.id.as_ref() {
                            "show" => {
                                if let Some(window) = app.get_webview_window("main") {
                                    // Add animation effect
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                    
                                    // Play sound effect
                                    let _ = app_handle.emit("play-sound", "show");
                                }
                            }
                            "quit" => {
                                // Add confirmation or animation before quit
                                debug_println!("🔄 Quitting Win Count by ArtYWoof...");
                                app.exit(0);
                            }
                            _ => {}
                        }
                    }
                });

                // Handle tray icon left click to show window
                debug_println!("🎯 Tray click: Use menu items for interaction");
                debug_println!("ℹ️ Click '👑 Show Win Counter' in tray menu to show window");

                
                
                // Update tray menu with current values periodically
                let tray_clone = tray.clone();
                let state_clone = state.clone();
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        let current_state = state_clone.lock().unwrap();
                        let win_text = format!("📊 Current Win: {}", current_state.win);
                        let goal_text = format!("🎯 Current Goal: {}", current_state.goal);
                        
                        // Note: Tray menu updates are handled by Tauri internally
                        // This thread is kept for potential future enhancements
                    }
                });
                
                debug_println!("✅ System tray setup completed");
                
                // เพิ่ม Global Hotkey เพื่อแสดงแอปจาก tray
                debug_println!("🎯 Setting up global hotkey for tray...");
                let app_handle_hotkey = app_handle.clone();
                
                // ใช้ global shortcut ที่ทำงานได้จริง
                if let Err(e) = app.global_shortcut().register("Ctrl+Shift+W") {
                    debug_println!("⚠️ Failed to register global hotkey: {:?}", e);
                } else {
                    debug_println!("✅ Global hotkey (Ctrl+Shift+W) registered successfully");
                }
                
                // DevTools are enabled via devtools: true in tauri.conf.json
                // Users can press F12 or Ctrl+Shift+I to open DevTools
                
                // 🛡️ Security: DISABLED FOR COMPATIBILITY
                // All anti-debugging and tampering checks disabled
                debug_println!("🛡️ Security checks disabled for app compatibility");
                // #[cfg(not(debug_assertions))]
                // {
                //     // Prevent debugging and reverse engineering
                //     unsafe {
                //         use winapi::um::debugapi::IsDebuggerPresent;
                //         if IsDebuggerPresent() != 0 {
                //             debug_println!("🚫 Debugger detected, terminating...");
                //             std::process::exit(1);
                //         }
                //     }
                //     
                //     // Anti-tampering checks
                //     std::thread::spawn(|| {
                //         loop {
                //             std::thread::sleep(std::time::Duration::from_secs(30));
                //             unsafe {
                //                 use winapi::um::debugapi::IsDebuggerPresent;
                //                 if IsDebuggerPresent() != 0 {
                //                     debug_println!("🚫 Runtime debugger detected, terminating...");
                //                     std::process::exit(1);
                //                 }
                //             }
                //         }
                //     });
                // }
                
                debug_println!("✅ Application setup completed");
                
                // Check license on startup
                let shared_state_clone = shared_state.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    if let Ok(new_tier) = startup_license_check(shared_state_clone).await {
                        debug_println!("🚀 Startup license check completed: {}", new_tier);
                    } else {
                        debug_println!("⚠️ Startup license check failed");
                    }
                });

                // Debug log sound dir for troubleshooting uploads
                // Log sounds directory hint
                #[cfg(target_os = "windows")]
                {
                    if let Ok(appdata) = std::env::var("APPDATA") {
                        let path = std::path::Path::new(&appdata).join("WinCount").join("sounds");
                        debug_println!("[DEBUG] Sounds dir (hint): {}", path.to_string_lossy());
                    }
                }
                
                Ok(())
            }
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                debug_println!("🔒 Close requested, hiding to tray...");
                api.prevent_close(); // Prevent normal close
                
                // Hide to tray instead
                if let Err(e) = hide_to_tray(window.clone()) {
                    debug_println!("❌ Failed to hide to tray: {:?}", e);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(windows)]
fn start_hotkey_polling(
    app: tauri::AppHandle,
    state: SharedWinState,
    broadcast_tx: tokio::sync::broadcast::Sender<WinState>,
) {
    use std::time::{Duration, Instant};
    use winapi::um::winuser::{
        VK_SHIFT, VK_MENU, VK_CONTROL, VK_LWIN, VK_RWIN, VK_SPACE, VK_TAB, VK_RETURN, VK_ESCAPE, VK_BACK,
        VK_DELETE, VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT, VK_OEM_PLUS, VK_ADD, VK_OEM_MINUS, VK_SUBTRACT
    };

    #[derive(Clone, Copy, Debug)]
    struct Combo { require_ctrl: bool, require_alt: bool, require_shift: bool, require_meta: bool, main_vk: i32 }

    fn map_token_to_vk(token: &str) -> Option<i32> {
        let t = token.trim();
        match t {
            "Equal" | "+" | "Plus" => Some(VK_OEM_PLUS),
            "Minus" | "-" | "Underscore" => Some(VK_OEM_MINUS),
            "Space" => Some(VK_SPACE),
            "Tab" => Some(VK_TAB),
            "Enter" | "Return" => Some(VK_RETURN),
            "Escape" | "Esc" => Some(VK_ESCAPE),
            "Backspace" => Some(VK_BACK),
            "Delete" => Some(VK_DELETE),
            "ArrowUp" => Some(VK_UP),
            "ArrowDown" => Some(VK_DOWN),
            "ArrowLeft" => Some(VK_LEFT),
            "ArrowRight" => Some(VK_RIGHT),
            "NumAdd" => Some(VK_ADD),
            "NumSubtract" => Some(VK_SUBTRACT),
            _ => {
                if let Some(ch) = t.strip_prefix("Key").and_then(|s| s.chars().next()) {
                    return Some(ch.to_ascii_uppercase() as i32);
                }
                if let Some(d) = t.strip_prefix("Digit").and_then(|s| s.chars().next()) {
                    return Some(d as i32); // '0'..'9'
                }
                if t.starts_with('F') && t.len() <= 3 {
                    if let Ok(n) = t[1..].parse::<i32>() { return Some(0x70 + (n - 1)); }
                }
                None
            }
        }
    }

    fn parse_combo(def: &str, default_main: &str) -> Option<Combo> {
        let mut require_ctrl = false;
        let mut require_alt = false;
        let mut require_shift = false;
        let mut require_meta = false;
        let mut main_vk: Option<i32> = map_token_to_vk(default_main);
        for token in def.split('+') {
            let tk = token.trim();
            match tk.to_lowercase().as_str() {
                "ctrl" | "control" => require_ctrl = true,
                "alt" => require_alt = true,
                "shift" => require_shift = true,
                "meta" | "super" | "win" => require_meta = true,
                _ => { if let Some(vk) = map_token_to_vk(tk) { main_vk = Some(vk); } }
            }
        }
        main_vk.map(|vk| Combo { require_ctrl, require_alt, require_shift, require_meta, main_vk: vk })
    }

    fn load_combos() -> (Option<Combo>, Option<Combo>, Option<Combo>, Option<Combo>) {
        // Defaults
        let mut inc = parse_combo("Alt+Equal", "Equal");
        let mut dec = parse_combo("Alt+Minus", "Minus");
        let mut inc10 = parse_combo("Alt+Shift+Equal", "Equal");
        let mut dec10 = parse_combo("Alt+Shift+Minus", "Minus");
        let map = crate::hotkeys::load_custom_hotkeys();
        if let Some(s) = map.get("increment") { inc = parse_combo(s, "Equal"); }
        if let Some(s) = map.get("decrement") { dec = parse_combo(s, "Minus"); }
        if let Some(s) = map.get("increment10") { inc10 = parse_combo(s, "Equal"); }
        if let Some(s) = map.get("decrement10") { dec10 = parse_combo(s, "Minus"); }
        (inc, dec, inc10, dec10)
    }

    let mut last_inc = false;
    let mut last_dec = false;
    let mut last_inc10 = false;
    let mut last_dec10 = false;
    let mut combos = load_combos();
    let mut last_reload = Instant::now();

    loop {
        std::thread::sleep(Duration::from_millis(5)); // Ultra-fast polling for better responsiveness

        // Periodically reload combos to reflect changes from frontend
        if last_reload.elapsed() > Duration::from_millis(500) {
            combos = load_combos();
            last_reload = Instant::now();
        }

        let (inc_c, dec_c, inc10_c, dec10_c) = combos;

        let ctrl_pressed = unsafe { is_key_physically_pressed(VK_CONTROL) };
        let alt_pressed = unsafe { is_key_physically_pressed(VK_MENU) };
        let shift_pressed = unsafe { is_key_physically_pressed(VK_SHIFT) };
        let meta_pressed = unsafe { is_key_physically_pressed(VK_LWIN) } || unsafe { is_key_physically_pressed(VK_RWIN) };

        let check = |c: &Combo| -> bool {
            let mut ok = true;
            if c.require_ctrl { ok &= ctrl_pressed; }
            if c.require_alt { ok &= alt_pressed; }
            if c.require_shift { ok &= shift_pressed; }
            if c.require_meta { ok &= meta_pressed; }
            ok &= unsafe { is_key_physically_pressed(c.main_vk) };
            ok
        };

        let now_inc = inc_c.map_or(false, |c| check(&c));
        let now_dec = dec_c.map_or(false, |c| check(&c));
        let now_inc10 = inc10_c.map_or(false, |c| check(&c));
        let now_dec10 = dec10_c.map_or(false, |c| check(&c));

        // Priority: Handle +10/-10 first, then +1/-1 only if +10/-10 didn't trigger
        if now_inc10 && !last_inc10 { 
            change_win_with_step(&app, &state, &broadcast_tx, 1, 10); 
        } else if now_inc && !last_inc { 
            change_win(&app, &state, &broadcast_tx, 1); 
        }
        
        if now_dec10 && !last_dec10 { 
            change_win_with_step(&app, &state, &broadcast_tx, -1, 10); 
        } else if now_dec && !last_dec { 
            change_win(&app, &state, &broadcast_tx, -1); 
        }

        last_inc = now_inc;
        last_dec = now_dec;
        last_inc10 = now_inc10;
        last_dec10 = now_dec10;
    }
}

#[cfg(not(windows))]
fn start_hotkey_polling(
    _app: tauri::AppHandle,
    _state: SharedWinState,
    _broadcast_tx: tokio::sync::broadcast::Sender<WinState>,
) {
    // No-op on non-Windows platforms
}

// --- Security State ---
static T4MP3R_C0UNT: AtomicUsize = AtomicUsize::new(0);
static GR4C3_P3R10D: AtomicBool = AtomicBool::new(false);
static mut GRACE_PERIOD_START: Option<DateTime<Utc>> = None;
const GRACE_PERIOD_DURATION: i64 = 5 * 60; // 5 นาที (วินาที)

// --- Anti-Debugging & Tamper Detection ---
static ANTI_DEBUG_ACTIVE: AtomicBool = AtomicBool::new(false);
static HASH_VERIFICATION_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut APP_HASH_CACHE: Option<String> = None;

#[cfg(windows)]
use winapi::um::winuser::FindWindowA;
#[cfg(windows)]
// Windows API imports for security
#[cfg(windows)]
extern "system" {
    fn IsDebuggerPresent() -> i32;
}

// --- Heartbeat System ---
static H3A2T_4CT1V3: AtomicBool = AtomicBool::new(false);
static mut LAST_HEARTBEAT: Option<DateTime<Utc>> = None;
static mut LAST_LICENSE_CHECK: Option<DateTime<Utc>> = None;
static mut CACHED_LICENSE_VALID: Option<bool> = None;
const HEARTBEAT_INTERVAL: u64 = 600; // 10 นาที (ลดจาก 30 วินาที)
const LICENSE_CACHE_DURATION: i64 = 300; // 5 นาที cache

// Smart interval based on license tier
fn get_heartbeat_interval_for_tier(tier: &str) -> u64 {
    match tier {
        "premium" => 900,  // 15 นาที
        "pro" => 600,      // 10 นาที  
        "kiraeve" => 600,  // 10 นาที
        "test" => 300,     // 5 นาที
        "free" => 1800,    // 30 นาที
        _ => 600           // Default 10 นาที
    }
}

fn h4s5h6(path: &str) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher: Sha256Hasher = Default::default();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

// Anti-Debugging functions
#[cfg(windows)]
fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(not(windows))]
fn is_debugger_present() -> bool {
    false // Placeholder for non-Windows platforms
}

#[cfg(windows)]
fn detect_debugging_tools() -> bool {
    use std::ffi::CString;
    
    let debug_tools = [
        "ollydbg", "windbg", "x64dbg", "ida", "ghidra", 
        "cheat engine", "process hacker", "processhacker"
    ];
    
    for tool in &debug_tools {
        if let Ok(tool_name) = CString::new(*tool) {
            unsafe {
                if FindWindowA(tool_name.as_ptr(), std::ptr::null()) != std::ptr::null_mut() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(windows))]
fn detect_debugging_tools() -> bool {
    false // Placeholder for non-Windows platforms
}

// Enhanced hash verification with multiple files
fn verify_app_integrity() -> bool {
    let critical_files = [
        "win-count-by-artywoof.exe",
        "tauri.conf.json",
        "WebView2Loader.dll"
    ];
    
    for file in &critical_files {
        if let Some(current_hash) = h4s5h6(file) {
            // In production, these hashes should be hardcoded or encrypted
            debug_println!("[SECURITY] Verifying integrity of: {} - Hash: {}", file, &current_hash[..16]);
            
            // Store hash in cache for comparison
            unsafe {
                if APP_HASH_CACHE.is_none() {
                    APP_HASH_CACHE = Some(current_hash.clone());
                }
            }
        } else {
            debug_println!("[SECURITY] ⚠️ Could not verify integrity of: {}", file);
            return false;
        }
    }
    true
}

// Registry tamper detection (Windows only)
#[cfg(windows)]
fn check_registry_tampering() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::{KEY_READ, REG_SZ};
    use std::ffi::CString;
    use std::ptr;
    
    // Check common registry keys that might be modified
    let registry_paths = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Classes\\Applications",
    ];
    
    for path in &registry_paths {
        if let Ok(path_cstring) = CString::new(*path) {
            let mut hkey = ptr::null_mut();
            unsafe {
                let result = RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    path_cstring.as_ptr(),
                    0,
                    KEY_READ,
                    &mut hkey
                );
                
                if result == 0 {
                    // Registry key exists, perform additional checks if needed
                    debug_println!("[SECURITY] Registry key accessible: {}", path);
                }
            }
        }
    }
    true // Return true for now, implement specific checks as needed
}

#[cfg(not(windows))]
fn check_registry_tampering() -> bool {
    true // Always return true on non-Windows platforms
}

fn i9n8t7g() -> bool {
    // ตรวจสอบ hash ของ main.rs, tauri.conf.json, และ binary
    let main_hash = h4s5h6("src-tauri/src/main.rs");
    let conf_hash = h4s5h6("src-tauri/tauri.conf.json");
    let exe_hash = std::env::current_exe().ok().and_then(|p| h4s5h6(p.to_str().unwrap_or("")));
    // hash เหล่านี้ควรเก็บค่าไว้ตอน build (hardcode หรืออ่านจากไฟล์)
    let expected_main = option_env!("EXPECTED_MAIN_HASH");
    let expected_conf = option_env!("EXPECTED_CONF_HASH");
    let expected_exe = option_env!("EXPECTED_EXE_HASH");
    let mut tampered = false;
    if let (Some(h), Some(e)) = (main_hash, expected_main) { if h != e { tampered = true; } }
    if let (Some(h), Some(e)) = (conf_hash, expected_conf) { if h != e { tampered = true; } }
    if let (Some(h), Some(e)) = (exe_hash, expected_exe) { if h != e { tampered = true; } }
    tampered
}

// Enhanced security monitor with anti-debugging
fn start_security_monitor(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            // In development, disable harsh security exits to allow workflow
            #[cfg(debug_assertions)]
            {
                continue;
            }

            // Anti-Debugging Detection
            if is_debugger_present() || detect_debugging_tools() {
                let _ = app.emit("security_issue", "🚨 ตรวจพบ Debugger หรือ Hacking Tools - แจ้งเตือนเท่านั้น".to_string());
                debug_println!("[SECURITY] 🚨 Debugger or hacking tools detected! (Warning only - not exiting)");
                // std::process::exit(1); // DISABLED - Don't exit, just warn
            }
            
            // App Integrity Verification
            if !verify_app_integrity() {
                let count = T4MP3R_C0UNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("🔍 ตรวจพบการแก้ไขไฟล์แอป ({} / 3)", count);
                let _ = app.emit("security_issue", msg.clone());
                debug_println!("[SECURITY] {}", msg);
                
                if count >= 3 {
                    let _ = app.emit("security_issue", "⛔ ตรวจพบการแก้ไขไฟล์เกิน 3 ครั้ง - แจ้งเตือนเท่านั้น".to_string());
                    debug_println!("[SECURITY] ⛔ App tampering detected - warning only (not exiting)");
                    // std::process::exit(1); // DISABLED - Don't exit, just warn
                }
            }
            
            // Registry Tampering Check
            if !check_registry_tampering() {
                let _ = app.emit("security_issue", "⚠️ ตรวจพบการแก้ไข Registry ที่น่าสงสัย".to_string());
                debug_println!("[SECURITY] ⚠️ Suspicious registry modifications detected");
            }
            
            // Original Tamper Detection
            if i9n8t7g() {
                let count = T4MP3R_C0UNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("ตรวจพบการแก้ไขไฟล์ระบบ ({} / 5)", count);
                let _ = app.emit("security_issue", msg.clone());
                debug_println!("[SECURITY] {}", msg);
                if count >= 5 {
                    let _ = app.emit("security_issue", "⛔ ตรวจพบการแก้ไขระบบเกิน 5 ครั้ง แอปถูกบล็อก".to_string());
                }
            }
            
            // Grace Period - ปิดในโหมด dev
            // if GR4C3_P3R10D.load(Ordering::SeqCst) {
            //     let now = Utc::now();
            //     let expired = unsafe {
            //         if let Some(start) = GRACE_PERIOD_START {
            //             (now - start).num_seconds() > GRACE_PERIOD_DURATION
            //         } else { false }
            //     };
            //     if expired {
            //         let _ = app.emit("security_issue", "⛔ หมดเวลา Grace Period กรุณาเชื่อมต่ออินเทอร์เน็ตเพื่อตรวจสอบ License".to_string());
            //         debug_println!("[SECURITY] Grace period expired, blocking app");
            //     }
            // }
        }
    });
}

// Startup license check - เช็ค license เมื่อเปิดแอป
async fn startup_license_check(state: SharedWinState) -> Result<String, String> {
    debug_println!("🚀 Startup license check...");
    
    // Get current tier
    let current_tier = {
        let s = state.lock().map_err(|e| e.to_string())?;
        match s.license_tier {
            LicenseTier::Premium => "premium",
            LicenseTier::Kiraeve => "kiraeve",
            LicenseTier::Pro => "pro",
            LicenseTier::Test => "test",
            LicenseTier::Free => "free",
        }
    };
    
    // ถ้าเป็น free อยู่แล้ว แต่ยังต้องเช็คว่ามี license file อยู่หรือไม่
    if current_tier == "free" {
        debug_println!("📊 Currently free tier, checking for license file...");
        // เรียก h3a2r1t เพื่อตรวจสอบ license
        match h3a2r1t().await {
            Ok(is_valid) => {
                if !is_valid {
                    debug_println!("⏰ No valid license found, staying free");
                    Ok("free".to_string())
                } else {
                    // License valid - ตรวจสอบ license key เพื่อกำหนด tier ที่ถูกต้อง
                    debug_println!("✅ License valid, checking license key for correct tier");
                    
                    // อ่าน license file เพื่อดู license key
                    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
                        if let Ok(license_content) = fs::read_to_string(&license_path) {
                            let json_text = if license_content.trim_start().starts_with('{') {
                                license_content
                            } else {
                                match decrypt_for_machine(&license_content, &m4c5h6n().unwrap_or_default()) {
                                    Ok(txt) => txt,
                                    Err(_) => return Ok("premium".to_string()), // fallback to premium
                                }
                            };
                            
                            if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                                if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                                    let key = license_key.trim().to_uppercase();
                                    let new_tier = if key.starts_with("TEST-") {
                                        LicenseTier::Test
                                    } else if key.starts_with("PRO-") {
                                        LicenseTier::Pro
                                    } else if key.starts_with("PREMIUM-") {
                                        LicenseTier::Premium
                                    } else if key.starts_with("KIRAEVE-") {
                                        LicenseTier::Kiraeve
                                    } else {
                                        LicenseTier::Premium // fallback
                                    };
                                    
                                    let mut s = state.lock().map_err(|e| e.to_string())?;
                                    s.license_tier = new_tier.clone();
                                    
                                    let tier_string = match new_tier {
                                        LicenseTier::Test => "test",
                                        LicenseTier::Pro => "pro",
                                        LicenseTier::Premium => "premium",
                                        LicenseTier::Kiraeve => "kiraeve",
                                        _ => "free",
                                    };
                                    
                                    debug_println!("✅ License tier updated to: {}", tier_string);
                                    Ok(tier_string.to_string())
                                } else {
                                    // ไม่มี license key ในไฟล์ - fallback to premium
                                    let mut s = state.lock().map_err(|e| e.to_string())?;
                                    s.license_tier = LicenseTier::Premium;
                                    Ok("premium".to_string())
                                }
                            } else {
                                // JSON parse failed - fallback to premium
                                let mut s = state.lock().map_err(|e| e.to_string())?;
                                s.license_tier = LicenseTier::Premium;
                                Ok("premium".to_string())
                            }
                        } else {
                            // File read failed - fallback to premium
                            let mut s = state.lock().map_err(|e| e.to_string())?;
                            s.license_tier = LicenseTier::Premium;
                            Ok("premium".to_string())
                        }
                    } else {
                        // No license file - fallback to premium
                        let mut s = state.lock().map_err(|e| e.to_string())?;
                        s.license_tier = LicenseTier::Premium;
                        Ok("premium".to_string())
                    }
                }
            },
            Err(e) => {
                debug_println!("❌ License check failed: {}, staying free", e);
                Ok("free".to_string())
            }
        }
    } else {
        debug_println!("📊 Already {} tier, no startup check needed", current_tier);
        Ok(current_tier.to_string())
    }
}

// Heartbeat function - ส่งสัญญาณไป License Server ทุก 10 นาที (ลดจาก 30 วินาที)
async fn h3a2r1t() -> Result<bool, String> {
    debug_println!("[DEBUG] h3a2r1t() called - checking license validity");
    
    // Check cache first - ลดการเรียก API ถ้า cache ยัง valid
    unsafe {
        if let (Some(last_check), Some(cached_valid)) = (LAST_LICENSE_CHECK, CACHED_LICENSE_VALID) {
            let now = Utc::now();
            if (now - last_check).num_seconds() < LICENSE_CACHE_DURATION {
                debug_println!("[CACHE] Using cached license result: {}", cached_valid);
                return Ok(cached_valid);
            }
        }
    }
    if let Ok(license_path) = get_app_data_file("win_count_license.json") {
        debug_println!("[DEBUG] License file path: {:?}", license_path);
        if let Ok(license_content) = fs::read_to_string(&license_path) {
            debug_println!("[DEBUG] License file content: {}", license_content);
            
            // Decrypt license file if needed
            let json_text = if license_content.trim_start().starts_with('{') {
                license_content
            } else {
                match decrypt_for_machine(&license_content, &m4c5h6n().unwrap_or_default()) {
                    Ok(txt) => {
                        debug_println!("[DEBUG] Decrypted license content: {}", txt);
                        txt
                    },
                    Err(e) => {
                        debug_println!("[DEBUG] Failed to decrypt license: {}", e);
                        return Ok(true); // Return true to avoid forcing free tier
                    }
                }
            };
            
            if let Ok(license_data) = serde_json::from_str::<serde_json::Value>(&json_text) {
                if let Some(license_key) = license_data.get("license_key").and_then(|v| v.as_str()) {
                    debug_println!("[DEBUG] Found license key: {}", license_key);
                    if let Ok(machine_id) = m4c5h6n() {
                        let timestamp = Utc::now().timestamp();
                        
                        // สร้าง signature จาก Machine ID + Timestamp + License Key
                        let signature_data = format!("{}:{}:{}", machine_id, timestamp, license_key);
                        let mut hasher: Sha256Hasher = Default::default();
                        hasher.update(signature_data.as_bytes());
                        let signature = format!("{:x}", hasher.finalize());
                        
                        let client = reqwest::Client::new();
                        let url = format!("{}/verify-license", license_server_url());
                        
                        if !url.starts_with("https://") {
                            debug_println!("[SECURITY] License server URL is not HTTPS!");
                            return Ok(false);
                        }
                        
                        let verify_data = serde_json::json!({
                            "license_key": license_key,
                            "machine_id": machine_id
                        });
                        
                        let response = client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .json(&verify_data)
                            .send()
                            .await;
                        
                        match response {
                            Ok(resp) => {
                                let status = resp.status();
                                let body = resp.text().await.unwrap_or_default();
                                debug_println!("[LICENSE VERIFY] Server response: {} - {}", status, body);
                                
                                if status.is_success() {
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                        if let Some(success) = json.get("success").and_then(|v| v.as_bool()) {
                                            if success {
                                                unsafe { 
                                                    LAST_HEARTBEAT = Some(Utc::now());
                                                    LAST_LICENSE_CHECK = Some(Utc::now());
                                                    CACHED_LICENSE_VALID = Some(true);
                                                }
                                                debug_println!("[CACHE] License valid - cached for {} seconds", LICENSE_CACHE_DURATION);
                                                return Ok(true);
                                            } else {
                                                // ตรวจสอบ reason ว่าเป็น license_expired หรือไม่
                                                if let Some(reason) = json.get("reason").and_then(|v| v.as_str()) {
                                                    if reason == "license_expired" {
                                                        debug_println!("[LICENSE VERIFY] License expired - should update tier to free");
                                                        return Ok(false);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                // ถ้า response ไม่ success หรือ license ไม่ valid
                                debug_println!("[LICENSE VERIFY] License validation failed");
                                unsafe { 
                                    LAST_LICENSE_CHECK = Some(Utc::now());
                                    CACHED_LICENSE_VALID = Some(false);
                                }
                                GR4C3_P3R10D.store(true, Ordering::SeqCst);
                                unsafe { GRACE_PERIOD_START = Some(Utc::now()); }
                                return Ok(false);
                            }
                            Err(e) => {
                                debug_println!("[HEARTBEAT] Network error: {}", e);
                                
                                // Check if it's a network connectivity issue
                                let is_network_error = e.to_string().contains("timeout") || 
                                                     e.to_string().contains("connection") ||
                                                     e.to_string().contains("network");
                                
                                if is_network_error {
                                    debug_println!("[NETWORK] Detected network connectivity issue - using offline mode");
                                    // Use cached license data if available
                                    unsafe {
                                        if let Some(cached_valid) = CACHED_LICENSE_VALID {
                                            debug_println!("[OFFLINE] Using cached license result: {}", cached_valid);
                                            return Ok(cached_valid);
                                        }
                                    }
                                }
                                
                                // Cache network error result เพื่อลดการเรียก API ซ้ำ
                                unsafe { 
                                    LAST_LICENSE_CHECK = Some(Utc::now());
                                    CACHED_LICENSE_VALID = Some(false);
                                }
                                // Activate Grace Period เมื่อไม่สามารถเชื่อมต่อได้
                                GR4C3_P3R10D.store(true, Ordering::SeqCst);
                                unsafe { GRACE_PERIOD_START = Some(Utc::now()); }
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }
    }
    // ถ้าไม่มีไฟล์ license หรือไม่สามารถอ่านได้ ให้ถือว่า invalid
    // User ต้องใส่ license key ถึงจะได้ tier สูงกว่า free
    debug_println!("[DEBUG] No license file found or failed to read - returning false (invalid)");
    
    // Cache invalid result เพื่อลดการเรียก API ซ้ำ
    unsafe { 
        LAST_LICENSE_CHECK = Some(Utc::now());
        CACHED_LICENSE_VALID = Some(false);
    }
    Ok(false)
}

// Start heartbeat monitoring with smart interval and progressive backoff
fn m0n1t0r(app: tauri::AppHandle, shared_state: SharedWinState) {
    // Disable heartbeat enforcement in dev to avoid killing app before license entry
    #[cfg(debug_assertions)]
    {
        return;
    }
    if H3A2T_4CT1V3.load(Ordering::SeqCst) {
        return; // Already running
    }
    
    H3A2T_4CT1V3.store(true, Ordering::SeqCst);
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut consecutive_failures = 0u32;
        let mut current_interval = HEARTBEAT_INTERVAL;
        
        loop {
            // Get current tier for smart interval
            let tier_interval = {
                let state = shared_state.lock().unwrap();
                let tier = match state.license_tier {
                    LicenseTier::Premium => "premium",
                    LicenseTier::Kiraeve => "kiraeve",
                    LicenseTier::Pro => "pro",
                    LicenseTier::Test => "test",
                    LicenseTier::Free => "free",
                };
                get_heartbeat_interval_for_tier(tier)
            };
            
            // Use smart interval but respect progressive backoff
            let actual_interval = std::cmp::max(current_interval, tier_interval);
            std::thread::sleep(std::time::Duration::from_secs(actual_interval));
            
            if !H3A2T_4CT1V3.load(Ordering::SeqCst) {
                break; // Stop if disabled
            }
            
            debug_println!("[HEARTBEAT] Sending heartbeat to license server... (interval: {}s)", current_interval);
            
            let result = rt.block_on(async {
                h3a2r1t().await
            });
            
            match result {
                Ok(valid) => {
                    if valid {
                        debug_println!("[HEARTBEAT] ✅ License valid");
                        // Reset grace period if license is valid
                        GR4C3_P3R10D.store(false, Ordering::SeqCst);
                        consecutive_failures = 0;
                        current_interval = HEARTBEAT_INTERVAL; // Reset to normal interval
                    } else {
                        consecutive_failures += 1;
                        debug_println!("[HEARTBEAT] ❌ License invalid or network error (failures: {})", consecutive_failures);
                        
                        // Progressive backoff: เพิ่ม interval เมื่อ fail
                        if consecutive_failures > 3 {
                            current_interval = std::cmp::min(current_interval * 2, 3600); // Max 1 hour
                            debug_println!("[HEARTBEAT] 🔄 Progressive backoff: interval increased to {}s", current_interval);
                        }
                        
                        let _ = app.emit("security_issue", "⚠️ ตรวจพบปัญหา License กรุณาตรวจสอบการเชื่อมต่อ".to_string());
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    debug_println!("[HEARTBEAT] ❌ Error: {} (failures: {})", e, consecutive_failures);
                    
                    // Progressive backoff: เพิ่ม interval เมื่อ error
                    if consecutive_failures > 3 {
                        current_interval = std::cmp::min(current_interval * 2, 3600); // Max 1 hour
                        debug_println!("[HEARTBEAT] 🔄 Progressive backoff: interval increased to {}s", current_interval);
                    }
                    
                    let _ = app.emit("security_issue", "⚠️ เกิดข้อผิดพลาดในการตรวจสอบ License".to_string());
                }
            }
        }
    });
}




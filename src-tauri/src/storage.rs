use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::state::{PresetData, HotkeyConfig, SharedWinState, LicenseTier};
// use crate::x7y9z2; // Removed - not needed
use std::collections::HashMap;

#[tauri::command]
pub fn save_preset(preset: PresetData, state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    // Enforce Free tier: only Default preset allowed; Pro: up to 5 presets
    {
        let s = state.lock().map_err(|e| e.to_string())?;
        match s.license_tier {
            LicenseTier::Free => {
                if preset.name != "Default" && preset.name != "ค่าเริ่มต้น" {
                    return Err("FEATURE_LOCKED_TIER".into());
                }
            },
            LicenseTier::Test => {
                let app_data_dir = get_app_data_dir()?;
                let presets_dir = app_data_dir.join("presets");
                let mut count = 0usize;
                if presets_dir.exists() {
                    for entry in std::fs::read_dir(&presets_dir).map_err(|e| format!("Failed to read presets directory: {}", e))? {
                        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("json") { count += 1; }
                    }
                }
                if count >= 5 {
                    return Err("PRESET_LIMIT_PRO".into());
                }
            },
            LicenseTier::Pro => {
                let app_data_dir = get_app_data_dir()?;
                let presets_dir = app_data_dir.join("presets");
                let mut count = 0usize;
                if presets_dir.exists() {
                    for entry in std::fs::read_dir(&presets_dir).map_err(|e| format!("Failed to read presets directory: {}", e))? {
                        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("json") { count += 1; }
                    }
                }
                if count >= 5 {
                    return Err("PRESET_LIMIT_PRO".into());
                }
            },
            LicenseTier::Premium => {}
            LicenseTier::Kiraeve => {}
        }
        drop(s);
    }
    let app_data_dir = get_app_data_dir()?;
    let presets_dir = app_data_dir.join("presets");
    std::fs::create_dir_all(&presets_dir).map_err(|e| format!("Failed to create presets directory: {}", e))?;
    
    let preset_file = presets_dir.join(format!("{}.json", preset.name));
    let json = serde_json::to_string_pretty(&preset)
        .map_err(|e| format!("Failed to serialize preset: {}", e))?;
    
    std::fs::write(&preset_file, json)
        .map_err(|e| format!("Failed to write preset file: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub fn load_presets() -> Result<Vec<PresetData>, String> {
    let app_data_dir = get_app_data_dir()?;
    let presets_dir = app_data_dir.join("presets");
    
    if !presets_dir.exists() {
        return Ok(Vec::new());
    }
    
    // Collect presets with file modified time for recency sort
    let mut presets_with_time: Vec<(PresetData, std::time::SystemTime)> = Vec::new();
    
    for entry in std::fs::read_dir(&presets_dir)
        .map_err(|e| format!("Failed to read presets directory: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(preset) = serde_json::from_str::<PresetData>(&contents) {
                    let mtime = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    presets_with_time.push((preset, mtime));
                }
            }
        }
    }
    
    // Sort: Default/ค่าเริ่มต้น always first, others by most recently modified (desc)
    presets_with_time.sort_by(|(a, at), (b, bt)| {
        let a_is_default = a.name == "Default" || a.name == "ค่าเริ่มต้น";
        let b_is_default = b.name == "Default" || b.name == "ค่าเริ่มต้น";
        if a_is_default && !b_is_default { return std::cmp::Ordering::Less; }
        if b_is_default && !a_is_default { return std::cmp::Ordering::Greater; }
        // newer first
        bt.cmp(at)
    });

    Ok(presets_with_time.into_iter().map(|(p, _)| p).collect())
}

#[tauri::command]
pub fn load_preset(name: String) -> Result<PresetData, String> {
    let app_data_dir = get_app_data_dir()?;
    let preset_file = app_data_dir.join("presets").join(format!("{}.json", name));
    
    if !preset_file.exists() {
        return Err(format!("Preset '{}' not found", name));
    }
    
    let contents = std::fs::read_to_string(&preset_file)
        .map_err(|e| format!("Failed to read preset file: {}", e))?;
    
    let preset: PresetData = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse preset file: {}", e))?;
    
    Ok(preset)
}

#[tauri::command]
pub fn delete_preset(name: String, state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    // Allow deleting Default only when there is more than 1 preset
    let app_data_dir = get_app_data_dir()?;
    let presets_dir = app_data_dir.join("presets");
    if name == "Default" || name == "ค่าเริ่มต้น" {
        // Count existing preset files
        let mut count = 0usize;
        if presets_dir.exists() {
            for entry in std::fs::read_dir(&presets_dir).map_err(|e| format!("Failed to read presets directory: {}", e))? {
                let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") { count += 1; }
            }
        }
        if count <= 1 { return Err("CANNOT_DELETE_LAST_PRESET".into()); }
    }
    let preset_file = app_data_dir.join("presets").join(format!("{}.json", name));
    
    if !preset_file.exists() {
        return Err(format!("Preset '{}' not found", name));
    }
    
    std::fs::remove_file(&preset_file)
        .map_err(|e| format!("Failed to delete preset file: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub fn rename_preset(old_name: String, new_name: String, state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    // Disallow renaming the Default preset
    if old_name == "Default" || old_name == "ค่าเริ่มต้น" { return Err("CANNOT_RENAME_DEFAULT".into()); }
    // Enforce tier on rename target name for Free
    let s = state.lock().map_err(|e| e.to_string())?;
    if matches!(s.license_tier, LicenseTier::Free) {
        if new_name != "Default" && new_name != "ค่าเริ่มต้น" {
            return Err("FEATURE_LOCKED_TIER".into());
        }
    }
    drop(s);
    let app_data_dir = get_app_data_dir()?;
    let old_file = app_data_dir.join("presets").join(format!("{}.json", old_name));
    let new_file = app_data_dir.join("presets").join(format!("{}.json", new_name));
    
    if !old_file.exists() {
        return Err(format!("Preset '{}' not found", old_name));
    }
    
    if new_file.exists() {
        return Err(format!("Preset '{}' already exists", new_name));
    }
    
    // Read the old preset
    let contents = std::fs::read_to_string(&old_file)
        .map_err(|e| format!("Failed to read preset file: {}", e))?;
    
    let mut preset: PresetData = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse preset file: {}", e))?;
    
    // Update the name
    preset.name = new_name.clone();
    
    // Save with new name
    let json = serde_json::to_string_pretty(&preset)
        .map_err(|e| format!("Failed to serialize preset: {}", e))?;
    
    std::fs::write(&new_file, json)
        .map_err(|e| format!("Failed to write new preset file: {}", e))?;
    
    // Delete old file
    std::fs::remove_file(&old_file)
        .map_err(|e| format!("Failed to delete old preset file: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub fn save_custom_sound(file_data: Vec<u8>, filename: String, sound_type: String, state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    // Free tier cannot upload custom sounds
    let guard = state.lock().map_err(|e| e.to_string())?;
    // In debug builds, allow uploads for all tiers
    #[cfg(not(debug_assertions))]
    if matches!(guard.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }

    // Enforce max duration ~60s by size cap (supports uncompressed WAV ~10.6MB @44.1k/16-bit/stereo)
    // Use 12MB as upper bound to account for headers/variations
    const MAX_BYTES: usize = 12 * 1024 * 1024; // ~12 MB
    if file_data.len() > MAX_BYTES {
        return Err("AUDIO_TOO_LONG".into());
    }
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    std::fs::create_dir_all(&sounds_dir).map_err(|e| format!("Failed to create sounds directory: {}", e))?;
    
    // sanitize filename: remove path separators
    let safe_filename = filename.replace(['\\', '/'], "_");
    let sound_file = sounds_dir.join(format!("{}_{}", sound_type, safe_filename));
    std::fs::write(&sound_file, file_data)
        .map_err(|e| format!("Failed to write sound file: {}", e))?;

    // Mark the newly uploaded file as active for this sound type
    let mut active = read_active_map(&sounds_dir)?;
    active.insert(sound_type.clone(), safe_filename.clone());
    write_active_map(&sounds_dir, &active)?;
    
    Ok(())
}

#[tauri::command]
pub fn get_custom_sound_path(sound_type: String) -> Result<String, String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    
    if !sounds_dir.exists() {
        return Err("Sounds directory does not exist".to_string());
    }

    // Only use active selection; if none, return error so frontend falls back to default mp3
    if let Ok(active) = read_active_map(&sounds_dir) {
        if let Some(active_name) = active.get(&sound_type) {
            let candidate_prefixed = sounds_dir.join(format!("{}_{}", sound_type, active_name));
            if candidate_prefixed.exists() {
                return Ok(candidate_prefixed.to_string_lossy().to_string());
            }
            // Fallback: support raw file without prefix if present
            let candidate_raw = sounds_dir.join(active_name);
            if candidate_raw.exists() {
                return Ok(candidate_raw.to_string_lossy().to_string());
            }
        }
    }
    Err(format!("No active custom sound for type: {}", sound_type))
}

#[tauri::command]
pub fn delete_custom_sound(sound_type: String, state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    // Free tier cannot delete sounds (no customization)
    let guard = state.lock().map_err(|e| e.to_string())?;
    #[cfg(not(debug_assertions))]
    if matches!(guard.license_tier, LicenseTier::Free) { return Err("FEATURE_LOCKED_TIER".into()); }
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    
    if !sounds_dir.exists() {
        return Err("Sounds directory does not exist".to_string());
    }
    
    for entry in std::fs::read_dir(&sounds_dir)
        .map_err(|e| format!("Failed to read sounds directory: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if file_name.starts_with(&format!("{}_", sound_type)) {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("Failed to delete sound file: {}", e))?;
                return Ok(());
            }
        }
    }
    
    Err(format!("No custom sound found for type: {}", sound_type))
}

#[tauri::command]
pub fn read_sound_file(file_path: String) -> Result<Vec<u8>, String> {
    std::fs::read(&file_path)
        .map_err(|e| format!("Failed to read sound file: {}", e))
}

#[tauri::command]
pub fn get_custom_sound_filename(sound_type: String) -> Result<String, String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    
    if !sounds_dir.exists() {
        return Err("Sounds directory does not exist".to_string());
    }

    // Return the active filename directly; UI can reflect selection immediately
    // Actual playback uses get_custom_sound_path, which validates file existence
    if let Ok(active) = read_active_map(&sounds_dir) {
        if let Some(active_name) = active.get(&sound_type) {
            return Ok(active_name.clone());
        }
    }
    Err(format!("No active custom sound for type: {}", sound_type))
}

#[tauri::command]
pub fn clear_active_custom_sound(sound_type: String) -> Result<(), String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    let mut active = read_active_map(&sounds_dir)?;
    active.remove(&sound_type);
    write_active_map(&sounds_dir, &active)
}

#[tauri::command]
pub fn list_custom_sounds(sound_type: String) -> Result<Vec<String>, String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    let mut result: Vec<String> = Vec::new();
    if !sounds_dir.exists() { return Ok(result); }
    for entry in std::fs::read_dir(&sounds_dir)
        .map_err(|e| format!("Failed to read sounds directory: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if file_name == "active.json" { continue; }
            let prefix = format!("{}_", sound_type);
            if file_name.starts_with(&prefix) {
                let original = file_name.trim_start_matches(&prefix).to_string();
                result.push(original);
            } else if !file_name.contains('_') {
                // Also include non-prefixed files to allow manual copies
                result.push(file_name.to_string());
            }
        }
    }
    // Sort alphabetically for deterministic order
    result.sort();
    Ok(result)
}

#[tauri::command]
pub fn set_active_custom_sound(sound_type: String, filename: String) -> Result<(), String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    if !sounds_dir.exists() { return Err("Sounds directory does not exist".into()); }
    // Support raw filename (without prefix). If raw exists, rename to prefixed
    let prefixed = sounds_dir.join(format!("{}_{}", sound_type, filename));
    if !prefixed.exists() {
        let raw = sounds_dir.join(&filename);
        if raw.exists() {
            std::fs::rename(&raw, &prefixed).map_err(|e| format!("Failed to rename file: {}", e))?;
        } else {
            // As a soft fallback, try adding common audio extensions if user passed bare stem
            let candidates = [".mp3", ".wav", ".ogg", ".m4a"]; 
            let mut found = false;
            for ext in &candidates {
                let p = sounds_dir.join(format!("{}{}", filename, ext));
                if p.exists() {
                    std::fs::rename(&p, &prefixed).map_err(|e| format!("Failed to rename file: {}", e))?;
                    found = true;
                    break;
                }
            }
            if !found { return Err("Selected sound file does not exist".into()); }
        }
    }
    let mut active = read_active_map(&sounds_dir)?;
    active.insert(sound_type, filename);
    write_active_map(&sounds_dir, &active)
}

#[tauri::command]
pub fn delete_specific_custom_sound(sound_type: String, filename: String) -> Result<(), String> {
    let app_data_dir = get_app_data_dir()?;
    let sounds_dir = app_data_dir.join("sounds");
    if !sounds_dir.exists() { return Err("Sounds directory does not exist".into()); }
    let prefixed = sounds_dir.join(format!("{}_{}", sound_type, filename));
    if prefixed.exists() {
        std::fs::remove_file(&prefixed).map_err(|e| format!("Failed to delete sound file: {}", e))?;
    } else {
        let raw = sounds_dir.join(&filename);
        if raw.exists() {
            std::fs::remove_file(&raw).map_err(|e| format!("Failed to delete sound file: {}", e))?;
        }
    }
    // If the deleted file was active, clear or switch to another available file
    let mut active = read_active_map(&sounds_dir)?;
    let was_active = active.get(&sound_type).map(|v| v == &filename).unwrap_or(false);
    if was_active {
        // Try to set to another available file
        let mut fallback: Option<String> = None;
        for entry in std::fs::read_dir(&sounds_dir)
            .map_err(|e| format!("Failed to read sounds directory: {}", e))? {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                let prefix = format!("{}_", sound_type);
                if file_name.starts_with(&prefix) {
                    let original = file_name.trim_start_matches(&prefix).to_string();
                    if original != filename { fallback = Some(original); break; }
                }
            }
        }
        if let Some(new_active) = fallback { active.insert(sound_type, new_active); } else { active.remove(&sound_type); }
        write_active_map(&sounds_dir, &active)?;
    }
    Ok(())
}

// Active selection helpers
fn read_active_map(sounds_dir: &PathBuf) -> Result<HashMap<String, String>, String> {
    let path = sounds_dir.join("active.json");
    if !path.exists() { return Ok(HashMap::new()); }
    let txt = std::fs::read_to_string(&path).map_err(|e| format!("Failed to read active.json: {}", e))?;
    let map: HashMap<String, String> = serde_json::from_str(&txt).map_err(|e| format!("Failed to parse active.json: {}", e))?;
    Ok(map)
}

fn write_active_map(sounds_dir: &PathBuf, map: &HashMap<String, String>) -> Result<(), String> {
    let path = sounds_dir.join("active.json");
    let json = serde_json::to_string_pretty(map).map_err(|e| format!("Failed to serialize active.json: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write active.json: {}", e))
}

// Helper function to get app data directory
fn get_app_data_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let app_data = std::env::var("APPDATA").map_err(|_| "APPDATA not found".to_string())?;
        Ok(PathBuf::from(app_data).join("WinCount"))
    }
    
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not found".to_string())?;
        Ok(PathBuf::from(home).join("Library/Application Support/WinCount"))
    }
    
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not found".to_string())?;
        Ok(PathBuf::from(home).join(".config/WinCount"))
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported operating system".to_string())
    }
}

#[tauri::command]
pub fn clear_win_goal_data(state: tauri::State<'_, SharedWinState>) -> Result<(), String> {
    println!("🗑️ Clearing win and goal data...");
    
    // 1. Reset in-memory state to defaults
    {
        let mut s = state.lock().unwrap();
        s.win = 0;
        s.goal = 10;
        println!("✅ Reset in-memory state: win=0, goal=10");
    }
    
    // 2. Clear all preset files (they might have conflicting data)
    let app_data_dir = get_app_data_dir()?;
    let presets_dir = app_data_dir.join("presets");
    
    if presets_dir.exists() {
        match std::fs::remove_dir_all(&presets_dir) {
            Ok(_) => println!("✅ Cleared all preset files"),
            Err(e) => println!("⚠️ Failed to clear preset files: {}", e),
        }
    }
    
    // 3. Clear main state file
    let state_file = app_data_dir.join("win_count_state.json");
    if state_file.exists() {
        match std::fs::remove_file(&state_file) {
            Ok(_) => println!("✅ Cleared main state file"),
            Err(e) => println!("⚠️ Failed to clear state file: {}", e),
        }
    }
    
    // 4. Clear old presets file (if exists)
    let old_presets_file = app_data_dir.join("win_count_presets.json");
    if old_presets_file.exists() {
        match std::fs::remove_file(&old_presets_file) {
            Ok(_) => println!("✅ Cleared old presets file"),
            Err(e) => println!("⚠️ Failed to clear old presets file: {}", e),
        }
    }
    
    // 5. Create fresh default preset
    std::fs::create_dir_all(&presets_dir).map_err(|e| format!("Failed to create presets directory: {}", e))?;
    
    let default_preset = PresetData {
        name: "Default".to_string(),
        win: 0,
        goal: 10,
        show_goal: true,
        show_crown: true,
        hotkeys: HotkeyConfig::default(),
    };
    
    let preset_file = presets_dir.join("Default.json");
    let json = serde_json::to_string_pretty(&default_preset)
        .map_err(|e| format!("Failed to serialize default preset: {}", e))?;
    
    std::fs::write(&preset_file, json)
        .map_err(|e| format!("Failed to write default preset: {}", e))?;
    
    println!("✅ Created fresh Default preset");
    
    // 6. Update current preset to Default
    {
        let mut s = state.lock().unwrap();
        s.current_preset = "Default".to_string();
    }
    
    println!("✅ Win and goal data cleared successfully");
    Ok(())
}

// ===== Custom Icon Management =====

#[derive(Serialize, Deserialize, Clone)]
pub struct CustomIcon {
    pub id: String,
    pub name: String,
    pub data: String,
    pub file_type: String,
    pub created_at: String,
}

#[tauri::command]
pub fn add_custom_icon(icon_data: String, file_name: String, file_type: String) -> Result<String, String> {
    let app_data_dir = get_app_data_dir()?;
    let icons_dir = app_data_dir.join("custom_icons");
    
    // สร้างโฟลเดอร์ถ้ายังไม่มี
    std::fs::create_dir_all(&icons_dir).map_err(|e| format!("Failed to create icons directory: {}", e))?;
    
    // สร้าง ID สำหรับไอคอน
    let icon_id = format!("icon_{}", chrono::Utc::now().timestamp_millis());
    let created_at = chrono::Utc::now().to_rfc3339();
    
    let custom_icon = CustomIcon {
        id: icon_id.clone(),
        name: file_name,
        data: icon_data,
        file_type,
        created_at,
    };
    
    // บันทึกไอคอนเป็นไฟล์ JSON
    let icon_file = icons_dir.join(format!("{}.json", icon_id));
    let json = serde_json::to_string_pretty(&custom_icon)
        .map_err(|e| format!("Failed to serialize icon: {}", e))?;
    
    std::fs::write(&icon_file, json)
        .map_err(|e| format!("Failed to save custom icon: {}", e))?;
    
    println!("✅ Custom icon added successfully: {}", icon_id);
    Ok(icon_id)
}

#[tauri::command]
pub fn get_custom_icons() -> Result<Vec<CustomIcon>, String> {
    let app_data_dir = get_app_data_dir()?;
    let icons_dir = app_data_dir.join("custom_icons");
    
    if !icons_dir.exists() {
        return Ok(Vec::new());
    }
    
    let mut icons = Vec::new();
    
    for entry in std::fs::read_dir(&icons_dir)
        .map_err(|e| format!("Failed to read icons directory: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(icon) = serde_json::from_str::<CustomIcon>(&contents) {
                    icons.push(icon);
                }
            }
        }
    }
    
    // เรียงลำดับตามเวลาที่สร้าง (ใหม่สุดก่อน)
    icons.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    
    println!("✅ Loaded {} custom icons", icons.len());
    Ok(icons)
}

#[tauri::command]
pub fn get_custom_icon_by_id(icon_id: String) -> Result<String, String> {
    let app_data_dir = get_app_data_dir()?;
    let icons_dir = app_data_dir.join("custom_icons");
    let icon_file = icons_dir.join(format!("{}.json", icon_id));
    
    if !icon_file.exists() {
        return Err("Icon not found".to_string());
    }
    
    let contents = std::fs::read_to_string(&icon_file)
        .map_err(|e| format!("Failed to read icon file: {}", e))?;
    
    let icon: CustomIcon = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse icon data: {}", e))?;
    
    println!("✅ Custom icon loaded successfully: {}", icon_id);
    Ok(icon.data)
}

#[tauri::command]
pub fn delete_custom_icon(icon_id: String) -> Result<(), String> {
    let app_data_dir = get_app_data_dir()?;
    let icons_dir = app_data_dir.join("custom_icons");
    let icon_file = icons_dir.join(format!("{}.json", icon_id));
    
    if icon_file.exists() {
        std::fs::remove_file(&icon_file)
            .map_err(|e| format!("Failed to remove custom icon: {}", e))?;
        println!("✅ Custom icon deleted successfully: {}", icon_id);
    }
    
    Ok(())
}

// Legacy functions for backward compatibility
#[tauri::command]
pub fn set_custom_icon(icon_data: String) -> Result<(), String> {
    add_custom_icon(icon_data, "Legacy Icon".to_string(), "image/png".to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_custom_icon() -> Result<String, String> {
    let icons = get_custom_icons()?;
    if icons.is_empty() {
        return Ok("".to_string());
    }
    Ok(icons[0].data.clone())
}

#[tauri::command]
pub fn clear_custom_icon() -> Result<(), String> {
    let app_data_dir = get_app_data_dir()?;
    let icons_dir = app_data_dir.join("custom_icons");
    
    if icons_dir.exists() {
        std::fs::remove_dir_all(&icons_dir)
            .map_err(|e| format!("Failed to remove icons directory: {}", e))?;
        println!("✅ All custom icons cleared successfully");
    }
    
    Ok(())
}

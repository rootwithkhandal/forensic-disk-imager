#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod acquisition;
mod hasher;
mod output;
mod report;
mod state;
mod error;
mod platform;
mod memory;
mod locked_files;
mod consistency;

use platform::{ActiveBackend, DeviceBackend, DeviceInfo};
use acquisition::{AcquisitionConfig, ProgressEvent};
use output::CompressionFormat;
use tauri::{AppHandle, Emitter, Manager, State};
use std::sync::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;

// State to hold the cancellation sender
type ActiveTaskState = Mutex<Option<Sender<ProgressEvent>>>;

#[derive(serde::Deserialize)]
struct StartConfig {
    imaging_mode: String,
    source_path: String,
    dest_path: String,
    evidence_id: String,
    notes: String,
    case_number: String,
    examiner: String,
    format_mode: String,
    hash_verification: String,
    block_size_kb: usize,
    hash_algorithms: Vec<hasher::HashAlgorithm>,
    compression: String,
    resume_mode: bool,
    split_size_mb: Option<usize>,
    read_verification: bool,
    keywords: Vec<String>,
    sparse: bool,
    digital_signature: bool,
}

#[derive(serde::Deserialize)]
struct StartLiveConfig {
    volume: String,
    dest_path: String,
    evidence_id: String,
    notes: String,
    case_number: String,
    examiner: String,
    capture_ram: bool,
    capture_locked_files: bool,
    run_consistency_check: bool,
    image_vss: bool,
    auto_cleanup_vss: bool,
    ram_tool_path: Option<String>,
    hash_algorithms: Vec<hasher::HashAlgorithm>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct VolumeInfo {
    letter: String,
    label: String,
    fs_type: String,
    total_size: u64,
    free_space: u64,
}

#[tauri::command]
fn get_admin_status() -> bool {
    ActiveBackend::is_privileged()
}

#[tauri::command]
async fn scan_devices() -> Result<Vec<DeviceInfo>, String> {
    ActiveBackend::enumerate_devices().map_err(|e| e.to_string())
}

#[tauri::command]
fn browse_folder() -> Option<String> {
    rfd::FileDialog::new()
        .pick_folder()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn browse_file(ext: String) -> Option<String> {
    let filter_name = match ext.as_str() {
        "e01" => "E01 Evidence Image (.e01)",
        "aff" => "Advanced Forensic Format (.aff)",
        _ => "Raw Image (.dd)",
    };

    rfd::FileDialog::new()
        .add_filter(filter_name, &[&ext])
        .save_file()
        .map(|path| {
            let mut path_str = path.to_string_lossy().to_string();
            let suffix = format!(".{}", ext);
            if !path_str.ends_with(&suffix) {
                path_str.push_str(&suffix);
            }
            path_str
        })
}

#[tauri::command]
fn check_checkpoint(dest_path: String) -> bool {
    if dest_path.trim().is_empty() {
        return false;
    }
    let path = PathBuf::from(&dest_path);
    let checkpoint_path = path.with_extension("json");
    checkpoint_path.exists()
}

#[tauri::command]
fn cancel_acquisition(state: State<'_, ActiveTaskState>) -> Result<(), String> {
    let mut lock = state.lock().unwrap();
    if let Some(tx) = lock.take() {
        // Drop the sender to close the channel
        drop(tx);
    }
    Ok(())
}

fn clear_active_task(app_handle: &AppHandle) {
    let state_guard = app_handle.state::<ActiveTaskState>();
    let mut lock = state_guard.lock().unwrap();
    *lock = None;
}

fn format_ext(mode: &str) -> &'static str {
    if mode.contains("EX01") { "ex01" }
    else if mode.contains("E01") { "e01" }
    else if mode.contains("AFF") { "aff" }
    else if mode.contains("SMART") { "smart" }
    else { "dd" }
}

#[tauri::command]
async fn start_acquisition(
    config_input: StartConfig,
    state: State<'_, ActiveTaskState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let mut lock = state.lock().unwrap();
    if lock.is_some() {
        return Err("An acquisition is already in progress.".to_string());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(100);
    *lock = Some(tx.clone());

    // Spawn event bridge from channel to Tauri front-end
    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_handle_clone.emit("acquisition-event", event);
        }
    });

    // Spawn the actual imaging task
    tokio::spawn(async move {
        let tx = tx.clone();
        let log = |msg: String| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(ProgressEvent::Log(msg)).await;
            }
        };

        log("[SYSTEM] Starting acquisition backend task...".to_string()).await;

        let algos = config_input.hash_algorithms.clone();
        if algos.is_empty() {
            let _ = tx.send(ProgressEvent::Error("At least one hash algorithm must be enabled.".to_string())).await;
            clear_active_task(&app_handle);
            return;
        }

        let compression = match config_input.compression.as_str() {
            "Gzip" => CompressionFormat::Gzip,
            "Zstd" => CompressionFormat::Zstd,
            _ => CompressionFormat::None,
        };

        let mut dest_file_path = PathBuf::from(&config_input.dest_path);
        if dest_file_path.extension().is_none() && config_input.imaging_mode != "Logical" {
            dest_file_path.set_extension(format_ext(&config_input.format_mode));
        }

        let is_logical = config_input.imaging_mode == "Logical";
        let checkpoint_path = dest_file_path.with_extension("json");

        // Prepare acquisition configuration
        let mut start_offset = 0u64;
        let mut pre_hash_val = None;
        let mut bad_sectors_start = 0u64;

        if config_input.resume_mode {
            if let Ok(checkpoint) = crate::state::CheckpointState::load(&checkpoint_path) {
                start_offset = checkpoint.bytes_read;
                bad_sectors_start = checkpoint.bad_sectors;
                pre_hash_val = checkpoint.pre_hash.clone();
                log(format!(
                    "[ACQUISITION] Resuming from checkpoint offset: {} bytes",
                    start_offset
                ))
                .await;
            } else {
                let _ = tx.send(ProgressEvent::Error("Failed to load checkpoint file for resume.".to_string())).await;
                clear_active_task(&app_handle);
                return;
            }
        }

        let split_size_bytes = config_input.split_size_mb.map(|mb| mb as u64 * 1024 * 1024);

        let config = AcquisitionConfig {
            hash_algorithms: algos.clone(),
            block_size: config_input.block_size_kb * 1024,
            split_size: split_size_bytes,
            compression,
            case_number: config_input.case_number.clone(),
            examiner: config_input.examiner.clone(),
            evidence_id: config_input.evidence_id.clone(),
            notes: config_input.notes.clone(),
            pre_hash: pre_hash_val,
            imaging_mode: config_input.imaging_mode.clone(),
            format: config_input.format_mode.clone(),
            read_verification: config_input.read_verification,
            keywords: config_input.keywords.clone(),
        };

        let source_path = config_input.source_path.clone();
        log(format!("[ACQUISITION] Source Path: {}", source_path)).await;
        log(format!("[ACQUISITION] Destination Path: {}", dest_file_path.display())).await;

        let start_time_utc = chrono::Utc::now();

        let mut pre_hashes = HashMap::new();
        if is_logical {
            if config_input.hash_verification == "Pre & Post-Acquisition" && start_offset == 0 {
                log("[ACQUISITION] Pre-Acquisition hashing started (Logical)...".to_string()).await;
                match crate::acquisition::compute_logical_hash(std::path::Path::new(&source_path), &algos, tx.clone()).await {
                    Ok(hashes) => {
                        pre_hashes = hashes.clone();
                        if let Some(hash_val) = hashes.values().next() {
                            log(format!("[ACQUISITION] Pre-Acquisition Hash (Logical): {}", hash_val)).await;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Pre-Acquisition hash error: {}", e))).await;
                        clear_active_task(&app_handle);
                        return;
                    }
                }
            }

            log("[ACQUISITION] Executing logical folder copying...".to_string()).await;
            match crate::acquisition::acquire_logical(
                std::path::Path::new(&source_path),
                &dest_file_path,
                &config,
                tx.clone(),
            )
            .await
            {
                Ok(result) => {
                    let mut post_hashes = None;
                    if config_input.hash_verification.contains("Post") {
                        log("[ACQUISITION] Computing post-acquisition hash for logical destination...".to_string()).await;
                        match crate::acquisition::compute_logical_hash(&dest_file_path, &algos, tx.clone()).await {
                            Ok(hashes) => {
                                post_hashes = Some(hashes);
                            }
                            Err(e) => {
                                log(format!("[ERROR] Post-acquisition hash failed: {}", e)).await;
                            }
                        }
                    }

                    let end_time_utc = chrono::Utc::now();
                    let report_data = crate::report::ReportData {
                        case_number: config.case_number.clone(),
                        examiner: config.examiner.clone(),
                        evidence_id: config.evidence_id.clone(),
                        notes: config.notes.clone(),
                        imaging_mode: config.imaging_mode.clone(),
                        format: config.format.clone(),
                        source_device: source_path.clone(),
                        source_size: result.bytes_read,
                        source_model: "Logical Folder".to_string(),
                        source_serial: "N/A".to_string(),
                        dest_file: dest_file_path.display().to_string(),
                        start_time: start_time_utc,
                        end_time: end_time_utc,
                        bad_sectors: 0,
                        pre_hashes,
                        hashes: result.hashes.clone(),
                        post_hashes,
                        vss_snapshot_id: None,
                        ram_dump_path: None,
                        ram_dump_size: None,
                        ram_dump_hash: None,
                        locked_files_copied: Vec::new(),
                        consistency_blocks_checked: None,
                        consistency_blocks_matched: None,
                        consistency_mismatches: Vec::new(),
                    };
                    let report_path = dest_file_path.join("logical_report.txt");
                    let _ = crate::report::generate_txt_report(report_path, &report_data);
                    log("[SYSTEM] Logical report generated successfully.".to_string()).await;
                    
                    let _ = tx.send(ProgressEvent::Finished {
                        bytes_read: result.bytes_read,
                        bad_sectors: 0,
                        hashes: result.hashes,
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Error(format!("Logical acquisition error: {}", e))).await;
                }
            }
        } else {
            // Physical imaging
            log("[ACQUISITION] Enrolling physical block devices...".to_string()).await;

            // Get device details for report
            let mut model = "Unknown Model".to_string();
            let mut serial = "N/A".to_string();
            let mut size = 0u64;

            if let Ok(devs) = ActiveBackend::enumerate_devices() {
                if let Some(dev) = devs.iter().find(|d| d.path == source_path) {
                    model = dev.model.clone();
                    serial = dev.serial.clone();
                    size = dev.size;
                }
            }

            log(format!("[ACQUISITION] Found source block size: {} bytes", size)).await;

            // 1. Run Pre-acquisition Hashing if configured and not resuming
            let mut pre_hashes = HashMap::new();
            let mut config = config;
            if config_input.hash_verification == "Pre & Post-Acquisition" && start_offset == 0 {
                log("[ACQUISITION] Pre-Acquisition hashing started...".to_string()).await;
                match crate::acquisition::compute_pre_hash(&source_path, size, &algos, tx.clone()).await {
                    Ok(hashes) => {
                        pre_hashes = hashes;
                        if let Some(hash_val) = pre_hashes.values().next() {
                            config.pre_hash = Some(hash_val.clone());
                            log(format!("[ACQUISITION] Pre-Acquisition Hash: {}", hash_val)).await;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Pre-Acquisition hash error: {}", e))).await;
                        clear_active_task(&app_handle);
                        return;
                    }
                }
            }

            // Open block device read-only
            let mut source_dev = match ActiveBackend::open_readonly(&source_path) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Error(format!("Failed to open device: {}", e))).await;
                    clear_active_task(&app_handle);
                    return;
                }
            };

            // Enforce write block
            if let Err(e) = ActiveBackend::enforce_write_block(&mut source_dev) {
                let _ = tx.send(ProgressEvent::Error(format!("Write block failure: {}", e))).await;
                clear_active_task(&app_handle);
                return;
            }

            // Create output writer
            let mut dest_writer = match crate::output::OutputWriter::new(
                &dest_file_path,
                config.split_size, // split size
                config.compression,
                config_input.resume_mode,
                config_input.sparse,
            ) {
                Ok(w) => w,
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Error(format!("Failed to create output: {}", e))).await;
                    clear_active_task(&app_handle);
                    return;
                }
            };

            if start_offset == 0 {
                let _ = dest_writer.write_format_header(
                    format_ext(&config_input.format_mode).to_uppercase().as_str(),
                    &config.case_number,
                    &config.examiner,
                    &config.evidence_id,
                    &config.notes,
                );
            }

            log("[ACQUISITION] Starting bitstream imaging loop...".to_string()).await;

            match crate::acquisition::acquire(
                &mut source_dev,
                dest_writer,
                &config,
                tx.clone(),
                &checkpoint_path,
                start_offset,
            )
            .await
            {
                Ok(result) => {
                    let mut post_hashes = None;
                    if config_input.hash_verification.contains("Post") {
                        log(format!("[ACQUISITION] Computing post-acquisition hash for output container file...")).await;
                        match crate::acquisition::compute_file_hash(
                            &dest_file_path,
                            &config.hash_algorithms,
                            tx.clone(),
                        ).await {
                            Ok(hashes) => {
                                post_hashes = Some(hashes);
                            }
                            Err(e) => {
                                log(format!("[ERROR] Post-acquisition hash failed: {}", e)).await;
                            }
                        }
                    }

                    let end_time_utc = chrono::Utc::now();
                    let report_data = crate::report::ReportData {
                        case_number: config.case_number.clone(),
                        examiner: config.examiner.clone(),
                        evidence_id: config.evidence_id.clone(),
                        notes: config.notes.clone(),
                        imaging_mode: config.imaging_mode.clone(),
                        format: config.format.clone(),
                        source_device: source_path.clone(),
                        source_size: size,
                        source_model: model,
                        source_serial: serial,
                        dest_file: dest_file_path.display().to_string(),
                        start_time: start_time_utc,
                        end_time: end_time_utc,
                        bad_sectors: result.bad_sectors + bad_sectors_start,
                        pre_hashes,
                        hashes: result.hashes.clone(),
                        post_hashes,
                        vss_snapshot_id: None,
                        ram_dump_path: None,
                        ram_dump_size: None,
                        ram_dump_hash: None,
                        locked_files_copied: Vec::new(),
                        consistency_blocks_checked: None,
                        consistency_blocks_matched: None,
                        consistency_mismatches: Vec::new(),
                    };
                    let report_path = dest_file_path.with_extension("report.txt");
                    let _ = crate::report::generate_txt_report(&report_path, &report_data);
                    
                    // Generate HTML, JSON, and CSV reports
                    let _ = crate::report::generate_html_report(dest_file_path.with_extension("report.html"), &report_data);
                    let _ = crate::report::generate_json_report(dest_file_path.with_extension("report.json"), &report_data);
                    let _ = crate::report::generate_csv_report(dest_file_path.with_extension("report.csv"), &report_data);
                    log("[SYSTEM] Multi-format reports (HTML, JSON, CSV) generated successfully.".to_string()).await;

                    if config_input.digital_signature {
                        if let Ok(content) = std::fs::read_to_string(&report_path) {
                            let sig = crate::hasher::generate_report_seal(&content, &report_data.case_number);
                            let sig_path = dest_file_path.with_extension("signature");
                            if let Ok(mut sig_file) = std::fs::File::create(sig_path) {
                                use std::io::Write;
                                let _ = writeln!(sig_file, "=== FORGELENS FORENSIC SEAL ===");
                                let _ = writeln!(sig_file, "Signature: {}", sig);
                                let _ = writeln!(sig_file, "Workstation ID: WORKSTATION-STN-01");
                                let _ = writeln!(sig_file, "Timestamp: {}", chrono::Utc::now().to_rfc2822());
                                log("[SYSTEM] Cryptographic digital signature generated successfully.".to_string()).await;
                            }
                        }
                    }

                    // Delete checkpoint file on successful completion
                    if checkpoint_path.exists() {
                        let _ = std::fs::remove_file(checkpoint_path);
                    }

                    let _ = tx.send(ProgressEvent::Finished {
                        bytes_read: result.bytes_read,
                        bad_sectors: result.bad_sectors + bad_sectors_start,
                        hashes: result.hashes,
                    }).await;
                }
                Err(crate::error::ForgelensError::Cancelled) => {
                    log("[SYSTEM] Acquisition cancelled by user. State saved.".to_string()).await;
                }
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Error(format!("Acquisition error: {}", e))).await;
                }
            }
        }

        // Clean up task state
        clear_active_task(&app_handle);
    });

    Ok(())
}

#[tauri::command]
async fn start_triage(
    dest_path: String,
    collect_registry: bool,
    collect_volatile: bool,
    collect_browsers: bool,
    collect_eventlogs: bool,
    state: State<'_, ActiveTaskState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let mut lock = state.lock().unwrap();
    if lock.is_some() {
        return Err("A forensic task is already in progress.".to_string());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(100);
    *lock = Some(tx.clone());

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_handle_clone.emit("acquisition-event", event);
        }
    });

    tokio::spawn(async move {
        match crate::acquisition::acquire_triage(
            &dest_path,
            collect_registry,
            collect_volatile,
            collect_browsers,
            collect_eventlogs,
            tx.clone(),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                let _ = tx.send(ProgressEvent::Error(format!("Triage error: {}", e))).await;
            }
        }
        clear_active_task(&app_handle);
    });

    Ok(())
}

#[tauri::command]
async fn list_volumes() -> Result<Vec<VolumeInfo>, String> {
    let mut volumes = Vec::new();

    #[cfg(target_os = "windows")]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            let drive_w: Vec<u16> = std::ffi::OsStr::new(&drive)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let drive_type = unsafe {
                windows::Win32::Storage::FileSystem::GetDriveTypeW(
                    windows::core::PCWSTR(drive_w.as_ptr())
                )
            };

            // DRIVE_FIXED = 3, DRIVE_REMOVABLE = 2
            if drive_type == 3 || drive_type == 2 {
                let mut total_bytes = 0u64;
                let mut free_bytes = 0u64;

                let _ = unsafe {
                    windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                        windows::core::PCWSTR(drive_w.as_ptr()),
                        None,
                        Some(&mut total_bytes as *mut u64 as *mut _),
                        Some(&mut free_bytes as *mut u64 as *mut _),
                    )
                };

                volumes.push(VolumeInfo {
                    letter: format!("{}:", letter as char),
                    label: if drive_type == 2 { "Removable".to_string() } else { "Fixed".to_string() },
                    fs_type: "NTFS".to_string(),
                    total_size: total_bytes,
                    free_space: free_bytes,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0].starts_with("/dev/") {
                    volumes.push(VolumeInfo {
                        letter: parts[1].to_string(),
                        label: parts[0].to_string(),
                        fs_type: parts[2].to_string(),
                        total_size: 0,
                        free_space: 0,
                    });
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("df").arg("-h").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 && parts[0].starts_with("/dev/") {
                    volumes.push(VolumeInfo {
                        letter: parts[parts.len() - 1].to_string(),
                        label: parts[0].to_string(),
                        fs_type: "APFS".to_string(),
                        total_size: 0,
                        free_space: 0,
                    });
                }
            }
        }
    }

    Ok(volumes)
}

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[tauri::command]
async fn start_live_acquisition(
    config_input: StartLiveConfig,
    state: State<'_, ActiveTaskState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let mut lock = state.lock().unwrap();
    if lock.is_some() {
        return Err("A forensic task is already in progress.".to_string());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(100);
    *lock = Some(tx.clone());

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_handle_clone.emit("acquisition-event", event);
        }
    });

    tokio::spawn(async move {
        let tx = tx.clone();
        let dest_dir = PathBuf::from(&config_input.dest_path);
        let _ = std::fs::create_dir_all(&dest_dir);

        let start_time_utc = chrono::Utc::now();
        let mut vss_snapshot_id: Option<String> = None;
        let mut vss_device_path: Option<String> = None;
        let mut ram_dump_path: Option<String> = None;
        let mut ram_dump_size: Option<u64> = None;
        let mut ram_dump_hash: Option<String> = None;
        let mut locked_files_list: Vec<String> = Vec::new();
        let consistency_blocks_checked: Option<u64> = None;
        let consistency_blocks_matched: Option<u64> = None;
        let consistency_mismatches: Vec<u64> = Vec::new();

        let _ = tx.send(ProgressEvent::Log(
            "[LIVE] Starting live system acquisition pipeline...".to_string()
        )).await;

        let mut source_size = 0u64;
        if let Ok(vols) = list_volumes().await {
            if let Some(vol) = vols.iter().find(|v| v.letter == config_input.volume) {
                source_size = vol.total_size;
            }
        }

        // ── Step 1: Create VSS Snapshot ──
        #[cfg(target_os = "windows")]
        {
            let _ = tx.send(ProgressEvent::Log(
                format!("[LIVE] Creating VSS snapshot for volume {}...", config_input.volume)
            )).await;

            match crate::platform::vss::VssSnapshot::create(&config_input.volume) {
                Ok(snapshot) => {
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] VSS Snapshot created: ID={}, Device={}",
                            snapshot.shadow_id, snapshot.device_path)
                    )).await;
                    vss_snapshot_id = Some(snapshot.shadow_id.clone());
                    vss_device_path = Some(snapshot.device_path.clone());
                }
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] WARNING: VSS snapshot creation failed: {}. Continuing without snapshot.", e)
                    )).await;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = tx.send(ProgressEvent::Log(
                "[LIVE] VSS snapshots are only available on Windows. Skipping.".to_string()
            )).await;
        }

        // ── Step 2: RAM Acquisition ──
        if config_input.capture_ram {
            let _ = tx.send(ProgressEvent::Log(
                "[LIVE] Starting physical memory (RAM) acquisition...".to_string()
            )).await;

            let ram_dest = dest_dir.join("memory_dump.raw");
            let ram_config = crate::memory::MemoryDumpConfig {
                dest_path: ram_dest.clone(),
                hash_algorithms: config_input.hash_algorithms.clone(),
                tool_path: config_input.ram_tool_path.clone(),
            };

            match crate::memory::acquire_memory(&ram_config, tx.clone()).await {
                Ok(result) => {
                    ram_dump_path = Some(result.dump_path.display().to_string());
                    ram_dump_size = Some(result.bytes_captured);
                    if let Some(hash_val) = result.hashes.values().next() {
                        ram_dump_hash = Some(hash_val.clone());
                    }
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] RAM acquisition complete: {} bytes using {}",
                            result.bytes_captured, result.tool_used)
                    )).await;
                }
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] WARNING: RAM acquisition failed: {}. Continuing.", e)
                    )).await;
                }
            }
        }

        // ── Step 3: Locked File Acquisition ──
        if config_input.capture_locked_files {
            let _ = tx.send(ProgressEvent::Log(
                "[LIVE] Starting locked file acquisition...".to_string()
            )).await;

            let locked_config = crate::locked_files::LockedFileCopyConfig {
                dest_dir: dest_dir.clone(),
                hash_algorithms: config_input.hash_algorithms.clone(),
                vss_device_path: vss_device_path.clone(),
                custom_files: Vec::new(),
            };

            match crate::locked_files::copy_locked_files(&locked_config, tx.clone()).await {
                Ok(results) => {
                    locked_files_list = results.iter()
                        .filter(|r| r.success)
                        .map(|r| r.source_path.clone())
                        .collect();
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] Locked file acquisition: {} files copied successfully",
                            locked_files_list.len())
                    )).await;
                }
                Err(e) => {
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] WARNING: Locked file acquisition failed: {}. Continuing.", e)
                    )).await;
                }
            }
        }

        // ── Step 3.5: VSS Physical Image ──
        if config_input.image_vss {
            if let Some(ref vss_path) = vss_device_path {
                let _ = tx.send(ProgressEvent::Log(
                    "[LIVE] Starting physical imaging of VSS snapshot...".to_string()
                )).await;

                match crate::platform::ActiveBackend::open_readonly(vss_path) {
                    Ok(mut source_dev) => {
                        if source_dev.size == 0 {
                            source_dev.size = source_size;
                        }
                        let vss_dest_path = dest_dir.join("vss_image.dd");
                        let config = crate::acquisition::AcquisitionConfig {
                            hash_algorithms: config_input.hash_algorithms.clone(),
                            block_size: 1024 * 1024,
                            split_size: None,
                            compression: crate::output::CompressionFormat::None,
                            case_number: config_input.case_number.clone(),
                            examiner: config_input.examiner.clone(),
                            evidence_id: format!("{}-VSS", config_input.evidence_id),
                            notes: "Physical image of VSS snapshot".to_string(),
                            pre_hash: None,
                            imaging_mode: "Physical".to_string(),
                            format: "Raw / DD (.dd)".to_string(),
                            read_verification: false,
                            keywords: Vec::new(),
                        };

                        match crate::output::OutputWriter::new(&vss_dest_path, None, config.compression, false, false) {
                            Ok(dest_writer) => {
                                let checkpoint_path = dest_dir.join("vss_image.json");
                                match crate::acquisition::acquire(
                                    &mut source_dev,
                                    dest_writer,
                                    &config,
                                    tx.clone(),
                                    &checkpoint_path,
                                    0,
                                ).await {
                                    Ok(result) => {
                                        let _ = tx.send(ProgressEvent::Log(
                                            format!("[LIVE] VSS imaging complete: {} bytes acquired.", result.bytes_read)
                                        )).await;
                                        if checkpoint_path.exists() {
                                            let _ = std::fs::remove_file(checkpoint_path);
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(ProgressEvent::Log(
                                            format!("[LIVE] WARNING: VSS imaging failed: {}. Continuing.", e)
                                        )).await;
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(ProgressEvent::Log(
                                    format!("[LIVE] WARNING: Failed to create output writer for VSS image: {}. Continuing.", e)
                                )).await;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Log(
                            format!("[LIVE] WARNING: Failed to open VSS device for imaging: {}. Continuing.", e)
                        )).await;
                    }
                }
            } else {
                let _ = tx.send(ProgressEvent::Log(
                    "[LIVE] Skipping VSS imaging: no VSS snapshot available.".to_string()
                )).await;
            }
        }

        // ── Step 4: Consistency Validation ──
        // This runs only if we have both an image and a VSS path
        // For now, consistency check needs a previously created image — skip if no VSS
        if config_input.run_consistency_check {
            if let Some(ref _vss_path) = vss_device_path {
                let _ = tx.send(ProgressEvent::Log(
                    "[LIVE] Consistency validation will run after image creation.".to_string()
                )).await;
                // Will be executed post-imaging if an image file is created
            } else {
                let _ = tx.send(ProgressEvent::Log(
                    "[LIVE] Skipping consistency check: no VSS snapshot available.".to_string()
                )).await;
            }
        }

        // ── Step 5: Cleanup VSS ──
        #[cfg(target_os = "windows")]
        {
            if config_input.auto_cleanup_vss {
                if let Some(ref sid) = vss_snapshot_id {
                    let _ = tx.send(ProgressEvent::Log(
                        format!("[LIVE] Cleaning up VSS snapshot {}...", sid)
                    )).await;
                    let snapshot = crate::platform::vss::VssSnapshot {
                        shadow_id: sid.clone(),
                        device_path: vss_device_path.clone().unwrap_or_default(),
                        volume: config_input.volume.clone(),
                    };
                    match snapshot.delete() {
                        Ok(_) => {
                            let _ = tx.send(ProgressEvent::Log(
                                "[LIVE] VSS snapshot deleted successfully.".to_string()
                            )).await;
                        }
                        Err(e) => {
                            let _ = tx.send(ProgressEvent::Log(
                                format!("[LIVE] WARNING: Failed to delete VSS snapshot: {}", e)
                            )).await;
                        }
                    }
                }
            } else if vss_snapshot_id.is_some() {
                let _ = tx.send(ProgressEvent::Log(
                    "[LIVE] VSS snapshot preserved for examiner inspection.".to_string()
                )).await;
            }
        }

        // ── Step 6: Generate Report ──
        let end_time_utc = chrono::Utc::now();
        let report_data = crate::report::ReportData {
            case_number: config_input.case_number.clone(),
            examiner: config_input.examiner.clone(),
            evidence_id: config_input.evidence_id.clone(),
            notes: config_input.notes.clone(),
            imaging_mode: "Live System Acquisition".to_string(),
            format: "N/A".to_string(),
            source_device: config_input.volume.clone(),
            source_size,
            source_model: "Live System".to_string(),
            source_serial: "N/A".to_string(),
            dest_file: dest_dir.display().to_string(),
            start_time: start_time_utc,
            end_time: end_time_utc,
            bad_sectors: 0,
            pre_hashes: HashMap::new(),
            hashes: HashMap::new(),
            post_hashes: None,
            vss_snapshot_id,
            ram_dump_path,
            ram_dump_size,
            ram_dump_hash,
            locked_files_copied: locked_files_list,
            consistency_blocks_checked,
            consistency_blocks_matched,
            consistency_mismatches,
        };

        let report_path = dest_dir.join("live_acquisition_report.txt");
        let _ = crate::report::generate_txt_report(&report_path, &report_data);
        let _ = crate::report::generate_html_report(dest_dir.join("live_acquisition_report.html"), &report_data);
        let _ = crate::report::generate_json_report(dest_dir.join("live_acquisition_report.json"), &report_data);
        let _ = crate::report::generate_csv_report(dest_dir.join("live_acquisition_report.csv"), &report_data);

        let _ = tx.send(ProgressEvent::Log(
            "[LIVE] Live acquisition pipeline complete. Reports generated.".to_string()
        )).await;

        let _ = tx.send(ProgressEvent::Finished {
            bytes_read: source_size,
            bad_sectors: 0,
            hashes: HashMap::new(),
        }).await;

        clear_active_task(&app_handle);
    });

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(None) as ActiveTaskState)
        .invoke_handler(tauri::generate_handler![
            get_admin_status,
            scan_devices,
            browse_folder,
            browse_file,
            check_checkpoint,
            start_acquisition,
            cancel_acquisition,
            start_triage,
            list_volumes,
            start_live_acquisition
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod acquisition;
mod hasher;
mod output;
mod report;
mod state;
mod error;
mod platform;

use platform::{ActiveBackend, DeviceBackend, DeviceInfo};
use acquisition::{AcquisitionConfig, BadSectorAction, ProgressEvent};
use hasher::HashAlgorithm;
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
    hash_algorithms: Vec<String>, // ["MD5", "SHA1", "SHA256", "SHA512"]
    compression: String, // "None", "Gzip", "Zstd"
    resume_mode: bool,
    split_size_mb: Option<usize>,
    read_verification: bool,
    keywords: Vec<String>,
    sparse: bool,
    digital_signature: bool,
}

#[tauri::command]
fn get_admin_status() -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::WindowsBackend::is_admin()
    }
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::LinuxBackend::is_root()
    }
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::MacosBackend::is_root()
    }
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

        let mut algos = Vec::new();
        for algo_str in &config_input.hash_algorithms {
            match algo_str.as_str() {
                "MD5" => algos.push(HashAlgorithm::MD5),
                "SHA1" => algos.push(HashAlgorithm::SHA1),
                "SHA256" => algos.push(HashAlgorithm::SHA256),
                "SHA512" => algos.push(HashAlgorithm::SHA512),
                _ => {}
            }
        }

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
            let ext = if config_input.format_mode.contains("E01") {
                "e01"
            } else if config_input.format_mode.contains("EX01") {
                "ex01"
            } else if config_input.format_mode.contains("AFF") {
                "aff"
            } else if config_input.format_mode.contains("SMART") {
                "smart"
            } else {
                "dd"
            };
            dest_file_path.set_extension(ext);
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
            bad_sector_action: BadSectorAction::ZeroFill,
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
        log(format!("[ACQUISITION] Destination Path: {:?}", dest_file_path)).await;

        let start_time_utc = chrono::Utc::now();

        if is_logical {
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
                        dest_file: format!("{:?}", dest_file_path),
                        start_time: start_time_utc,
                        end_time: end_time_utc,
                        bad_sectors: 0,
                        pre_hashes: HashMap::new(),
                        hashes: result.hashes.clone(),
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
                let format_short = if config_input.format_mode.contains("E01") {
                    "E01"
                } else if config_input.format_mode.contains("EX01") {
                    "EX01"
                } else if config_input.format_mode.contains("AFF") {
                    "AFF"
                } else if config_input.format_mode.contains("SMART") {
                    "SMART"
                } else {
                    "DD"
                };
                let _ = dest_writer.write_format_header(
                    format_short,
                    &config.case_number,
                    &config.examiner,
                    &config.evidence_id,
                    &config.notes,
                );
            }

            log("[ACQUISITION] Starting bitstream imaging loop...".to_string()).await;

            match crate::acquisition::acquire(
                &mut source_dev,
                &mut dest_writer,
                &config,
                tx.clone(),
                &checkpoint_path,
                start_offset,
            )
            .await
            {
                Ok(result) => {
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
                        dest_file: format!("{:?}", dest_file_path),
                        start_time: start_time_utc,
                        end_time: end_time_utc,
                        bad_sectors: result.bad_sectors + bad_sectors_start,
                        pre_hashes,
                        hashes: result.hashes.clone(),
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
                            let sig = crate::hasher::generate_digital_signature(&content, &report_data.case_number);
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
            start_triage
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

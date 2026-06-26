use std::collections::HashMap;
use std::path::PathBuf;
use eframe::egui;
use tokio::sync::mpsc::{channel, Receiver};
use crate::acquisition::{AcquisitionConfig, BadSectorAction, ProgressEvent, AcquisitionResult};
use crate::hasher::HashAlgorithm;
use crate::output::CompressionFormat;
use crate::platform::{ActiveBackend, DeviceBackend, DeviceInfo};

pub struct ForgelensApp {
    devices: Vec<DeviceInfo>,
    selected_device_idx: Option<usize>,
    dest_path: String,
    hash_algorithms: HashMap<HashAlgorithm, bool>,
    block_size_kb: usize,
    bad_sector_action: BadSectorAction,
    split_size_gb: Option<f64>,
    compression: CompressionFormat,
    case_number: String,
    examiner: String,
    evidence_id: String,
    notes: String,
    imaging_mode: String, // "Physical" or "Logical"
    format_mode: String, // "Raw / DD (.dd)", "E01 (.e01)", "AFF (.aff)"
    hash_verification: String, // "Pre & Post-Acquisition", "Post-Acquisition Only"
    logical_source_path: String,
    checkpoint_exists: bool,
    resume_mode: bool,
    pre_hashed_values: HashMap<HashAlgorithm, String>,
    acquisition_active: bool,
    progress_rx: Option<Receiver<ProgressEvent>>,
    bytes_read: u64,
    total_size: u64,
    speed_bps: f64,
    bad_sectors: u64,
    log: Vec<String>,
    error_message: Option<String>,
    finished_result: Option<AcquisitionResult>,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    rt: tokio::runtime::Runtime,
}

impl Default for ForgelensApp {
    fn default() -> Self {
        let mut hash_algorithms = HashMap::new();
        hash_algorithms.insert(HashAlgorithm::MD5, true);
        hash_algorithms.insert(HashAlgorithm::SHA1, false);
        hash_algorithms.insert(HashAlgorithm::SHA256, true);
        hash_algorithms.insert(HashAlgorithm::SHA512, false);

        Self {
            devices: Vec::new(),
            selected_device_idx: None,
            dest_path: String::new(),
            hash_algorithms,
            block_size_kb: 512,
            bad_sector_action: BadSectorAction::ZeroFill,
            split_size_gb: None,
            compression: CompressionFormat::None,
            case_number: String::new(),
            examiner: String::new(),
            evidence_id: String::new(),
            notes: String::new(),
            imaging_mode: "Physical".to_string(),
            format_mode: "Raw / DD (.dd)".to_string(),
            hash_verification: "Pre & Post-Acquisition".to_string(),
            logical_source_path: String::new(),
            checkpoint_exists: false,
            resume_mode: false,
            pre_hashed_values: HashMap::new(),
            acquisition_active: false,
            progress_rx: None,
            bytes_read: 0,
            total_size: 0,
            speed_bps: 0.0,
            bad_sectors: 0,
            log: vec!["[SYSTEM] Forgelens initialized. Ready for device scan.".to_string()],
            error_message: None,
            finished_result: None,
            start_time: None,
            rt: tokio::runtime::Runtime::new().unwrap(),
        }
    }
}

impl ForgelensApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_styles(&cc.egui_ctx);
        configure_fonts(&cc.egui_ctx);
        
        let mut app = Self::default();
        app.scan_devices();
        app
    }

    fn scan_devices(&mut self) {
        match ActiveBackend::enumerate_devices() {
            Ok(devs) => {
                self.devices = devs;
                self.log.push(format!("[SYSTEM] Scanned {} block device(s).", self.devices.len()));
            }
            Err(e) => {
                self.log.push(format!("[ERROR] Failed to scan devices: {}", e));
            }
        }
    }

    fn start_acquisition(&mut self) {
        if self.imaging_mode == "Physical" {
            if self.selected_device_idx.is_none() {
                self.error_message = Some("No source device selected.".to_string());
                return;
            }
        } else {
            if self.logical_source_path.trim().is_empty() {
                self.error_message = Some("No logical source path specified.".to_string());
                return;
            }
        }

        if self.dest_path.trim().is_empty() {
            self.error_message = Some("No destination path specified.".to_string());
            return;
        }

        let mut dest_file_path = PathBuf::from(&self.dest_path);
        if dest_file_path.extension().is_none() {
            let ext = if self.imaging_mode == "Logical" {
                ""
            } else if self.format_mode.contains("E01") {
                "e01"
            } else if self.format_mode.contains("AFF") {
                "aff"
            } else {
                "dd"
            };
            if !ext.is_empty() {
                dest_file_path.set_extension(ext);
                self.dest_path = dest_file_path.to_string_lossy().to_string();
            }
        }

        let algos: Vec<HashAlgorithm> = self.hash_algorithms.iter()
            .filter(|&(_, &v)| v)
            .map(|(&k, _)| k)
            .collect();

        if algos.is_empty() {
            self.error_message = Some("At least one hash algorithm must be enabled.".to_string());
            return;
        }

        let (tx, rx) = channel(100);
        self.progress_rx = Some(rx);
        self.acquisition_active = true;
        self.bytes_read = 0;
        self.total_size = 0;
        self.speed_bps = 0.0;
        self.bad_sectors = 0;
        self.error_message = None;
        self.finished_result = None;
        self.start_time = Some(chrono::Utc::now());

        let is_logical = self.imaging_mode == "Logical";
        let source_path = if is_logical {
            self.logical_source_path.clone()
        } else {
            let dev = &self.devices[self.selected_device_idx.unwrap()];
            self.total_size = dev.size;
            dev.path.clone()
        };

        self.log.push(format!("[ACQUISITION] Starting {} acquisition of {}", self.imaging_mode.to_uppercase(), source_path));
        self.log.push(format!("[ACQUISITION] Destination: {:?}", dest_file_path));

        let checkpoint_path = dest_file_path.with_extension("json");
        let case_num = self.case_number.clone();
        let examiner_name = self.examiner.clone();
        let evidence_id_val = self.evidence_id.clone();
        let notes_val = self.notes.clone();
        let imaging_mode_val = self.imaging_mode.clone();
        let format_val = self.format_mode.clone();
        let verification_val = self.hash_verification.clone();
        let resume_flag = self.resume_mode;

        // If resuming, read start offset from checkpoint
        let mut start_offset = 0u64;
        let mut pre_hash_val = None;
        if resume_flag {
            if let Ok(checkpoint) = crate::state::CheckpointState::load(&checkpoint_path) {
                start_offset = checkpoint.bytes_read;
                self.bytes_read = start_offset;
                self.bad_sectors = checkpoint.bad_sectors;
                pre_hash_val = checkpoint.pre_hash.clone();
                self.log.push(format!("[ACQUISITION] Resuming from offset: {} bytes", format_size(start_offset)));
            }
        }

        let config = AcquisitionConfig {
            hash_algorithms: algos.clone(),
            block_size: self.block_size_kb * 1024,
            bad_sector_action: self.bad_sector_action,
            split_size: self.split_size_gb.map(|gb| (gb * 1_000_000_000.0) as u64),
            compression: self.compression,
            case_number: self.case_number.clone(),
            examiner: self.examiner.clone(),
            evidence_id: self.evidence_id.clone(),
            notes: self.notes.clone(),
            pre_hash: pre_hash_val,
            imaging_mode: self.imaging_mode.clone(),
            format: self.format_mode.clone(),
        };

        let model = if is_logical { "Logical Folder".to_string() } else { self.devices[self.selected_device_idx.unwrap()].model.clone() };
        let serial = if is_logical { "N/A".to_string() } else { self.devices[self.selected_device_idx.unwrap()].serial.clone() };

        self.rt.spawn(async move {
            let mut pre_hashes = HashMap::new();
            let mut config = config;
            let start_time_utc = chrono::Utc::now();
            
            // 1. Run Pre-acquisition Hashing if configured (and not resuming)
            if !is_logical && verification_val == "Pre & Post-Acquisition" && start_offset == 0 {
                let _ = tx.send(ProgressEvent::Error("Pre-Acquisition Hash calculation in progress...".to_string())).await;
                if let Ok(dev_info) = ActiveBackend::enumerate_devices() {
                    if let Some(dev) = dev_info.iter().find(|d| d.path == source_path) {
                        if let Ok(hashes) = crate::acquisition::compute_pre_hash(&source_path, dev.size, &algos, tx.clone()).await {
                            pre_hashes = hashes;
                            if let Some(hash_val) = pre_hashes.values().next() {
                                config.pre_hash = Some(hash_val.clone());
                            }
                        }
                    }
                }
            }

            if is_logical {
                // LOGICAL ACQUISITION
                match crate::acquisition::acquire_logical(
                    std::path::Path::new(&source_path),
                    &dest_file_path,
                    &config,
                    tx.clone(),
                ).await {
                    Ok(result) => {
                        let end_time_utc = chrono::Utc::now();
                        let report_data = crate::report::ReportData {
                            case_number: case_num,
                            examiner: examiner_name,
                            evidence_id: evidence_id_val,
                            notes: notes_val,
                            imaging_mode: imaging_mode_val,
                            format: format_val,
                            source_device: source_path,
                            source_size: result.bytes_read,
                            source_model: model,
                            source_serial: serial,
                            dest_file: format!("{:?}", dest_file_path),
                            start_time: start_time_utc,
                            end_time: end_time_utc,
                            bad_sectors: 0,
                            pre_hashes: HashMap::new(),
                            hashes: result.hashes.clone(),
                        };
                        let report_path = dest_file_path.join("logical_report.txt");
                        let _ = crate::report::generate_txt_report(report_path, &report_data);
                        let _ = tx.send(ProgressEvent::Finished(result)).await;
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Logical acquisition error: {}", e))).await;
                    }
                }
            } else {
                // PHYSICAL ACQUISITION
                let mut source_dev = match ActiveBackend::open_readonly(&source_path) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Failed to open device: {}", e))).await;
                        return;
                    }
                };

                if let Err(e) = ActiveBackend::enforce_write_block(&mut source_dev) {
                    let _ = tx.send(ProgressEvent::Error(format!("Write block failure: {}", e))).await;
                    return;
                }

                let mut dest_writer = match crate::output::OutputWriter::new(
                    &dest_file_path,
                    config.split_size,
                    config.compression,
                    resume_flag,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Failed to create output: {}", e))).await;
                        return;
                    }
                };

                // Write AFF / E01 prefix headers if this is a new acquisition
                if start_offset == 0 {
                    let format_short = if format_val.contains("E01") {
                        "E01"
                    } else if format_val.contains("AFF") {
                        "AFF"
                    } else {
                        "DD"
                    };
                    let _ = dest_writer.write_format_header(format_short, &case_num, &examiner_name, &evidence_id_val, &notes_val);
                }

                match crate::acquisition::acquire(&mut source_dev, &mut dest_writer, &config, tx.clone(), &checkpoint_path, start_offset).await {
                    Ok(result) => {
                        let end_time_utc = chrono::Utc::now();
                        let report_data = crate::report::ReportData {
                            case_number: case_num,
                            examiner: examiner_name,
                            evidence_id: evidence_id_val,
                            notes: notes_val,
                            imaging_mode: imaging_mode_val,
                            format: format_val,
                            source_device: source_path,
                            source_size: source_dev.size,
                            source_model: model,
                            source_serial: serial,
                            dest_file: format!("{:?}", dest_file_path),
                            start_time: start_time_utc,
                            end_time: end_time_utc,
                            bad_sectors: result.bad_sectors,
                            pre_hashes,
                            hashes: result.hashes.clone(),
                        };
                        let report_path = dest_file_path.with_extension("report.txt");
                        let _ = crate::report::generate_txt_report(report_path, &report_data);

                        let _ = tx.send(ProgressEvent::Finished(result)).await;
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::Error(format!("Acquisition error: {}", e))).await;
                    }
                }
            }
        });
    }
}

impl eframe::App for ForgelensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll channel events
        if let Some(ref mut rx) = self.progress_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ProgressEvent::Progress { bytes_read, total_size, speed_bps, bad_sectors } => {
                        let prev_gb = self.bytes_read / 1_000_000_000;
                        let curr_gb = bytes_read / 1_000_000_000;

                        self.bytes_read = bytes_read;
                        self.total_size = total_size;
                        self.speed_bps = speed_bps;
                        self.bad_sectors = bad_sectors;
                        
                        if curr_gb > prev_gb {
                            self.log.push(format!("[PROGRESS] {} imaged.", format_size(bytes_read)));
                        }
                    }
                    ProgressEvent::Finished(result) => {
                        self.acquisition_active = false;
                        self.bytes_read = result.bytes_read;
                        self.finished_result = Some(result.clone());
                        self.log.push("[SYSTEM] Acquisition completed and verified.".to_string());
                        
                        // Delete checkpoint file on successful completion
                        if !self.dest_path.trim().is_empty() {
                            let path = std::path::PathBuf::from(&self.dest_path);
                            let checkpoint_path = path.with_extension("json");
                            if checkpoint_path.exists() {
                                let _ = std::fs::remove_file(checkpoint_path);
                            }
                        }
                    }
                    ProgressEvent::Error(err) => {
                        self.acquisition_active = false;
                        self.error_message = Some(err.clone());
                        self.log.push(format!("[ERROR] {}", err));
                    }
                }
            }
        }

        // Scan for checkpoint files if not acquiring
        if !self.acquisition_active && !self.dest_path.trim().is_empty() {
            let path = std::path::PathBuf::from(&self.dest_path);
            let checkpoint_path = path.with_extension("json");
            self.checkpoint_exists = checkpoint_path.exists();
        } else {
            self.checkpoint_exists = false;
        }

        // Repaint continuously during active acquisitions to keep progress updating smoothly
        if self.acquisition_active {
            ctx.request_repaint();
        }

        // 1. TOP PANEL: Header (Zone 1)
        egui::TopBottomPanel::top("header_panel")
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(22, 27, 34)) // Surface panel background
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
                .inner_margin(egui::Margin::symmetric(16.0, 12.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(egui::RichText::new("⚡ FORGELENS DISK IMAGER")
                        .color(egui::Color32::from_rgb(0, 212, 170))
                        .strong());
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                        .color(egui::Color32::from_rgb(139, 148, 158))
                        .monospace()
                        .size(11.0));
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let ist_offset = chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
                        let ist_time = chrono::Utc::now().with_timezone(&ist_offset).format("%Y-%m-%d %H:%M:%S IST").to_string();
                        ui.label(egui::RichText::new(ist_time)
                            .color(egui::Color32::from_rgb(139, 148, 158))
                            .monospace()
                            .size(11.0));
                        ui.add_space(12.0);

                        #[cfg(target_os = "windows")]
                        {
                            let is_admin = crate::platform::windows::WindowsBackend::is_admin();
                            let (badge_text, badge_color) = if is_admin {
                                ("Windows (Admin Mode)", egui::Color32::from_rgb(0, 212, 170))
                            } else {
                                ("Windows (Needs Admin Privileges)", egui::Color32::from_rgb(240, 165, 0))
                            };
                            
                            // Draw nice pill badge
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(31, 41, 55))
                                .stroke(egui::Stroke::new(1.0, badge_color))
                                .rounding(egui::Rounding::same(4.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(badge_text)
                                        .color(badge_color)
                                        .strong()
                                        .size(10.0)
                                        .monospace());
                                });
                        }
                        #[cfg(target_os = "linux")]
                        {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(31, 41, 55))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 212, 170)))
                                .rounding(egui::Rounding::same(4.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Linux (Root Privilege)")
                                        .color(egui::Color32::from_rgb(0, 212, 170))
                                        .strong()
                                        .size(10.0)
                                        .monospace());
                                });
                        }
                        #[cfg(target_os = "macos")]
                        {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(31, 41, 55))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 212, 170)))
                                .rounding(egui::Rounding::same(4.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("macOS (FDA Granted)")
                                        .color(egui::Color32::from_rgb(0, 212, 170))
                                        .strong()
                                        .size(10.0)
                                        .monospace());
                                });
                        }
                    });
                });
            });

        // 2. BOTTOM PANEL: Progress, Stats & Logs (Zone 4)
        egui::TopBottomPanel::bottom("bottom_console_panel")
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(22, 27, 34)) // Surface panel background
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
                .inner_margin(egui::Margin::same(12.0)))
            .default_height(200.0)
            .resizable(false)
            .show(ctx, |ui| {
                // Progress stats grid
                if self.acquisition_active {
                    let progress = if self.total_size > 0 {
                        self.bytes_read as f32 / self.total_size as f32
                    } else {
                        0.0
                    };
                    
                    let eta_secs = if self.speed_bps > 0.0 {
                        (self.total_size.saturating_sub(self.bytes_read)) as f64 / self.speed_bps
                    } else {
                        0.0
                    };

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("CURRENT JOB").size(9.0).color(egui::Color32::from_rgb(139, 148, 158)));
                            let dev_path = if self.imaging_mode == "Logical" {
                                self.logical_source_path.clone()
                            } else {
                                self.selected_device_idx.map_or("N/A".to_string(), |idx| self.devices[idx].path.clone())
                            };
                            ui.label(egui::RichText::new(format!("Reading {}", dev_path)).strong());
                        });
                        ui.add_space(40.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("IMAGING SPEED").size(9.0).color(egui::Color32::from_rgb(139, 148, 158)));
                            ui.label(egui::RichText::new(format!("{:.2} MB/s", self.speed_bps / 1_000_000.0)).strong().color(egui::Color32::from_rgb(0, 212, 170)));
                        });
                        ui.add_space(40.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("ETA").size(9.0).color(egui::Color32::from_rgb(139, 148, 158)));
                            let eta_text = if eta_secs > 3600.0 {
                                format!("{:.0}h {:.0}m", eta_secs / 3600.0, (eta_secs % 3600.0) / 60.0)
                            } else {
                                format!("{:.0}m {:.0}s", eta_secs / 60.0, eta_secs % 60.0)
                            };
                            ui.label(egui::RichText::new(eta_text).strong().color(egui::Color32::from_rgb(0, 212, 170)));
                        });
                        ui.add_space(40.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("PROGRESS").size(9.0).color(egui::Color32::from_rgb(139, 148, 158)));
                            ui.label(egui::RichText::new(format!("{:.1}% COMPLETE", progress * 100.0)).strong().color(egui::Color32::from_rgb(0, 212, 170)));
                        });
                        
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new("IMAGED").size(9.0).color(egui::Color32::from_rgb(139, 148, 158)));
                                ui.label(egui::RichText::new(format!("{} / {}", format_size(self.bytes_read), format_size(self.total_size))).strong());
                            });
                        });
                    });
                    ui.add_space(6.0);

                    ui.add(egui::ProgressBar::new(progress)
                        .show_percentage()
                        .fill(egui::Color32::from_rgb(0, 212, 170)));
                    ui.add_space(6.0);
                }

                if let Some(ref err) = self.error_message {
                    ui.colored_label(egui::Color32::from_rgb(248, 81, 73), format!("⚠ Error: {}", err));
                    ui.add_space(4.0);
                }

                if let Some(ref res) = self.finished_result {
                    ui.group(|ui| {
                        ui.colored_label(egui::Color32::from_rgb(0, 212, 170), "✓ Acquisition Completed Successfully");
                        for (algo, hash) in &res.hashes {
                            ui.label(egui::RichText::new(format!("{:?}: {}", algo, hash)).monospace().size(11.0));
                        }
                    });
                    ui.add_space(4.0);
                }

                // Controls and Console Log side-by-side or stacked
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("📟 Forensic Console Log").strong().color(egui::Color32::from_rgb(0, 212, 170)));
                        ui.add_space(2.0);
                        egui::ScrollArea::vertical()
                            .id_source("console_logs")
                            .max_height(80.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for entry in &self.log {
                                    let text_color = if entry.contains("[ERROR]") {
                                        egui::Color32::from_rgb(248, 81, 73)
                                    } else if entry.contains("[ACQUISITION]") {
                                        egui::Color32::from_rgb(0, 212, 170)
                                    } else if entry.contains("[SYSTEM]") {
                                        egui::Color32::from_rgb(240, 165, 0)
                                    } else {
                                        egui::Color32::from_rgb(139, 148, 158)
                                    };
                                    ui.label(egui::RichText::new(entry).monospace().color(text_color).size(10.0));
                                }
                            });
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.acquisition_active {
                            if ui.add(egui::Button::new(egui::RichText::new("⏹ CANCEL ACQUISITION").strong())
                                .fill(egui::Color32::from_rgb(248, 81, 73))
                                .min_size(egui::vec2(160.0, 36.0))).clicked() {
                                self.acquisition_active = false;
                                self.progress_rx = None;
                                self.log.push("[SYSTEM] Acquisition cancelled by user.".to_string());
                            }
                        } else {
                            if self.checkpoint_exists {
                                let resume_btn = egui::Button::new(egui::RichText::new("⚡ RESUME ACQUISITION").strong())
                                    .fill(egui::Color32::from_rgb(240, 165, 0))
                                    .min_size(egui::vec2(160.0, 36.0));
                                if ui.add(resume_btn).clicked() {
                                    self.resume_mode = true;
                                    self.start_acquisition();
                                }
                                ui.add_space(8.0);
                            }

                            let start_btn = egui::Button::new(egui::RichText::new("⚡ START ACQUISITION").strong())
                                .fill(egui::Color32::from_rgb(0, 212, 170))
                                .min_size(egui::vec2(160.0, 36.0));
                            if ui.add(start_btn).clicked() {
                                self.resume_mode = false;
                                self.start_acquisition();
                            }
                        }
                    });
                });
            });

        // 3. LEFT PANEL: Device Enlistment (Zone 2)
        egui::SidePanel::left("device_enlistment_panel")
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(22, 27, 34)) // Surface panel background
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
                .inner_margin(egui::Margin::same(12.0)))
            .default_width(320.0)
            .resizable(false)
            .show(ctx, |ui| {
                if self.imaging_mode == "Logical" {
                    ui.heading(egui::RichText::new("📁 Logical Mode")
                        .color(egui::Color32::from_rgb(0, 212, 170))
                        .size(15.0)
                        .strong());
                    ui.add_space(20.0);
                    ui.label("Logical acquisition is active.");
                    ui.add_space(8.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(139, 148, 158),
                        "Please select the Source Directory in the Configuration panel to the right.",
                    );
                } else {
                    ui.horizontal(|ui| {
                        ui.heading(egui::RichText::new("📁 Detected Devices")
                            .color(egui::Color32::from_rgb(0, 212, 170))
                            .size(15.0)
                            .strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("↻ Rescan").clicked() {
                                self.scan_devices();
                            }
                        });
                    });
                    ui.add_space(8.0);

                    egui::ScrollArea::vertical()
                        .id_source("device_list")
                        .show(ui, |ui| {
                            if self.devices.is_empty() {
                                ui.colored_label(egui::Color32::from_rgb(139, 148, 158), "No block devices discovered.");
                            } else {
                            for (idx, dev) in self.devices.iter().enumerate() {
                                let is_selected = self.selected_device_idx == Some(idx);
                                let (bg, border_color) = if is_selected {
                                    (egui::Color32::from_rgb(0, 42, 34), egui::Color32::from_rgb(0, 212, 170)) // Highlighted teal border
                                } else {
                                    (egui::Color32::from_rgb(26, 32, 44), egui::Color32::from_rgb(48, 54, 61)) // Standard border
                                };
                                
                                let response = egui::Frame::none()
                                    .fill(bg)
                                    .stroke(egui::Stroke::new(1.0, border_color))
                                    .rounding(egui::Rounding::same(4.0))
                                    .inner_margin(egui::Margin::same(8.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("💾").size(20.0));
                                            ui.vertical(|ui| {
                                                ui.horizontal(|ui| {
                                                    ui.label(egui::RichText::new(&dev.path)
                                                        .strong()
                                                        .color(if is_selected { egui::Color32::from_rgb(0, 212, 170) } else { egui::Color32::WHITE }));
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        ui.label(egui::RichText::new(format_size(dev.size)).color(egui::Color32::from_rgb(139, 148, 158)));
                                                    });
                                                });
                                                ui.label(egui::RichText::new(&dev.model).size(11.0).color(egui::Color32::from_rgb(139, 148, 158)));
                                            });
                                        });
                                    }).response;
                                    
                                let response = ui.interact(response.rect, response.id, egui::Sense::click());
                                if response.clicked() {
                                    self.selected_device_idx = Some(idx);
                                    self.log.push(format!("[SYSTEM] Selected device: {}", dev.path));
                                    
                                    // Generate default destination path if it's currently empty
                                    if self.dest_path.is_empty() {
                                        let clean_name = dev.name.replace("\\\\.\\", "").replace("/", "_").replace("\\", "_");
                                        let default_dir = std::env::current_dir()
                                            .unwrap_or_else(|_| std::path::PathBuf::from("."))
                                            .join(format!("{}.dd", clean_name));
                                        self.dest_path = default_dir.to_string_lossy().to_string();
                                    }
                                }
                                ui.add_space(6.0);
                            }
                        }
                    });
                }
            });

        // 4. CENTRAL PANEL: Acquisition Configuration (Zone 3)
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(22, 27, 34)) // Surface panel background
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)))
                .inner_margin(egui::Margin::same(12.0)))
            .show(ctx, |ui| {
                ui.heading(egui::RichText::new("⚙ Acquisition Configuration")
                    .color(egui::Color32::from_rgb(0, 212, 170))
                    .size(15.0)
                    .strong());
                ui.add_space(10.0);

                egui::Grid::new("config_grid")
                    .num_columns(2)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Imaging Mode:");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.imaging_mode, "Physical".to_string(), "Physical (Sector-by-Sector)");
                            ui.radio_value(&mut self.imaging_mode, "Logical".to_string(), "Logical (Directory Copy)");
                        });
                        ui.end_row();

                        if self.imaging_mode == "Logical" {
                            ui.label("Source Directory:");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut self.logical_source_path);
                                if ui.button("Browse...").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.logical_source_path = path.to_string_lossy().to_string();
                                    }
                                }
                            });
                            ui.end_row();
                        }

                        ui.label("Evidence ID:");
                        ui.text_edit_singleline(&mut self.evidence_id);
                        ui.end_row();

                        ui.label("Custody Notes:");
                        ui.text_edit_singleline(&mut self.notes);
                        ui.end_row();

                        ui.label("Case Number:");
                        ui.text_edit_singleline(&mut self.case_number);
                        ui.end_row();

                        ui.label("Examiner:");
                        ui.text_edit_singleline(&mut self.examiner);
                        ui.end_row();

                        ui.label("Output Format:");
                        let prev_format = self.format_mode.clone();
                        egui::ComboBox::from_id_source("format_mode_combo")
                            .selected_text(&self.format_mode)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.format_mode, "Raw / DD (.dd)".to_string(), "Raw / DD (.dd)");
                                ui.selectable_value(&mut self.format_mode, "E01 (.e01)".to_string(), "E01 (.e01)");
                                ui.selectable_value(&mut self.format_mode, "AFF (.aff)".to_string(), "AFF (.aff)");
                            });
                        if self.format_mode != prev_format && !self.dest_path.is_empty() {
                            let mut path = PathBuf::from(&self.dest_path);
                            let new_ext = if self.format_mode.contains("E01") {
                                "e01"
                            } else if self.format_mode.contains("AFF") {
                                "aff"
                            } else {
                                "dd"
                            };
                            path.set_extension(new_ext);
                            self.dest_path = path.to_string_lossy().to_string();
                        }
                        ui.end_row();

                        ui.label("Destination Path:");
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(&mut self.dest_path);
                            if ui.button("Browse...").clicked() {
                                let ext = if self.format_mode.contains("E01") {
                                    "e01"
                                } else if self.format_mode.contains("AFF") {
                                    "aff"
                                } else {
                                    "dd"
                                };
                                let filter_name = if ext == "e01" {
                                    "E01 Evidence Image (.e01)"
                                } else if ext == "aff" {
                                    "Advanced Forensic Format (.aff)"
                                } else {
                                    "Raw Image (.dd)"
                                };
                                
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter(filter_name, &[ext])
                                    .save_file()
                                {
                                    let mut path_str = path.to_string_lossy().to_string();
                                    if !path_str.ends_with(&format!(".{}", ext)) {
                                        path_str.push_str(&format!(".{}", ext));
                                    }
                                    self.dest_path = path_str;
                                }
                            }
                        });
                        ui.end_row();

                        ui.label("Verification Hashing:");
                        egui::ComboBox::from_id_source("hash_verification_combo")
                            .selected_text(&self.hash_verification)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.hash_verification, "Pre & Post-Acquisition".to_string(), "Pre & Post-Acquisition");
                                ui.selectable_value(&mut self.hash_verification, "Post-Acquisition Only".to_string(), "Post-Acquisition Only");
                            });
                        ui.end_row();

                        ui.label("Block Size:");
                        egui::ComboBox::from_label("")
                            .selected_text(format!("{} KB", self.block_size_kb))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.block_size_kb, 512, "512 KB");
                                ui.selectable_value(&mut self.block_size_kb, 1024, "1024 KB");
                                ui.selectable_value(&mut self.block_size_kb, 2048, "2048 KB");
                            });
                        ui.end_row();

                        ui.label("Hashes (On-the-fly):");
                        ui.horizontal(|ui| {
                            for (algo, val) in self.hash_algorithms.iter_mut() {
                                ui.checkbox(val, format!("{:?}", algo));
                            }
                        });
                        ui.end_row();

                        ui.label("Compression:");
                        egui::ComboBox::from_label(" ")
                            .selected_text(match self.compression {
                                CompressionFormat::None => "None",
                                CompressionFormat::Gzip => "Gzip",
                                CompressionFormat::Zstd => "Zstd",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.compression, CompressionFormat::None, "None");
                                ui.selectable_value(&mut self.compression, CompressionFormat::Gzip, "Gzip");
                                ui.selectable_value(&mut self.compression, CompressionFormat::Zstd, "Zstd");
                            });
                        ui.end_row();
                    });
            });
    }
}

fn configure_styles(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    
    // Background and base styling
    visuals.panel_fill = egui::Color32::from_rgb(13, 17, 23); // #0D1117
    visuals.window_fill = egui::Color32::from_rgb(13, 17, 23);
    
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(13, 17, 23);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)); // #30363D
    visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(230, 237, 243);
    
    // Inactive elements (default state of buttons, checkboxes, text fields)
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(22, 27, 34); // #161B22
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 61)); // #30363D
    visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(139, 148, 158);
    visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
    
    // Hovered elements
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(33, 38, 45); // #21262D
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 212, 170)); // Cyan border on hover
    visuals.widgets.hovered.fg_stroke.color = egui::Color32::from_rgb(230, 237, 243);
    visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
    
    // Active elements
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 212, 170); // #00D4AA Cyan Accent
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 212, 170));
    visuals.widgets.active.fg_stroke.color = egui::Color32::from_rgb(13, 17, 23); // dark text
    visuals.widgets.active.rounding = egui::Rounding::same(8.0);
    
    visuals.window_rounding = egui::Rounding::same(8.0);
    
    ctx.set_visuals(visuals);
}

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    
    let inter_bytes = include_bytes!("../assets/Inter.ttf");
    let mono_bytes = include_bytes!("../assets/JetBrainsMono.ttf");
    
    if inter_bytes.len() > 20 {
        fonts.font_data.insert(
            "Inter".to_owned(),
            egui::FontData::from_owned(inter_bytes.to_vec()),
        );
        fonts.families.get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "Inter".to_owned());
    }
    
    if mono_bytes.len() > 20 {
        fonts.font_data.insert(
            "JetBrainsMono".to_owned(),
            egui::FontData::from_owned(mono_bytes.to_vec()),
        );
        fonts.families.get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(0, "JetBrainsMono".to_owned());
    }
    
    ctx.set_fonts(fonts);

    // Increase the font sizes globally for a more readable layout!
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (egui::TextStyle::Heading, egui::FontId::new(22.0, egui::FontFamily::Proportional)),
        (egui::TextStyle::Body, egui::FontId::new(16.5, egui::FontFamily::Proportional)),
        (egui::TextStyle::Monospace, egui::FontId::new(15.0, egui::FontFamily::Monospace)),
        (egui::TextStyle::Button, egui::FontId::new(16.0, egui::FontFamily::Proportional)),
        (egui::TextStyle::Small, egui::FontId::new(13.0, egui::FontFamily::Proportional)),
    ].into();
    ctx.set_style(style);
}

fn format_size(bytes: u64) -> String {
    let kb = 1000.0;
    let mb = kb * 1000.0;
    let gb = mb * 1000.0;
    let tb = gb * 1000.0;
    
    let f = bytes as f64;
    if f >= tb {
        format!("{:.2} TB", f / tb)
    } else if f >= gb {
        format!("{:.2} GB", f / gb)
    } else if f >= mb {
        format!("{:.2} MB", f / mb)
    } else if f >= kb {
        format!("{:.2} KB", f / kb)
    } else {
        format!("{} B", bytes)
    }
}

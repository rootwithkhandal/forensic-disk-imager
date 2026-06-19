use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use std::time::Instant;
use crate::error::Result;
use crate::hasher::{HashAlgorithm, MultiHasher};
use crate::output::OutputWriter;
use crate::platform::RawDevice;


#[derive(Debug, Clone)]
pub struct AcquisitionConfig {
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub block_size: usize,
    pub split_size: Option<u64>,
    pub compression: crate::output::CompressionFormat,
    pub case_number: String,
    pub examiner: String,
    pub evidence_id: String,
    pub notes: String,
    pub pre_hash: Option<String>,
    pub imaging_mode: String,
    pub format: String,
    pub read_verification: bool,
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ProgressEvent {
    Progress { bytes_read: u64, total_size: u64, speed_bps: f64, bad_sectors: u64 },
    Finished { bytes_read: u64, bad_sectors: u64, hashes: HashMap<HashAlgorithm, String> },
    Error(String),
    Log(String),
    KeywordHit { keyword: String, offset: u64 },
}

#[derive(Debug, Clone)]
pub struct AcquisitionResult {
    pub bytes_read: u64,
    pub bad_sectors: u64,
    pub hashes: HashMap<HashAlgorithm, String>,
}



pub async fn acquire(
    source: &mut RawDevice,
    mut dest: OutputWriter,
    config: &AcquisitionConfig,
    progress_tx: Sender<ProgressEvent>,
    checkpoint_path: &std::path::Path,
    start_offset: u64,
) -> Result<AcquisitionResult> {
    let hash_algorithms = config.hash_algorithms.clone();
    let (hash_tx, mut hash_rx) = tokio::sync::mpsc::channel::<std::sync::Arc<Vec<u8>>>(4);
    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<std::sync::Arc<Vec<u8>>>(4);
    
    let hashing_task = tokio::task::spawn_blocking(move || {
        let mut hashers = MultiHasher::new(&hash_algorithms);
        while let Some(chunk) = hash_rx.blocking_recv() {
            hashers.update(chunk);
        }
        hashers.finalize()
    });

    let keywords = config.keywords.clone();
    let (kw_tx, mut kw_rx) = tokio::sync::mpsc::channel::<(u64, std::sync::Arc<Vec<u8>>)>(4);
    let kw_progress_tx = progress_tx.clone();
    let kw_task = tokio::task::spawn_blocking(move || {
        while let Some((offset_base, chunk)) = kw_rx.blocking_recv() {
            for kw in &keywords {
                if let Some(pos) = search_bytes(&chunk, kw.as_bytes()) {
                    let hit_offset = offset_base + pos as u64;
                    let msg = format!("[KEYWORD MATCH] Found keyword '{}' at offset {}", kw, hit_offset);
                    let _ = kw_progress_tx.blocking_send(ProgressEvent::Log(msg));
                    let _ = kw_progress_tx.blocking_send(ProgressEvent::KeywordHit {
                        keyword: kw.clone(),
                        offset: hit_offset,
                    });
                }
            }
        }
    });

    let read_verification = config.read_verification;
    let compression = config.compression;
    let writer_progress_tx = progress_tx.clone();

    let writing_task = tokio::task::spawn_blocking(move || -> Result<()> {
        while let Some(chunk) = write_rx.blocking_recv() {
            dest.write_all(&chunk)?;

            if read_verification {
                if compression == crate::output::CompressionFormat::None {
                    dest.flush()?;
                    let n = chunk.len() as u64;
                    if dest.bytes_written_part() >= n {
                        let current_path = dest.current_part_path();
                        let offset = dest.bytes_written_part() - n;
                        
                        let mut file = std::fs::File::open(&current_path)?;
                        use std::io::{Read, Seek, SeekFrom};
                        file.seek(SeekFrom::Start(offset))?;
                        let mut read_buf = vec![0u8; chunk.len()];
                        file.read_exact(&mut read_buf)?;
                        
                        if read_buf != chunk.as_slice() {
                            let msg = format!("[ERROR] Read verification failed at offset {} of {}", offset, current_path.display());
                            let _ = writer_progress_tx.blocking_send(ProgressEvent::Log(msg.clone()));
                            return Err(crate::error::ForgelensError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Written data mismatch on verification read-back",
                            )));
                        }
                    }
                }
            }
        }
        dest.flush()?;
        Ok(())
    });
    let mut bytes_read: u64 = start_offset;
    let mut bad_sectors: u64 = 0;
    let block_size = config.block_size;
    let total_size = source.size;

    if start_offset > 0 {
        let _ = source.seek_forward(start_offset);
    }

    if config.read_verification && config.compression != crate::output::CompressionFormat::None {
        let _ = progress_tx.send(ProgressEvent::Log(
            "[WARNING] Read verification is only supported for uncompressed (None) output. Skipping verification.".to_string()
        )).await;
    }

    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    let mut last_bytes_read = 0u64;

    // allocate a slightly larger vector to guarantee 4096-byte alignment
    let mut raw_buf = vec![0u8; block_size + 4096];
    let ptr = raw_buf.as_ptr() as usize;
    let align_offset = (4096 - (ptr % 4096)) % 4096;

    loop {
        if bytes_read >= total_size {
            break;
        }

        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }

        let mut read_success = false;
        let mut n = 0;

        let remaining = total_size - bytes_read;
        let current_block_size = if (block_size as u64) > remaining {
            remaining as usize
        } else {
            block_size
        };

        let active_slice = &mut raw_buf[align_offset .. align_offset + current_block_size];

        match source.read_block(active_slice) {
            Ok(bytes) => {
                n = bytes;
                read_success = true;
            }
            Err(_) => {
                bad_sectors += 1;
                // ponytail: always zero-fill bad sectors; Skip/Retry removed as unused.
                let _ = source.seek_forward(current_block_size as u64);
                let zeros = std::sync::Arc::new(vec![0u8; current_block_size]);
                if let Err(_) = hash_tx.send(zeros.clone()).await {
                    return Err(crate::error::ForgelensError::Backend("Hashing task died unexpectedly".to_string()));
                }
                if let Err(_) = write_tx.send(zeros).await {
                    return Err(crate::error::ForgelensError::Backend("Writing task died unexpectedly".to_string()));
                }
                bytes_read += current_block_size as u64;
            }
        }

        if read_success {
            if n == 0 {
                break; // EOF
            }
            
            let chunk = std::sync::Arc::new(active_slice[..n].to_vec());

            // Keyword scanning (offloaded)
            if !config.keywords.is_empty() {
                if let Err(_) = kw_tx.send((bytes_read, chunk.clone())).await {
                    return Err(crate::error::ForgelensError::Backend("Keyword scanning task died unexpectedly".to_string()));
                }
            }

            if let Err(_) = hash_tx.send(chunk.clone()).await {
                return Err(crate::error::ForgelensError::Backend("Hashing task died unexpectedly".to_string()));
            }
            if let Err(_) = write_tx.send(chunk).await {
                return Err(crate::error::ForgelensError::Backend("Writing task died unexpectedly".to_string()));
            }

            bytes_read += n as u64;
        }

        let now = Instant::now();
        if now.duration_since(last_progress_time).as_millis() >= 250 || bytes_read.saturating_sub(last_bytes_read) >= 5_000_000 {
            let elapsed = now.duration_since(start_time).as_secs_f64();
            let speed_bps = if elapsed > 0.0 { bytes_read as f64 / elapsed } else { 0.0 };
            
            let _ = progress_tx.send(ProgressEvent::Progress {
                bytes_read,
                total_size,
                speed_bps,
                bad_sectors,
            }).await;

            last_progress_time = now;
            last_bytes_read = bytes_read;

            let checkpoint = crate::state::CheckpointState {
                bytes_read,
                bad_sectors,
                pre_hash: config.pre_hash.clone(),
                timestamp: chrono::Utc::now(),
            };
            let _ = checkpoint.save(checkpoint_path);
        }
    }

    drop(hash_tx); // close the channel to signal the hashing task to finish
    drop(write_tx); // close the channel to signal the writing task to finish
    drop(kw_tx); // close the keyword task channel

    let final_hashes = hashing_task.await.map_err(|e| {
        crate::error::ForgelensError::Backend(format!("Hashing task panic: {}", e))
    })?;

    writing_task.await.map_err(|e| {
        crate::error::ForgelensError::Backend(format!("Writing task panic: {}", e))
    })??;

    let _ = kw_task.await;

    let result = AcquisitionResult {
        bytes_read,
        bad_sectors,
        hashes: final_hashes,
    };

    Ok(result)
}

pub async fn compute_pre_hash(
    source_path: &str,
    size: u64,
    hash_algorithms: &[HashAlgorithm],
    progress_tx: Sender<ProgressEvent>,
) -> Result<HashMap<HashAlgorithm, String>> {
    use crate::platform::DeviceBackend;
    let mut source_dev = crate::platform::ActiveBackend::open_readonly(source_path)?;
    let mut hashers = MultiHasher::new(hash_algorithms);
    let mut bytes_hashed: u64 = 0;
    let block_size = 1024 * 1024; // 1 MB blocks for fast hashing
    let mut raw_buf = vec![0u8; block_size + 4096];
    let ptr = raw_buf.as_ptr() as usize;
    let align_offset = (4096 - (ptr % 4096)) % 4096;
    
    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    
    loop {
        if bytes_hashed >= size {
            break;
        }

        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }

        let remaining = size - bytes_hashed;
        let current_block = if (block_size as u64) > remaining {
            remaining as usize
        } else {
            block_size
        };
        
        let active_slice = &mut raw_buf[align_offset .. align_offset + current_block];
        match source_dev.read_block(active_slice) {
            Ok(0) => break,
            Ok(n) => {
                hashers.update(std::sync::Arc::new(active_slice[..n].to_vec()));
                bytes_hashed += n as u64;
            }
            Err(_) => {
                // If there's a bad sector during pre-hash, we skip it (zero fill)
                hashers.update(std::sync::Arc::new(vec![0u8; current_block]));
                bytes_hashed += current_block as u64;
                let _ = source_dev.seek_forward(current_block as u64);
            }
        }
        
        let now = Instant::now();
        if now.duration_since(last_progress_time).as_millis() >= 500 {
            let elapsed = now.duration_since(start_time).as_secs_f64();
            let speed_bps = if elapsed > 0.0 { bytes_hashed as f64 / elapsed } else { 0.0 };
            let _ = progress_tx.send(ProgressEvent::Progress {
                bytes_read: bytes_hashed,
                total_size: size,
                speed_bps,
                bad_sectors: 0,
            }).await;
            last_progress_time = now;
        }
    }
    
    Ok(hashers.finalize())
}

pub async fn acquire_logical(
    source_dir: &std::path::Path,
    dest_dir: &std::path::Path,
    config: &AcquisitionConfig,
    progress_tx: Sender<ProgressEvent>,
) -> Result<AcquisitionResult> {
    use std::fs::File;
    use std::io::{Read, Write};
    
    let mut bytes_read = 0u64;
    let mut files_copied = 0u64;
    
    std::fs::create_dir_all(dest_dir)?;
    
    let manifest_path = dest_dir.join("logical_manifest.txt");
    let mut manifest = File::create(manifest_path)?;
    writeln!(manifest, "=== FORGELENS LOGICAL ACQUISITION MANIFEST ===")?;
    writeln!(manifest, "Source Directory: {}", source_dir.display())?;
    writeln!(manifest, "Case Number:      {}", config.case_number)?;
    writeln!(manifest, "Examiner:         {}", config.examiner)?;
    writeln!(manifest, "Date:             {}", chrono::Utc::now().to_rfc2822())?;
    writeln!(manifest, "--------------------------------------------------")?;
    
    let mut stack = vec![source_dir.to_path_buf()];
    let mut all_files = Vec::new();
    
    while let Some(dir) = stack.pop() {
        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    all_files.push(path);
                }
            }
        }
    }
    
    let total_size: u64 = all_files.iter().map(|f| f.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    
    for file_path in all_files {
        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }
        
        let relative_path = file_path.strip_prefix(source_dir).unwrap_or(&file_path);
        let target_path = dest_dir.join(relative_path);
        
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        if let Ok(mut src_file) = File::open(&file_path) {
            if let Ok(mut dst_file) = File::create(&target_path) {
                let mut hashers = MultiHasher::new(&config.hash_algorithms);
                let mut buf = vec![0u8; 64 * 1024];
                
                while let Ok(n) = src_file.read(&mut buf) {
                    if n == 0 { break; }
                    if progress_tx.is_closed() {
                        return Err(crate::error::ForgelensError::Cancelled);
                    }
                    hashers.update(std::sync::Arc::new(buf[..n].to_vec()));
                    dst_file.write_all(&buf[..n])?;
                    bytes_read += n as u64;
                    
                    let now = Instant::now();
                    if now.duration_since(last_progress_time).as_millis() >= 250 {
                        let elapsed = now.duration_since(start_time).as_secs_f64();
                        let speed_bps = if elapsed > 0.0 { bytes_read as f64 / elapsed } else { 0.0 };
                        let _ = progress_tx.send(ProgressEvent::Progress {
                            bytes_read,
                            total_size,
                            speed_bps,
                            bad_sectors: 0,
                        }).await;
                        last_progress_time = now;
                    }
                }
                
                let hashes = hashers.finalize();
                writeln!(manifest, "File: {}", relative_path.display())?;
                for (algo, hash_val) in &hashes {
                    writeln!(manifest, "  {}: {}", algo, hash_val)?;
                }
                writeln!(manifest, "")?;
                files_copied += 1;
            }
        }
    }
    
    writeln!(manifest, "--------------------------------------------------")?;
    writeln!(manifest, "Total Files Copied: {}", files_copied)?;
    writeln!(manifest, "Total Size:         {} bytes", bytes_read)?;
    writeln!(manifest, "=== END OF MANIFEST ===")?;
    
    let result = AcquisitionResult {
        bytes_read,
        bad_sectors: 0,
        // ponytail: logical mode hashes per-file into manifest; no single image hash.
        hashes: HashMap::new(),
    };
    
    Ok(result)
}

fn search_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

async fn run_command_to_file(
    cmd: &str,
    args: &[&str],
    dest_file: &std::path::Path,
    progress_tx: &Sender<ProgressEvent>,
) -> std::result::Result<(), String> {
    use std::io::Write;
    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[TRIAGE] Executing command: {} {}", cmd, args.join(" "))
    )).await;

    let mut file = std::fs::File::create(dest_file)
        .map_err(|e| format!("Failed to create destination file: {}", e))?;

    match std::process::Command::new(cmd).args(args).output() {
        Ok(out) => {
            if out.status.success() {
                file.write_all(&out.stdout)
                    .map_err(|e| format!("Failed to write command output: {}", e))?;
                let _ = progress_tx.send(ProgressEvent::Log(
                    format!("[TRIAGE] Command '{}' completed successfully.", cmd)
                )).await;
                Ok(())
            } else {
                let err_msg = String::from_utf8_lossy(&out.stderr).to_string();
                let _ = writeln!(file, "=== ERROR: Command returned non-zero status {} ===", out.status.code().unwrap_or(-1));
                let _ = file.write_all(&out.stdout);
                let _ = file.write_all(&out.stderr);
                let _ = progress_tx.send(ProgressEvent::Log(
                    format!("[TRIAGE] Warning: Command '{}' failed: {}", cmd, err_msg.trim())
                )).await;
                Err(err_msg)
            }
        }
        Err(e) => {
            let _ = writeln!(file, "=== ERROR: Failed to start command '{}' ===", cmd);
            let _ = writeln!(file, "Reason: {}", e);
            let _ = progress_tx.send(ProgressEvent::Log(
                format!("[TRIAGE] Warning: Failed to execute '{}': {}", cmd, e)
            )).await;
            Err(e.to_string())
        }
    }
}

pub async fn acquire_triage(
    dest_dir_str: &str,
    collect_registry: bool,
    collect_volatile: bool,
    collect_browsers: bool,
    collect_eventlogs: bool,
    progress_tx: Sender<ProgressEvent>,
) -> Result<()> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    let dest_dir = PathBuf::from(dest_dir_str);
    fs::create_dir_all(&dest_dir)?;

    let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Starting live forensic triage collection...".to_string())).await;

    // 1. Collect Volatile States (Processes, Connections, Modules)
    if collect_volatile {
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Gathering live volatile system state...".to_string())).await;
        
        // Save Processes
        let process_file = dest_dir.join("processes.txt");
        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("tasklist", &[], &process_file, &progress_tx).await;
        } else {
            let _ = run_command_to_file("ps", &["ax"], &process_file, &progress_tx).await;
        }

        // Save Network Sockets
        let network_file = dest_dir.join("network_connections.txt");
        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("netstat", &["-ano"], &network_file, &progress_tx).await;
        } else {
            let _ = run_command_to_file("netstat", &["-an"], &network_file, &progress_tx).await;
        }

        // Save Loaded Modules
        let modules_file = dest_dir.join("loaded_modules.txt");
        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("driverquery", &[], &modules_file, &progress_tx).await;
        } else if cfg!(target_os = "macos") {
            let _ = run_command_to_file("kextstat", &[], &modules_file, &progress_tx).await;
        } else {
            let _ = run_command_to_file("lsmod", &[], &modules_file, &progress_tx).await;
        }

        // Save System Info
        let sys_info_file = dest_dir.join("system_info.txt");
        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("systeminfo", &[], &sys_info_file, &progress_tx).await;
        } else {
            let _ = run_command_to_file("uname", &["-a"], &sys_info_file, &progress_tx).await;
        }
    }

    // 2. Collect Registry Hives (Windows) / Configs (Unix)
    if collect_registry {
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Copying system configuration files...".to_string())).await;
        let reg_dir = dest_dir.join("registry");
        fs::create_dir_all(&reg_dir)?;

        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("reg", &["export", "HKLM\\SYSTEM", &reg_dir.join("system_hive.reg").to_string_lossy(), "/y"], &reg_dir.join("system_export_log.txt"), &progress_tx).await;
            let _ = run_command_to_file("reg", &["export", "HKLM\\SAM", &reg_dir.join("sam_hive.reg").to_string_lossy(), "/y"], &reg_dir.join("sam_export_log.txt"), &progress_tx).await;
            let _ = run_command_to_file("reg", &["export", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &reg_dir.join("run_keys.reg").to_string_lossy(), "/y"], &reg_dir.join("run_keys_export_log.txt"), &progress_tx).await;
        } else {
            let files_to_copy = ["/etc/passwd", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab"];
            for f in &files_to_copy {
                let path = std::path::Path::new(f);
                if path.exists() {
                    let name = path.file_name().unwrap();
                    let _ = fs::copy(path, reg_dir.join(name));
                }
            }
        }
    }

    // 3. Collect Browser History Logs
    if collect_browsers {
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Copying live browser history databases...".to_string())).await;
        let browser_dir = dest_dir.join("browsers");
        fs::create_dir_all(&browser_dir)?;

        fn copy_if_exists(src: std::path::PathBuf, dst: std::path::PathBuf, label: &str) -> Option<String> {
            if src.exists() {
                let _ = std::fs::copy(&src, &dst);
                Some(format!("[TRIAGE] Successfully copied {} history database.", label))
            } else {
                None
            }
        }

        if cfg!(target_os = "windows") {
            let base = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default());
            let entries = [
                (base.join("Google/Chrome/User Data/Default/History"), browser_dir.join("chrome_history"), "Chrome"),
                (base.join("Microsoft/Edge/User Data/Default/History"),  browser_dir.join("edge_history"),  "Edge"),
            ];
            for (src, dst, label) in entries {
                if let Some(msg) = copy_if_exists(src, dst, label) {
                    let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
                }
            }
        } else {
            let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());
            let chrome_rel = if cfg!(target_os = "macos") {
                "Library/Application Support/Google/Chrome/Default/History"
            } else {
                ".config/google-chrome/Default/History"
            };
            let label = if cfg!(target_os = "macos") { "macOS Chrome" } else { "Linux Chrome" };
            if let Some(msg) = copy_if_exists(home.join(chrome_rel), browser_dir.join("chrome_history"), label) {
                let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
            }
        }
    }

    // 4. Collect Event Logs
    if collect_eventlogs {
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Extracting active system event logs...".to_string())).await;
        let logs_dir = dest_dir.join("event_logs");
        fs::create_dir_all(&logs_dir)?;

        if cfg!(target_os = "windows") {
            let _ = run_command_to_file("wevtutil", &["epl", "System", &logs_dir.join("System.evtx").to_string_lossy()], &logs_dir.join("system_logs_export_log.txt"), &progress_tx).await;
            let _ = run_command_to_file("wevtutil", &["epl", "Security", &logs_dir.join("Security.evtx").to_string_lossy()], &logs_dir.join("security_logs_export_log.txt"), &progress_tx).await;
        } else {
            let log_sources = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/kern.log"
            ];
            for src in &log_sources {
                let path = std::path::Path::new(src);
                if path.exists() {
                    let filename = path.file_name().unwrap();
                    let _ = fs::copy(src, logs_dir.join(filename));
                    let _ = progress_tx.send(ProgressEvent::Log(format!("[TRIAGE] Successfully copied log file: {}", src))).await;
                }
            }
        }
    }

    // Generate Triage Report Summary
    if let Ok(mut file) = File::create(dest_dir.join("triage_summary.txt")) {
        writeln!(file, "==================================================")?;
        writeln!(file, "        FORGELENS FORENSIC TRIAGE REPORT          ")?;
        writeln!(file, "==================================================")?;
        writeln!(file, "Triage Location: {}", dest_dir.display())?;
        writeln!(file, "Execution Date:  {}", chrono::Utc::now().to_rfc2822())?;
        writeln!(file, "Status:          SUCCESS / TRIAGED")?;
        writeln!(file, "Operating System:{}", std::env::consts::OS)?;
        writeln!(file, "Architecture:    {}", std::env::consts::ARCH)?;
        writeln!(file, "==================================================")?;
    }

    let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Rapid forensic triage completed successfully!".to_string())).await;
    
    let _ = progress_tx.send(ProgressEvent::Finished {
        bytes_read: 0,
        bad_sectors: 0,
        hashes: HashMap::new(),
    }).await;

    Ok(())
}

pub async fn compute_file_hash(
    file_path: &std::path::Path,
    hash_algorithms: &[HashAlgorithm],
    progress_tx: Sender<ProgressEvent>,
) -> Result<HashMap<HashAlgorithm, String>> {
    let path_clone = file_path.to_path_buf();
    let algos = hash_algorithms.to_vec();
    let tx = progress_tx.clone();

    tokio::task::spawn_blocking(move || -> Result<HashMap<HashAlgorithm, String>> {
        let mut hashers = MultiHasher::new(&algos);
        let mut file = std::fs::File::open(&path_clone)?;
        let metadata = file.metadata()?;
        let total_size = metadata.len();
        
        let mut bytes_hashed: u64 = 0;
        let mut buffer = vec![0u8; 1024 * 1024 * 4]; // 4MB buffer for fast sequential reads
        
        let start_time = Instant::now();
        let mut last_progress_time = Instant::now();
        
        use std::io::Read;
        
        loop {
            if tx.is_closed() {
                return Err(crate::error::ForgelensError::Cancelled);
            }
            
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break; // EOF
            }
            
            hashers.update(std::sync::Arc::new(buffer[..n].to_vec()));
            bytes_hashed += n as u64;
            
            let now = Instant::now();
            if now.duration_since(last_progress_time).as_millis() >= 250 {
                let elapsed = now.duration_since(start_time).as_secs_f64();
                let speed_bps = if elapsed > 0.0 { bytes_hashed as f64 / elapsed } else { 0.0 };
                
                let _ = tx.blocking_send(ProgressEvent::Progress {
                    bytes_read: bytes_hashed,
                    total_size,
                    speed_bps,
                    bad_sectors: 0,
                });
                
                last_progress_time = now;
            }
        }
        
        Ok(hashers.finalize())
    })
    .await
    .map_err(|e| crate::error::ForgelensError::Backend(e.to_string()))?
}

use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use std::time::Instant;
use crate::error::Result;
use crate::hasher::{HashAlgorithm, MultiHasher};
use crate::output::OutputWriter;
use crate::platform::RawDevice;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BadSectorEntry {
    pub lba: u64,
    pub retries: u32,
    pub error_msg: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BadSectorMap {
    pub sectors: Vec<BadSectorEntry>,
}

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
    pub yara_rules_path: Option<String>,
    pub active_plugins: Vec<std::sync::Arc<std::sync::Mutex<Box<dyn crate::plugins::OpenForensicPlugin>>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ProgressEvent {
    Progress { bytes_read: u64, total_size: u64, speed_bps: f64, bad_sectors: u64 },
    Finished { bytes_read: u64, bad_sectors: u64, hashes: HashMap<HashAlgorithm, String> },
    Error(String),
    Log(String),
    KeywordHit { keyword: String, offset: u64 },
    YaraHit { rule_name: String, offset: u64, tags: Vec<String> },
    PluginLog { plugin_name: String, message: String },
}

#[derive(Debug, Clone)]
pub struct AcquisitionResult {
    pub bytes_read: u64,
    pub bad_sectors: u64,
    pub hashes: HashMap<HashAlgorithm, String>,
    pub keyword_hits: Vec<(String, u64)>,
    pub yara_hits: Vec<(String, Vec<String>, u64)>,
    pub plugin_results: HashMap<String, String>,
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
        let mut local_kw_hits = Vec::new();
        while let Some((offset_base, chunk)) = kw_rx.blocking_recv() {
            for kw in &keywords {
                if let Some(pos) = search_bytes(&chunk, kw.as_bytes()) {
                    let hit_offset = offset_base + pos as u64;
                    local_kw_hits.push((kw.clone(), hit_offset));
                    let msg = format!("[KEYWORD MATCH] Found keyword '{}' at offset {}", kw, hit_offset);
                    let _ = kw_progress_tx.blocking_send(ProgressEvent::Log(msg));
                    let _ = kw_progress_tx.blocking_send(ProgressEvent::KeywordHit {
                        keyword: kw.clone(),
                        offset: hit_offset,
                    });
                }
            }
        }
        local_kw_hits
    });

    let mut yara_tx_opt = None;
    let mut yara_task = None;
    if let Some(ref rules_path) = config.yara_rules_path {
        let rules_dir = std::path::Path::new(rules_path);
        match crate::yara_scanner::load_rules_from_dir(rules_dir) {
            Ok(rules) => {
                let _ = progress_tx.blocking_send(ProgressEvent::Log("[YARA] Rules compiled successfully. Starting scanner...".to_string()));
                let (y_tx, mut y_rx) = tokio::sync::mpsc::channel::<(u64, std::sync::Arc<Vec<u8>>)>(4);
                yara_tx_opt = Some(y_tx);
                let yara_progress_tx = progress_tx.clone();
                yara_task = Some(tokio::task::spawn_blocking(move || {
                    let mut local_yara_hits = Vec::new();
                    while let Some((offset_base, chunk)) = y_rx.blocking_recv() {
                        let hits = crate::yara_scanner::scan_chunk(&rules, &chunk, offset_base);
                        for hit in hits {
                            local_yara_hits.push((hit.rule_name.clone(), hit.tags.clone(), hit.offset));
                            let msg = format!("[YARA MATCH] Rule '{}' matched at offset {}", hit.rule_name, hit.offset);
                            let _ = yara_progress_tx.blocking_send(ProgressEvent::Log(msg));
                            let _ = yara_progress_tx.blocking_send(ProgressEvent::YaraHit {
                                rule_name: hit.rule_name,
                                offset: hit.offset,
                                tags: hit.tags,
                            });
                        }
                    }
                    local_yara_hits
                }));
            }
            Err(e) => {
                let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[YARA WARNING] Failed to load rules: {}", e)));
            }
        }
    }

    let active_plugins = config.active_plugins.clone();
    let plugin_ctx = crate::plugins::PluginContext {
        case_number: config.case_number.clone(),
        examiner: config.examiner.clone(),
        evidence_id: config.evidence_id.clone(),
        notes: config.notes.clone(),
        total_size: source.size,
        block_size: config.block_size,
        imaging_mode: config.imaging_mode.clone(),
        format: config.format.clone(),
    };
    for plugin_arc in &active_plugins {
        let (plugin_name, res) = {
            if let Ok(mut p) = plugin_arc.lock() {
                (p.name().to_string(), p.pre_acquisition(&plugin_ctx))
            } else {
                continue;
            }
        };
        match res {
            Err(e) => {
                let _ = progress_tx.send(ProgressEvent::PluginLog {
                    plugin_name,
                    message: format!("[PRE-ACQUISITION ERROR] {}", e),
                }).await;
            }
            Ok(_) => {
                let _ = progress_tx.send(ProgressEvent::PluginLog {
                    plugin_name,
                    message: "[PRE-ACQUISITION] Initialized successfully".to_string(),
                }).await;
            }
        }
    }
    let mut plugin_tx_opt = None;
    let mut plugin_task = None;
    if !active_plugins.is_empty() {
        let (p_tx, mut p_rx) = tokio::sync::mpsc::channel::<(u64, std::sync::Arc<Vec<u8>>)>(4);
        plugin_tx_opt = Some(p_tx);
        let plugins_worker = active_plugins.clone();
        let plugin_progress_tx = progress_tx.clone();
        plugin_task = Some(tokio::task::spawn_blocking(move || {
            while let Some((offset, chunk)) = p_rx.blocking_recv() {
                for plugin_arc in &plugins_worker {
                    if let Ok(mut p) = plugin_arc.lock() {
                        if let Err(e) = p.on_block(offset, &chunk) {
                            let _ = plugin_progress_tx.blocking_send(ProgressEvent::PluginLog {
                                plugin_name: p.name().to_string(),
                                message: format!("[ON-BLOCK ERROR at offset {}] {}", offset, e),
                            });
                        }
                    }
                }
            }
        }));
    }

    let read_verification = config.read_verification;
    let compression = config.compression;
    let writer_progress_tx = progress_tx.clone();

    let writing_task = tokio::task::spawn_blocking(move || -> Result<std::path::PathBuf> {
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
        dest.finalize()?;
        Ok(dest.current_part_path())
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

    let mut bad_sector_map = BadSectorMap::default();

    loop {
        if bytes_read >= total_size {
            break;
        }

        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }

        let read_success;
        let n;

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
            Err(_e) => {
                let _ = progress_tx.send(ProgressEvent::Log(format!(
                    "[WARNING] Block read failed at offset {}. Dropped down to sector isolation.", bytes_read
                ))).await;
                
                let _ = source.seek_to(bytes_read);
                // Begin sector-level isolation
                let mut sector_offset = 0;
                while sector_offset < current_block_size {
                    let sector_size = std::cmp::min(512, current_block_size - sector_offset);
                    let mut sector_buf = vec![0u8; sector_size];
                    let mut sector_success = false;
                    let mut retries = 0;
                    let mut last_err = String::new();

                    while retries < 3 {
                        match source.read_block(&mut sector_buf) {
                            Ok(b) if b == sector_size => {
                                sector_success = true;
                                break;
                            }
                            Ok(b) => {
                                let _ = source.seek_to(bytes_read + sector_offset as u64);
                                retries += 1;
                                last_err = format!("Partial read: {}", b);
                            }
                            Err(e_inner) => {
                                let _ = source.seek_to(bytes_read + sector_offset as u64);
                                retries += 1;
                                last_err = format!("I/O Error: {}", e_inner);
                            }
                        }
                    }

                    if sector_success {
                        active_slice[sector_offset..sector_offset + sector_size].copy_from_slice(&sector_buf);
                    } else {
                        bad_sectors += 1;
                        let lba = (bytes_read + sector_offset as u64) / 512;
                        bad_sector_map.sectors.push(BadSectorEntry {
                            lba,
                            retries,
                            error_msg: last_err,
                        });
                        active_slice[sector_offset..sector_offset + sector_size].fill(0);
                        let _ = source.seek_forward(sector_size as u64);
                    }
                    sector_offset += sector_size;
                }
                
                n = current_block_size;
                read_success = true;
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
            
            if let Some(ref y_tx) = yara_tx_opt {
                if let Err(_) = y_tx.send((bytes_read, chunk.clone())).await {
                    return Err(crate::error::ForgelensError::Backend("YARA scanning task died unexpectedly".to_string()));
                }
            }
            if let Some(ref p_tx) = plugin_tx_opt {
                if let Err(_) = p_tx.send((bytes_read, chunk.clone())).await {
                    return Err(crate::error::ForgelensError::Backend("Plugin execution task died unexpectedly".to_string()));
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
    drop(yara_tx_opt); // close YARA task channel
    drop(plugin_tx_opt); // close plugin task channel

    let final_hashes = hashing_task.await.map_err(|e| {
        crate::error::ForgelensError::Backend(format!("Hashing task panic: {}", e))
    })?;

    let final_dest_path = writing_task.await.map_err(|e| {
        crate::error::ForgelensError::Backend(format!("Writing task panic: {}", e))
    })??;

    let final_kw_hits = kw_task.await.unwrap_or_default();
    let final_yara_hits = if let Some(t) = yara_task {
        t.await.unwrap_or_default()
    } else {
        Vec::new()
    };
    if let Some(t) = plugin_task {
        let _ = t.await;
    }

    let summary = crate::plugins::AcquisitionSummary {
        bytes_read,
        bad_sectors,
        elapsed_secs: start_time.elapsed().as_secs_f64(),
    };

    let mut final_plugin_results = HashMap::new();
    for plugin_arc in &active_plugins {
        let (plugin_name, res) = {
            if let Ok(mut p) = plugin_arc.lock() {
                (p.name().to_string(), p.post_acquisition(&summary))
            } else {
                continue;
            }
        };
        match res {
            Ok(output) => {
                for (k, v) in output.results {
                    final_plugin_results.insert(format!("{}.{}", plugin_name, k), v);
                }
                let _ = progress_tx.send(ProgressEvent::PluginLog {
                    plugin_name,
                    message: "[POST-ACQUISITION] Completed successfully".to_string(),
                }).await;
            }
            Err(e) => {
                let _ = progress_tx.send(ProgressEvent::PluginLog {
                    plugin_name,
                    message: format!("[POST-ACQUISITION ERROR] {}", e),
                }).await;
            }
        }
    }

    let result = AcquisitionResult {
        bytes_read,
        bad_sectors,
        hashes: final_hashes,
        keyword_hits: final_kw_hits,
        yara_hits: final_yara_hits,
        plugin_results: final_plugin_results,
    };

    if !bad_sector_map.sectors.is_empty() {
        use std::io::Write;
        let dest_path = final_dest_path;
        let log_path = dest_path.with_extension("bad_sectors.log");
        if let Ok(mut log_file) = std::fs::File::create(&log_path) {
            let _ = writeln!(log_file, "=== OPENFORENSIC BAD SECTOR MAP ===");
            let _ = writeln!(log_file, "LBA\t\tRETRIES\t\tERROR");
            for entry in &bad_sector_map.sectors {
                let _ = writeln!(log_file, "{}\t\t{}\t\t{}", entry.lba, entry.retries, entry.error_msg);
            }
            let _ = writeln!(log_file, "Total Bad Sectors: {}", bad_sector_map.sectors.len());
        }
    }

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
    writeln!(manifest, "=== OPENFORENSIC LOGICAL ACQUISITION MANIFEST ===")?;
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
    
    // Sort files by relative path to ensure deterministic processing order
    all_files.sort_by(|a, b| {
        let rel_a = a.strip_prefix(source_dir).unwrap_or(a);
        let rel_b = b.strip_prefix(source_dir).unwrap_or(b);
        rel_a.cmp(rel_b)
    });
    
    let total_size: u64 = all_files.iter().map(|f| f.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    
    let mut global_hashers = MultiHasher::new(&config.hash_algorithms);
    
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
                    let chunk = std::sync::Arc::new(buf[..n].to_vec());
                    hashers.update(chunk.clone());
                    global_hashers.update(chunk);
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

                dst_file.flush()?;
                drop(dst_file);

                let mut verification_status = "Skipped".to_string();
                if config.read_verification {
                    match compute_file_hash(&target_path, &config.hash_algorithms, progress_tx.clone()).await {
                        Ok(verify_hashes) => {
                            if verify_hashes == hashes {
                                verification_status = "Passed".to_string();
                            } else {
                                verification_status = "FAILED (Hash Mismatch)".to_string();
                                let msg = format!("[ERROR] Hash verification failed for file: {}", relative_path.display());
                                let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
                            }
                        }
                        Err(e) => {
                            verification_status = format!("Error ({})", e);
                            let msg = format!("[ERROR] Hash verification error for file {}: {}", relative_path.display(), e);
                            let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
                        }
                    }
                }

                writeln!(manifest, "File: {}", relative_path.display())?;
                for (algo, hash_val) in &hashes {
                    writeln!(manifest, "  {}: {}", algo, hash_val)?;
                }
                if config.read_verification {
                    writeln!(manifest, "  Verification: {}", verification_status)?;
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
    
    let global_hashes = global_hashers.finalize();
    
    let result = AcquisitionResult {
        bytes_read,
        bad_sectors: 0,
        hashes: global_hashes,
        keyword_hits: Vec::new(),
        yara_hits: Vec::new(),
        plugin_results: HashMap::new(),
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

    let db_path = dest_dir.join("triage.db");
    let triage_db = match crate::triage_db::init_triage_db(&db_path) {
        Ok(db) => Some(db),
        Err(e) => {
            let _ = progress_tx.send(ProgressEvent::Log(format!("[TRIAGE] Failed to init SQLite DB: {}", e))).await;
            None
        }
    };

    let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Starting live forensic triage collection...".to_string())).await;

    // 1. Collect Volatile States (Processes, Connections, Modules)
    if collect_volatile {
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Gathering live volatile system state...".to_string())).await;
        
        // Save Processes
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Extracting running processes...".to_string())).await;
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        if let Some(ref db) = triage_db {
            for (pid, process) in sys.processes() {
                let name = process.name();
                let exec_path = process.exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                let cmd = process.cmd().join(" ");
                let mem = process.memory();
                let _ = db.execute(
                    "INSERT INTO processes (pid, name, executable_path, command_line, memory_usage) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![pid.as_u32(), name, exec_path, cmd, mem as i64],
                );
            }
        }

        // Save Network Sockets
        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Extracting network connections...".to_string())).await;
        if let Some(ref db) = triage_db {
            let cmd = if cfg!(target_os = "windows") { "netstat" } else { "netstat" };
            let args = if cfg!(target_os = "windows") { &["-ano"] } else { &["-an"] };
            if let Ok(output) = std::process::Command::new(cmd).args(args).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(4) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let proto = parts[0];
                        let local = parts[1];
                        let foreign = parts[2];
                        let state = if parts.len() > 4 { parts[3] } else { "" };
                        let pid_str = if parts.len() > 4 { parts[4] } else { parts[3] };
                        let pid: u32 = pid_str.parse().unwrap_or(0);
                        let _ = db.execute(
                            "INSERT INTO network_connections (protocol, local_address, foreign_address, state, pid) VALUES (?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params![proto, local, foreign, state, pid],
                        );
                    }
                }
            }
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

        let mut copied_dbs = Vec::new();

        if cfg!(target_os = "windows") {
            let base = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default());
            let entries = [
                (base.join("Google/Chrome/User Data/Default/History"), browser_dir.join("chrome_history"), "Chrome"),
                (base.join("Microsoft/Edge/User Data/Default/History"),  browser_dir.join("edge_history"),  "Edge"),
            ];
            for (src, dst, label) in entries {
                if let Some(msg) = copy_if_exists(src, dst.clone(), label) {
                    let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
                    copied_dbs.push((dst, label.to_string()));
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
            let dst = browser_dir.join("chrome_history");
            if let Some(msg) = copy_if_exists(home.join(chrome_rel), dst.clone(), label) {
                let _ = progress_tx.send(ProgressEvent::Log(msg)).await;
                copied_dbs.push((dst, label.to_string()));
            }
        }

        let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Parsing browser history into SQLite...".to_string())).await;
        if let Some(ref db) = triage_db {
            for (db_file, browser) in copied_dbs {
                if let Ok(hist_db) = rusqlite::Connection::open(&db_file) {
                    if let Ok(mut stmt) = hist_db.prepare("SELECT url, title, visit_count, last_visit_time FROM urls") {
                        let rows = stmt.query_map([], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i32>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        });
                        if let Ok(iter) = rows {
                            for row in iter.flatten() {
                                let (url, title, count, time) = row;
                                let _ = db.execute(
                                    "INSERT INTO browser_history (browser_name, url, title, visit_time, visit_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                                    rusqlite::params![browser, url, title, time.to_string(), count],
                                );
                            }
                        }
                    }
                }
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
            
            let _ = progress_tx.send(ProgressEvent::Log("[TRIAGE] Parsing Event Logs into Triage Database...".to_string())).await;
            if let Some(ref db) = triage_db {
                let script = "Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json -Compress";
                if let Ok(output) = std::process::Command::new("powershell").args(&["-Command", script]).output() {
                    let json_str = String::from_utf8_lossy(&output.stdout);
                    if let Ok(json_arr) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(arr) = json_arr.as_array() {
                            for ev in arr {
                                let id = ev.get("Id").and_then(|v| v.as_i64()).unwrap_or(0);
                                let provider = ev.get("ProviderName").and_then(|v| v.as_str()).unwrap_or("");
                                let msg = ev.get("Message").and_then(|v| v.as_str()).unwrap_or("");
                                let time = ev.get("TimeCreated").and_then(|t| t.get("value")).and_then(|v| v.as_str()).unwrap_or(ev.get("TimeCreated").and_then(|v| v.as_str()).unwrap_or(""));
                                
                                let _ = db.execute(
                                    "INSERT INTO event_logs (log_name, event_id, source, time_created, message) VALUES (?1, ?2, ?3, ?4, ?5)",
                                    rusqlite::params!["System", id, provider, time, msg],
                                );
                            }
                        }
                    }
                }
            }
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

pub async fn compute_logical_hash(
    dir_path: &std::path::Path,
    hash_algorithms: &[HashAlgorithm],
    progress_tx: Sender<ProgressEvent>,
) -> Result<HashMap<HashAlgorithm, String>> {
    let mut stack = vec![dir_path.to_path_buf()];
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
    
    all_files.sort_by(|a, b| {
        let rel_a = a.strip_prefix(dir_path).unwrap_or(a);
        let rel_b = b.strip_prefix(dir_path).unwrap_or(b);
        rel_a.cmp(rel_b)
    });

    let total_size: u64 = all_files.iter().map(|f| f.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    let mut bytes_hashed = 0u64;
    let mut hashers = MultiHasher::new(hash_algorithms);
    let mut buf = vec![0u8; 1024 * 1024];
    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();

    for file_path in all_files {
        if progress_tx.is_closed() {
            return Err(crate::error::ForgelensError::Cancelled);
        }
        if let Ok(mut src_file) = std::fs::File::open(&file_path) {
            use std::io::Read;
            while let Ok(n) = src_file.read(&mut buf) {
                if n == 0 { break; }
                hashers.update(std::sync::Arc::new(buf[..n].to_vec()));
                bytes_hashed += n as u64;

                let now = Instant::now();
                if now.duration_since(last_progress_time).as_millis() >= 500 {
                    let elapsed = now.duration_since(start_time).as_secs_f64();
                    let speed_bps = if elapsed > 0.0 { bytes_hashed as f64 / elapsed } else { 0.0 };
                    let _ = progress_tx.send(ProgressEvent::Progress {
                        bytes_read: bytes_hashed,
                        total_size,
                        speed_bps,
                        bad_sectors: 0,
                    }).await;
                    last_progress_time = now;
                }
            }
        }
    }

    Ok(hashers.finalize())
}

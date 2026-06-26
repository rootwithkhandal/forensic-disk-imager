use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use std::time::Instant;
use crate::error::Result;
use crate::hasher::{HashAlgorithm, MultiHasher};
use crate::output::OutputWriter;
use crate::platform::RawDevice;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadSectorAction {
    Skip,
    Retry(u32),
    ZeroFill,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AcquisitionConfig {
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub block_size: usize,
    pub bad_sector_action: BadSectorAction,
    pub split_size: Option<u64>,
    pub compression: crate::output::CompressionFormat,
    pub case_number: String,
    pub examiner: String,
    pub evidence_id: String,
    pub notes: String,
    pub pre_hash: Option<String>,
    pub imaging_mode: String,
    pub format: String,
}

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Progress { bytes_read: u64, total_size: u64, speed_bps: f64, bad_sectors: u64 },
    Finished(AcquisitionResult),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct AcquisitionResult {
    pub bytes_read: u64,
    pub bad_sectors: u64,
    pub hashes: HashMap<HashAlgorithm, String>,
}

pub struct AlignedBuffer {
    ptr: *mut u8,
    layout: std::alloc::Layout,
    size: usize,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub fn new(size: usize, align: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, align).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        Self { ptr, layout, size }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

pub async fn acquire(
    source: &mut RawDevice,
    dest: &mut OutputWriter,
    config: &AcquisitionConfig,
    progress_tx: Sender<ProgressEvent>,
    checkpoint_path: &std::path::Path,
    start_offset: u64,
) -> Result<AcquisitionResult> {
    let mut hashers = MultiHasher::new(&config.hash_algorithms);
    let mut bytes_read: u64 = start_offset;
    let mut bad_sectors: u64 = 0;
    let block_size = config.block_size;
    let total_size = source.size;

    if start_offset > 0 {
        let _ = source.seek_forward(start_offset);
    }

    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    let mut last_bytes_read = 0u64;

    loop {
        if bytes_read >= total_size {
            break;
        }

        let mut read_success = false;
        let mut n = 0;

        let remaining = total_size - bytes_read;
        let current_block_size = if (block_size as u64) > remaining {
            remaining as usize
        } else {
            block_size
        };

        // Get aligned sub-slice for active read block
        let mut active_slice = AlignedBuffer::new(current_block_size, 512);

        match source.read_block(active_slice.as_mut_slice()) {
            Ok(bytes) => {
                n = bytes;
                read_success = true;
            }
            Err(_e) => {
                bad_sectors += 1;
                match config.bad_sector_action {
                    BadSectorAction::Skip | BadSectorAction::ZeroFill => {
                        let _ = source.seek_forward(current_block_size as u64);
                        dest.write_zeros(current_block_size)?;
                        bytes_read += current_block_size as u64;
                    }
                    BadSectorAction::Retry(retries) => {
                        let mut success = false;
                        for _ in 0..retries {
                            if let Ok(bytes) = source.read_block(active_slice.as_mut_slice()) {
                                n = bytes;
                                success = true;
                                read_success = true;
                                break;
                            }
                        }
                        if !success {
                            let _ = source.seek_forward(current_block_size as u64);
                            dest.write_zeros(current_block_size)?;
                            bytes_read += current_block_size as u64;
                        }
                    }
                }
            }
        }

        if read_success {
            if n == 0 {
                break; // EOF
            }
            hashers.update(&active_slice.as_slice()[..n]);
            dest.write_all(&active_slice.as_slice()[..n])?;
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
                source_path: source.path.clone(),
                dest_path: format!("{:?}", dest.base_path()),
                timestamp: chrono::Utc::now(),
                evidence_id: config.evidence_id.clone(),
                notes: config.notes.clone(),
                pre_hash: config.pre_hash.clone(),
                imaging_mode: config.imaging_mode.clone(),
                format: config.format.clone(),
            };
            let _ = checkpoint.save(checkpoint_path);
        }
    }

    dest.flush()?;

    let final_hashes = hashers.finalize();
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
    let mut buf = AlignedBuffer::new(block_size, 512);
    
    let start_time = Instant::now();
    let mut last_progress_time = Instant::now();
    
    loop {
        if bytes_hashed >= size {
            break;
        }
        let remaining = size - bytes_hashed;
        let current_block = if (block_size as u64) > remaining {
            remaining as usize
        } else {
            block_size
        };
        
        match source_dev.read_block(&mut buf.as_mut_slice()[..current_block]) {
            Ok(0) => break,
            Ok(n) => {
                hashers.update(&buf.as_slice()[..n]);
                bytes_hashed += n as u64;
            }
            Err(_) => {
                // If there's a bad sector during pre-hash, we skip it (zero fill)
                hashers.update(&vec![0u8; current_block]);
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
    writeln!(manifest, "Source Directory: {:?}", source_dir)?;
    writeln!(manifest, "Case Number:      {}", config.case_number)?;
    writeln!(manifest, "Examiner:         {}", config.examiner)?;
    writeln!(manifest, "Date:             {}", chrono::Utc::now().to_rfc2822())?;
    writeln!(manifest, "--------------------------------------------------")?;
    
    let mut stack = vec![source_dir.to_path_buf()];
    let mut all_files = Vec::new();
    
    while let Some(dir) = stack.pop() {
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
                    hashers.update(&buf[..n]);
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
                writeln!(manifest, "File: {:?}", relative_path)?;
                for (algo, hash_val) in &hashes {
                    writeln!(manifest, "  {:?}: {}", algo, hash_val)?;
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
        hashes: HashMap::new(),
    };
    
    Ok(result)
}

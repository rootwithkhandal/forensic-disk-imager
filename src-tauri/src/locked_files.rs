//! Locked file acquisition module.
//! Copies OS-locked files (registry hives, MFT, pagefile, etc.) via VSS shadow paths.

use crate::acquisition::ProgressEvent;
use crate::error::Result;
use crate::hasher::{HashAlgorithm, MultiHasher};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;

/// Information about a single copied locked file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CopiedFileInfo {
    pub source_path: String,
    pub dest_path: String,
    pub size: u64,
    pub hashes: HashMap<HashAlgorithm, String>,
    pub success: bool,
    pub error: Option<String>,
}

/// Configuration for locked file acquisition.
#[derive(Debug, Clone)]
pub struct LockedFileCopyConfig {
    /// Destination directory to copy files into.
    pub dest_dir: PathBuf,
    /// Hash algorithms for per-file integrity.
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// VSS shadow copy device path (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1).
    /// If provided, files are read through this path to bypass OS locks.
    pub vss_device_path: Option<String>,
    /// Override the list of files to copy. If empty, defaults are used.
    pub custom_files: Vec<String>,
}

/// Default list of locked system files to capture on Windows.
#[cfg(target_os = "windows")]
fn default_locked_files() -> Vec<&'static str> {
    vec![
        "Windows\\System32\\config\\SAM",
        "Windows\\System32\\config\\SECURITY",
        "Windows\\System32\\config\\SYSTEM",
        "Windows\\System32\\config\\SOFTWARE",
        "Windows\\System32\\config\\DEFAULT",
        "Windows\\System32\\config\\COMPONENTS",
        "Windows\\System32\\config\\BBI",
        // MFT — root of the volume
        "$MFT",
        // Pagefile and hibernation
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        // Windows event logs
        "Windows\\System32\\winevt\\Logs\\System.evtx",
        "Windows\\System32\\winevt\\Logs\\Security.evtx",
        "Windows\\System32\\winevt\\Logs\\Application.evtx",
        // Amcache for execution history
        "Windows\\AppCompat\\Programs\\Amcache.hve",
    ]
}

#[cfg(target_os = "linux")]
fn default_locked_files() -> Vec<&'static str> {
    vec![
        "etc/passwd",
        "etc/shadow",
        "etc/group",
        "etc/hosts",
        "etc/fstab",
        "var/log/auth.log",
        "var/log/syslog",
        "var/log/kern.log",
        "var/log/secure",
    ]
}

#[cfg(target_os = "macos")]
fn default_locked_files() -> Vec<&'static str> {
    vec![
        "etc/passwd",
        "etc/hosts",
        "var/log/system.log",
        "var/log/install.log",
    ]
}

/// Build the full source path for a locked file.
fn build_source_path(vss_device_path: &Option<String>, relative_path: &str) -> PathBuf {
    if let Some(ref vss_path) = vss_device_path {
        // Read through VSS shadow copy to bypass OS locks
        let base = vss_path.trim_end_matches('\\');
        let rel = relative_path.trim_start_matches('\\').trim_start_matches('/');
        PathBuf::from(format!("{}\\{}", base, rel))
    } else {
        // Try direct access (may fail for locked files)
        #[cfg(target_os = "windows")]
        {
            // Default to C: drive
            PathBuf::from(format!("C:\\{}", relative_path))
        }
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from(format!("/{}", relative_path))
        }
    }
}

/// Copy a single file with hashing.
fn copy_file_with_hash(
    src: &Path,
    dst: &Path,
    algorithms: &[HashAlgorithm],
) -> std::result::Result<(u64, HashMap<HashAlgorithm, String>), String> {
    let mut src_file = std::fs::File::open(src)
        .map_err(|e| format!("Failed to open {}: {}", src.display(), e))?;

    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
    }

    let mut dst_file = std::fs::File::create(dst)
        .map_err(|e| format!("Failed to create {}: {}", dst.display(), e))?;

    let mut hashers = MultiHasher::new(algorithms);
    let mut buf = vec![0u8; 64 * 1024]; // 64 KB chunks
    let mut total_bytes = 0u64;

    loop {
        match src_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hashers.update(std::sync::Arc::new(buf[..n].to_vec()));
                dst_file.write_all(&buf[..n])
                    .map_err(|e| format!("Write error: {}", e))?;
                total_bytes += n as u64;
            }
            Err(e) => {
                // For locked files, partial read is still valuable
                if total_bytes > 0 {
                    break;
                }
                return Err(format!("Read error: {}", e));
            }
        }
    }

    let hashes = hashers.finalize();
    Ok((total_bytes, hashes))
}

/// Copy all configured locked files from the system.
pub async fn copy_locked_files(
    config: &LockedFileCopyConfig,
    progress_tx: Sender<ProgressEvent>,
) -> Result<Vec<CopiedFileInfo>> {
    let _ = progress_tx.send(ProgressEvent::Log(
        "[LOCKED FILES] Starting locked file acquisition...".to_string()
    )).await;

    if config.vss_device_path.is_some() {
        let _ = progress_tx.send(ProgressEvent::Log(
            format!("[LOCKED FILES] Using VSS shadow copy path: {}",
                config.vss_device_path.as_ref().unwrap())
        )).await;
    } else {
        let _ = progress_tx.send(ProgressEvent::Log(
            "[LOCKED FILES] WARNING: No VSS snapshot available. Some locked files may fail to copy.".to_string()
        )).await;
    }

    // Build file list
    let file_list: Vec<String> = if !config.custom_files.is_empty() {
        config.custom_files.clone()
    } else {
        default_locked_files().iter().map(|s| s.to_string()).collect()
    };

    std::fs::create_dir_all(&config.dest_dir)?;

    let locked_files_dir = config.dest_dir.join("locked_files");
    std::fs::create_dir_all(&locked_files_dir)?;

    let mut results = Vec::new();
    let total = file_list.len();

    for (i, relative_path) in file_list.iter().enumerate() {
        let src_path = build_source_path(&config.vss_device_path, relative_path);
        
        // Create a safe destination filename (replace backslashes/slashes with underscores)
        let safe_name = relative_path
            .replace('\\', "_")
            .replace('/', "_")
            .replace('$', "_DOLLAR_");
        let dst_path = locked_files_dir.join(&safe_name);

        let _ = progress_tx.send(ProgressEvent::Log(
            format!("[LOCKED FILES] [{}/{}] Copying: {} ...", i + 1, total, relative_path)
        )).await;

        match copy_file_with_hash(&src_path, &dst_path, &config.hash_algorithms) {
            Ok((size, hashes)) => {
                let _ = progress_tx.send(ProgressEvent::Log(
                    format!("[LOCKED FILES] [{}/{}] ✓ Copied {} ({} bytes)", 
                        i + 1, total, relative_path, size)
                )).await;

                results.push(CopiedFileInfo {
                    source_path: src_path.display().to_string(),
                    dest_path: dst_path.display().to_string(),
                    size,
                    hashes,
                    success: true,
                    error: None,
                });
            }
            Err(err) => {
                let _ = progress_tx.send(ProgressEvent::Log(
                    format!("[LOCKED FILES] [{}/{}] ✗ Failed to copy {}: {}",
                        i + 1, total, relative_path, err)
                )).await;

                results.push(CopiedFileInfo {
                    source_path: src_path.display().to_string(),
                    dest_path: dst_path.display().to_string(),
                    size: 0,
                    hashes: HashMap::new(),
                    success: false,
                    error: Some(err),
                });
            }
        }
    }

    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.iter().filter(|r| !r.success).count();

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[LOCKED FILES] Locked file acquisition complete: {} succeeded, {} failed",
            success_count, fail_count)
    )).await;

    // Write a manifest
    let manifest_path = locked_files_dir.join("_manifest.txt");
    if let Ok(mut manifest) = std::fs::File::create(&manifest_path) {
        use std::io::Write;
        let _ = writeln!(manifest, "=== FORGELENS LOCKED FILE ACQUISITION MANIFEST ===");
        let _ = writeln!(manifest, "Date: {}", chrono::Utc::now().to_rfc2822());
        let _ = writeln!(manifest, "VSS Path: {}", config.vss_device_path.as_deref().unwrap_or("N/A (direct access)"));
        let _ = writeln!(manifest, "Total Files: {} (Success: {}, Failed: {})", results.len(), success_count, fail_count);
        let _ = writeln!(manifest, "---------------------------------------------------");
        for info in &results {
            let status = if info.success { "OK" } else { "FAILED" };
            let _ = writeln!(manifest, "[{}] {} -> {} ({} bytes)",
                status, info.source_path, info.dest_path, info.size);
            if info.success {
                for (algo, hash_val) in &info.hashes {
                    let _ = writeln!(manifest, "  {}: {}", algo, hash_val);
                }
            }
            if let Some(ref err) = info.error {
                let _ = writeln!(manifest, "  Error: {}", err);
            }
        }
        let _ = writeln!(manifest, "=== END OF MANIFEST ===");
    }

    Ok(results)
}

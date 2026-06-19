//! Physical memory (RAM) acquisition module.
//! Invokes external memory dumping tools to capture the system's physical memory.

use crate::acquisition::ProgressEvent;
use crate::error::{ForgelensError, Result};
use crate::hasher::{HashAlgorithm, MultiHasher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone)]
pub struct MemoryDumpConfig {
    pub dest_path: PathBuf,
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// Optional path to the memory dumping tool (e.g. winpmem_mini_x64.exe).
    /// If None, will search PATH and common locations.
    pub tool_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryDumpResult {
    pub bytes_captured: u64,
    #[allow(dead_code)]
    pub duration_secs: f64,
    pub hashes: HashMap<HashAlgorithm, String>,
    pub dump_path: PathBuf,
    pub tool_used: String,
}

/// Find the memory dumping tool on the system.
#[cfg(target_os = "windows")]
fn find_memory_tool(custom_path: &Option<String>) -> Option<PathBuf> {
    if let Some(ref path) = custom_path {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    
    // Check various potential locations for the bundled winpmem tools
    let candidates = [
        PathBuf::from("winpmem/winpmem_mini_x64_rc2.exe"),
        PathBuf::from("src-tauri/winpmem/winpmem_mini_x64_rc2.exe"),
        PathBuf::from("../src-tauri/winpmem/winpmem_mini_x64_rc2.exe"),
        PathBuf::from("winpmem/winpmem_mini_x86.exe"),
        PathBuf::from("src-tauri/winpmem/winpmem_mini_x86.exe"),
        PathBuf::from("../src-tauri/winpmem/winpmem_mini_x86.exe"),
    ];
    
    for candidate in &candidates {
        if candidate.exists() {
            return Some(candidate.clone());
        }
    }
    
    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop(); // remove exe name
        // Try looking next to the executable
        let p1 = exe_path.join("winpmem").join("winpmem_mini_x64_rc2.exe");
        if p1.exists() { return Some(p1); }
        let p2 = exe_path.join("winpmem").join("winpmem_mini_x86.exe");
        if p2.exists() { return Some(p2); }
    }

    // fallback to searching PATH with the new default name
    Some(PathBuf::from("winpmem_mini_x64_rc2.exe"))
}

#[cfg(target_os = "linux")]
fn find_memory_tool(custom_path: &Option<String>) -> Option<PathBuf> {
    if let Some(ref path) = custom_path {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Check various potential locations for the bundled avml tools
    let candidates = [
        PathBuf::from("avml/avml"),
        PathBuf::from("src-tauri/avml/avml"),
        PathBuf::from("../src-tauri/avml/avml"),
        PathBuf::from("/usr/bin/avml"),
        PathBuf::from("/usr/local/bin/avml"),
    ];
    
    for candidate in &candidates {
        if candidate.exists() {
            return Some(candidate.clone());
        }
    }
    
    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop(); // remove exe name
        // Try looking next to the executable
        let p1 = exe_path.join("avml").join("avml");
        if p1.exists() { return Some(p1); }
    }

    // Check if /proc/kcore is available (requires root)
    if Path::new("/proc/kcore").exists() {
        return Some(PathBuf::from("/proc/kcore"));
    }

    None
}

#[cfg(target_os = "macos")]
fn find_memory_tool(custom_path: &Option<String>) -> Option<PathBuf> {
    if let Some(ref path) = custom_path {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    // macOS SIP blocks direct memory access, so no tool available by default
    None
}

/// Hash an existing file on disk and return the hash values.
async fn hash_file(
    path: &Path,
    algorithms: &[HashAlgorithm],
    progress_tx: &Sender<ProgressEvent>,
) -> Result<HashMap<HashAlgorithm, String>> {
    use std::io::Read;

    let file_size = std::fs::metadata(path)?.len();
    let mut file = std::fs::File::open(path)?;
    let mut hashers = MultiHasher::new(algorithms);
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MB blocks
    let mut bytes_hashed = 0u64;
    let start = Instant::now();
    let mut last_progress = Instant::now();

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hashers.update(std::sync::Arc::new(buf[..n].to_vec()));
        bytes_hashed += n as u64;

        let now = Instant::now();
        if now.duration_since(last_progress).as_millis() >= 500 {
            let elapsed = now.duration_since(start).as_secs_f64();
            let speed = if elapsed > 0.0 { bytes_hashed as f64 / elapsed } else { 0.0 };
            let _ = progress_tx.send(ProgressEvent::Log(
                format!("[MEMORY] Hashing memory dump: {:.1}% ({:.1} MB/s)",
                    bytes_hashed as f64 / file_size as f64 * 100.0,
                    speed / 1_000_000.0)
            )).await;
            last_progress = now;
        }
    }

    Ok(hashers.finalize())
}

/// Acquire physical memory from the running system.
pub async fn acquire_memory(
    config: &MemoryDumpConfig,
    progress_tx: Sender<ProgressEvent>,
) -> Result<MemoryDumpResult> {
    let start_time = Instant::now();

    let tool = find_memory_tool(&config.tool_path);
    if tool.is_none() {
        return Err(ForgelensError::Backend(
            "No memory acquisition tool found. Please install WinPmem (Windows) or avml (Linux) and ensure it is accessible.".to_string()
        ));
    }
    let tool_path = tool.unwrap();
    let tool_name = tool_path.file_name().unwrap_or_default().to_string_lossy().to_string();

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[MEMORY] Found memory acquisition tool: {}", tool_path.display())
    )).await;

    let dest_path = &config.dest_path;

    // Ensure parent directory exists
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Special case: /proc/kcore on Linux — just copy it
    #[cfg(target_os = "linux")]
    let is_proc_kcore = tool_path == PathBuf::from("/proc/kcore");
    #[cfg(not(target_os = "linux"))]
    let is_proc_kcore = false;

    if is_proc_kcore {
        let _ = progress_tx.send(ProgressEvent::Log(
            "[MEMORY] Reading from /proc/kcore (kernel virtual memory)...".to_string()
        )).await;

        // Read a reasonable amount from /proc/kcore (first 2 GB or system RAM)
        use std::io::{Read, Write};
        let mut src = std::fs::File::open("/proc/kcore")?;
        let mut dst = std::fs::File::create(dest_path)?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        let max_read = 2 * 1024 * 1024 * 1024u64; // 2 GB cap

        loop {
            if total >= max_read { break; }
            match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    dst.write_all(&buf[..n])?;
                    total += n as u64;
                }
                Err(_) => break,
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let _ = progress_tx.send(ProgressEvent::Log(
            format!("[MEMORY] Captured {} bytes from /proc/kcore in {:.1}s", total, elapsed)
        )).await;

        // Hash the dump
        let _ = progress_tx.send(ProgressEvent::Log(
            "[MEMORY] Computing forensic hashes of memory dump...".to_string()
        )).await;
        let hashes = hash_file(dest_path, &config.hash_algorithms, &progress_tx).await?;

        return Ok(MemoryDumpResult {
            bytes_captured: total,
            duration_secs: elapsed,
            hashes,
            dump_path: dest_path.clone(),
            tool_used: "/proc/kcore".to_string(),
        });
    }

    // Standard tool invocation (winpmem / avml)
    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[MEMORY] Launching memory capture: {} -> {}", tool_name, dest_path.display())
    )).await;

    let output = std::process::Command::new(&tool_path)
        .arg(dest_path.to_string_lossy().as_ref())
        .output()
        .map_err(|e| ForgelensError::Backend(
            format!("Failed to execute memory tool '{}': {}", tool_name, e)
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ForgelensError::Backend(format!(
            "Memory acquisition tool '{}' failed:\nstdout: {}\nstderr: {}",
            tool_name,
            stdout.trim(),
            stderr.trim()
        )));
    }

    // Log tool output
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let _ = progress_tx.send(ProgressEvent::Log(
                format!("[MEMORY] {}", trimmed)
            )).await;
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();

    // Get dump file size
    let dump_size = std::fs::metadata(dest_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[MEMORY] Memory dump completed: {} bytes captured in {:.1}s", dump_size, elapsed)
    )).await;

    // Hash the dump file
    let _ = progress_tx.send(ProgressEvent::Log(
        "[MEMORY] Computing forensic hashes of memory dump...".to_string()
    )).await;
    let hashes = hash_file(dest_path, &config.hash_algorithms, &progress_tx).await?;

    for (algo, hash_val) in &hashes {
        let _ = progress_tx.send(ProgressEvent::Log(
            format!("[MEMORY] Memory dump {}: {}", algo, hash_val)
        )).await;
    }

    Ok(MemoryDumpResult {
        bytes_captured: dump_size,
        duration_secs: elapsed,
        hashes,
        dump_path: dest_path.clone(),
        tool_used: tool_name,
    })
}

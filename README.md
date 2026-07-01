# ⚡ Forgelens Disk Imager

Forgelens is a professional, cross-platform forensic disk imaging and system triage application built in Rust and powered by Tauri. It provides a secure, write-blocked method to copy physical storage media, perform logical acquisitions, collect volatile memory, and verify digital evidence integrity.

---

## 💻 System Requirements

**Operating Systems Supported:**
*   **Windows**: Windows 10, Windows 11 (64-bit)
*   **Linux**: Ubuntu 20.04+, Debian, Fedora, Arch Linux (Requires root access)
*   **macOS**: macOS 11.0 Big Sur or later (Requires Full Disk Access)

**Hardware Requirements:**
*   **RAM**: 4GB Minimum (8GB+ recommended for large multi-threaded hash verifications)
*   **Storage**: 100MB for the application, plus sufficient destination storage for acquired disk images and memory dumps.
*   **Permissions**: **Administrator / Root access is strictly required** for raw disk and memory access.

---

## ✨ Features

*   **100% Secure Write-Blocking**: Software-level safety switches ensure the original drive is never altered during the physical copying process.
*   **Logical Acquisition**: Targeted copying of specific files and folders, complete with dynamic hashing-based verification against read data.
*   **Live Physical Memory (RAM) Acquisition**: 
    *   **Windows**: Bundles `winpmem_mini_x64_rc2.exe` to seamlessly capture live system RAM.
    *   **Linux**: Supports capturing via `/proc/kcore` or `avml`.
    *   *Note: macOS memory capture is disabled by default due to System Integrity Protection (SIP).*
*   **Rapid System Triage**: Captures live diagnostic data (running processes, network sockets, loaded modules), copies live configs (Registry hives on Windows, `/etc` files on Unix), grabs browser history (Chrome/Edge), and extracts event logs (EVTX/syslog).
*   **Forensic Hash Verification**: Computes multi-algorithm digital fingerprints (MD5, SHA-1, SHA-256, SHA-512) simultaneously in a single pass to prove that the copy is a perfect match of the original.
*   **Real-Time Keyword & YARA Scanning**: Searches for specific strings or Indicators of Compromise (IOCs) on-the-fly during acquisition. Supports dropping in `.yar` rulesets for full pattern matching via a pure-Rust `yara-x` engine.
*   **Forensic Case Management System**: Automatically tracks all acquisitions in a secure local SQLite database. Generates court-admissible HTML reports mapping evidence tags, chain of custody hashes, and examiner notes to each case.
*   **Sparse Imaging & Compression**: Optimizes storage space by skipping sectors containing all zeroes and supports advanced compression formats (zstd, gzip).
*   **Advanced Filesystem & Encryption Detector**: Identifies partition formats (APFS, HFS+, ext2/3/4, XFS, Btrfs, ReFS) and encryption wrappers (BitLocker, LUKS, FileVault) automatically.
*   **Modern User Interface**: A premium, responsive dashboard showing progress, speed, and real-time logs in dedicated panels.

---

## 🏛️ System Design & Architecture

Forgelens uses a decoupled architecture powered by **Tauri**, providing a lightweight, native GUI experience without shipping a heavy browser runtime.

### 1. Frontend Layer
*   **Framework**: Built with modern web technologies and styled with raw CSS for a premium, dark-themed forensic interface.
*   **Communication**: Invokes backend Rust commands asynchronously via Tauri's IPC mechanism.

### 2. Backend Engine (Rust)
*   **Concurrency**: Utilizes `tokio` for highly concurrent, non-blocking I/O. Tasks are offloaded to blocking threads when dealing with heavy file I/O.
*   **Streaming & Hashing**: Employs an asynchronous streaming architecture. As data blocks are read from raw devices, they are simultaneously passed through `tokio::sync::mpsc` channels to background writing, hashing (`sha2`, `md-5`), and keyword scanning tasks.
*   **Cross-Platform Abstractions**: Abstracts OS-specific raw block device controls behind a unified `DeviceBackend` trait:
    *   **Windows**: Queries `\\.\PhysicalDriveX` using the `windows` crate. Uses `CreateFileW` with query-only sharing to enforce software write-blocking.
    *   **Linux**: Opens `/sys/block` devices with `O_DIRECT` to bypass the page cache and uses the `BLKROSET` ioctl to enforce read-only status.
    *   **macOS**: Enumerates `/dev/rdiskX` nodes to bypass OS buffer caches.
*   **Tool Integration**: Packages external forensics tools (like WinPmem) as bundled resources, executing them securely via `std::process::Command` to acquire physical memory on supported operating systems.

---

## 🚀 How to Use

Because accessing raw disks and physical memory are highly privileged operations, **Forgelens must be run with administrative permissions**.

### 🪟 Windows
1.  Locate the compiled `forgelens-disk-imager.exe` binary.
2.  Double-click the application. It has been configured with an embedded manifest to **always request Administrator privileges** automatically via UAC.
3.  Click **Yes** on the UAC prompt to launch the dashboard.
4.  Navigate to **Memory**, **Triage**, or **Image** tabs to begin forensic acquisition.

### 🐧 Linux
1.  Open your terminal.
2.  Run the application with superuser privileges:
    ```bash
    sudo ./forgelens-disk-imager
    ```

### 🍎 macOS
1.  Before running, you must grant your terminal application (e.g., Terminal, iTerm) **Full Disk Access** under:
    `System Settings ➔ Privacy & Security ➔ Full Disk Access`.
2.  Run with:
    ```bash
    sudo ./forgelens-disk-imager
    ```

---

## 📚 Documentation & Guides

*   [**ForgeLens Hash System Guide**](docs/hashes_guides.md): Learn how our 3-stage hashing architecture works and why container hashes (like AFF) behave differently from raw evidence hashes.

---

## 🛠️ Building from Source

### Prerequisites
We use **`mise`** to manage the Rust toolchain version. Make sure you have it installed:
*   [mise documentation](https://mise.jdx.dev/)

### Step 1: Install Dependencies
Install Node.js dependencies for the Tauri CLI:
```bash
npm install
```

### Step 2: Build & Run in Development Mode
To run the live-reloading Tauri window in development mode:
```bash
npx tauri dev
```

### Step 3: Compile for Production
To bundle the application into a production executable, MSI, or app package:
```bash
npx tauri build
```
*(Or use `mise run build` which runs `cargo build --release` under the hood).*

---

## ⚖️ Legal Disclaimer
*This tool is intended for authorized forensic investigations and data recovery purposes only. Unauthorized imaging of storage media or accessing private devices without consent may violate local computer privacy and security legislation.*

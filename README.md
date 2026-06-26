# ⚡ Forgelens Disk Imager

Forgelens is a professional, cross-platform forensic disk imaging and system triage application built in Rust and powered by Tauri. It provides a secure, write-blocked method to copy physical storage media (like USB drives, HDDs, and SSDs) byte-for-byte, collect volatile triage memory, and verify digital evidence integrity.

---

## 👥 Guide for Non-Technical Users

### What is Forgelens?
When digital investigators need to examine a computer, USB drive, or memory card, they must never work directly on the original device. Doing so could accidentally change dates, modify files, or corrupt evidence. 

**Forgelens** makes an exact, clone-like copy of the drive (called an "image" or "bitstream image") and saves it to a file. It uses hardware-level and software-level safety switches to ensure that the device being copied is **never written to** (this is called "write-blocking").

In addition, Forgelens provides a **System Triage** module to rapidly capture volatile system information (such as running processes, network connections, and system settings) from live systems, which is crucial for incident response.

### Key Features
*   **100% Secure Write-Blocking**: Guarantees the original drive is not altered during the copying process.
*   **Forensic Hash Verification**: Computes digital fingerprints (hashes) of the drive to prove that the copy is a perfect match of the original.
*   **Rapid System Triage & RAM Capture**: Executes live diagnostic commands (collecting active processes, sockets, and driver lists) and copies live files (registry hives, security configs, Chrome/Edge browsing history databases, and syslog/evtx logs) safely into a structured forensic package.
*   **Real-Time Keyword & IOC Pre-Scanning**: Searches for specific strings or Indicators of Compromise (IOCs) on-the-fly during acquisition.
*   **Sparse Imaging**: Optimizes storage space by skipping sectors containing all zeroes while maintaining correct logical file size.
*   **Cryptographic Digital Signing**: Generates workstation-tethered validation seals (`.signature` files) to prove evidence authenticity and prevent tampering.
*   **Advanced Filesystem & Encryption Detector**: Identifies partition formats (APFS, HFS+, ext2/3/4, XFS, Btrfs, ReFS) and encryption wrappers (BitLocker, LUKS, FileVault) automatically.
*   **Multi-Format Forensic Reports**: Automatically generates printable HTML reports, JSON audit logs, and CSV timeline files.
*   **Modern User Interface**: A premium, clean dark-themed dashboard showing progress, speed, and real-time logs in three dedicated panels: **Disk Imaging**, **System Triage**, and **Image Manager**.
*   **Cross-Platform**: Runs natively on Windows 10/11, Linux, and macOS.

### Getting Started (How to Run)
Because accessing raw disks is a highly privileged operation, Forgelens requires administrative permissions to run. 

#### 🪟 Windows
1.  Locate the compiled `forgelens-disk-imager.exe` binary.
2.  Right-click on the file and select **Run as Administrator**.
3.  Click **Yes** on the UAC prompt.

#### 🐧 Linux
1.  Open your terminal.
2.  Run the application with superuser privileges:
    ```bash
    sudo ./forgelens-disk-imager
    ```

#### 🍎 macOS
1.  Before running, you must grant your terminal application (e.g., Terminal, iTerm) **Full Disk Access** under:
    `System Preferences ➔ Privacy & Security ➔ Full Disk Access`.
2.  Run with:
    ```bash
    sudo ./forgelens-disk-imager
    ```

---

## 🛠️ Guide for Technical Users & Developers

### Technical Architecture
Forgelens abstracts OS-specific raw block device controls behind a unified trait interface (`DeviceBackend`) using Rust conditional compilation:

```rust
pub trait DeviceBackend {
    fn enumerate_devices() -> Result<Vec<DeviceInfo>>;
    fn open_readonly(path: &str) -> Result<RawDevice>;
    fn enforce_write_block(device: &mut RawDevice) -> Result<()>;
}
```

*   **Windows**: Queries physical drives via `\\.\PhysicalDriveX` using the `windows` crate. Utilizes `CreateFileW` with query-only sharing flags to enforce software write-blocking.
*   **Linux**: Parses `/sys/block` to enumerate physical devices, opens files with `O_DIRECT` to bypass the Linux page cache for forensic integrity, and uses the `BLKROSET` ioctl to enforce kernel-level read-only status.
*   **macOS**: Enumerates block devices via `/dev/diskX` and opens corresponding `/dev/rdiskX` raw device nodes to bypass OS buffer caches.

### Hashing & Verification
Acquisitions calculate digital fingerprints in a **single streaming pass** using a concurrent `MultiHasher`. Supported algorithms include:
*   MD5
*   SHA-1
*   SHA-256
*   SHA-512

Upon completion, Forgelens generates a forensic chain of custody report (`.report.txt`) containing examiner metadata, device specs, bad sector counts, and the computed validation hashes.

### Building from Source

#### Prerequisites
We use **`mise`** to manage the Rust toolchain version. Make sure you have it installed:
*   [mise documentation](https://mise.jdx.dev/)

#### Step 1: Install Dependencies
Install Node.js dependencies for the Tauri CLI:
```bash
npm install
```

#### Step 2: Build & Run in Development Mode
To run the live-reloading Tauri window in development mode:
```bash
npx tauri dev
```

#### Step 3: Compile for Production
To bundle the application into a production executable, MSI, or app package:
```bash
npx tauri build
```
*(Or use `mise run build` which runs `cargo build --release` under the hood).*

---

## ⚖️ Legal Disclaimer
*This tool is intended for authorized forensic investigations and data recovery purposes only. Unauthorized imaging of storage media or accessing private devices without consent may violate local computer privacy and security legislation.*

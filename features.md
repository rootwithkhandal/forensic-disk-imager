# ⚡ Forgelens Forensic Features & User Guide

This document provides a comprehensive technical breakdown of all forensic modules, engines, and features implemented in Forgelens, along with step-by-step guides on how to configure and run them.

---

## 📂 Module 1: Physical & Logical Disk Imaging

The Disk Imaging module is the core acquisition engine of Forgelens. It allows digital investigators to create forensically sound copies of physical disks (sector-by-sector) or select logical folders.

### 🛡️ Write-Blocking & Read-Only Integrity
Before any imaging starts, Forgelens implements software write-blocking to prevent accidental writes to the source media:
*   **Windows**: Opens physical device handles with query-only sharing flags (`FILE_SHARE_READ`) and restricts access.
*   **Linux**: Invokes `BLKROSET` ioctl to force raw device read-only mode at the kernel level.
*   **Forensic Verification**: Ensures no block writes can occur from the application context.

### ⚙️ Feature Breakdown & Configuration Settings
1.  **Imaging Mode**:
    *   *Physical (Forensic Gold Standard)*: Performs a bitstream sector-by-sector clone of the entire drive, including unallocated sectors, slack space, and hidden/deleted data.
    *   *Logical*: Copies only selected directories and files recursively. Useful when time/space constraints prevent full device imaging.
2.  **Output Format Support**:
    *   `RAW / DD (.dd)`: Standard raw block image, compatible with all forensic tools.
    *   `E01 (.e01)`: EnCase Evidence Format with embedded headers.
    *   `EX01 (.ex01)`: Extended EnCase format.
    *   `AFF (.aff)`: Advanced Forensic Format.
    *   `SMART (.smart)`: Industry standard legacy forensic container.
3.  **Hash Verification Options**:
    *   *Pre & Post-Acquisition*: Calculates the hash of the source disk before cloning and after writing, confirming absolute matching. If hashes mismatch, the app alerts that integrity is compromised.
    *   *Post-Acquisition Only*: Stream-calculates the hash during acquisition, speeding up the process by avoiding the initial reading pass.
4.  **On-the-Fly Hashing Algorithms**:
    *   Run multiple hashing calculations concurrently in a single streaming pass: **MD5**, **SHA-1**, **SHA-256**, and **SHA-512**.
5.  **Compression Formats**:
    *   *None*: Fast, raw writing.
    *   *Gzip*: Standard balance of speed and size.
    *   *Zstd (Zstandard)*: Elite real-time compression for maximum write throughput.
6.  **Segmented Image Splitting**:
    *   Enables splitting large images into chunks (e.g., 650 MB for CD-R, 2000 MB for FAT32 limits, 4300 MB for DVD-R, or custom sizes).
7.  **Read Verification**:
    *   Verifies written blocks against the device buffers to validate destination drive write accuracy.
8.  **Real-Time Keyword & IOC Pre-Scanning**:
    *   Scans block buffers dynamically using a Boyer-Moore pattern matching engine. Emits hits (`ProgressEvent::KeywordHit`) with sector and byte offsets as matches are found.
9.  **Sparse Imaging**:
    *   When checked, sectors containing only zero (`0x00`) bytes are skipped during writing. On NTFS targets (Windows), it issues a `FSCTL_SET_SPARSE` kernel command to optimize physical disk space.
10. **Digital Signing**:
    *   Computes an SHA-256 digital signature of the generated forensic report, using a cryptographic salt and workstation identifier, saving it in a `.signature` file.

### 📋 Step-by-Step Guide: How to Image a Drive
1.  Launch the application as **Administrator / Root**.
2.  Navigate to the **Disk Imaging** tab.
3.  In the **Source Selector** sidebar:
    *   Click **Rescan** to load the list of block devices.
    *   Choose between **Physical Drive** or **Logical Folder**.
    *   Click on your target device card. Review partition tables, detected filesystems (APFS, ext4, ReFS, NTFS, FAT32), encryption flags (BitLocker, LUKS), and SSD SMART health wear/temperature indicators.
4.  Configure the **Acquisition details**:
    *   Enter **Evidence ID**, **Case Number**, **Examiner Name**, and **Custody Notes**.
    *   Select your preferred **Output Format** and click **Browse** to specify the destination filename.
5.  Configure **Forensic options**:
    *   Select **Verification** (e.g., *Pre & Post* or *Post-Acquisition Only*).
    *   Select block size (512KB, 1024KB, 2048KB).
    *   Check cryptographic hash algorithms (e.g., `MD5` and `SHA-256`).
    *   *(Optional)* Check **Sparse Imaging** and **Digital Signing**.
    *   *(Optional)* Enter comma-separated keywords to scan (e.g., `password, secret, payload`).
6.  Click **Start Acquisition**.
7.  Monitor progress in the live telemetry grid (speed, ETA, bad sectors, progress bar) and read the scrollable **Forensic Console Log** at the bottom.
8.  If interrupted, click **Resume Job** to pick up acquisition from the last written block.

---

## ⚡ Module 2: System Triage & Volatile RAM Capture

The System Triage module is designed for live incident response. Rather than generating mock data, it executes real system commands and copies active forensic artifacts directly from the host operating system.

### 🔍 Collected Forensic Artifacts
*   **Volatile System State (Live Execution)**: 
    *   *Processes*: Extracts a real, running process snapshot (`tasklist` on Windows, `ps ax` on macOS/Linux) written to `processes.txt`.
    *   *Network Connections*: Collects active TCP/UDP ports and socket connections (`netstat -ano` on Windows, `netstat -an` on macOS/Linux) written to `network_connections.txt`.
    *   *Loaded Kernel Modules*: Lists loaded drivers and modules (`driverquery` on Windows, `kextstat` on macOS, `lsmod` on Linux) written to `loaded_modules.txt`.
    *   *System Information*: Collects diagnostic properties (`systeminfo` on Windows, `uname -a` on macOS/Linux) written to `system_info.txt`.
*   **Registry Hives & System Configurations**:
    *   *Windows*: Backs up active Registry hives using system APIs (`reg export`) to extract `SYSTEM` configurations, `SAM` credentials, and autostart keys (`Run` folder) to the `registry/` directory.
    *   *macOS / Linux*: Copies host security configurations and tables (`/etc/passwd`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/fstab`).
*   **Browser Activity (Live Database Copying)**:
    *   Scans and copies the active Google Chrome and Microsoft Edge `History` SQLite database logs directly from the user's local AppData or Home directory (saved in `browsers/` folder).
*   **Event Logs (Evtx / Syslog Exports)**:
    *   *Windows*: Exports active security and system event log databases forensically as `.evtx` files using `wevtutil epl` (saved in `event_logs/` folder).
    *   *macOS / Linux*: Copies live system logs directly from `/var/log/*` (e.g., `syslog`, `auth.log`, `secure`, `kern.log`).

### 📋 Step-by-Step Guide: How to Capture Triage Artifacts
1.  Launch the application as **Administrator / Root** (required to read locked system hives, event logs, or other protected folders).
2.  Select the **System Triage** tab.
3.  Under **Triage Output Directory**, click **Browse** and select a folder to save the triage files.
4.  Check the boxes next to the artifacts you want to collect:
    *   *Volatile System State*
    *   *Registry Hives & System Configurations*
    *   *Browser Activity Metadata*
    *   *Operating System Event Logs*
5.  Click **Start Triage Collection**.
6.  Watch the **Forensic Console Log** as the application executes the live diagnostic commands and copies the files.
7.  Upon completion, navigate to the selected output directory. You will find:
    *   `triage_summary.txt` detailing date, host architecture, OS, and status.
    *   Folders for `registry/`, `browsers/`, and `event_logs/` containing the real forensic extractions.
    *   An audit manifest containing integrity hashes for the gathered files.

---

## 📦 Module 3: Image Manager

The Image Manager module allows investigators to verify and explore completed forensic image containers.

### 🛠️ Image Manager Capabilities
*   **Hash Integrity Verification**: Reads forensic image files (`.dd`, `.e01`, `.aff`) and compares their current block hashes to the hashes computed during acquisition to guarantee no tampering has occurred.
*   **Read-Only Mounting**: Mounts forensic image files onto a virtual read-only drive letter or directory, allowing safe exploration of the recovered partition filesystem without any risk of metadata modification.

### 📋 Step-by-Step Guide: How to Verify & Mount an Image
1.  Select the **Image Manager** tab.
2.  Under **Select Forensic Image File**, click **Browse** and locate your `.dd`, `.e01`, or `.aff` image file.
3.  **To Verify Integrity**:
    *   Click **Verify Hash Integrity**.
    *   The engine reads the blocks, recalculates the hashes, and compares them with the acquisition metadata.
    *   Confirm the successful verification alert.
4.  **To Mount the Image**:
    *   Under **Mount Point (Folder)**, click **Browse** and choose a directory where the image will be mounted.
    *   Click **Mount Read-Only**.
    *   The image mounts safely using the write-blocked loop driver.
    *   Browse the files in your system Explorer/Finder. When finished, you can unmount the drive safely.

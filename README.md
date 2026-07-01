# ⚡ OpenForensic Disk Imager & Digital Forensics Suite

[![Version](https://img.shields.io/badge/version-2.0.2-blue.svg?style=for-the-badge&logo=semver)](package.json)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg?style=for-the-badge&logo=rust)](src-tauri/Cargo.toml)
[![Tauri](https://img.shields.io/badge/tauri-2.11-24C8DB.svg?style=for-the-badge&logo=tauri)](src-tauri/tauri.conf.json)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg?style=for-the-badge&logo=linux)]()
[![License](https://img.shields.io/badge/license-Proprietary-red.svg?style=for-the-badge)]()

**OpenForensic** is an enterprise-grade, cross-platform digital forensics and incident response (DFIR) application built in high-performance **Rust** and powered by **Tauri 2**. Designed for forensic investigators, incident responders, and law enforcement, OpenForensic provides an end-to-end, write-blocked investigation suite capable of physical disk cloning, live volatile system triage, deep memory analysis, IOC scanning, and automated chain-of-custody reporting.

---

## 🌟 Key Forensic Capabilities

| Module | Features & Capabilities |
| :--- | :--- |
| **📂 Disk Imaging** | Physical sector-by-sector and logical file acquisition. Supports Raw (`.dd`), E01 (`.e01`), and Advanced Forensic Format (`.aff`). Automatic sparse zero-block skipping and multi-threaded compression (`zstd`, `gzip`). |
| **🔴 Live Acquisition** | Zero-downtime live evidence collection using Volume Shadow Copy Service (**VSS**) on Windows to freeze filesystem state. Safely captures OS-locked artifacts including NTFS MFT (`$MFT`), Registry Hives (`SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`), and Event Logs. |
| **⚡ Rapid System Triage** | Instantaneous extraction of volatile system state: running processes, network connections, kernel modules, Chrome/Edge browser history databases, and EVTX/syslog event records. Includes an interactive **Triage SQL Workbench** to query and inspect sqlite databases directly within the app. |
| **🧠 Memory Forensics (Volatility 3)** | Native integration with **Volatility 3** for analyzing acquired RAM dumps (`.raw`, `.vmem`, `.dmp`). Supports execution of Windows, Linux, and macOS memory profiles (e.g., `pslist`, `netstat`, `cmdline`, `filescan`, `malfind`, `printkey`) with real-time log streaming. |
| **🛡️ Threat Intelligence Enrichment** | Automated real-time IOC enrichment during memory analysis. Verifies extracted IP addresses against **AbuseIPDB** reputation scores and queries file/process hashes against **VirusTotal**. |
| **⏱️ Timeline Generator** | Automated chronological artifact reconstruction. Extracts and parses timestamps from MFT records, `$LogFile`, and Ext4 journals to produce unified master timelines exported to structured **CSV** and **JSON** formats. |
| **🔍 On-the-Fly YARA & Keyword Scanning** | Powered by a pure-Rust **YARA-X** engine. Performs real-time pattern matching against custom `.yar` rulesets and regular expression keyword searches simultaneously while streaming disk or memory data. |
| **🧩 Extensible Plugin Platform** | Modular plugin architecture supporting compiled native shared libraries (`.so`, `.dll`, `.dylib`) and sandboxed WebAssembly (`.wasm`) modules via `wasmtime`. Features standardized lifecycle hooks (`pre_acquisition`, `on_block`, `post_acquisition`) for real-time data streaming, custom hashing, and automated report enrichment. |
| **🔐 4-Algorithm Hash Verification** | Simultaneous single-pass hashing using **MD5, SHA-1, SHA-256, and SHA-512** to establish cryptographic proof of evidence integrity. Includes built-in checkpointing to pause and resume long acquisitions without data corruption. |
| **📁 Case Management & Reporting** | Integrated SQLite case database tracking evidence tags, investigator notes, device metadata, and cryptographic hashes. Generates court-admissible HTML and PDF forensic reports. |

---

## 🏛️ Architecture & Asynchronous Pipeline

OpenForensic achieves maximum I/O throughput by separating disk reading, cryptographic hashing, IOC scanning, and file writing into distinct asynchronous processing streams managed by Tokio runtime channels.

```mermaid
graph TD
    subgraph Storage & Memory Sources
        RawDisk[Physical Drive / dev/rdisk / sys/block]
        LiveSys[Live OS / VSS Shadow Copy]
        RamDump[Physical RAM / winpmem / avml]
    end

    subgraph Rust Backend Engine
        Reader[Async Block Reader / Software Write-Blocker]
        Broadcast[Tokio MPSC Broadcast Channel]
        
        Hashers[4x Concurrent Hasher<br/>MD5 | SHA1 | SHA256 | SHA512]
        Yara[YARA-X & Keyword Scanner]
        Plugins[Plugin Engine<br/>Native DLL/SO | Sandboxed Wasm]
        Writer[Image Writer & Compression Engine<br/>Raw | E01 | AFF | Sparse]
        
        VolEngine[Volatility 3 & Threat Intel Engine<br/>AbuseIPDB | VirusTotal]
    end

    subgraph Storage & UI
        CaseDB[(SQLite Case Management DB)]
        Reports[HTML / PDF Evidence Reports]
        UI[Tauri 2 / Vanilla CSS Forensic Dashboard]
    end

    RawDisk --> Reader
    LiveSys --> Reader
    RamDump --> VolEngine

    Reader --> Broadcast
    Broadcast --> Hashers
    Broadcast --> Yara
    Broadcast --> Plugins
    Broadcast --> Writer

    Hashers --> CaseDB
    Yara --> CaseDB
    Plugins --> CaseDB
    Writer --> CaseDB
    VolEngine --> CaseDB

    CaseDB --> Reports
    CaseDB <-->|Asynchronous IPC| UI
    VolEngine -->|Real-time Event Streams| UI
```

### 🧩 Extensible Plugin Architecture
OpenForensic operates as an extensible forensics platform rather than a static tool. Third-party modules integrate seamlessly into the acquisition pipeline through standardized lifecycle hooks defined in `OpenForensicPlugin`:
* **`pre_acquisition`**: Called before imaging starts to inspect case metadata, volume geometry, and initialize resources.
* **`on_block`**: Invoked for every data chunk read from disk. Chunks are dispatched across non-blocking multi-producer channels to background worker threads, guaranteeing zero degradation to disk reading throughput.
* **`post_acquisition`**: Executed upon acquisition completion. Returns custom metrics, hashes, or analytical outputs that are embedded directly into official PDF, HTML, and text case reports.

#### Dual-Loader Security & Execution
* **Native Shared Libraries (`.so` / `.dll` / `.dylib`)**: High-performance compiled extensions loaded dynamically via FFI symbols (`_openforensic_plugin_create`) for OS-level operations.
* **WebAssembly Modules (`.wasm`)**: Executed inside secure, memory-isolated sandboxes powered by `wasmtime`. Wasm plugins operate with zero host filesystem or network access unless explicitly granted, enabling safe execution of community detection rules and proprietary heuristics.

### 🛡️ Hardware & Software Write-Blocking
OpenForensic enforces read-only access at the OS kernel boundary:
*   **Windows**: Opens block devices via `CreateFileW` requesting strictly `GENERIC_READ` with shared access attributes, preventing any write modification by the operating system or application.
*   **Linux**: Opens block devices using `O_RDONLY | O_DIRECT` to bypass browser and OS page caches, and queries `BLKROSET` ioctls to verify read-only device enforcement.
*   **macOS**: Communicates directly with raw disk nodes (`/dev/rdiskX`) to achieve unbuffered, read-only hardware speed.

---

## 💻 System Requirements & Supported Platforms

| Platform | Supported Versions | Required Privileges | Special Notes |
| :--- | :--- | :--- | :--- |
| **🪟 Windows** | Windows 10, Windows 11 (64-bit) | **Administrator (UAC Uplevel)** | Bundles `winpmem_mini_x64` for RAM capture; requires VSS privileges for locked file extraction. |
| **🐧 Linux** | Ubuntu 20.04+, Debian, Arch, Fedora | **Root (`sudo` / `su`)** | Requires raw block device access (`/dev/sdX`, `/dev/nvme0n1`). Supports `/proc/kcore` & `avml`. |
| **🍎 macOS** | macOS 11.0 Big Sur or newer | **Root + Full Disk Access** | Terminal / app must be granted *Full Disk Access* under System Settings ➔ Privacy & Security. |

### Minimum Hardware
*   **CPU**: 4+ Cores recommended for parallel SHA-512 hashing and YARA rule compilation.
*   **RAM**: 4 GB minimum (8 GB+ recommended when analyzing multi-gigabyte RAM dumps in Volatility).
*   **Storage**: NVMe / SSD destination storage recommended to prevent write-bottlenecks during multi-algorithm hashing.

---

## 🚀 Quick Start & Installation

Because OpenForensic interacts directly with raw block storage devices and kernel memory, it **must be executed with elevated administrative privileges**.

### 1. Running on Windows
1. Download or compile the `openforensic.exe` binary.
2. Launch the application. The embedded UAC manifest will automatically prompt for **Administrator elevation**.
3. Click **Yes** on the UAC dialog.
4. Select your target device from the **Source Selector** sidebar and choose your investigation tab.

### 2. Running on Linux
Execute the binary via terminal using `sudo`:
```bash
sudo ./target/release/openforensic
```

### 3. Running on macOS
1. Open **System Settings** ➔ **Privacy & Security** ➔ **Full Disk Access**.
2. Enable access for your Terminal or target IDE.
3. Launch from terminal with superuser privileges:
```bash
sudo ./target/release/openforensic
```

---

## 🖥️ Dashboard Overview & Workflow

1. **📂 Disk Imaging Tab**:
   * Select a physical block device or logical directory.
   * Choose destination format (`Raw .dd`, `E01`, or `AFF`).
   * Enable sector compression, sparse zero-block skipping, and select verification hash algorithms.
   * Attach optional YARA rulesets (`.yar`) for real-time IOC alerting during the imaging process.

2. **⚡ System Triage Tab**:
   * One-click execution of rapid system collection: running processes, network sockets, browser histories, and event logs.
   * Open the built-in **Triage Workbench** to load acquired SQLite databases (such as Chrome History or triage output) and run custom SQL queries.

3. **🔴 Live Acquisition Tab**:
   * Acquire live system volume shadow copies without rebooting.
   * Check **Capture Physical Memory (RAM)** to dump volatile system memory using auto-detected or custom tools (`winpmem`, `avml`).

4. **⏱️ Timeline Generator Tab**:
   * Input any acquired raw disk image (`.dd`).
   * Specify output destination to generate a unified, chronological timeline (`timeline.csv` / `timeline.json`) of file system modifications and journal entries.

5. **📁 Case Management Tab**:
   * Create and manage forensic cases with investigator details and agency metadata.
   * Review historical acquisition jobs, verify stored SHA-256/SHA-512 hashes, and export self-contained HTML evidence reports.

6. **🧠 RAM Analysis Tab**:
   * Select an acquired memory dump (`.raw`, `.vmem`, `.dmp`) and specify your Volatility 3 script/executable path.
   * Select an analysis profile (e.g., `windows.pslist.PsList`, `windows.netstat.NetStat`, `windows.malfind.Malfind`).
   * Enable **AbuseIPDB** and **VirusTotal** API enrichment to automatically flag malicious remote IP connections and suspicious process hashes in real time.

---

## 🛠️ Building & Developing from Source

We use [**mise**](https://mise.jdx.dev/) to manage reproducible toolchains (Rust 1.85+, Node.js).

### Step 1: Clone & Install Dependencies
```bash
git clone https://github.com/rootwithkhandal/forensic-disk-imager.git
cd forensic-disk-imager
npm install
```

### Step 2: Verify Toolchain & Check Build
```bash
mise run check
# Or manually:
cargo check --manifest-path src-tauri/Cargo.toml
```

### Step 3: Run Development Server with Live-Reload
To launch the Tauri dev window:
```bash
npm run tauri dev
```
*(On Windows, run your terminal as Administrator if testing raw physical disk scanning).*

### Step 4: Compile Production Executable
To build the optimized release binary and installer packages:
```bash
npm run tauri build
```
The compiled standalone binary will be output to `src-tauri/target/release/openforensic.exe`.

---

## 📚 Documentation & Reference Guides

*   [**OpenForensic Hash System Guide**](docs/hashes_guides.md): Deep dive into our 3-stage cryptographic verification architecture and how container hashes (E01/AFF) differ from raw stream hashes.
*   [**Security Policy**](SECURITY.md): Vulnerability reporting guidelines and scope definitions.

---

## ⚖️ Legal & Forensic Disclaimer

*OpenForensic is developed strictly for lawful digital forensics investigations, incident response, data recovery, and academic research. Accessing raw physical disks, acquiring volatile system memory, or imaging computer media without explicit legal authorization or device ownership may violate local, state, or international computer privacy and crime laws. The developers assume no liability for misuse.*

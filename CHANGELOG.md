# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.2] - 2026-07-01

### Added
- **Extensible Plugin Architecture**: Added modular plugin platform transforming OpenForensic into an extensible digital forensics ecosystem.
- **`OpenForensicPlugin` Trait**: Defined standardized lifecycle hooks:
  - `pre_acquisition`: Invoked before disk imaging to inspect case metadata, volume dimensions, and initialize resources.
  - `on_block`: Streamed asynchronously for every block chunk read from source devices without degrading disk reading throughput.
  - `post_acquisition`: Executed upon completion to return custom metrics, hashes, and analytical outputs.
- **Dual-Loader Extension Engine**:
  - **Native Loader**: Support for dynamically loading compiled shared libraries (`.so`, `.dll`, `.dylib`) via FFI symbols (`_openforensic_plugin_create`) using `libloading`.
  - **WebAssembly Loader**: Support for running sandboxed `.wasm` modules inside memory-isolated runtime environments powered by `wasmtime`.
- **Pipeline & Report Integration**: Integrated asynchronous broadcast channels into disk imaging and live VSS acquisition workflows. Embedded plugin results into generated PDF, HTML, and text case reports.
- **Tauri Management Commands**: Exposed front-end IPC commands (`load_plugin`, `list_plugins`, `unload_plugin`, `scan_plugins_directory`) to manage registered plugins.
- **Automated Testing**: Added unit tests verifying plugin lifecycle ordering and manager operations.

## [2.0.1] - 2026-06-15

### Added
- **YARA-X & Keyword Scanning**: Integrated pure-Rust YARA engine for real-time pattern matching against custom `.yar` rulesets and regular expression keyword searches during acquisition.
- **Timeline Generator**: Added chronological artifact reconstruction module parsing timestamps from NTFS MFT (`$MFT`), `$LogFile`, and Ext4 journals into unified master timelines (`.csv` and `.json`).
- **RAM Analysis & Threat Intelligence**: Added memory forensics module with Volatility 3 integration (supporting Windows, Linux, and macOS profiles) and real-time IOC enrichment querying AbuseIPDB reputation scores and VirusTotal file hashes.
- **Triage SQL Workbench**: Added interactive database query inspector inside the dashboard to examine extracted SQLite evidence (Chrome/Edge history, event logs).
- **PDF & HTML Case Reporting**: Added automated court-admissible report generation with embedded cryptographic verification tables.

### Fixed
- Improved UAC elevation prompts and OS permission handling across Windows and macOS Full Disk Access settings.

## [2.0.0] - 2026-05-01

### Added
- **Asynchronous Storage Backend**: Re-architected storage engine using Tokio MPSC broadcast channels to separate disk reading, multi-algorithm hashing, scanning, and writing into parallel non-blocking execution streams.
- **4-Algorithm Cryptographic Hashing**: Added simultaneous single-pass calculation of MD5, SHA-1, SHA-256, and SHA-512 hashes.
- **Acquisition Checkpointing**: Added state persistence allowing long-running physical drive imaging to pause and resume without data corruption.
- **Write-Blocking Enforcement**: Implemented OS-kernel boundary read-only protection across Windows (`CreateFileW` with `GENERIC_READ`), Linux (`BLKROSET` / `O_DIRECT`), and macOS (`/dev/rdiskX`).
- **Multi-Format Image Writer**: Added support for Raw (`.dd`), Expert Witness Format (`.e01`), and Advanced Forensic Format (`.aff`) with sparse zero-block skipping and multi-threaded compression (`zstd`, `gzip`).
- **Tauri 2 Framework Upgrade**: Fully rebuilt frontend user interface with modern styling, dark mode, and real-time progress broadcasting.

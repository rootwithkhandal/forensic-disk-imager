use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;
use crate::error::Result;
use crate::hasher::HashAlgorithm;

#[derive(serde::Serialize)]
pub struct ReportData {
    pub case_number: String,
    pub examiner: String,
    pub evidence_id: String,
    pub notes: String,
    pub imaging_mode: String,
    pub format: String,
    pub source_device: String,
    pub source_size: u64,
    pub source_model: String,
    pub source_serial: String,
    pub dest_file: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub bad_sectors: u64,
    pub pre_hashes: HashMap<HashAlgorithm, String>,
    pub hashes: HashMap<HashAlgorithm, String>,
    pub post_hashes: Option<HashMap<HashAlgorithm, String>>,
    // Live acquisition fields
    pub vss_snapshot_id: Option<String>,
    pub ram_dump_path: Option<String>,
    pub ram_dump_size: Option<u64>,
    pub ram_dump_hash: Option<String>,
    pub locked_files_copied: Vec<String>,
    pub consistency_blocks_checked: Option<u64>,
    pub consistency_blocks_matched: Option<u64>,
    pub consistency_mismatches: Vec<u64>,
    pub plugin_results: HashMap<String, String>,
}

fn to_ist_rfc2822(dt: &chrono::DateTime<chrono::Utc>) -> String {
    let ist_offset = chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
    dt.with_timezone(&ist_offset).to_rfc2822()
}

pub fn generate_txt_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "==================================================")?;
    writeln!(file, "              OPENFORENSIC REPORT                 ")?;
    writeln!(file, "==================================================")?;
    writeln!(file, "Case Number:     {}", data.case_number)?;
    writeln!(file, "Examiner:        {}", data.examiner)?;
    writeln!(file, "Evidence ID:     {}", data.evidence_id)?;
    writeln!(file, "Notes/Summary:   {}", data.notes)?;
    writeln!(file, "Report Date:     {}", to_ist_rfc2822(&chrono::Utc::now()))?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "IMAGING PARAMETERS")?;
    writeln!(file, "  Mode:          {}", data.imaging_mode)?;
    writeln!(file, "  Target Format: {}", data.format)?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "SOURCE DETAILS")?;
    writeln!(file, "  Device Path:   {}", data.source_device)?;
    writeln!(file, "  Model:         {}", data.source_model)?;
    writeln!(file, "  Serial Number: {}", data.source_serial)?;
    writeln!(file, "  Total Size:    {} bytes ({:.2} GB)", data.source_size, data.source_size as f64 / 1_000_000_000.0)?;
    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "ACQUISITION DETAILS")?;
    writeln!(file, "  Destination:   {}", data.dest_file)?;
    writeln!(file, "  Start Time:    {}", to_ist_rfc2822(&data.start_time))?;
    writeln!(file, "  End Time:      {}", to_ist_rfc2822(&data.end_time))?;
    let duration = data.end_time.signed_duration_since(data.start_time);
    writeln!(file, "  Duration:      {}h {}m {}s", duration.num_hours(), duration.num_minutes() % 60, duration.num_seconds() % 60)?;
    writeln!(file, "  Bad Sectors:   {}", data.bad_sectors)?;
    
    if !data.pre_hashes.is_empty() {
        writeln!(file, "--------------------------------------------------")?;
        writeln!(file, "PRE-ACQUISITION HASHES")?;
        for (algo, hash_val) in &data.pre_hashes {
            writeln!(file, "  {}: {}", algo, hash_val)?;
        }
    }

    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "ACQUISITION HASHES (STREAM VERIFICATION)")?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "  {}: {}", algo, hash_val)?;
    }

    if let Some(post) = &data.post_hashes {
        writeln!(file, "--------------------------------------------------")?;
        if data.imaging_mode == "Logical" {
            writeln!(file, "FINAL HASHES (DESTINATION FOLDER HASH)")?;
        } else {
            writeln!(file, "CONTAINER HASHES (POST-ACQUISITION FILE HASH)")?;
        }
        for (algo, hash_val) in post {
            writeln!(file, "  {}: {}", algo, hash_val)?;
        }
    }

    writeln!(file, "--------------------------------------------------")?;
    
    // Perform Verification matching
    let mut verified = true;
    if !data.pre_hashes.is_empty() || (data.imaging_mode == "Logical" && data.post_hashes.is_some()) {
        writeln!(file, "INTEGRITY VERIFICATION LOG")?;
        for (algo, stream_hash) in &data.hashes {
            let mut match_status = true;
            let mut checks = Vec::new();

            if let Some(pre_hash) = data.pre_hashes.get(algo) {
                if pre_hash == stream_hash {
                    checks.push("Pre-Hash: MATCHED");
                } else {
                    checks.push("Pre-Hash: MISMATCH");
                    match_status = false;
                }
            }

            if data.imaging_mode == "Logical" {
                if let Some(post_hashes) = &data.post_hashes {
                    if let Some(post_hash) = post_hashes.get(algo) {
                        if post_hash == stream_hash {
                            checks.push("Final-Hash: MATCHED");
                        } else {
                            checks.push("Final-Hash: MISMATCH");
                            match_status = false;
                        }
                    }
                }
            }

            if match_status {
                let check_str = if checks.is_empty() { "Integrity Confirmed".to_string() } else { checks.join(" | ") };
                writeln!(file, "  {}: MATCHED ({})", algo, check_str)?;
            } else {
                let check_str = if checks.is_empty() { "WARNING: Integrity Compromised!".to_string() } else { checks.join(" | ") };
                writeln!(file, "  {}: MISMATCHED ({})", algo, check_str)?;
                verified = false;
            }
        }
        writeln!(file, "--------------------------------------------------")?;
    }

    if verified {
        writeln!(file, "Acquisition Status: COMPLETED / VERIFIED")?;
    } else {
        writeln!(file, "Acquisition Status: WARNING - HASH MISMATCH")?;
    }

    // Live Acquisition sections (only printed when data is present)
    if data.vss_snapshot_id.is_some() || data.ram_dump_path.is_some() || !data.locked_files_copied.is_empty() {
        writeln!(file, "")?;
        writeln!(file, "==================================================")?;
        writeln!(file, "          LIVE ACQUISITION DETAILS                ")?;
        writeln!(file, "==================================================")?;

        if let Some(ref vss_id) = data.vss_snapshot_id {
            writeln!(file, "--------------------------------------------------")?;
            writeln!(file, "VSS SNAPSHOT")?;
            writeln!(file, "  Shadow Copy ID: {}", vss_id)?;
        }

        if let Some(ref ram_path) = data.ram_dump_path {
            writeln!(file, "--------------------------------------------------")?;
            writeln!(file, "RAM ACQUISITION")?;
            writeln!(file, "  Dump Path:      {}", ram_path)?;
            if let Some(ram_size) = data.ram_dump_size {
                writeln!(file, "  Dump Size:      {} bytes ({:.2} GB)", ram_size, ram_size as f64 / 1_000_000_000.0)?;
            }
            if let Some(ref ram_hash) = data.ram_dump_hash {
                writeln!(file, "  Dump Hash:      {}", ram_hash)?;
            }
        }

        if !data.locked_files_copied.is_empty() {
            writeln!(file, "--------------------------------------------------")?;
            writeln!(file, "LOCKED FILES ACQUIRED")?;
            for f in &data.locked_files_copied {
                writeln!(file, "  ✓ {}", f)?;
            }
        }

        if let Some(checked) = data.consistency_blocks_checked {
            writeln!(file, "--------------------------------------------------")?;
            writeln!(file, "FILESYSTEM CONSISTENCY VALIDATION")?;
            let matched = data.consistency_blocks_matched.unwrap_or(0);
            let mismatched = checked.saturating_sub(matched);
            let pct = if checked > 0 { matched as f64 / checked as f64 * 100.0 } else { 100.0 };
            writeln!(file, "  Blocks Checked:  {}", checked)?;
            writeln!(file, "  Blocks Matched:  {}", matched)?;
            writeln!(file, "  Blocks Mismatch: {}", mismatched)?;
            writeln!(file, "  Consistency:     {:.2}%", pct)?;
            if mismatched == 0 {
                writeln!(file, "  Status:          PASSED")?;
            } else {
                writeln!(file, "  Status:          FAILED — {} blocks differ", mismatched)?;
                for offset in data.consistency_mismatches.iter().take(20) {
                    writeln!(file, "    Offset: 0x{:X}", offset)?;
                }
            }
        }
    }

    if !data.plugin_results.is_empty() {
        writeln!(file, "\n--- Plugin Results & Custom Hashes ---")?;
        for (k, v) in &data.plugin_results {
            writeln!(file, "  {}: {}", k, v)?;
        }
    }

    writeln!(file, "==================================================")?;
    Ok(())
}

pub fn generate_html_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    
    let duration = data.end_time.signed_duration_since(data.start_time);
    let hours = duration.num_hours();
    let minutes = duration.num_minutes() % 60;
    let seconds = duration.num_seconds() % 60;
    let duration_str = format!("{}h {}m {}s", hours, minutes, seconds);
    let short_duration_str = format!("{}h {}m", hours, minutes);
    
    let duration_secs = duration.num_seconds().max(1);
    let speed_mb = (data.source_size as f64 / 1_048_576.0) / (duration_secs as f64);
    
    let mut hashes_html = String::new();
    let mut verified_all = true;
    for (algo, stream_hash) in &data.hashes {
        let pre_hash = data.pre_hashes.get(algo).cloned().unwrap_or_else(|| "N/A".to_string());
        
        let mut matched = true;
        let mut checks_performed = 0;

        if pre_hash != "N/A" {
            checks_performed += 1;
            if pre_hash != *stream_hash {
                matched = false;
            }
        }

        if data.imaging_mode == "Logical" {
            if let Some(post_hashes) = &data.post_hashes {
                if let Some(post_hash) = post_hashes.get(algo) {
                    checks_performed += 1;
                    if *post_hash != *stream_hash {
                        matched = false;
                    }
                }
            }
        }
        
        if !matched {
            verified_all = false;
        }
        
        let match_text = if matched && checks_performed > 0 {
            r#"<span class="badge success">MATCHED</span>"#
        } else if checks_performed == 0 {
            r#"<span class="badge neutral">NO VERIFICATION</span>"#
        } else {
            r#"<span class="badge error">MISMATCH</span>"#
        };

        let post_file_hash_html = if let Some(post) = &data.post_hashes {
            let val = post.get(algo).cloned().unwrap_or_else(|| "N/A".to_string());
            let label = if data.imaging_mode == "Logical" {
                "Final Hash (Destination Folder)"
            } else {
                "Post-Acquisition (Image File Hash)"
            };
            format!(r#"<div class="hash-item-label">{}</div><div class="hash-item-value"><span>{}</span><button class="copy-btn" title="Copy">📋</button></div>"#, label, val)
        } else {
            String::new()
        };

        hashes_html.push_str(&format!(r#"
            <div class="hash-row">
                <div class="hash-algo">{algo}</div>
                <div>
                    <div class="hash-item-label">Pre-Acquisition (Source Device)</div>
                    <div class="hash-item-value"><span>{pre_hash}</span><button class="copy-btn" title="Copy">📋</button></div>
                    <div class="hash-item-label">Acquisition (Stream Verification)</div>
                    <div class="hash-item-value"><span>{stream_hash}</span><button class="copy-btn" title="Copy">📋</button></div>
                    {post_file_hash_html}
                </div>
                <div class="hash-match">{match_text}</div>
            </div>
"#, algo=algo, pre_hash=pre_hash, stream_hash=stream_hash, post_file_hash_html=post_file_hash_html, match_text=match_text));
    }

    let status_badge = if verified_all {
        "COMPLETED & VERIFIED"
    } else {
        "WARNING — MISMATCH"
    };
    
    let status_class = if verified_all { "success" } else { "error" };

    let template = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenForensic Report — {{CASE_NUMBER}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Light Theme (Forensic Precision) */
            --bg: #f8f9ff;
            --surface: #ffffff;
            --text-main: #0b1c30;
            --text-muted: #424656;
            --border: #c2c6d8;
            --primary: #0066ff;
            --success: #10b981;
            --success-bg: #ecfdf5;
            --error: #ba1a1a;
            --error-bg: #ffdad6;
            --card-hover: rgba(0, 102, 255, 0.02);
            --border-hover: #0066ff;
            --shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        [data-theme="dark"] {
            /* Dark Theme (Cyber-Forensic Protocol) */
            --bg: #0f141a;
            --surface: #1b2027;
            --text-main: #dee2ec;
            --text-muted: #849495;
            --border: #2c3138;
            --primary: #00f5ff;
            --success: #4edea3;
            --success-bg: rgba(78, 222, 163, 0.1);
            --error: #ffb4ab;
            --error-bg: rgba(255, 180, 171, 0.1);
            --card-hover: rgba(0, 245, 255, 0.02);
            --border-hover: #00f5ff;
            --shadow: 0 4px 6px rgba(0,0,0,0.3);
        }

        * { box-sizing: border-box; }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
            transition: background-color 0.3s, color 0.3s;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            padding-bottom: 24px;
            border-bottom: 2px solid var(--border);
            margin-bottom: 32px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .header-title h1 {
            margin: 0;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-main);
        }
        .header-meta {
            font-size: 14px;
            color: var(--text-muted);
            text-align: right;
            line-height: 1.8;
        }
        
        .controls {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 12px;
        }

        .btn {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 4px;
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn:hover {
            border-color: var(--primary);
            color: var(--primary);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
            margin-bottom: 32px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            box-shadow: var(--shadow);
            transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
        }
        .card:hover {
            transform: translateY(-2px);
            border-color: var(--border-hover);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin-top: 0;
            font-size: 14px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 20px;
            font-weight: 700;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }
        .field {
            margin-bottom: 16px;
        }
        .field:last-child {
            margin-bottom: 0;
        }
        .label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 700;
            margin-bottom: 4px;
            letter-spacing: 0.05em;
            font-family: 'JetBrains Mono', monospace;
        }
        .value {
            font-size: 15px;
            font-weight: 600;
            word-break: break-all;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .data-mono {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            font-size: 14px;
        }
        
        .copy-btn {
            background: none;
            border: none;
            color: var(--primary);
            cursor: pointer;
            padding: 4px;
            opacity: 0;
            transition: opacity 0.2s;
        }
        .value:hover .copy-btn {
            opacity: 1;
        }

        .hash-section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        
        .hash-header {
            padding: 16px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface);
            transition: background 0.2s;
        }
        .hash-header:hover {
            background: var(--card-hover);
        }
        .hash-header h3 {
            margin: 0;
            font-size: 14px;
            color: var(--text-main);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 700;
        }
        
        .hash-content-wrapper {
            display: block;
        }

        .hash-row {
            display: grid;
            grid-template-columns: 120px 1fr 150px;
            padding: 20px 24px;
            border-top: 1px solid var(--border);
            align-items: center;
            transition: background 0.2s;
        }
        .hash-row:hover {
            background: var(--card-hover);
        }
        .hash-algo {
            font-weight: 700;
            font-size: 18px;
            color: var(--primary);
        }
        .hash-item-label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 700;
            letter-spacing: 0.05em;
            margin-top: 12px;
            font-family: 'JetBrains Mono', monospace;
        }
        .hash-item-label:first-child { margin-top: 0; }
        .hash-item-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            color: var(--text-main);
            font-weight: 500;
            margin-top: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .hash-item-value:hover .copy-btn { opacity: 1; }
        
        .hash-match {
            display: flex;
            align-items: center;
            justify-content: flex-end;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 12px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.05em;
        }
        .badge.success {
            background: var(--success-bg);
            color: var(--success);
            border: 1px solid var(--success);
        }
        .badge.error {
            background: var(--error-bg);
            color: var(--error);
            border: 1px solid var(--error);
        }
        .badge.neutral {
            background: var(--surface);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }

        @media (max-width: 900px) {
            .grid { grid-template-columns: 1fr; }
            .header { flex-direction: column; align-items: flex-start; }
            .header-meta { text-align: left; margin-top: 16px; }
            .hash-row {
                grid-template-columns: 1fr;
                gap: 16px;
            }
            .hash-match { justify-content: flex-start; margin-top: 8px; }
        }
    </style>
</head>
<body data-theme="dark">
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>Forensic Disk Acquisition Dashboard</h1>
                <div style="margin-top: 8px; font-size: 18px; font-weight: 600; color: var(--primary);">Case: {{CASE_NUMBER}} | Evidence ID: {{EVIDENCE_ID}}</div>
                <div class="controls">
                    <button class="btn" id="theme-toggle">Toggle Light Mode</button>
                </div>
            </div>
            <div class="header-meta">
                <div><strong>Examiner:</strong> {{EXAMINER}}</div>
                <div><strong>Report Generated:</strong> {{REPORT_DATE}}</div>
                <div style="margin-top: 8px;"><span class="badge {{STATUS_CLASS}}">{{STATUS_BADGE}}</span></div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Imaging Parameters</h3>
                <div class="field"><div class="label">IMAGING MODE</div><div class="value">{{IMAGING_MODE}}</div></div>
                <div class="field"><div class="label">TARGET FORMAT</div><div class="value">{{FORMAT}}</div></div>
                <div class="field"><div class="label">NOTES</div><div class="value">{{NOTES}}</div></div>
            </div>
            
            <div class="card">
                <h3>Source Details</h3>
                <div class="field"><div class="label">DEVICE PATH</div><div class="value data-mono"><span>{{SOURCE_DEVICE}}</span><button class="copy-btn" title="Copy">📋</button></div></div>
                <div class="field"><div class="label">HARDWARE MODEL</div><div class="value">{{SOURCE_MODEL}}</div></div>
                <div class="field"><div class="label">SERIAL NUMBER</div><div class="value data-mono"><span>{{SOURCE_SERIAL}}</span><button class="copy-btn" title="Copy">📋</button></div></div>
                <div class="field"><div class="label">TOTAL CAPACITY</div><div class="value">{{SOURCE_SIZE_GB}} GB <span style="font-weight:400; color:var(--text-muted); font-size:13px;">({{SOURCE_SIZE_BYTES}} bytes)</span></div></div>
            </div>

            <div class="card">
                <h3>Acquisition Details</h3>
                <div class="field"><div class="label">DESTINATION FILE</div><div class="value data-mono"><span>{{DEST_FILE}}</span><button class="copy-btn" title="Copy">📋</button></div></div>
                <div class="field"><div class="label">START TIME</div><div class="value data-mono">{{START_TIME}}</div></div>
                <div class="field"><div class="label">END TIME</div><div class="value data-mono">{{END_TIME}}</div></div>
                <div class="field"><div class="label">TOTAL DURATION</div><div class="value">{{DURATION_FULL}}</div></div>
                <div class="field"><div class="label">BAD SECTORS</div><div class="value">{{BAD_SECTORS}}</div></div>
            </div>
        </div>

        {{LIVE_ACQUISITION_HTML}}

        <div class="hash-section">
            <div class="hash-header" id="hash-toggle">
                <h3>Hash Verification</h3>
                <span id="hash-icon">▼</span>
            </div>
            <div class="hash-content-wrapper" id="hash-content">
                {{HASHES_HTML}}
            </div>
        </div>
    </div>

    <script>
        const themeBtn = document.getElementById('theme-toggle');
        themeBtn.addEventListener('click', () => {
            const body = document.body;
            if (body.getAttribute('data-theme') === 'dark') {
                body.setAttribute('data-theme', 'light');
                themeBtn.textContent = 'Toggle Dark Mode';
            } else {
                body.setAttribute('data-theme', 'dark');
                themeBtn.textContent = 'Toggle Light Mode';
            }
        });

        const hashToggle = document.getElementById('hash-toggle');
        const hashContent = document.getElementById('hash-content');
        const hashIcon = document.getElementById('hash-icon');
        hashToggle.addEventListener('click', () => {
            if (hashContent.style.display === 'none') {
                hashContent.style.display = 'block';
                hashIcon.textContent = '▼';
            } else {
                hashContent.style.display = 'none';
                hashIcon.textContent = '▶';
            }
        });

        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const text = e.target.previousElementSibling.textContent;
                try {
                    await navigator.clipboard.writeText(text);
                    const original = e.target.textContent;
                    e.target.textContent = '✓';
                    setTimeout(() => e.target.textContent = original, 2000);
                } catch (err) {
                    console.error('Failed to copy', err);
                }
            });
        });
    </script>
</body>
</html>"#;

        let live_acq_html = if data.vss_snapshot_id.is_some() || data.ram_dump_path.is_some() || !data.locked_files_copied.is_empty() {
            let mut html = String::from(r#"<div class="card" style="grid-column: 1 / -1; margin-bottom: 32px;">
                <h3>Live Acquisition Details</h3>
                <div class="grid" style="margin-bottom: 0;">"#);

            if let Some(ref vss_id) = data.vss_snapshot_id {
                html.push_str(&format!(r#"
                <div class="card" style="box-shadow: none; border-color: var(--border);">
                    <h4 style="margin-top: 0; color: var(--text-muted); font-size: 12px;">VSS SNAPSHOT</h4>
                    <div class="field"><div class="label">SHADOW COPY ID</div><div class="value data-mono">{}</div></div>
                </div>"#, vss_id));
            }

            if let Some(ref ram_path) = data.ram_dump_path {
                let size_str = if let Some(s) = data.ram_dump_size { format!("{} bytes", s) } else { "Unknown".to_string() };
                html.push_str(&format!(r#"
                <div class="card" style="box-shadow: none; border-color: var(--border);">
                    <h4 style="margin-top: 0; color: var(--text-muted); font-size: 12px;">RAM ACQUISITION</h4>
                    <div class="field"><div class="label">DUMP PATH</div><div class="value data-mono">{}</div></div>
                    <div class="field"><div class="label">SIZE</div><div class="value">{}</div></div>
                </div>"#, ram_path, size_str));
            }

            if !data.locked_files_copied.is_empty() {
                html.push_str(&format!(r#"
                <div class="card" style="box-shadow: none; border-color: var(--border);">
                    <h4 style="margin-top: 0; color: var(--text-muted); font-size: 12px;">LOCKED FILES COPIED</h4>
                    <div class="field"><div class="label">FILES</div><div class="value" style="font-size: 12px;">{}</div></div>
                </div>"#, data.locked_files_copied.join("<br>")));
            }

            html.push_str("</div></div>");
            html
        } else {
            String::new()
        };

    let html_content = template
        .replace("{{CASE_NUMBER}}", &data.case_number)
        .replace("{{IMAGING_MODE}}", &data.imaging_mode)
        .replace("{{FORMAT}}", &data.format)
        .replace("{{STATUS_BADGE}}", status_badge)
        .replace("{{STATUS_CLASS}}", status_class)
        .replace("{{REPORT_DATE}}", &to_ist_rfc2822(&chrono::Utc::now()))
        .replace("{{EXAMINER}}", &data.examiner)
        .replace("{{EVIDENCE_ID}}", &data.evidence_id)
        .replace("{{SOURCE_SIZE_GB}}", &format!("{:.2}", data.source_size as f64 / 1_000_000_000.0))
        .replace("{{SOURCE_SIZE_BYTES}}", &data.source_size.to_string())
        .replace("{{DURATION_SHORT}}", &short_duration_str)
        .replace("{{DURATION_FULL}}", &duration_str)
        .replace("{{BAD_SECTORS}}", &data.bad_sectors.to_string())
        .replace("{{SPEED_MB}}", &format!("{:.1}", speed_mb))
        .replace("{{NOTES}}", &data.notes)
        .replace("{{SOURCE_DEVICE}}", &data.source_device)
        .replace("{{SOURCE_MODEL}}", &data.source_model)
        .replace("{{SOURCE_SERIAL}}", &data.source_serial)
        .replace("{{DEST_FILE}}", &data.dest_file)
        .replace("{{START_TIME}}", &to_ist_rfc2822(&data.start_time))
        .replace("{{END_TIME}}", &to_ist_rfc2822(&data.end_time))
        .replace("{{HASHES_HTML}}", &hashes_html)
        .replace("{{LIVE_ACQUISITION_HTML}}", &live_acq_html);

    file.write_all(html_content.as_bytes())?;
    Ok(())
}

pub fn generate_json_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    // ponytail: derive Serialize is strictly better than manually mapping fields.
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, data)?;
    Ok(())
}

pub fn generate_csv_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "Timestamp,Event,Details")?;
    writeln!(file, "\"{}\",\"Acquisition Started\",\"Source: {}\"", to_ist_rfc2822(&data.start_time), data.source_device)?;
    writeln!(file, "\"{}\",\"Acquisition Finished\",\"Destination: {}\"", to_ist_rfc2822(&data.end_time), data.dest_file)?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "\"{}\",\"Acquisition Hash Computed\",\"{}: {}\"", to_ist_rfc2822(&data.end_time), algo, hash_val)?;
    }
    if let Some(post) = &data.post_hashes {
        for (algo, hash_val) in post {
            writeln!(file, "\"{}\",\"File Hash Computed\",\"{}: {}\"", to_ist_rfc2822(&chrono::Utc::now()), algo, hash_val)?;
        }
    }
    Ok(())
}


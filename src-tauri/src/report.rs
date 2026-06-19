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
}

fn to_ist_rfc2822(dt: &chrono::DateTime<chrono::Utc>) -> String {
    let ist_offset = chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
    dt.with_timezone(&ist_offset).to_rfc2822()
}

pub fn generate_txt_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "==================================================")?;
    writeln!(file, "          FORGELENS DISK IMAGER REPORT            ")?;
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
        writeln!(file, "CONTAINER HASHES (POST-ACQUISITION FILE HASH)")?;
        for (algo, hash_val) in post {
            writeln!(file, "  {}: {}", algo, hash_val)?;
        }
    }

    writeln!(file, "--------------------------------------------------")?;
    
    // Perform Verification matching
    let mut verified = true;
    if !data.pre_hashes.is_empty() {
        writeln!(file, "INTEGRITY VERIFICATION LOG")?;
        for (algo, post_hash) in &data.hashes {
            if let Some(pre_hash) = data.pre_hashes.get(algo) {
                if pre_hash == post_hash {
                    writeln!(file, "  {}: MATCHED (Integrity Confirmed)", algo)?;
                } else {
                    writeln!(file, "  {}: MISMATCHED (WARNING: Integrity Compromised!)", algo)?;
                    verified = false;
                }
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
    for (algo, post_hash) in &data.hashes {
        let pre_hash = data.pre_hashes.get(algo).cloned().unwrap_or_else(|| "N/A".to_string());
        let matched = if pre_hash == *post_hash {
            true
        } else {
            verified_all = false;
            false
        };
        
        let match_text = if matched {
            r#"<span class="badge success">MATCHED</span>"#
        } else if pre_hash == "N/A" {
            r#"<span class="badge neutral">NO PRE-HASH</span>"#
        } else {
            r#"<span class="badge error">MISMATCH</span>"#
        };

        let post_file_hash_html = if let Some(post) = &data.post_hashes {
            let val = post.get(algo).cloned().unwrap_or_else(|| "N/A".to_string());
            format!(r#"<div class="hash-label">Post-Acquisition (Image File Hash)</div><div class="hash-value">{}</div>"#, val)
        } else {
            String::new()
        };

        hashes_html.push_str(&format!(r#"
            <div class="hash-row">
                <div class="hash-algo">{algo}</div>
                <div class="hash-content">
                    <div class="hash-label">Pre-Acquisition (Source Device)</div>
                    <div class="hash-value">{pre_hash}</div>
                    <div class="hash-label">Acquisition (Stream Verification)</div>
                    <div class="hash-value">{post_hash}</div>
                    {post_file_hash_html}
                </div>
                <div class="hash-match">{match_text}</div>
            </div>
"#, algo=algo, pre_hash=pre_hash, post_hash=post_hash, post_file_hash_html=post_file_hash_html, match_text=match_text));
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
    <title>ForgeLens Forensic Report — {{CASE_NUMBER}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #0284c7;
            --success: #10b981;
            --success-bg: #d1fae5;
            --error: #ef4444;
            --error-bg: #fee2e2;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 40px;
            line-height: 1.5;
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
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
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
        }
        .data-mono {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            font-size: 14px;
        }
        .hash-table {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .hash-row {
            display: grid;
            grid-template-columns: 120px 1fr 150px;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            align-items: center;
        }
        .hash-row:last-child {
            border-bottom: none;
        }
        .hash-algo {
            font-weight: 700;
            font-size: 18px;
            color: var(--primary);
        }
        .hash-content .hash-label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 700;
            letter-spacing: 0.05em;
            margin-top: 12px;
            font-family: 'JetBrains Mono', monospace;
        }
        .hash-content .hash-label:first-child {
            margin-top: 0;
        }
        .hash-content .hash-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            color: var(--text-main);
            font-weight: 500;
            margin-top: 4px;
        }
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
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .badge.error {
            background: var(--error-bg);
            color: var(--error);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .badge.neutral {
            background: #f1f5f9;
            color: var(--text-muted);
            border: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>Cyber-Forensic Acquisition Report</h1>
                <div style="margin-top: 8px; font-size: 18px; font-weight: 600; color: var(--primary);">Case: {{CASE_NUMBER}} | Evidence ID: {{EVIDENCE_ID}}</div>
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
                <div class="field"><div class="label">DEVICE PATH</div><div class="value data-mono">{{SOURCE_DEVICE}}</div></div>
                <div class="field"><div class="label">HARDWARE MODEL</div><div class="value">{{SOURCE_MODEL}}</div></div>
                <div class="field"><div class="label">SERIAL NUMBER</div><div class="value data-mono">{{SOURCE_SERIAL}}</div></div>
                <div class="field"><div class="label">TOTAL CAPACITY</div><div class="value">{{SOURCE_SIZE_GB}} GB <span style="font-weight:400; color:var(--text-muted); font-size:13px;">({{SOURCE_SIZE_BYTES}} bytes)</span></div></div>
            </div>

            <div class="card">
                <h3>Acquisition Details</h3>
                <div class="field"><div class="label">DESTINATION FILE</div><div class="value data-mono">{{DEST_FILE}}</div></div>
                <div class="field"><div class="label">START TIME</div><div class="value data-mono">{{START_TIME}}</div></div>
                <div class="field"><div class="label">END TIME</div><div class="value data-mono">{{END_TIME}}</div></div>
                <div class="field"><div class="label">TOTAL DURATION</div><div class="value">{{DURATION_FULL}}</div></div>
                <div class="field"><div class="label">BAD SECTORS</div><div class="value">{{BAD_SECTORS}}</div></div>
            </div>
        </div>

        <h3 style="color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; font-weight: 700; font-size: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px;">Hash Verification</h3>
        <div class="hash-table">
            {{HASHES_HTML}}
        </div>
    </div>
</body>
</html>"#;

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
        .replace("{{HASHES_HTML}}", &hashes_html);

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


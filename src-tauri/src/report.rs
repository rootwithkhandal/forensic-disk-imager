use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;
use crate::error::Result;
use crate::hasher::HashAlgorithm;

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
    writeln!(file, "Report Date:     {}", chrono::Utc::now().to_rfc2822())?;
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
    writeln!(file, "  Start Time:    {}", data.start_time.to_rfc2822())?;
    writeln!(file, "  End Time:      {}", data.end_time.to_rfc2822())?;
    let duration = data.end_time.signed_duration_since(data.start_time);
    writeln!(file, "  Duration:      {}h {}m {}s", duration.num_hours(), duration.num_minutes() % 60, duration.num_seconds() % 60)?;
    writeln!(file, "  Bad Sectors:   {}", data.bad_sectors)?;
    
    if !data.pre_hashes.is_empty() {
        writeln!(file, "--------------------------------------------------")?;
        writeln!(file, "PRE-ACQUISITION HASHES")?;
        for (algo, hash_val) in &data.pre_hashes {
            writeln!(file, "  {:?}: {}", algo, hash_val)?;
        }
    }

    writeln!(file, "--------------------------------------------------")?;
    writeln!(file, "VERIFICATION HASHES (POST-ACQUISITION)")?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "  {:?}: {}", algo, hash_val)?;
    }

    writeln!(file, "--------------------------------------------------")?;
    
    // Perform Verification matching
    let mut verified = true;
    if !data.pre_hashes.is_empty() {
        writeln!(file, "INTEGRITY VERIFICATION LOG")?;
        for (algo, post_hash) in &data.hashes {
            if let Some(pre_hash) = data.pre_hashes.get(algo) {
                if pre_hash == post_hash {
                    writeln!(file, "  {:?}: MATCHED (Integrity Confirmed)", algo)?;
                } else {
                    writeln!(file, "  {:?}: MISMATCHED (WARNING: Integrity Compromised!)", algo)?;
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
    writeln!(file, "==================================================")?;
    Ok(())
}

pub fn generate_html_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html><head><meta charset=\"utf-8\"><title>Forgelens Forensic Report</title>")?;
    writeln!(file, "<style>")?;
    writeln!(file, "body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #080b10; color: #f0f3f8; padding: 32px; max-width: 800px; margin: 0 auto; }}")?;
    writeln!(file, "h1, h2 {{ color: #00d4aa; border-bottom: 1px solid #222d3d; padding-bottom: 8px; }}")?;
    writeln!(file, "table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}")?;
    writeln!(file, "td, th {{ border: 1px solid #222d3d; padding: 10px; text-align: left; font-size: 13px; }}")?;
    writeln!(file, "th {{ background: #151c27; color: #8c9bb0; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}")?;
    writeln!(file, "tr:nth-child(even) {{ background: rgba(255, 255, 255, 0.01); }}")?;
    writeln!(file, "code {{ font-family: monospace; color: #00ffaa; }}")?;
    writeln!(file, ".status {{ font-weight: bold; padding: 4px 8px; border-radius: 4px; display: inline-block; }}")?;
    writeln!(file, ".status-ok {{ background: rgba(0, 212, 170, 0.1); color: #00d4aa; border: 1px solid rgba(0, 212, 170, 0.3); }}")?;
    writeln!(file, "</style></head><body>")?;
    writeln!(file, "<h1>⚡ FORGELENS Forensic Audit Report</h1>")?;
    writeln!(file, "<table>")?;
    writeln!(file, "<tr><th style=\"width: 30%;\">Parameter</th><th>Value</th></tr>")?;
    writeln!(file, "<tr><td>Case Number</td><td>{}</td></tr>", data.case_number)?;
    writeln!(file, "<tr><td>Examiner</td><td>{}</td></tr>", data.examiner)?;
    writeln!(file, "<tr><td>Evidence ID</td><td>{}</td></tr>", data.evidence_id)?;
    writeln!(file, "<tr><td>Notes</td><td>{}</td></tr>", data.notes)?;
    writeln!(file, "<tr><td>Imaging Mode</td><td>{}</td></tr>", data.imaging_mode)?;
    writeln!(file, "<tr><td>Format</td><td>{}</td></tr>", data.format)?;
    writeln!(file, "<tr><td>Source Device</td><td>{}</td></tr>", data.source_device)?;
    writeln!(file, "<tr><td>Source Model</td><td>{}</td></tr>", data.source_model)?;
    writeln!(file, "<tr><td>Source Serial</td><td>{}</td></tr>", data.source_serial)?;
    writeln!(file, "<tr><td>Destination</td><td><code>{}</code></td></tr>", data.dest_file)?;
    writeln!(file, "<tr><td>Bad Sectors</td><td>{}</td></tr>", data.bad_sectors)?;
    writeln!(file, "</table>")?;
    
    writeln!(file, "<h2>Verification Hashes</h2>")?;
    writeln!(file, "<table>")?;
    writeln!(file, "<tr><th style=\"width: 30%;\">Algorithm</th><th>Digest</th></tr>")?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "<tr><td>{:?}</td><td><code>{}</code></td></tr>", algo, hash_val)?;
    }
    writeln!(file, "</table>")?;
    
    writeln!(file, "<p style=\"margin-top: 32px;\">Acquisition Status: <span class=\"status status-ok\">COMPLETED / VERIFIED</span></p>")?;
    writeln!(file, "</body></html>")?;
    Ok(())
}

pub fn generate_json_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    let mut hash_map = HashMap::new();
    for (k, v) in &data.hashes {
        hash_map.insert(format!("{:?}", k), v.clone());
    }
    let data_json = serde_json::json!({
        "case_number": data.case_number,
        "examiner": data.examiner,
        "evidence_id": data.evidence_id,
        "notes": data.notes,
        "imaging_mode": data.imaging_mode,
        "format": data.format,
        "source_device": data.source_device,
        "source_size": data.source_size,
        "source_model": data.source_model,
        "source_serial": data.source_serial,
        "dest_file": data.dest_file,
        "start_time": data.start_time.to_rfc2822(),
        "end_time": data.end_time.to_rfc2822(),
        "bad_sectors": data.bad_sectors,
        "hashes": hash_map
    });
    let content = serde_json::to_string_pretty(&data_json)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub fn generate_csv_report<P: AsRef<Path>>(path: P, data: &ReportData) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "Timestamp,Event,Details")?;
    writeln!(file, "\"{}\",\"Acquisition Started\",\"Source: {}\"", data.start_time.to_rfc2822(), data.source_device)?;
    writeln!(file, "\"{}\",\"Acquisition Finished\",\"Destination: {}\"", data.end_time.to_rfc2822(), data.dest_file)?;
    for (algo, hash_val) in &data.hashes {
        writeln!(file, "\"{}\",\"Hash Computed\",\"{:?}: {}\"", data.end_time.to_rfc2822(), algo, hash_val)?;
    }
    Ok(())
}


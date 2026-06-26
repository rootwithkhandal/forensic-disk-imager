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

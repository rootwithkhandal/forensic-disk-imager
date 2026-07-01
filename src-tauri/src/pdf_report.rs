use std::path::Path;
use std::fs::File;
use std::io::BufWriter;
use printpdf::*;
use chrono::{DateTime, Utc};
use crate::acquisition::{AcquisitionConfig, AcquisitionResult};

pub fn generate_pdf_report(
    config: &AcquisitionConfig,
    result: &AcquisitionResult,
    start_time: &DateTime<Utc>,
    end_time: &DateTime<Utc>,
    dest_path: &Path,
) -> Result<(), String> {
    let report_path = if dest_path.is_dir() {
        dest_path.join("report.pdf")
    } else if let Some(ext) = dest_path.extension() {
        let mut new_ext = ext.to_string_lossy().into_owned();
        new_ext.push_str("_report.pdf");
        dest_path.with_extension(new_ext)
    } else {
        dest_path.with_extension("report.pdf")
    };

    let (doc, page1, layer1) = PdfDocument::new(
        "OpenForensic Acquisition Report",
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );

    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;

    let current_layer = doc.get_page(page1).get_layer(layer1);

    let mut cursor_y: f64 = 280.0;
    let margin_left: f64 = 20.0;
    
    // Helper to write a line of text
    let write_text = |text: &str, font: &printpdf::IndirectFontRef, size: f64, x: f64, y: &mut f64, line_height: f64| {
        current_layer.use_text(text, size, Mm(x), Mm(*y), font);
        *y -= line_height;
    };

    // Title
    write_text("OpenForensic Acquisition Report", &font_bold, 18.0, margin_left, &mut cursor_y, 10.0);
    cursor_y -= 5.0; // Extra spacing

    // Case Information
    write_text("Case Information", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
    write_text(&format!("Case Number: {}", config.case_number), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Examiner: {}", config.examiner), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Evidence ID: {}", config.evidence_id), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Notes: {}", config.notes), &font_regular, 10.0, margin_left, &mut cursor_y, 10.0);

    // Timestamps
    write_text("Acquisition Details", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
    write_text(&format!("Start Time (UTC): {}", start_time.format("%Y-%m-%d %H:%M:%S")), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("End Time (UTC): {}", end_time.format("%Y-%m-%d %H:%M:%S")), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Imaging Mode: {}", config.imaging_mode), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Total Bytes Processed: {}", result.bytes_read), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    write_text(&format!("Bad Sectors Encountered: {}", result.bad_sectors), &font_regular, 10.0, margin_left, &mut cursor_y, 10.0);

    // Hashes
    write_text("Chain of Custody (Cryptographic Hashes)", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
    if let Some(pre) = &config.pre_hash {
        write_text(&format!("Pre-Acquisition Hash: {}", pre), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    }
    for (algo, hash_val) in &result.hashes {
        write_text(&format!("{:?} Hash: {}", algo, hash_val), &font_regular, 10.0, margin_left, &mut cursor_y, 5.0);
    }
    cursor_y -= 5.0;

    // Keyword Hits
    if !result.keyword_hits.is_empty() {
        write_text("Keyword Hits", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
        let max_display = 20; // limit lines on PDF to avoid page overrun
        for (i, (kw, offset)) in result.keyword_hits.iter().take(max_display).enumerate() {
            if cursor_y < 20.0 { break; } // basic page boundary protection
            write_text(&format!("{}. '{}' at offset {}", i + 1, kw, offset), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        if result.keyword_hits.len() > max_display {
            write_text(&format!("... and {} more hits.", result.keyword_hits.len() - max_display), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        cursor_y -= 5.0;
    }

    // YARA Hits
    if !result.yara_hits.is_empty() {
        write_text("YARA Rule Hits", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
        let max_display = 20;
        for (i, (rule, tags, offset)) in result.yara_hits.iter().take(max_display).enumerate() {
            if cursor_y < 20.0 { break; }
            let tags_str = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
            write_text(&format!("{}. Rule '{}'{} at offset {}", i + 1, rule, tags_str, offset), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        if result.yara_hits.len() > max_display {
            write_text(&format!("... and {} more YARA hits.", result.yara_hits.len() - max_display), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        cursor_y -= 5.0;
    }

    // Plugin Results
    if !result.plugin_results.is_empty() {
        write_text("Plugin Results & Custom Hashes", &font_bold, 14.0, margin_left, &mut cursor_y, 6.0);
        let max_display = 20;
        for (i, (key, val)) in result.plugin_results.iter().take(max_display).enumerate() {
            if cursor_y < 20.0 { break; }
            write_text(&format!("{}. {}: {}", i + 1, key, val), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        if result.plugin_results.len() > max_display {
            write_text(&format!("... and {} more plugin results.", result.plugin_results.len() - max_display), &font_regular, 9.0, margin_left + 5.0, &mut cursor_y, 4.0);
        }
        cursor_y -= 5.0;
    }

    // Signature Block (if near bottom, we just place it where it fits)
    if cursor_y < 40.0 {
        // Not enough room for signature, but simple layout doesn't do auto-pagination here.
        // We just print it if possible.
    }
    cursor_y -= 10.0;
    write_text("Examiner Signature: _________________________________", &font_bold, 12.0, margin_left, &mut cursor_y, 6.0);
    write_text(&format!("Date: {}", Utc::now().format("%Y-%m-%d")), &font_regular, 10.0, margin_left, &mut cursor_y, 6.0);

    let file = File::create(&report_path).map_err(|e| format!("Failed to create PDF file: {}", e))?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer).map_err(|e| format!("Failed to save PDF: {}", e))?;

    Ok(())
}

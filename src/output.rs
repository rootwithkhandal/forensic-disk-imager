use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use flate2::write::GzEncoder;
use flate2::Compression;
use zstd::Encoder as ZstdEncoder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    None,
    Gzip,
    Zstd,
}

pub struct OutputWriter {
    base_path: PathBuf,
    split_size: Option<u64>,
    compression: CompressionFormat,
    current_writer: Box<dyn Write + Send>,
    current_part: u32,
    bytes_written_part: u64,
}

impl OutputWriter {
    pub fn new(base_path: &Path, split_size: Option<u64>, compression: CompressionFormat, resume: bool) -> std::io::Result<Self> {
        let part = 1;
        let path = if split_size.is_some() {
            Self::get_part_path(base_path, part)
        } else {
            base_path.to_path_buf()
        };

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)?;
            
        if resume {
            use std::io::Seek;
            let _ = file.seek(std::io::SeekFrom::End(0));
        } else {
            file.set_len(0)?; // truncate if not resuming
        }
        
        let writer = Self::wrap_writer(file, &compression)?;

        Ok(Self {
            base_path: base_path.to_path_buf(),
            split_size,
            compression,
            current_writer: writer,
            current_part: part,
            bytes_written_part: 0,
        })
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub fn write_format_header(&mut self, format: &str, case: &str, examiner: &str, evidence_id: &str, notes: &str) -> std::io::Result<()> {
        if format == "E01" {
            writeln!(self.current_writer, "=== EXPERT WITNESS COMPRESSION FORMAT HEADER (E01) ===")?;
            writeln!(self.current_writer, "Case Number: {}", case)?;
            writeln!(self.current_writer, "Examiner:    {}", examiner)?;
            writeln!(self.current_writer, "Evidence ID: {}", evidence_id)?;
            writeln!(self.current_writer, "Notes:       {}", notes)?;
            writeln!(self.current_writer, "Acquisition: EWF-E01 Staged Archive")?;
            writeln!(self.current_writer, "======================================================")?;
            self.bytes_written_part += 256; // estimated header size or block offset
        } else if format == "AFF" {
            writeln!(self.current_writer, "=== ADVANCED FORENSIC FORMAT HEADER (AFF) ===")?;
            writeln!(self.current_writer, "Case Number: {}", case)?;
            writeln!(self.current_writer, "Examiner:    {}", examiner)?;
            writeln!(self.current_writer, "Evidence ID: {}", evidence_id)?;
            writeln!(self.current_writer, "Notes:       {}", notes)?;
            writeln!(self.current_writer, "Acquisition: AFF Staged Metadata Block")?;
            writeln!(self.current_writer, "=============================================")?;
            self.bytes_written_part += 256;
        }
        Ok(())
    }

    fn get_part_path(base_path: &Path, part: u32) -> PathBuf {
        let ext = format!("{:03}", part);
        base_path.with_extension(ext)
    }

    fn wrap_writer(file: File, compression: &CompressionFormat) -> std::io::Result<Box<dyn Write + Send>> {
        match compression {
            CompressionFormat::None => Ok(Box::new(file)),
            CompressionFormat::Gzip => {
                let encoder = GzEncoder::new(file, Compression::default());
                Ok(Box::new(encoder))
            }
            CompressionFormat::Zstd => {
                let encoder = ZstdEncoder::new(file, 3)?.auto_finish();
                Ok(Box::new(encoder))
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if let Some(max_size) = self.split_size {
            let mut offset = 0usize;
            let total_len = buf.len();

            while (offset as u64) < (total_len as u64) {
                let bytes_left_in_part = max_size.saturating_sub(self.bytes_written_part);
                if bytes_left_in_part == 0 {
                    // Flush current, open new part
                    self.current_writer.flush()?;
                    self.current_part += 1;
                    let path = Self::get_part_path(&self.base_path, self.current_part);
                    let file = File::create(&path)?;
                    self.current_writer = Self::wrap_writer(file, &self.compression)?;
                    self.bytes_written_part = 0;
                    continue;
                }

                let chunk_size = std::cmp::min((total_len - offset) as u64, bytes_left_in_part) as usize;
                self.current_writer.write_all(&buf[offset..offset + chunk_size])?;
                self.bytes_written_part += chunk_size as u64;
                offset += chunk_size;
            }
        } else {
            self.current_writer.write_all(buf)?;
            self.bytes_written_part += buf.len() as u64;
        }
        Ok(())
    }

    pub fn write_zeros(&mut self, count: usize) -> std::io::Result<()> {
        let chunk_size = 65536; // 64KB chunks
        let mut remaining = count;
        let zeros = vec![0u8; std::cmp::min(chunk_size, remaining)];

        while remaining > 0 {
            let write_len = std::cmp::min(zeros.len(), remaining);
            self.write_all(&zeros[..write_len])?;
            remaining -= write_len;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.current_writer.flush()
    }
}

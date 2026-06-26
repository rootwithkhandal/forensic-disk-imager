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

pub enum WriterType {
    Raw(File),
    Compressed(Box<dyn Write + Send>),
}

impl Write for WriterType {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WriterType::Raw(f) => f.write(buf),
            WriterType::Compressed(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriterType::Raw(f) => f.flush(),
            WriterType::Compressed(w) => w.flush(),
        }
    }
}

impl WriterType {
    pub fn seek_forward(&mut self, offset: i64) -> std::io::Result<()> {
        match self {
            WriterType::Raw(f) => {
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Current(offset))?;
            }
            WriterType::Compressed(w) => {
                let zeros = vec![0u8; offset as usize];
                w.write_all(&zeros)?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn mark_sparse(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    let handle = file.as_raw_handle();
    let mut bytes_returned = 0u32;
    unsafe {
        let _ = DeviceIoControl(
            windows::Win32::Foundation::HANDLE(handle as _),
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );
    }
}

pub struct OutputWriter {
    base_path: PathBuf,
    split_size: Option<u64>,
    compression: CompressionFormat,
    current_writer: WriterType,
    current_part: u32,
    bytes_written_part: u64,
    sparse: bool,
}

impl OutputWriter {
    pub fn new(
        base_path: &Path,
        split_size: Option<u64>,
        compression: CompressionFormat,
        resume: bool,
        sparse: bool,
    ) -> std::io::Result<Self> {
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
            
        #[cfg(target_os = "windows")]
        if sparse {
            mark_sparse(&file);
        }

        if resume {
            use std::io::Seek;
            let _ = file.seek(std::io::SeekFrom::End(0));
        } else {
            file.set_len(0)?;
        }
        
        let writer = Self::wrap_writer(file, &compression)?;

        Ok(Self {
            base_path: base_path.to_path_buf(),
            split_size,
            compression,
            current_writer: writer,
            current_part: part,
            bytes_written_part: 0,
            sparse,
        })
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub fn current_part_path(&self) -> PathBuf {
        if self.split_size.is_some() {
            Self::get_part_path(&self.base_path, self.current_part)
        } else {
            self.base_path.to_path_buf()
        }
    }

    pub fn bytes_written_part(&self) -> u64 {
        self.bytes_written_part
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
            self.bytes_written_part += 256;
        } else if format == "EX01" {
            writeln!(self.current_writer, "=== EXPERT WITNESS INTEGRATION FORMAT HEADER (EX01) ===")?;
            writeln!(self.current_writer, "Case Number: {}", case)?;
            writeln!(self.current_writer, "Examiner:    {}", examiner)?;
            writeln!(self.current_writer, "Evidence ID: {}", evidence_id)?;
            writeln!(self.current_writer, "Notes:       {}", notes)?;
            writeln!(self.current_writer, "Acquisition: EWF-EX01 Staged Archive")?;
            writeln!(self.current_writer, "=======================================================")?;
            self.bytes_written_part += 256;
        } else if format == "AFF" {
            writeln!(self.current_writer, "=== ADVANCED FORENSIC FORMAT HEADER (AFF) ===")?;
            writeln!(self.current_writer, "Case Number: {}", case)?;
            writeln!(self.current_writer, "Examiner:    {}", examiner)?;
            writeln!(self.current_writer, "Evidence ID: {}", evidence_id)?;
            writeln!(self.current_writer, "Notes:       {}", notes)?;
            writeln!(self.current_writer, "Acquisition: AFF Staged Metadata Block")?;
            writeln!(self.current_writer, "=============================================")?;
            self.bytes_written_part += 256;
        } else if format == "SMART" {
            writeln!(self.current_writer, "=== SMART FORENSIC IMAGE HEADER (SMART) ===")?;
            writeln!(self.current_writer, "Case Number: {}", case)?;
            writeln!(self.current_writer, "Examiner:    {}", examiner)?;
            writeln!(self.current_writer, "Evidence ID: {}", evidence_id)?;
            writeln!(self.current_writer, "Notes:       {}", notes)?;
            writeln!(self.current_writer, "Acquisition: SMART Staged Volume")?;
            writeln!(self.current_writer, "===========================================")?;
            self.bytes_written_part += 256;
        }
        Ok(())
    }

    fn get_part_path(base_path: &Path, part: u32) -> PathBuf {
        let ext = format!("{:03}", part);
        base_path.with_extension(ext)
    }

    fn wrap_writer(file: File, compression: &CompressionFormat) -> std::io::Result<WriterType> {
        match compression {
            CompressionFormat::None => Ok(WriterType::Raw(file)),
            CompressionFormat::Gzip => {
                let encoder = GzEncoder::new(file, Compression::default());
                Ok(WriterType::Compressed(Box::new(encoder)))
            }
            CompressionFormat::Zstd => {
                let encoder = ZstdEncoder::new(file, 3)?.auto_finish();
                Ok(WriterType::Compressed(Box::new(encoder)))
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let is_sparse_candidate = self.sparse && 
            self.compression == CompressionFormat::None && 
            buf.iter().all(|&x| x == 0);

        if let Some(max_size) = self.split_size {
            let mut offset = 0usize;
            let total_len = buf.len();

            while (offset as u64) < (total_len as u64) {
                let bytes_left_in_part = max_size.saturating_sub(self.bytes_written_part);
                if bytes_left_in_part == 0 {
                    self.current_writer.flush()?;
                    self.current_part += 1;
                    let path = Self::get_part_path(&self.base_path, self.current_part);
                    let file = File::create(&path)?;
                    
                    #[cfg(target_os = "windows")]
                    if self.sparse {
                        mark_sparse(&file);
                    }

                    self.current_writer = Self::wrap_writer(file, &self.compression)?;
                    self.bytes_written_part = 0;
                    continue;
                }

                let chunk_size = std::cmp::min((total_len - offset) as u64, bytes_left_in_part) as usize;
                let chunk = &buf[offset..offset + chunk_size];
                
                let chunk_is_zero = self.sparse && 
                    self.compression == CompressionFormat::None && 
                    chunk.iter().all(|&x| x == 0);

                if chunk_is_zero {
                    self.current_writer.seek_forward(chunk_size as i64)?;
                } else {
                    self.current_writer.write_all(chunk)?;
                }
                
                self.bytes_written_part += chunk_size as u64;
                offset += chunk_size;
            }
        } else {
            if is_sparse_candidate {
                self.current_writer.seek_forward(buf.len() as i64)?;
            } else {
                self.current_writer.write_all(buf)?;
            }
            self.bytes_written_part += buf.len() as u64;
        }
        Ok(())
    }

    pub fn write_zeros(&mut self, count: usize) -> std::io::Result<()> {
        if self.sparse && self.compression == CompressionFormat::None {
            if let Some(max_size) = self.split_size {
                let mut remaining = count;
                while remaining > 0 {
                    let bytes_left_in_part = max_size.saturating_sub(self.bytes_written_part);
                    if bytes_left_in_part == 0 {
                        self.current_writer.flush()?;
                        self.current_part += 1;
                        let path = Self::get_part_path(&self.base_path, self.current_part);
                        let file = File::create(&path)?;
                        
                        #[cfg(target_os = "windows")]
                        if self.sparse {
                            mark_sparse(&file);
                        }

                        self.current_writer = Self::wrap_writer(file, &self.compression)?;
                        self.bytes_written_part = 0;
                        continue;
                    }
                    let chunk_size = std::cmp::min(remaining as u64, bytes_left_in_part) as usize;
                    self.current_writer.seek_forward(chunk_size as i64)?;
                    self.bytes_written_part += chunk_size as u64;
                    remaining -= chunk_size;
                }
            } else {
                self.current_writer.seek_forward(count as i64)?;
                self.bytes_written_part += count as u64;
            }
            Ok(())
        } else {
            let chunk_size = 65536;
            let mut remaining = count;
            let zeros = vec![0u8; std::cmp::min(chunk_size, remaining)];

            while remaining > 0 {
                let write_len = std::cmp::min(zeros.len(), remaining);
                self.write_all(&zeros[..write_len])?;
                remaining -= write_len;
            }
            Ok(())
        }
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.current_writer.flush()
    }
}

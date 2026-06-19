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

// ponytail: WriterKind keeps the raw File accessible for sparse seek; compressed writers zero-fill instead.
enum WriterKind {
    Raw(File),
    Compressed(Box<dyn Write + Send>),
}

impl WriterKind {
    fn as_write(&mut self) -> &mut dyn Write {
        match self {
            WriterKind::Raw(f) => f,
            WriterKind::Compressed(w) => w.as_mut(),
        }
    }

    fn seek_forward(&mut self, n: usize) -> std::io::Result<()> {
        match self {
            WriterKind::Raw(f) => {
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Current(n as i64))?;
            }
            WriterKind::Compressed(w) => {
                // ponytail: can't seek a compressed stream; zero-fill instead. Static buf avoids per-call alloc.
                const ZEROS: [u8; 65536] = [0u8; 65536];
                let mut rem = n;
                while rem > 0 {
                    let chunk = rem.min(ZEROS.len());
                    w.write_all(&ZEROS[..chunk])?;
                    rem -= chunk;
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.as_write().flush()
    }
}

fn wrap_writer(file: File, compression: &CompressionFormat) -> std::io::Result<WriterKind> {
    match compression {
        CompressionFormat::None => Ok(WriterKind::Raw(file)),
        CompressionFormat::Gzip => Ok(WriterKind::Compressed(Box::new(GzEncoder::new(file, Compression::default())))),
        CompressionFormat::Zstd => Ok(WriterKind::Compressed(Box::new(ZstdEncoder::new(file, 3)?.auto_finish()))),
    }
}

pub struct OutputWriter {
    base_path: PathBuf,
    split_size: Option<u64>,
    compression: CompressionFormat,
    current_writer: WriterKind,
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

        Ok(Self {
            base_path: base_path.to_path_buf(),
            split_size,
            compression,
            current_writer: wrap_writer(file, &compression)?,
            current_part: part,
            bytes_written_part: 0,
            sparse,
        })
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
        let title = match format {
            "E01"   => "=== EXPERT WITNESS COMPRESSION FORMAT HEADER (E01) ===",
            "EX01"  => "=== EXPERT WITNESS INTEGRATION FORMAT HEADER (EX01) ===",
            "AFF"   => "=== ADVANCED FORENSIC FORMAT HEADER (AFF) ===",
            "SMART" => "=== SMART FORENSIC IMAGE HEADER (SMART) ===",
            _       => return Ok(()),
        };
        let header = format!("{}\nCase Number: {}\nExaminer:    {}\nEvidence ID: {}\nNotes:       {}\nAcquisition: {} Staged Archive\n=======================================================\n", title, case, examiner, evidence_id, notes, format);
        let w = self.current_writer.as_write();
        w.write_all(header.as_bytes())?;
        self.bytes_written_part += header.len() as u64;
        Ok(())
    }

    fn get_part_path(base_path: &Path, part: u32) -> PathBuf {
        base_path.with_extension(format!("{:03}", part))
    }

    fn rotate_part(&mut self) -> std::io::Result<()> {
        self.current_writer.flush()?;
        self.current_part += 1;
        let path = Self::get_part_path(&self.base_path, self.current_part);
        let file = File::create(&path)?;
        #[cfg(target_os = "windows")]
        if self.sparse { mark_sparse(&file); }
        self.current_writer = wrap_writer(file, &self.compression)?;
        self.bytes_written_part = 0;
        Ok(())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let is_zero = self.sparse
            && self.compression == CompressionFormat::None
            && buf.iter().all(|&x| x == 0);

        if let Some(max_size) = self.split_size {
            let mut offset = 0usize;
            while offset < buf.len() {
                let left = max_size.saturating_sub(self.bytes_written_part);
                if left == 0 {
                    self.rotate_part()?;
                    continue;
                }
                let chunk_len = std::cmp::min(buf.len() - offset, left as usize);
                let chunk = &buf[offset..offset + chunk_len];
                let chunk_is_zero = self.sparse
                    && self.compression == CompressionFormat::None
                    && chunk.iter().all(|&x| x == 0);
                if chunk_is_zero {
                    self.current_writer.seek_forward(chunk_len)?;
                } else {
                    self.current_writer.as_write().write_all(chunk)?;
                }
                self.bytes_written_part += chunk_len as u64;
                offset += chunk_len;
            }
        } else {
            if is_zero {
                self.current_writer.seek_forward(buf.len())?;
            } else {
                self.current_writer.as_write().write_all(buf)?;
            }
            self.bytes_written_part += buf.len() as u64;
        }
        Ok(())
    }



    pub fn flush(&mut self) -> std::io::Result<()> {
        self.current_writer.flush()
    }
}

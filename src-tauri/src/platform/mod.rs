use crate::error::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartitionInfo {
    pub name: String,
    pub size: u64,
    pub fs_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub model: String,
    pub serial: String,
    pub vendor: String,
    pub device_type: String, // HDD, SSD, USB, NVMe, etc.
    pub is_mounted: bool,
    pub mount_points: Vec<String>,
    pub partitions: Vec<PartitionInfo>,
    pub smart_health: String,
}

pub trait DeviceBackend {
    fn enumerate_devices() -> Result<Vec<DeviceInfo>>;
    fn open_readonly(path: &str) -> Result<RawDevice>;
    fn enforce_write_block(device: &mut RawDevice) -> Result<()>;
}

// Struct to represent a Raw Device handle
pub struct RawDevice {
    pub path: String,
    pub size: u64,
    
    #[cfg(target_os = "windows")]
    pub handle: ::windows::Win32::Foundation::HANDLE,
    
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub file: std::fs::File,
}

// Since HANDLE is a pointer type, we need to implement Send/Sync so we can use RawDevice in async tasks
unsafe impl Send for RawDevice {}
unsafe impl Sync for RawDevice {}

impl RawDevice {
    pub fn read_block(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "windows")]
        {
            use ::windows::Win32::Storage::FileSystem::ReadFile;
            
            let mut bytes_read = 0u32;
            let res = unsafe {
                ReadFile(
                    self.handle,
                    Some(buf),
                    Some(&mut bytes_read as *mut u32),
                    None,
                )
            };
            if res.is_ok() {
                Ok(bytes_read as usize)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::io::Read;
            self.file.read(buf)
        }
    }

    pub fn seek_forward(&mut self, bytes: u64) -> std::io::Result<u64> {
        #[cfg(target_os = "windows")]
        {
            use ::windows::Win32::Storage::FileSystem::{SetFilePointerEx, FILE_CURRENT};
            let mut new_pos = 0i64;
            let res = unsafe {
                SetFilePointerEx(
                    self.handle,
                    bytes as i64,
                    Some(&mut new_pos),
                    FILE_CURRENT
                )
            };
            if res.is_ok() {
                Ok(new_pos as u64)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::io::{Seek, SeekFrom};
            self.file.seek(SeekFrom::Current(bytes as i64))
        }
    }

    pub fn seek_to(&mut self, pos: u64) -> std::io::Result<u64> {
        #[cfg(target_os = "windows")]
        {
            use ::windows::Win32::Storage::FileSystem::{SetFilePointerEx, FILE_BEGIN};
            let mut new_pos = 0i64;
            let res = unsafe {
                SetFilePointerEx(
                    self.handle,
                    pos as i64,
                    Some(&mut new_pos),
                    FILE_BEGIN
                )
            };
            if res.is_ok() {
                Ok(new_pos as u64)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::io::{Seek, SeekFrom};
            self.file.seek(SeekFrom::Start(pos))
        }
    }
}

impl Drop for RawDevice {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use ::windows::Win32::Foundation::CloseHandle;
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

pub fn detect_partitions(device_path: &str) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();
    
    // Open the raw device
    let mut dev = match ActiveBackend::open_readonly(device_path) {
        Ok(d) => d,
        Err(_) => return partitions,
    };
    
    // Read sector 0 (MBR)
    let mut sector0 = vec![0u8; 512];
    if dev.read_block(&mut sector0).is_err() {
        return partitions;
    }
    
    // Check boot signature 0x55AA
    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return partitions;
    }
    
    // Parse MBR partition entries
    let mut is_gpt = false;
    let mut mbr_parts = Vec::new();
    
    for i in 0..4 {
        let offset = 446 + i * 16;
        let part_type = sector0[offset + 4];
        let starting_lba = u32::from_le_bytes([
            sector0[offset + 8],
            sector0[offset + 9],
            sector0[offset + 10],
            sector0[offset + 11],
        ]) as u64;
        let size_sectors = u32::from_le_bytes([
            sector0[offset + 12],
            sector0[offset + 13],
            sector0[offset + 14],
            sector0[offset + 15],
        ]) as u64;
        
        if part_type == 0xEE {
            is_gpt = true;
            break;
        }
        
        if part_type != 0 && size_sectors > 0 {
            mbr_parts.push((i + 1, part_type, starting_lba, size_sectors * 512));
        }
    }
    
    if is_gpt {
        // Parse GPT partitions
        // Read GPT Header at LBA 1
        if dev.seek_to(512).is_ok() {
            let mut gpt_header = vec![0u8; 512];
            if dev.read_block(&mut gpt_header).is_ok() {
                // Verify signature "EFI PART"
                if &gpt_header[0..8] == b"EFI PART" {
                    let partition_entries_lba = u64::from_le_bytes([
                        gpt_header[72], gpt_header[73], gpt_header[74], gpt_header[75],
                        gpt_header[76], gpt_header[77], gpt_header[78], gpt_header[79],
                    ]);
                    let num_entries = u32::from_le_bytes([
                        gpt_header[80], gpt_header[81], gpt_header[82], gpt_header[83],
                    ]) as usize;
                    let entry_size = u32::from_le_bytes([
                        gpt_header[84], gpt_header[85], gpt_header[86], gpt_header[87],
                    ]) as usize;
                    
                    // Seek to partition entries LBA
                    if dev.seek_to(partition_entries_lba * 512).is_ok() {
                        let total_size = num_entries * entry_size;
                        let mut entries_buf = vec![0u8; total_size];
                        if dev.read_block(&mut entries_buf).is_ok() {
                            for e in 0..num_entries {
                                let entry_offset = e * entry_size;
                                // Read GUID (16 bytes)
                                let type_guid = &entries_buf[entry_offset..entry_offset + 16];
                                if type_guid.iter().all(|&b| b == 0) {
                                    continue;
                                }
                                
                                let starting_lba = u64::from_le_bytes([
                                    entries_buf[entry_offset + 32], entries_buf[entry_offset + 33],
                                    entries_buf[entry_offset + 34], entries_buf[entry_offset + 35],
                                    entries_buf[entry_offset + 36], entries_buf[entry_offset + 37],
                                    entries_buf[entry_offset + 38], entries_buf[entry_offset + 39],
                                ]);
                                let ending_lba = u64::from_le_bytes([
                                    entries_buf[entry_offset + 40], entries_buf[entry_offset + 41],
                                    entries_buf[entry_offset + 42], entries_buf[entry_offset + 43],
                                    entries_buf[entry_offset + 44], entries_buf[entry_offset + 45],
                                    entries_buf[entry_offset + 46], entries_buf[entry_offset + 47],
                                ]);
                                
                                if ending_lba < starting_lba {
                                    continue;
                                }
                                
                                let size_bytes = (ending_lba - starting_lba + 1) * 512;
                                
                                // UTF-16LE Partition Name (72 bytes, from offset 56 to 127)
                                let name_bytes = &entries_buf[entry_offset + 56..entry_offset + 128];
                                let mut name_utf16 = Vec::new();
                                for chunk in name_bytes.chunks_exact(2) {
                                    let val = u16::from_le_bytes([chunk[0], chunk[1]]);
                                    if val == 0 {
                                        break;
                                    }
                                    name_utf16.push(val);
                                }
                                let mut gpt_name = String::from_utf16(&name_utf16).unwrap_or_default().trim().to_string();
                                if gpt_name.is_empty() {
                                    gpt_name = format!("Partition {}", e + 1);
                                }
                                
                                let basic_data_guid = [
                                    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                                    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
                                ];
                                let efi_guid = [
                                    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                                    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
                                ];
                                let ms_reserved_guid = [
                                    0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D,
                                    0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE
                                ];
                                let recovery_guid = [
                                    0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D,
                                    0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC
                                ];
                                
                                let mut fs_type = if type_guid == &basic_data_guid {
                                    "Basic Data".to_string()
                                } else if type_guid == &efi_guid {
                                    "EFI System Partition".to_string()
                                } else if type_guid == &ms_reserved_guid {
                                    "Microsoft Reserved".to_string()
                                } else if type_guid == &recovery_guid {
                                    "Windows Recovery (Hidden)".to_string()
                                } else {
                                    "Generic Data".to_string()
                                };
                                
                                // Try to detect filesystem from VBR
                                if fs_type == "Basic Data" || fs_type == "Generic Data" {
                                    if let Some(detected) = read_vbr_fs(&mut dev, starting_lba) {
                                        fs_type = detected;
                                    }
                                }
                                
                                partitions.push(PartitionInfo {
                                    name: gpt_name,
                                    size: size_bytes,
                                    fs_type,
                                });
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Process MBR partitions
        for (idx, part_type, starting_lba, size_bytes) in mbr_parts {
            let mut fs_type = match part_type {
                0x07 => "NTFS/exFAT".to_string(),
                0x0B | 0x0C => "FAT32".to_string(),
                0x01 | 0x04 | 0x06 | 0x0E => "FAT16/FAT12".to_string(),
                0x83 => "Linux ext".to_string(),
                0x82 => "Linux swap".to_string(),
                0x27 => "Windows Recovery (NTFS Hidden)".to_string(),
                _ => format!("MBR Partition Type 0x{:02X}", part_type),
            };
            
            // Try to detect exact filesystem
            if let Some(detected) = read_vbr_fs(&mut dev, starting_lba) {
                fs_type = detected;
            }
            
            partitions.push(PartitionInfo {
                name: format!("Partition {}", idx),
                size: size_bytes,
                fs_type,
            });
        }
    }
    
    partitions
}

fn read_vbr_fs(dev: &mut RawDevice, starting_lba: u64) -> Option<String> {
    if dev.seek_to(starting_lba * 512).is_ok() {
        let mut vbr = vec![0u8; 512];
        if dev.read_block(&mut vbr).is_ok() {
            // Check BitLocker
            if vbr.len() >= 11 && &vbr[3..11] == b"-FVE-FS-" {
                return Some("BitLocker Encrypted".to_string());
            }
            // Check LUKS: bytes 0..6 == [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]
            if vbr.len() >= 6 && &vbr[0..6] == &[0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE] {
                return Some("LUKS Encrypted".to_string());
            }
            // Check NTFS: bytes 3..11 == b"NTFS    "
            if &vbr[3..11] == b"NTFS    " {
                return Some("NTFS".to_string());
            }
            // Check exFAT: bytes 3..11 == b"EXFAT   "
            if &vbr[3..11] == b"EXFAT   " {
                return Some("exFAT".to_string());
            }
            // Check FAT32: bytes 82..90 == b"FAT32   "
            if &vbr[82..90] == b"FAT32   " {
                return Some("FAT32".to_string());
            }
            // Check FAT16: bytes 54..62 == b"FAT16   "
            if &vbr[54..62] == b"FAT16   " {
                return Some("FAT16".to_string());
            }
            // Check ReFS: bytes 3..7 == b"ReFS"
            if &vbr[3..7] == b"ReFS" {
                return Some("ReFS".to_string());
            }
            // Check APFS: bytes 32..36 == b"NXSB"
            if vbr.len() >= 36 && &vbr[32..36] == b"NXSB" {
                return Some("APFS".to_string());
            }
            // Check XFS: bytes 0..4 == b"XFSB"
            if vbr.len() >= 4 && &vbr[0..4] == b"XFSB" {
                return Some("XFS".to_string());
            }
        }
    }

    // Check HFS+ and ext2/3/4 which require offsets >= 1024
    if dev.seek_to(starting_lba * 512 + 1024).is_ok() {
        let mut buf = vec![0u8; 1024];
        if dev.read_block(&mut buf).is_ok() {
            if buf.len() >= 2 && (&buf[0..2] == b"H+" || &buf[0..2] == b"HX") {
                return Some("HFS+".to_string());
            }
            if buf.len() >= 2 && &buf[0..2] == b"BD" {
                return Some("HFS".to_string());
            }
            if buf.len() >= 58 {
                let magic = u16::from_le_bytes([buf[56], buf[57]]);
                if magic == 0xEF53 {
                    return Some("ext2/3/4".to_string());
                }
            }
        }
    }

    // Check Btrfs: magic "_BHRfS_M" at offset 65600 (i.e. offset 64KB + 64 bytes)
    if dev.seek_to(starting_lba * 512 + 65536).is_ok() {
        let mut buf = vec![0u8; 128];
        if dev.read_block(&mut buf).is_ok() {
            if buf.len() >= 72 && &buf[64..72] == b"_BHRfS_M" {
                return Some("Btrfs".to_string());
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsBackend as ActiveBackend;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxBackend as ActiveBackend;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosBackend as ActiveBackend;


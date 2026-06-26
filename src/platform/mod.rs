use crate::error::Result;

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

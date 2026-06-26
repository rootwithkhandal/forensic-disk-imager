use crate::error::{ForgelensError, Result};
use super::{DeviceBackend, DeviceInfo, RawDevice};
use std::os::unix::io::AsRawFd;

pub struct MacosBackend;

impl DeviceBackend for MacosBackend {
    fn enumerate_devices() -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        for i in 0..16 {
            let path = format!("/dev/disk{}", i);
            if std::path::Path::new(&path).exists() {
                if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&path) {
                    let fd = file.as_raw_fd();
                    let mut sector_size: u32 = 0;
                    let mut sector_count: u64 = 0;
                    unsafe {
                        // DKIOCGETBLOCKSIZE (0x40046418)
                        let _ = libc::ioctl(fd, 0x40046418, &mut sector_size);
                        // DKIOCGETBLOCKCOUNT (0x40086419)
                        let _ = libc::ioctl(fd, 0x40086419, &mut sector_count);
                    }
                    let size = sector_count * sector_size as u64;
                    if size > 0 {
                        devices.push(DeviceInfo {
                            name: format!("disk{}", i),
                            path: format!("/dev/rdisk{}", i),
                            size,
                            model: "Apple Mass Storage".to_string(),
                            serial: "".to_string(),
                            vendor: "Apple".to_string(),
                            device_type: "Storage".to_string(),
                            is_mounted: false,
                            mount_points: Vec::new(),
                        });
                    }
                }
            }
        }
        Ok(devices)
    }

    fn open_readonly(path: &str) -> Result<RawDevice> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| ForgelensError::Backend(format!("Failed to open macos device {}: {}", path, e)))?;

        let fd = file.as_raw_fd();
        let mut sector_size: u32 = 0;
        let mut sector_count: u64 = 0;
        unsafe {
            let _ = libc::ioctl(fd, 0x40046418, &mut sector_size);
            let _ = libc::ioctl(fd, 0x40086419, &mut sector_count);
        }
        let size = sector_count * sector_size as u64;

        Ok(RawDevice {
            path: path.to_string(),
            size,
            file,
        })
    }

    fn enforce_write_block(_device: &mut RawDevice) -> Result<()> {
        Ok(())
    }
}

impl MacosBackend {
    #[allow(dead_code)]
    pub fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

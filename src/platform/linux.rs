use crate::error::{ForgelensError, Result};
use super::{DeviceBackend, DeviceInfo, RawDevice};
use std::fs::{self, File};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

pub struct LinuxBackend;

const BLKROSET: u64 = 0x125d;

impl DeviceBackend for LinuxBackend {
    fn enumerate_devices() -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        if let Ok(entries) = fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let dev_name = entry.file_name().into_string().unwrap_or_default();
                if dev_name.starts_with("loop") || dev_name.starts_with("ram") {
                    continue;
                }

                let dev_path = format!("/dev/{}", dev_name);
                let sys_path = format!("/sys/block/{}", dev_name);

                let size_str = fs::read_to_string(format!("{}/size", sys_path)).unwrap_or_default();
                let blocks: u64 = size_str.trim().parse().unwrap_or(0);
                let size = blocks * 512;

                if size == 0 {
                    continue;
                }

                let model = fs::read_to_string(format!("{}/device/model", sys_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "Unknown Model".to_string());
                let vendor = fs::read_to_string(format!("{}/device/vendor", sys_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "Unknown Vendor".to_string());
                let serial = fs::read_to_string(format!("{}/device/serial", sys_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "".to_string());

                let rotational = fs::read_to_string(format!("{}/queue/rotational", sys_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                
                let device_type = if rotational == "0" {
                    if dev_name.starts_with("nvme") {
                        "NVMe SSD".to_string()
                    } else {
                        "SSD".to_string()
                    }
                } else {
                    "HDD".to_string()
                };

                let mut is_mounted = false;
                let mut mount_points = Vec::new();
                if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
                    for line in mounts.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0].starts_with(&dev_path) {
                            is_mounted = true;
                            mount_points.push(parts[1].to_string());
                        }
                    }
                }

                devices.push(DeviceInfo {
                    name: dev_name,
                    path: dev_path,
                    size,
                    model,
                    serial,
                    vendor,
                    device_type,
                    is_mounted,
                    mount_points,
                });
            }
        }

        Ok(devices)
    }

    fn open_readonly(path: &str) -> Result<RawDevice> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        
        let file = match options.custom_flags(libc::O_DIRECT).open(path) {
            Ok(f) => f,
            Err(_) => {
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map_err(|e| ForgelensError::Backend(format!("Failed to open {}: {}", path, e)))?
            }
        };

        let metadata = file.metadata().map_err(|e| ForgelensError::Backend(e.to_string()))?;
        let mut size = metadata.len();

        if size == 0 {
            let fd = file.as_raw_fd();
            let mut bytes: u64 = 0;
            unsafe {
                if libc::ioctl(fd, 0x80081272, &mut bytes) == 0 {
                    size = bytes;
                }
            }
        }

        Ok(RawDevice {
            path: path.to_string(),
            size,
            file,
        })
    }

    fn enforce_write_block(device: &mut RawDevice) -> Result<()> {
        let fd = device.as_raw_fd();
        let ro: i32 = 1;
        unsafe {
            let res = libc::ioctl(fd, BLKROSET, &ro);
            if res != 0 {
                return Err(ForgelensError::Backend(format!(
                    "Failed to set kernel read-only mode via BLKROSET: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }
}

impl LinuxBackend {
    #[allow(dead_code)]
    pub fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }
}

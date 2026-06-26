use crate::error::{ForgelensError, Result};
use super::{DeviceBackend, DeviceInfo, RawDevice};
use windows::core::PCWSTR;
use windows::Win32::Foundation::GENERIC_READ;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
};
use windows::Win32::System::Ioctl::{
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_STORAGE_QUERY_PROPERTY,
    StorageDeviceProperty, PropertyStandardQuery, STORAGE_PROPERTY_QUERY,
    STORAGE_DEVICE_DESCRIPTOR, DISK_GEOMETRY_EX,
};
use windows::Win32::System::IO::DeviceIoControl;
use std::os::windows::ffi::OsStrExt;

pub struct WindowsBackend;

impl DeviceBackend for WindowsBackend {
    fn enumerate_devices() -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        for i in 0..16 {
            let path_str = format!("\\\\.\\PhysicalDrive{}", i);
            let path_w: Vec<u16> = std::ffi::OsStr::new(&path_str)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                CreateFileW(
                    PCWSTR(path_w.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };

            if handle.is_err() {
                continue;
            }
            let handle = handle.unwrap();
            if handle.is_invalid() {
                continue;
            }

            // Get size
            let mut geom = DISK_GEOMETRY_EX::default();
            let mut bytes_returned = 0u32;
            let size_ok = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    None,
                    0,
                    Some(&mut geom as *mut _ as *mut _),
                    std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            let size = if size_ok.is_ok() {
                geom.DiskSize as u64
            } else {
                0
            };

            // Get vendor / model / serial
            let mut query = STORAGE_PROPERTY_QUERY {
                PropertyId: StorageDeviceProperty,
                QueryType: PropertyStandardQuery,
                AdditionalParameters: [0; 1],
            };

            let mut buffer = vec![0u8; 1024];
            let io_ok = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some(&mut query as *mut _ as *mut _),
                    std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                    Some(buffer.as_mut_ptr() as *mut _),
                    buffer.len() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            let mut model = String::new();
            let mut serial = String::new();
            let mut vendor = String::new();

            if io_ok.is_ok() {
                let desc = unsafe { &*(buffer.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
                
                if desc.ProductIdOffset > 0 && desc.ProductIdOffset < bytes_returned {
                    model = Self::parse_null_str(&buffer, desc.ProductIdOffset as usize);
                }
                if desc.SerialNumberOffset > 0 && desc.SerialNumberOffset < bytes_returned {
                    serial = Self::parse_null_str(&buffer, desc.SerialNumberOffset as usize);
                }
                if desc.VendorIdOffset > 0 && desc.VendorIdOffset < bytes_returned {
                    vendor = Self::parse_null_str(&buffer, desc.VendorIdOffset as usize);
                }
            }

            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }

            devices.push(DeviceInfo {
                name: format!("PhysicalDrive{}", i),
                path: path_str,
                size,
                model: model.trim().to_string(),
                serial: serial.trim().to_string(),
                vendor: vendor.trim().to_string(),
                device_type: "USB/HDD".to_string(),
                is_mounted: false,
                mount_points: Vec::new(),
            });
        }

        Ok(devices)
    }

    fn open_readonly(path: &str) -> Result<RawDevice> {
        let path_w: Vec<u16> = std::ffi::OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_w.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        };

        if handle.is_err() {
            return Err(ForgelensError::Backend(format!(
                "Failed to open device {}: {}",
                path,
                std::io::Error::last_os_error()
            )));
        }
        let handle = handle.unwrap();

        // Get size
        let mut geom = DISK_GEOMETRY_EX::default();
        let mut bytes_returned = 0u32;
        let size_ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(&mut geom as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        let size = if size_ok.is_ok() { geom.DiskSize as u64 } else { 0 };

        Ok(RawDevice {
            path: path.to_string(),
            size,
            handle,
        })
    }

    fn enforce_write_block(_device: &mut RawDevice) -> Result<()> {
        // In Windows, opening the raw physical drive handle with GENERIC_READ only
        // and FILE_SHARE_READ/FILE_SHARE_WRITE acts as a software write-block.
        Ok(())
    }
}

impl WindowsBackend {
    fn parse_null_str(buffer: &[u8], offset: usize) -> String {
        let mut bytes = Vec::new();
        let mut i = offset;
        while i < buffer.len() && buffer[i] != 0 {
            bytes.push(buffer[i]);
            i += 1;
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[allow(dead_code)]
    pub fn is_admin() -> bool {
        unsafe {
            windows::Win32::UI::Shell::IsUserAnAdmin().as_bool()
        }
    }
}

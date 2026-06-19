use std::fs::{create_dir_all, write};
use std::path::Path;

const TINY_PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 156, 99, 96, 0, 1, 0, 0, 5, 0, 1, 252, 202, 217, 145, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130
];

fn main() {
    let icons_dir = Path::new("icons");
    let _ = create_dir_all(icons_dir);

    let png_files = ["32x32.png", "128x128.png", "128x128@2x.png", "icon.png"];
    for file in &png_files {
        let path = icons_dir.join(file);
        let _ = write(&path, TINY_PNG);
    }

    let ico_path = icons_dir.join("icon.ico");
    let mut ico_bytes = vec![0u8; 22];
    ico_bytes[..6].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00]);
    ico_bytes[6] = 1; // Width
    ico_bytes[7] = 1; // Height
    ico_bytes[8] = 0;
    ico_bytes[9] = 0;
    ico_bytes[10..12].copy_from_slice(&[0x01, 0x00]); // Planes
    ico_bytes[12..14].copy_from_slice(&[0x20, 0x00]); // BPP
    ico_bytes[14..18].copy_from_slice(&(TINY_PNG.len() as u32).to_le_bytes()); // Size
    ico_bytes[18..22].copy_from_slice(&22u32.to_le_bytes()); // Offset
    ico_bytes.extend_from_slice(TINY_PNG);
    let _ = write(&ico_path, ico_bytes);

    let icns_path = icons_dir.join("icon.icns");
    let _ = write(&icns_path, TINY_PNG);

    let mut attrs = tauri_build::Attributes::new();

    #[cfg(target_os = "windows")]
    {
        attrs = attrs.windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#));
    }

    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}

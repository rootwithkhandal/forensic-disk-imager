use std::path::Path;
use std::sync::{Arc, Mutex};
use crate::plugins::native::NativePlugin;
use crate::plugins::wasm::WasmPlugin;
use crate::plugins::types::{OpenForensicPlugin, PluginInfo};

pub struct PluginManager {
    plugins: Vec<(PluginInfo, Arc<Mutex<Box<dyn OpenForensicPlugin>>>)>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// List all registered plugin metadata.
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.iter().map(|(info, _)| info.clone()).collect()
    }

    /// Get references to all active plugins for execution in an acquisition session.
    pub fn get_active_plugins(&self) -> Vec<(PluginInfo, Arc<Mutex<Box<dyn OpenForensicPlugin>>>)> {
        self.plugins.clone()
    }

    /// Unload a registered plugin by name.
    pub fn unload_plugin(&mut self, name: &str) -> Result<(), String> {
        let len_before = self.plugins.len();
        self.plugins.retain(|(info, _)| info.name != name);
        if self.plugins.len() < len_before {
            Ok(())
        } else {
            Err(format!("Plugin '{}' not found", name))
        }
    }

    /// Load a compiled plugin library or WebAssembly module from file.
    pub fn load_plugin_from_file(&mut self, path: &Path) -> Result<PluginInfo, String> {
        if !path.exists() {
            return Err(format!("Plugin file does not exist: {}", path.display()));
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let (plugin_box, loader_type): (Box<dyn OpenForensicPlugin>, &str) = match ext.as_str() {
            "dll" | "so" | "dylib" => {
                let native = unsafe { NativePlugin::load(path)? };
                (Box::new(native), "Native")
            }
            "wasm" => {
                let wasm = WasmPlugin::load(path)?;
                (Box::new(wasm), "WebAssembly")
            }
            _ => {
                return Err(format!(
                    "Unsupported plugin file extension '.{}' for file {}",
                    ext,
                    path.display()
                ));
            }
        };

        let info = PluginInfo {
            name: plugin_box.name().to_string(),
            version: plugin_box.version().to_string(),
            plugin_type: plugin_box.plugin_type(),
            source_path: path.display().to_string(),
            loader: loader_type.to_string(),
        };

        // Remove existing plugin with the same name if already loaded
        self.plugins.retain(|(p, _)| p.name != info.name);

        self.plugins.push((info.clone(), Arc::new(Mutex::new(plugin_box))));

        Ok(info)
    }

    /// Automatically scan a directory and load any compatible plugin files found.
    pub fn scan_directory(&mut self, dir: &Path) -> usize {
        let mut loaded_count = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if ["dll", "so", "dylib", "wasm"].contains(&ext_str.as_str()) {
                            if self.load_plugin_from_file(&path).is_ok() {
                                loaded_count += 1;
                            }
                        }
                    }
                }
            }
        }
        loaded_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::types::{
        PluginContext, AcquisitionSummary, PluginOutput, PluginType, OpenForensicPlugin
    };
    use std::collections::HashMap;

    #[derive(Debug)]
    struct MockPlugin {
        blocks_seen: usize,
    }

    impl OpenForensicPlugin for MockPlugin {
        fn name(&self) -> &str {
            "mock-plugin"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        fn plugin_type(&self) -> PluginType {
            PluginType::Hasher
        }

        fn pre_acquisition(&mut self, _context: &PluginContext) -> Result<(), String> {
            self.blocks_seen = 0;
            Ok(())
        }

        fn on_block(&mut self, _offset: u64, _data: &[u8]) -> Result<(), String> {
            self.blocks_seen += 1;
            Ok(())
        }

        fn post_acquisition(&mut self, _summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
            let mut results = HashMap::new();
            results.insert("blocks_processed".to_string(), self.blocks_seen.to_string());
            Ok(PluginOutput { results })
        }
    }

    #[test]
    fn test_plugin_manager_empty() {
        let mgr = PluginManager::new();
        assert!(mgr.list_plugins().is_empty());
        assert!(mgr.get_active_plugins().is_empty());
    }

    #[test]
    fn test_unload_nonexistent_plugin() {
        let mut mgr = PluginManager::new();
        assert!(mgr.unload_plugin("non-existent").is_err());
    }

    #[test]
    fn test_mock_plugin_lifecycle() {
        let mut plugin = MockPlugin { blocks_seen: 0 };
        let ctx = PluginContext {
            case_number: "CASE-123".to_string(),
            examiner: "Test Examiner".to_string(),
            evidence_id: "EVID-001".to_string(),
            notes: "Unit test".to_string(),
            total_size: 4096,
            block_size: 1024,
            imaging_mode: "Physical".to_string(),
            format: "Raw".to_string(),
        };

        assert!(plugin.pre_acquisition(&ctx).is_ok());
        assert_eq!(plugin.blocks_seen, 0);

        assert!(plugin.on_block(0, &[0u8; 1024]).is_ok());
        assert!(plugin.on_block(1024, &[0u8; 1024]).is_ok());
        assert_eq!(plugin.blocks_seen, 2);

        let summary = AcquisitionSummary {
            bytes_read: 2048,
            bad_sectors: 0,
            elapsed_secs: 1.5,
        };
        let output = plugin.post_acquisition(&summary).unwrap();
        assert_eq!(output.results.get("blocks_processed"), Some(&"2".to_string()));
    }
}

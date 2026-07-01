use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginType {
    Hasher,
    Exporter,
    AcquisitionModule,
    Analyzer,
    General,
}

impl std::fmt::Display for PluginType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginType::Hasher => f.write_str("Hasher"),
            PluginType::Exporter => f.write_str("Exporter"),
            PluginType::AcquisitionModule => f.write_str("AcquisitionModule"),
            PluginType::Analyzer => f.write_str("Analyzer"),
            PluginType::General => f.write_str("General"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub case_number: String,
    pub examiner: String,
    pub evidence_id: String,
    pub notes: String,
    pub total_size: u64,
    pub block_size: usize,
    pub imaging_mode: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionSummary {
    pub bytes_read: u64,
    pub bad_sectors: u64,
    pub elapsed_secs: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginOutput {
    pub results: HashMap<String, String>,
}

impl PluginOutput {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.results.insert(key.into(), val.into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub source_path: String,
    pub loader: String, // "Native" or "WebAssembly"
}

/// The core trait defining a standardized OpenForensic plugin.
///
/// Implementors can hook into three stages of the forensic acquisition lifecycle:
/// 1. `pre_acquisition`: Called before reading begins. Can inspect configuration and initialize resources.
/// 2. `on_block`: Called for every data block read from the source device.
/// 3. `post_acquisition`: Called when acquisition completes to produce final metrics, hashes, or exports.
pub trait OpenForensicPlugin: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn plugin_type(&self) -> PluginType;

    fn pre_acquisition(&mut self, _context: &PluginContext) -> Result<(), String> {
        Ok(())
    }

    fn on_block(&mut self, _offset: u64, _data: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn post_acquisition(&mut self, _summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
        Ok(PluginOutput::default())
    }
}

/// Function signature for dynamic native library symbol creation.
/// Native plugins (.so / .dll / .dylib) should export a symbol `_openforensic_plugin_create` of this type.
#[allow(improper_ctypes_definitions)]
pub type PluginCreateFn = unsafe extern "C" fn() -> *mut dyn OpenForensicPlugin;

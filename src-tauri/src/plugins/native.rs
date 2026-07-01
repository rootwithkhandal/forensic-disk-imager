use std::path::Path;
use std::sync::Arc;
use libloading::{Library, Symbol};
use crate::plugins::types::{
    AcquisitionSummary, OpenForensicPlugin, PluginContext, PluginCreateFn, PluginOutput, PluginType,
};

pub struct NativePlugin {
    // Declared before _lib so that inner is dropped before the dynamic library is unloaded
    inner: Box<dyn OpenForensicPlugin>,
    _lib: Arc<Library>,
}

unsafe impl Send for NativePlugin {}
unsafe impl Sync for NativePlugin {}

impl NativePlugin {
    /// Load a compiled native plugin (.so / .dll / .dylib) from disk and instantiate it.
    pub unsafe fn load(path: &Path) -> Result<Self, String> {
        unsafe {
            let lib = Library::new(path)
                .map_err(|e| format!("Failed to load native library at {}: {}", path.display(), e))?;
            let lib = Arc::new(lib);

            let constructor: Symbol<PluginCreateFn> = lib
                .get(b"_openforensic_plugin_create\0")
                .map_err(|e| format!("Failed to find symbol '_openforensic_plugin_create' in {}: {}", path.display(), e))?;

            let raw_ptr = constructor();
            if raw_ptr.is_null() {
                return Err(format!("Plugin constructor in {} returned null pointer", path.display()));
            }

            let inner = Box::from_raw(raw_ptr);

            Ok(Self { inner, _lib: lib })
        }
    }
}

impl OpenForensicPlugin for NativePlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn version(&self) -> &str {
        self.inner.version()
    }

    fn plugin_type(&self) -> PluginType {
        self.inner.plugin_type()
    }

    fn pre_acquisition(&mut self, context: &PluginContext) -> Result<(), String> {
        self.inner.pre_acquisition(context)
    }

    fn on_block(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        self.inner.on_block(offset, data)
    }

    fn post_acquisition(&mut self, summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
        self.inner.post_acquisition(summary)
    }
}

impl std::fmt::Debug for NativePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativePlugin")
            .field("name", &self.name())
            .field("version", &self.version())
            .field("type", &self.plugin_type())
            .finish()
    }
}

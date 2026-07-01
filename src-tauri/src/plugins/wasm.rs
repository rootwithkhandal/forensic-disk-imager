use std::path::Path;
use std::sync::Mutex;
use wasmtime::*;
use crate::plugins::types::{
    AcquisitionSummary, OpenForensicPlugin, PluginContext, PluginOutput, PluginType,
};

struct WasmRuntime {
    store: Store<()>,
    instance: Instance,
    memory: Option<Memory>,
}

impl WasmRuntime {
    fn read_string(&mut self, ptr_func_name: &str, len_func_name: &str) -> Option<String> {
        let memory = self.memory?;
        let ptr_func = self.instance.get_typed_func::<(), i32>(&mut self.store, ptr_func_name).ok()?;
        let len_func = self.instance.get_typed_func::<(), i32>(&mut self.store, len_func_name).ok()?;

        let ptr = ptr_func.call(&mut self.store, ()).ok()? as usize;
        let len = len_func.call(&mut self.store, ()).ok()? as usize;

        let data = memory.data(&self.store);
        if ptr + len <= data.len() {
            String::from_utf8(data[ptr..ptr + len].to_vec()).ok()
        } else {
            None
        }
    }

    fn pre_acquisition(&mut self, context: &PluginContext) -> Result<(), String> {
        if let Ok(func) = self.instance.get_typed_func::<(i64, i32), i32>(&mut self.store, "pre_acquisition") {
            let res = func
                .call(&mut self.store, (context.total_size as i64, context.block_size as i32))
                .map_err(|e| format!("Wasm pre_acquisition error: {}", e))?;
            if res != 0 {
                return Err(format!("Wasm plugin pre_acquisition returned non-zero status: {}", res));
            }
        }
        Ok(())
    }

    fn on_block(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        if let Ok(func) = self.instance.get_typed_func::<(i64, i32, i32), i32>(&mut self.store, "on_block") {
            let memory = self.memory.ok_or_else(|| "Wasm module has no exported 'memory'".to_string())?;

            let alloc_ptr = if let Ok(alloc_func) = self.instance.get_typed_func::<i32, i32>(&mut self.store, "alloc") {
                alloc_func.call(&mut self.store, data.len() as i32).map_err(|e| e.to_string())? as usize
            } else if let Ok(malloc_func) = self.instance.get_typed_func::<i32, i32>(&mut self.store, "malloc") {
                malloc_func.call(&mut self.store, data.len() as i32).map_err(|e| e.to_string())? as usize
            } else {
                0usize
            };

            let mem_slice = memory.data_mut(&mut self.store);
            if alloc_ptr + data.len() > mem_slice.len() {
                return Err("Wasm memory out of bounds for data block".to_string());
            }
            mem_slice[alloc_ptr..alloc_ptr + data.len()].copy_from_slice(data);

            let res = func
                .call(&mut self.store, (offset as i64, alloc_ptr as i32, data.len() as i32))
                .map_err(|e| format!("Wasm on_block error: {}", e))?;

            if let Ok(dealloc_func) = self.instance.get_typed_func::<(i32, i32), ()>(&mut self.store, "dealloc") {
                let _ = dealloc_func.call(&mut self.store, (alloc_ptr as i32, data.len() as i32));
            } else if let Ok(free_func) = self.instance.get_typed_func::<i32, ()>(&mut self.store, "free") {
                let _ = free_func.call(&mut self.store, alloc_ptr as i32);
            }

            if res != 0 {
                return Err(format!("Wasm plugin on_block returned non-zero status: {}", res));
            }
        }
        Ok(())
    }

    fn post_acquisition(&mut self, summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
        if let Ok(func) = self.instance.get_typed_func::<(i64, i64), i32>(&mut self.store, "post_acquisition") {
            let res = func
                .call(&mut self.store, (summary.bytes_read as i64, summary.bad_sectors as i64))
                .map_err(|e| format!("Wasm post_acquisition error: {}", e))?;
            if res != 0 {
                return Err(format!("Wasm plugin post_acquisition returned non-zero status: {}", res));
            }
        }

        let mut output = PluginOutput::new();
        if let Some(json_str) = self.read_string("get_results_json_ptr", "get_results_json_len") {
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(&json_str) {
                output.results = map;
            }
        }
        Ok(output)
    }
}

pub struct WasmPlugin {
    name: String,
    version: String,
    plugin_type: PluginType,
    runtime: Mutex<WasmRuntime>,
}

unsafe impl Send for WasmPlugin {}
unsafe impl Sync for WasmPlugin {}

impl WasmPlugin {
    /// Load and instantiate a compiled WebAssembly plugin (.wasm) using Wasmtime.
    pub fn load(path: &Path) -> Result<Self, String> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)
            .map_err(|e| format!("Failed to load Wasm module at {}: {}", path.display(), e))?;

        let mut store = Store::new(&engine, ());
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| format!("Failed to instantiate Wasm module {}: {}", path.display(), e))?;

        let memory = instance.get_memory(&mut store, "memory");

        let plugin_type = if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, "plugin_type") {
            match func.call(&mut store, ()).unwrap_or(4) {
                0 => PluginType::Hasher,
                1 => PluginType::Exporter,
                2 => PluginType::AcquisitionModule,
                3 => PluginType::Analyzer,
                _ => PluginType::General,
            }
        } else {
            PluginType::General
        };

        let file_stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "wasm_plugin".to_string());

        let mut runtime = WasmRuntime {
            store,
            instance,
            memory,
        };

        let name = runtime.read_string("name_ptr", "name_len").unwrap_or(file_stem);
        let version = runtime
            .read_string("version_ptr", "version_len")
            .unwrap_or_else(|| "1.0.0".to_string());

        Ok(Self {
            name,
            version,
            plugin_type,
            runtime: Mutex::new(runtime),
        })
    }
}

impl OpenForensicPlugin for WasmPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn plugin_type(&self) -> PluginType {
        self.plugin_type
    }

    fn pre_acquisition(&mut self, context: &PluginContext) -> Result<(), String> {
        let mut rt = self.runtime.lock().map_err(|_| "Wasm runtime mutex poisoned".to_string())?;
        rt.pre_acquisition(context)
    }

    fn on_block(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        let mut rt = self.runtime.lock().map_err(|_| "Wasm runtime mutex poisoned".to_string())?;
        rt.on_block(offset, data)
    }

    fn post_acquisition(&mut self, summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
        let mut rt = self.runtime.lock().map_err(|_| "Wasm runtime mutex poisoned".to_string())?;
        rt.post_acquisition(summary)
    }
}

impl std::fmt::Debug for WasmPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPlugin")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("type", &self.plugin_type)
            .finish()
    }
}

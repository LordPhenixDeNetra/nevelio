//! Runtime WASM plugin loader — v0.7.
//!
//! ## Plugin ABI (from the plugin side)
//!
//! A `.wasm` plugin must export:
//!
//! ```text
//! // Allocate `size` bytes in WASM linear memory; return pointer.
//! #[no_mangle] pub extern "C" fn nevelio_alloc(size: u32) -> u32;
//!
//! // Write manifest JSON to `buf[0..buf_len]`; return bytes written.
//! #[no_mangle] pub extern "C" fn nevelio_manifest(buf: u32, buf_len: u32) -> u32;
//!
//! // Receive JSON-encoded Vec<Endpoint> at `in_ptr`/`in_len`;
//! // write JSON-encoded Vec<Finding> to `out_ptr`/`out_len`;
//! // return 0 on success, non-zero on error.
//! #[no_mangle]
//! pub extern "C" fn nevelio_run(
//!     in_ptr: u32, in_len: u32,
//!     out_ptr: u32, out_len: u32,
//! ) -> u32;
//! ```
//!
//! Both JSON payloads are UTF-8 and must fit within the allocated buffers.
//! The host allocates buffers using `nevelio_alloc` before calling the exports.

use crate::module_trait::AttackModule;
use crate::plugin::PluginManifest;
use crate::session::ScanSession;
use crate::http_client::HttpClient;
use crate::types::{Endpoint, Finding};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use wasmtime::{Config, Engine, Instance, Linker, Memory, Module, Store};

// Size of the scratch buffer the host allocates for receiving manifest/findings JSON.
const OUTPUT_BUFFER_SIZE: u32 = 256 * 1024; // 256 KiB

/// A loaded WASM plugin instance.
pub struct WasmPlugin {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
}

impl WasmPlugin {
    /// Load and instantiate a `.wasm` file from `path`.
    ///
    /// The plugin runs in a WASI-sandboxed environment with:
    /// - No filesystem access (no `preopened_dirs`)
    /// - No network access (no WASI socket capability)
    /// - No environment variable access
    /// - No stdin/stdout/stderr (all redirected to /dev/null)
    pub fn load(path: &str) -> Result<Self> {
        // Build a sandboxed engine with conservative limits
        let mut config = Config::default();
        config.epoch_interruption(false);
        config.max_wasm_stack(512 * 1024); // 512 KiB stack limit
        let engine = Engine::new(&config)?;

        let module = Module::from_file(&engine, path)
            .with_context(|| format!("Impossible de charger le plugin WASM : {}", path))?;
        let mut store = Store::new(&engine, ());

        // Note: fuel-based limits require the `fuel` wasmtime feature.
        // We rely on the stack size limit + timeout at the caller level instead.

        let linker: Linker<()> = Linker::new(&engine);

        // Note: We intentionally do NOT add wasmtime_wasi to the linker.
        // Plugins that import WASI functions will fail to instantiate — this is
        // the sandbox boundary. Plugins must be pure-compute with no I/O.
        let instance = linker
            .instantiate(&mut store, &module)
            .with_context(|| format!("Instanciation du plugin WASM échouée : {}", path))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("Le plugin WASM doit exporter 'memory'"))?;
        Ok(Self { store, instance, memory })
    }

    /// Return the plugin's manifest (name, version, description, author).
    pub fn manifest(&mut self) -> Result<PluginManifest> {
        let buf_ptr = self.alloc(OUTPUT_BUFFER_SIZE)?;
        let manifest_fn = self
            .instance
            .get_typed_func::<(u32, u32), u32>(&mut self.store, "nevelio_manifest")
            .context("Plugin manquant : export 'nevelio_manifest'")?;

        let written =
            manifest_fn.call(&mut self.store, (buf_ptr, OUTPUT_BUFFER_SIZE))?;

        let json = self.read_memory_str(buf_ptr, written)?;
        serde_json::from_str(&json).context("nevelio_manifest a retourné un JSON invalide")
    }

    /// Run the plugin against a list of endpoints; return detected findings.
    pub fn run(&mut self, endpoints: &[Endpoint]) -> Result<Vec<Finding>> {
        let input_json = serde_json::to_string(endpoints)?;
        let input_bytes = input_json.as_bytes();

        // Write input JSON to WASM memory
        let in_ptr = self.alloc(input_bytes.len() as u32)?;
        self.write_memory(in_ptr, input_bytes)?;

        // Allocate output buffer
        let out_ptr = self.alloc(OUTPUT_BUFFER_SIZE)?;

        let run_fn = self
            .instance
            .get_typed_func::<(u32, u32, u32, u32), u32>(&mut self.store, "nevelio_run")
            .context("Plugin manquant : export 'nevelio_run'")?;

        let rc = run_fn.call(
            &mut self.store,
            (in_ptr, input_bytes.len() as u32, out_ptr, OUTPUT_BUFFER_SIZE),
        )?;

        if rc != 0 {
            return Err(anyhow!("nevelio_run a retourné une erreur : code {}", rc));
        }

        // Read output: first 4 bytes are little-endian length, then JSON
        let data = self.memory.data(&self.store);
        let base = out_ptr as usize;
        if base + 4 > data.len() {
            return Err(anyhow!("Buffer de sortie WASM hors limites"));
        }
        let out_len = u32::from_le_bytes(data[base..base + 4].try_into()?) as usize;
        if base + 4 + out_len > data.len() {
            return Err(anyhow!("Longueur de sortie WASM hors limites : {}", out_len));
        }
        let json = std::str::from_utf8(&data[base + 4..base + 4 + out_len])
            .context("La sortie du plugin WASM n'est pas de l'UTF-8 valide")?;
        serde_json::from_str(json).context("nevelio_run a retourné un JSON invalide")
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn alloc(&mut self, size: u32) -> Result<u32> {
        let alloc_fn = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "nevelio_alloc")
            .context("Plugin manquant : export 'nevelio_alloc'")?;
        Ok(alloc_fn.call(&mut self.store, size)?)
    }

    fn write_memory(&mut self, ptr: u32, data: &[u8]) -> Result<()> {
        let mem = self.memory.data_mut(&mut self.store);
        let start = ptr as usize;
        if start + data.len() > mem.len() {
            return Err(anyhow!("Écriture WASM hors limites : ptr={}, len={}", ptr, data.len()));
        }
        mem[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn read_memory_str(&self, ptr: u32, len: u32) -> Result<String> {
        let data = self.memory.data(&self.store);
        let start = ptr as usize;
        let end = start + len as usize;
        if end > data.len() {
            return Err(anyhow!("Lecture WASM hors limites : ptr={}, len={}", ptr, len));
        }
        std::str::from_utf8(&data[start..end])
            .map(|s| s.to_string())
            .context("Données WASM non UTF-8")
    }
}

/// Wraps a `WasmPlugin` to implement `AttackModule`, enabling WASM plugins
/// to be registered alongside built-in Rust modules in the scanner.
pub struct WasmAttackModule {
    inner: Mutex<WasmPlugin>,
    name: String,
    description: String,
}

impl WasmAttackModule {
    /// Load a `.wasm` plugin from `path` and read its manifest.
    pub fn load(path: &str) -> Result<Self> {
        let mut plugin = WasmPlugin::load(path)?;
        let manifest = plugin.manifest()?;
        Ok(Self {
            inner: Mutex::new(plugin),
            name: manifest.name,
            description: manifest.description,
        })
    }
}

#[async_trait]
impl AttackModule for WasmAttackModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    async fn run(
        &self,
        _session: &ScanSession,
        _client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut plugin = self.inner.lock().await;
        match plugin.run(endpoints) {
            Ok(findings) => findings,
            Err(e) => {
                tracing::error!("WASM plugin '{}' error: {}", self.name, e);
                Vec::new()
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_nonexistent_path_returns_error() {
        let result = WasmPlugin::load("/tmp/nonexistent_nevelio_plugin.wasm");
        assert!(result.is_err());
    }

    #[test]
    fn attack_module_load_nonexistent_returns_error() {
        let result = WasmAttackModule::load("/tmp/nonexistent_nevelio_plugin.wasm");
        assert!(result.is_err());
    }
}

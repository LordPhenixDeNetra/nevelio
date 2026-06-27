//! Plugin ABI for Nevelio — v0.6 skeleton, runtime WASM loading in v0.7.
//!
//! This module defines the stable interface that plugins must implement.
//! Plugins compiled to `.wasm` will expose these entry points via the host ABI.
//!
//! ## Plugin entry points (future WASM exports)
//!
//! ```text
//! #[no_mangle]
//! pub extern "C" fn nevelio_manifest() -> *const u8 { ... }
//!
//! #[no_mangle]
//! pub extern "C" fn nevelio_run(endpoints_ptr: u32, out_ptr: u32) -> u32 { ... }
//! ```

use crate::types::{Endpoint, Finding, ScanConfig};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// ABI version — bumped on breaking changes.
pub const PLUGIN_ABI_VERSION: u32 = 1;

/// Metadata about a plugin, returned by its `nevelio_manifest()` export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Short identifier used in CLI output and report labels
    pub name: String,
    /// Plugin semver (e.g. "1.0.0")
    pub version: String,
    /// One-line description shown in `nevelio modules list`
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Nevelio ABI version this plugin was compiled against
    pub nevelio_abi: u32,
}

impl PluginManifest {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            author: author.into(),
            nevelio_abi: PLUGIN_ABI_VERSION,
        }
    }
}

/// Trait that in-process (non-WASM) plugins implement directly.
/// WASM plugins implement the same interface across the memory boundary.
pub trait NevelioPlugin: Send + Sync {
    fn manifest(&self) -> PluginManifest;
    fn run(
        &self,
        config: &ScanConfig,
        endpoints: &[Endpoint],
    ) -> Result<Vec<Finding>>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sets_abi_version() {
        let m = PluginManifest::new("test", "1.0.0", "Test plugin", "dev");
        assert_eq!(m.nevelio_abi, PLUGIN_ABI_VERSION);
        assert_eq!(m.name, "test");
    }

    #[test]
    fn manifest_serializes_to_json() {
        let m = PluginManifest::new("demo", "0.1.0", "Demo", "alice");
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"name\":\"demo\""));
        assert!(json.contains("\"nevelio_abi\""));
    }
}

// FFI vers leechcore (PCILeech) — https://github.com/ufrisk/LeechCore
//
// leechcore est une bibliothèque C/C++ qui abstrait l'accès au hardware DMA
// (FPGA PCILeech, Thunderbolt, USB3380, etc.) pour lire la mémoire physique.
//
// Sur un système Linux : libLeechCore.so (disponible dans le repo PCILeech-FPGA)
// Sur Windows          : LeechCore.dll
//
// Liaison conditionnelle : disponible uniquement avec la feature "leechcore".

#[cfg(feature = "leechcore")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    pub const LC_CONFIG_VERSION: u64 = 0x0007_0000_0000_0000;

    /// Configuration d'un device leechcore.
    #[repr(C)]
    pub struct LcConfig {
        pub version:           u64,
        pub sz_device:         [c_char; 260],   // ex: "fpga" ou "FPGA://max:100"
        pub sz_remote:         [c_char; 260],   // vide si local
        pub flags:             u64,
        pub pa_max:            u64,             // adresse physique maximale
        pub cb_max_size_rd:    u32,             // taille max lecture par appel
        pub cb_max_size_wr:    u32,
        pub version_minor:     u32,
        pub version_major:     u16,
        pub version_build:     u16,
        _reserved:             [u8; 128],
    }

    impl Default for LcConfig {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    extern "C" {
        /// Crée un handle leechcore. Retourne NULL si échoue.
        pub fn LcCreate(config: *mut LcConfig) -> *mut c_void;

        /// Ferme un handle leechcore.
        pub fn LcClose(handle: *mut c_void);

        /// Lit de la mémoire physique à l'adresse `pa` dans `pb` (cb octets).
        pub fn LcRead(
            handle: *mut c_void,
            pa:     u64,
            cb:     u32,
            pb:     *mut u8,
        ) -> c_int;

        /// Écrit de la mémoire physique (autorisation requise).
        pub fn LcWrite(
            handle: *mut c_void,
            pa:     u64,
            cb:     u32,
            pb:     *const u8,
        ) -> c_int;

        /// Récupère des informations sur le device.
        pub fn LcGetOption(
            handle:  *mut c_void,
            option:  u64,
            val_out: *mut u64,
        ) -> c_int;
    }

    // Options LcGetOption
    pub const LC_OPT_FPGA_PROBE_MAXPAGES:  u64 = 0x0001_0300_0000_0003;
    pub const LC_OPT_MEMMAP_MAX_ADDRESS:   u64 = 0x0001_0000_0000_0001;
    pub const LC_OPT_FPGA_VERSION_MAJOR:   u64 = 0x0001_0300_0000_0007;
    pub const LC_OPT_FPGA_VERSION_MINOR:   u64 = 0x0001_0300_0000_0008;
}

/// Handle sécurisé vers un device leechcore.
#[cfg(feature = "leechcore")]
pub struct LeechCoreHandle {
    raw: *mut std::os::raw::c_void,
}

#[cfg(feature = "leechcore")]
impl LeechCoreHandle {
    /// Ouvre un device FPGA PCILeech.
    pub fn open_fpga(max_address: u64) -> anyhow::Result<Self> {
        use std::os::raw::c_char;

        let mut cfg = ffi::LcConfig::default();
        cfg.version = ffi::LC_CONFIG_VERSION;
        cfg.pa_max  = max_address;

        // "fpga" → auto-détection du FPGA connecté
        let device_str = b"fpga\0";
        let dest = &mut cfg.sz_device[..device_str.len()];
        for (i, &b) in device_str.iter().enumerate() {
            dest[i] = b as c_char;
        }

        let handle = unsafe { ffi::LcCreate(&mut cfg) };
        if handle.is_null() {
            anyhow::bail!(
                "leechcore: impossible d'ouvrir le device FPGA. \
                 Vérifier que le FPGA est connecté et que leechcore est installé."
            );
        }
        Ok(Self { raw: handle })
    }

    /// Lit `len` octets depuis l'adresse physique `pa`.
    pub fn read_phys(&self, pa: u64, len: u32) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        let ok = unsafe { ffi::LcRead(self.raw, pa, len, buf.as_mut_ptr()) };
        if ok == 0 {
            anyhow::bail!("leechcore: LcRead échoué à 0x{:016x}", pa);
        }
        Ok(buf)
    }

    /// Retourne l'adresse physique maximale accessible.
    pub fn max_address(&self) -> u64 {
        let mut val = 0u64;
        unsafe {
            ffi::LcGetOption(self.raw, ffi::LC_OPT_MEMMAP_MAX_ADDRESS, &mut val);
        }
        val
    }
}

#[cfg(feature = "leechcore")]
impl Drop for LeechCoreHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::LcClose(self.raw) };
        }
    }
}

// Garantit Send+Sync pour utilisation dans un thread Tokio
#[cfg(feature = "leechcore")]
unsafe impl Send for LeechCoreHandle {}
#[cfg(feature = "leechcore")]
unsafe impl Sync for LeechCoreHandle {}

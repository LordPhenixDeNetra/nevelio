/// Nevelio — PCIe DMA FPGA Module
///
/// Audit de sécurité DMA : détection IOMMU, niveau Thunderbolt,
/// et interface leechcore FFI pour tests DMA autorisés en lab.
pub mod leechcore;
pub mod pcileech;

rust_i18n::i18n!("../hw-cli/locales", fallback = "fr");

#[cfg(feature = "leechcore")]
use rust_i18n::t;

pub use pcileech::{
    check_iommu_status,
    check_thunderbolt_dma,
    run_passive_dma_audit,
};

use hw_core::{HardwareFinding, HwModule, HwScanContext};

/// Module hw-dma-fpga : audit DMA matériel (IOMMU, Thunderbolt, PCILeech).
pub struct FpgaDmaModule;

impl HwModule for FpgaDmaModule {
    fn name(&self)        -> &'static str { "hw-dma-fpga" }
    fn description(&self) -> &'static str {
        "Audit DMA matériel : IOMMU/VT-d, Thunderbolt security level, \
         PCIe TLP (leechcore FFI — lab uniquement)"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        #[allow(unused_mut)]
        let mut findings = run_passive_dma_audit();

        if !ctx.dry_run {
            #[cfg(feature = "leechcore")]
            {
                // Tests actifs leechcore (nécessite FPGA connecté)
                findings.push(hw_core::HardwareFinding::new(
                    t!("fpga.leechcore.active.title"),
                    t!("fpga.leechcore.active.desc"),
                    hw_core::HwSeverity::Informative,
                    "hw-dma-fpga",
                    None, None,
                    "feature=leechcore actif",
                    t!("fpga.leechcore.active.rem"),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpga_module_dry_run_does_not_panic() {
        let ctx = HwScanContext { dry_run: true, ..Default::default() };
        let f = FpgaDmaModule.run(&ctx);
        assert!(!f.is_empty());
    }

    #[test]
    fn fpga_module_name() {
        assert_eq!(FpgaDmaModule.name(), "hw-dma-fpga");
    }

    #[test]
    fn iommu_check_does_not_panic() {
        let _ = check_iommu_status();
    }

    #[test]
    fn thunderbolt_check_does_not_panic() {
        let _ = check_thunderbolt_dma();
    }
}

/// Nevelio — PCIe DMA FPGA Module
///
/// Audit de sécurité DMA : détection IOMMU, niveau Thunderbolt,
/// et interface leechcore FFI pour tests DMA autorisés en lab.
pub mod leechcore;
pub mod pcileech;

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
        let mut findings = run_passive_dma_audit();

        if !ctx.dry_run {
            #[cfg(feature = "leechcore")]
            {
                // Tests actifs leechcore (nécessite FPGA connecté)
                findings.push(hw_core::HardwareFinding::new(
                    "Test DMA actif — leechcore disponible",
                    "La feature leechcore est activée. Un FPGA PCILeech connecté \
                     permettrait de tester l'accès DMA à la mémoire physique. \
                     Exécuter nevelio-hw scan --active --target fpga:// pour le test complet.",
                    hw_core::HwSeverity::Informative,
                    "hw-dma-fpga",
                    None, None,
                    "feature=leechcore actif",
                    "Connecter le FPGA et lancer le test DMA complet.",
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

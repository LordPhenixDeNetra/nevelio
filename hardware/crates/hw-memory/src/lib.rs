use hw_core::{HardwareFinding, HwModule, HwScanContext};

pub mod avml;
pub mod swap;

pub use avml::{detect_avml, run_avml_dump, run_lime_dump};
pub use swap::check_swap_encryption;

pub struct MemoryModule;

impl HwModule for MemoryModule {
    fn name(&self)        -> &'static str { "hw-memory" }
    fn description(&self) -> &'static str {
        "Audit mémoire physique : présence avml, chiffrement swap, KASLR, dump forensique"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();

        // 1. Détection d'avml
        findings.extend(detect_avml());

        // 2. Vérification chiffrement swap + KASLR
        findings.extend(check_swap_encryption());

        // 3. Dump mémoire forensique (mode actif uniquement)
        if !ctx.dry_run {
            findings.extend(run_avml_dump());
        } else {
            findings.push(HardwareFinding::new(
                "Dump mémoire ignoré (mode dry-run)",
                "En mode --dry-run, le dump de la RAM physique n'est pas effectué. \
                 Utiliser --active pour lancer avml ou LiME.",
                hw_core::HwSeverity::Informative,
                "hw-memory",
                None, None,
                "dry_run = true",
                "nevelio-hw scan --active pour activer le dump mémoire.",
            ));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_module_dry_run_does_not_panic() {
        let ctx = HwScanContext { dry_run: true, ..Default::default() };
        let findings = MemoryModule.run(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn memory_module_name() {
        assert_eq!(MemoryModule.name(), "hw-memory");
    }
}

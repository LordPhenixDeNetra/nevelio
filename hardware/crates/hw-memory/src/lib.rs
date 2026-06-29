use hw_core::{HardwareFinding, HwModule, HwScanContext, HwSeverity};

pub mod avml;
pub mod forensics;
pub mod rowhammer;
pub mod swap;

pub use avml::{detect_avml, run_avml_dump, run_lime_dump};
pub use forensics::{check_core_dumps, run_volatility_analysis};
pub use rowhammer::{check_ecc_availability, check_trr_status, run_rowhammer_test};
pub use swap::check_swap_encryption;

pub struct MemoryModule;

impl HwModule for MemoryModule {
    fn name(&self)        -> &'static str { "hw-memory" }
    fn description(&self) -> &'static str {
        "Audit mémoire physique : swap+KASLR, Rowhammer/ECC, core dumps, \
         Volatility forensics (DKOM, malfind, hashdump), dump avml/LiME"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();

        // 1. Détection d'avml
        findings.extend(detect_avml());

        // 2. Vérification chiffrement swap + KASLR
        findings.extend(check_swap_encryption());

        // 3. Configuration des core dumps
        findings.extend(check_core_dumps());

        // 4. Statut ECC et TRR (passif — pas besoin de root)
        findings.extend(check_ecc_availability());
        findings.extend(check_trr_status());

        if ctx.dry_run {
            // Mode passif : pas de dump ni de rowhammer
            findings.push(HardwareFinding::new(
                "Tests actifs mémoire ignorés (mode dry-run)",
                "En mode --dry-run, le dump RAM (avml), le test Rowhammer et l'analyse \
                 Volatility ne sont pas exécutés. Utiliser --active sur une machine de lab dédiée.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "dry_run = true",
                "nevelio-hw scan --active  (lab uniquement — jamais en production)",
            ));
        } else {
            // Mode actif : dump mémoire
            findings.extend(run_avml_dump());

            // Rowhammer (mode actif + warning légal)
            findings.extend(run_rowhammer_test(128, false));

            // Analyse Volatility si un dump vient d'être créé
            let dump_path = "/tmp/nevelio_memory.lime";
            if std::path::Path::new(dump_path).exists() {
                findings.extend(run_volatility_analysis(dump_path));
            }
        }

        // Analyse Volatility sur un dump fourni via --target
        if let Some(dump) = &ctx.target {
            if dump.ends_with(".lime") || dump.ends_with(".raw") || dump.ends_with(".mem") {
                findings.push(HardwareFinding::new(
                    format!("Analyse forensique du dump : {}", dump),
                    "Lancement de l'analyse Volatility sur le dump mémoire fourni.",
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    dump.as_str(),
                    "",
                ));
                findings.extend(run_volatility_analysis(dump.as_str()));
            }
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

    #[test]
    fn rowhammer_dry_run_informative() {
        let findings = run_rowhammer_test(64, true);
        assert!(!findings.is_empty());
    }

    #[test]
    fn core_dump_check_runs() {
        let findings = check_core_dumps();
        assert!(!findings.is_empty());
    }

    #[test]
    fn volatility_missing_dump() {
        let findings = run_volatility_analysis("/nonexistent.lime");
        assert!(!findings.is_empty());
    }
}

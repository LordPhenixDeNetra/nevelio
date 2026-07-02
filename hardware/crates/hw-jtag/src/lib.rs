use hw_core::{HardwareFinding, HwModule, HwScanContext};

rust_i18n::i18n!("../hw-cli/locales", fallback = "fr");

pub mod openocd;
pub mod probe;

pub use openocd::{run_firmware_analyzer, run_openocd_audit};
use probe::check_jtag_probes;

// Chemins par défaut (relatifs au répertoire courant d'exécution)
const TCL_SCRIPT: &str = "hardware/tcl/jtag_audit.tcl";
const PY_SCRIPT:  &str = "hardware/python/firmware_analyzer.py";

pub struct JtagModule;

impl HwModule for JtagModule {
    fn name(&self)        -> &'static str { "hw-jtag" }
    fn description(&self) -> &'static str {
        "Audit JTAG/SWD : détection de sondes, RDP STM32, UART, \
         analyse firmware Python/binwalk/r2pipe"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();

        // 1. Détection de sondes JTAG + UART via lsusb
        let (probe_findings, probes) = check_jtag_probes();
        findings.extend(probe_findings);

        // 2. Audit OpenOCD (seulement si une sonde est détectée et non dry-run)
        if !ctx.dry_run && !probes.is_empty() {
            let (iface, target_cfg, target_name) = pick_openocd_config(&probes);
            findings.extend(run_openocd_audit(
                iface, target_cfg, target_name,
                ctx.dry_run,
                TCL_SCRIPT,
            ));
        }

        // 4. Analyse firmware si --target pointe vers un chemin local (pas une URL)
        if let Some(fw_path) = &ctx.target {
            let looks_like_file = !fw_path.starts_with("http://") && !fw_path.starts_with("https://");
            if looks_like_file {
                findings.extend(run_firmware_analyzer(
                    fw_path.as_str(),
                    PY_SCRIPT,
                    false,
                ));
            }
        }

        findings
    }
}

/// Choisit la config OpenOCD selon la sonde détectée.
fn pick_openocd_config(probes: &[String]) -> (&'static str, &'static str, &'static str) {
    let probe_lower = probes.first().map(|p| p.to_lowercase()).unwrap_or_default();

    if probe_lower.contains("j-link") {
        ("interface/jlink.cfg", "target/stm32f4x.cfg", "stm32f4x")
    } else if probe_lower.contains("st-link") {
        ("interface/stlink.cfg", "target/stm32f4x.cfg", "stm32f4x")
    } else if probe_lower.contains("daplink") || probe_lower.contains("cmsis-dap") {
        ("interface/cmsis-dap.cfg", "target/stm32f4x.cfg", "stm32f4x")
    } else {
        // FTDI ou inconnu → config générique
        ("interface/ftdi/ft2232h.cfg", "target/stm32f4x.cfg", "stm32f4x")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jtag_module_dry_run_does_not_panic() {
        let ctx = HwScanContext { dry_run: true, ..Default::default() };
        let findings = JtagModule.run(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn jtag_module_name() {
        assert_eq!(JtagModule.name(), "hw-jtag");
    }

    #[test]
    fn firmware_missing_file_returns_finding() {
        let ctx = HwScanContext {
            dry_run: false,
            target: Some("/nonexistent/firmware.bin".to_string()),
            verbose: false,
        };
        let findings = JtagModule.run(&ctx);
        let fw_finding = findings.iter().find(|f| matches!(f.severity, hw_core::HwSeverity::Informative));
        assert!(fw_finding.is_some());
    }
}

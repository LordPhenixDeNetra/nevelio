mod timing;
mod cache;
mod checksec;

pub use timing::check_timing_oracle;
pub use cache::check_flush_reload;
pub use checksec::check_stack_protections;

use hw_core::{HardwareFinding, HwModule, HwScanContext};

pub struct SideChannelModule;

impl HwModule for SideChannelModule {
    fn name(&self) -> &'static str { "hw-sidechannel" }

    fn description(&self) -> &'static str {
        "Détection side-channels : timing oracle HTTP, Flush+Reload cache, protections stack"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();

        // Flush+Reload — x86_64 Linux uniquement, safe en dry_run
        findings.extend(check_flush_reload());

        // Stack protections — via checksec subprocess
        findings.extend(check_stack_protections());

        // Timing oracle HTTP — requiert --target
        if let Some(ref url) = ctx.target {
            findings.extend(check_timing_oracle(url));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hw_core::HwModule;

    #[test]
    fn module_name() {
        assert_eq!(SideChannelModule.name(), "hw-sidechannel");
    }

    #[test]
    fn run_no_target() {
        let ctx = HwScanContext { dry_run: true, target: None, verbose: false };
        let findings = SideChannelModule.run(&ctx);
        // Sans cible, timing oracle n'est pas exécuté — pas de panique.
        let _ = findings;
    }
}

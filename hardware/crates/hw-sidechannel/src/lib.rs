mod timing;
mod cache;
mod checksec;
mod ebpf;

pub use timing::check_timing_oracle;
pub use cache::check_flush_reload;
pub use checksec::check_stack_protections;
pub use ebpf::check_ebpf_timing;

use hw_core::{HardwareFinding, HwModule, HwScanContext};

pub struct SideChannelModule;

impl HwModule for SideChannelModule {
    fn name(&self) -> &'static str { "hw-sidechannel" }

    fn description(&self) -> &'static str {
        "Détection side-channels : timing oracle HTTP, Flush+Reload cache, eBPF latence, protections stack"
    }

    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();

        // Flush+Reload via intrinsics x86_64 (Linux) — sûr sans root
        findings.extend(check_flush_reload());

        // Protections stack (perf_event_paranoid, ptrace_scope, checksec)
        findings.extend(check_stack_protections());

        // Timing oracle HTTP — requiert --target
        if let Some(ref url) = ctx.target {
            findings.extend(check_timing_oracle(url));
        }

        // eBPF syscall latency — mode actif uniquement (CAP_BPF requis)
        if !ctx.dry_run {
            findings.extend(check_ebpf_timing());
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
    fn run_no_target_dry_run() {
        let ctx = HwScanContext { dry_run: true, target: None, verbose: false };
        let findings = SideChannelModule.run(&ctx);
        // dry_run : timing oracle HTTP absent, eBPF absent → pas de panique
        let _ = findings;
    }

    #[test]
    fn ebpf_check_does_not_panic() {
        // check_ebpf_timing() retourne toujours au moins un finding (informatif si non-Linux)
        let findings = check_ebpf_timing();
        assert!(!findings.is_empty());
    }
}

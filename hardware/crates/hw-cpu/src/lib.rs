use hw_core::{HardwareFinding, HwModule};

mod sysfs;
mod microcode;
mod memory_protection;

pub struct CpuModule;

impl HwModule for CpuModule {
    fn name(&self) -> &'static str { "hw-cpu" }

    fn description(&self) -> &'static str {
        "Audit des mitigations CPU : Spectre, Meltdown, MDS, ASLR, microcode"
    }

    fn run(&self, _dry_run: bool) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();
        findings.extend(sysfs::check_cpu_vulnerabilities());
        findings.extend(memory_protection::check_aslr());
        findings.extend(memory_protection::check_kaslr());
        findings.extend(microcode::check_microcode());
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hw_core::HwModule;

    #[test]
    fn module_name() {
        assert_eq!(CpuModule.name(), "hw-cpu");
    }

    #[test]
    fn run_returns_vec() {
        // En environnement de test, les fichiers sysfs peuvent ne pas exister.
        // On vérifie simplement que run() ne panique pas.
        let findings = CpuModule.run(true);
        // Aucune assertion sur le contenu — dépend de la machine hôte.
        let _ = findings;
    }
}

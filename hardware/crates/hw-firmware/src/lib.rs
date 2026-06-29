use hw_core::{HardwareFinding, HwModule};

mod uefi;
mod flash;

pub struct FirmwareModule;

impl HwModule for FirmwareModule {
    fn name(&self) -> &'static str { "hw-firmware" }

    fn description(&self) -> &'static str {
        "Audit firmware UEFI/BIOS : Secure Boot, version, entrées boot, flash SPI"
    }

    fn run(&self, dry_run: bool) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();
        findings.extend(uefi::check_secure_boot());
        findings.extend(uefi::check_bios_info());
        findings.extend(uefi::check_uefi_shell());
        findings.extend(uefi::check_firmware_updates());
        if !dry_run {
            findings.extend(flash::check_spi_flash());
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name() {
        assert_eq!(FirmwareModule.name(), "hw-firmware");
    }

    #[test]
    fn dry_run_skips_flash() {
        // En dry_run, flash::check_spi_flash n'est pas appelé
        // On vérifie simplement que run() ne panique pas.
        let _ = FirmwareModule.run(true);
    }
}

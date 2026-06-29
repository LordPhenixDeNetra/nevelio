use hw_core::{run_command, HardwareFinding, HwSeverity};

// VID USB → nom de sonde JTAG connus
const JTAG_PROBES: &[(&str, &str)] = &[
    ("0403", "FTDI (FT2232H/FT232H — sonde générique)"),
    ("1366", "Segger J-Link"),
    ("0483:3748", "STMicroelectronics ST-Link v2"),
    ("0483:374b", "STMicroelectronics ST-Link v2.1"),
    ("0483:374f", "STMicroelectronics ST-Link v3"),
    ("0d28:0204", "DAPLink / CMSIS-DAP"),
    ("1fc9:0090", "NXP LPC-Link2"),
    ("04b4:8613", "Cypress FX2LP (sonde générique)"),
];

/// Détecte les sondes JTAG connectées via lsusb.
/// Retourne les findings + la liste des sondes trouvées.
pub fn detect_jtag_probes() -> (Vec<HardwareFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut found    = Vec::new();

    let output = match run_command("lsusb", &[]) {
        Some(o) => o,
        None    => {
            findings.push(HardwareFinding::new(
                "lsusb non disponible — détection sonde JTAG ignorée",
                "lsusb est requis pour détecter les sondes JTAG connectées. \
                 Installer : apt-get install usbutils",
                HwSeverity::Informative,
                "hw-jtag",
                None, None,
                "lsusb absent du PATH",
                "sudo apt-get install usbutils",
            ));
            return (findings, found);
        }
    };

    for line in output.lines() {
        let line_lower = line.to_lowercase();

        for (vid_pid, probe_name) in JTAG_PROBES {
            // Vérifier VID seul ou VID:PID
            let vid = &vid_pid[..4];
            let matches = if vid_pid.len() > 4 {
                // VID:PID exact
                line_lower.contains(&format!("id {}:", vid_pid.to_lowercase()))
            } else {
                // VID seul — n'importe quel PID
                line_lower.contains(&format!("id {}:", vid.to_lowercase()))
            };

            if matches {
                found.push(probe_name.to_string());
                findings.push(HardwareFinding::new(
                    format!("Sonde JTAG détectée : {}", probe_name),
                    format!(
                        "Une sonde JTAG/SWD est connectée à la machine ({probe_name}). \
                         Si la machine est un système de production, cette sonde permet \
                         à un attaquant avec accès physique de déboguer, lire la flash \
                         ou modifier l'exécution de tout firmware connecté.",
                        probe_name = probe_name
                    ),
                    HwSeverity::Medium,
                    "hw-jtag",
                    Some(1240),
                    Some(5.2),
                    format!("lsusb : {}", line.trim()),
                    "Retirer les sondes JTAG des systèmes de production. \
                     Si nécessaire pour le développement, les conserver dans un lab isolé. \
                     Activer le RDP Level 2 sur les cibles STM32 en production.",
                ));
            }
        }
    }

    if found.is_empty() {
        findings.push(HardwareFinding::new(
            "Aucune sonde JTAG détectée via USB",
            "lsusb n'a pas détecté de sonde JTAG/SWD connue. \
             Cela ne garantit pas l'absence de sonde : les sondes PCIe ou internes \
             ne sont pas détectées par cette méthode.",
            HwSeverity::Informative,
            "hw-jtag",
            None, None,
            "lsusb scanné — 0 sonde JTAG reconnue",
            "Pour un audit complet, vérifier physiquement les connecteurs JTAG/SWD \
             sur les cartes cibles.",
        ));
    }

    (findings, found)
}

/// Détecte les ports UART/série connectés (USB-to-serial ou natifs).
pub fn detect_uart_ports() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    let mut ports    = Vec::new();

    // Ports USB-to-serial et CDC ACM
    for pattern in &["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS[0-9]*"] {
        if let Some(out) = run_command("sh", &["-c", &format!("ls {} 2>/dev/null", pattern)]) {
            for line in out.lines() {
                let port = line.trim().to_string();
                if !port.is_empty() {
                    ports.push(port);
                }
            }
        }
    }

    if ports.is_empty() {
        findings.push(HardwareFinding::new(
            "Aucun port série UART détecté",
            "Aucun /dev/ttyUSB*, /dev/ttyACM* ou /dev/ttyS* trouvé. \
             Connecter un adaptateur USB-série pour détecter les consoles UART des cibles.",
            HwSeverity::Informative,
            "hw-jtag",
            None, None,
            "ls /dev/ttyUSB* /dev/ttyACM* /dev/ttyS* → vide",
            "Connecter un adaptateur USB-série (FTDI, CP2102, CH340).",
        ));
        return findings;
    }

    // Tenter d'identifier si un shell Linux répond (115200 baud)
    let port_list = ports.join(", ");
    findings.push(HardwareFinding::new(
        format!("Port(s) série UART disponible(s) : {}", port_list),
        format!(
            "{} port(s) série détecté(s). Si connectés à un dispositif embarqué, \
             ces ports exposent potentiellement une console de débogage ou un shell root. \
             Tester manuellement : minicom -D <port> -b 115200",
            ports.len()
        ),
        HwSeverity::Medium,
        "hw-jtag",
        Some(912),
        Some(5.5),
        format!("Ports : {}", port_list),
        "Désactiver la console UART en production (kernel cmdline : console=). \
         Si nécessaire, protéger par authentification (U-Boot lockdown). \
         Physiquement, désactiver les test points UART sur les PCB de production.",
    ));

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detection_does_not_panic() {
        let (findings, _probes) = detect_jtag_probes();
        assert!(!findings.is_empty());
    }

    #[test]
    fn uart_detection_does_not_panic() {
        let findings = detect_uart_ports();
        assert!(!findings.is_empty());
    }
}

use hw_core::{HardwareFinding, HwSeverity, run_command};
use rust_i18n::t;

// Sondes JTAG/SWD connues identifiées par leur VID:PID USB
const KNOWN_JTAG_PROBES: &[(&str, &str)] = &[
    ("0403:6014", "FTDI FT232H (generic JTAG)"),
    ("0403:6010", "FTDI FT2232H (OpenOCD)"),
    ("0403:6011", "FTDI FT4232H"),
    ("1366:0101", "SEGGER J-Link (base)"),
    ("1366:0105", "SEGGER J-Link (PRO)"),
    ("1366:0107", "SEGGER J-Link (ULTRA+)"),
    ("0483:374b", "ST-Link/V2-1"),
    ("0483:3748", "ST-Link/V2"),
    ("0483:374d", "ST-Link/V3 (HLA)"),
    ("2233:1001", "Black Magic Probe"),
    ("1d50:6018", "GreatFET One"),
    ("0451:bef3", "Texas Instruments XDS110"),
    ("0451:c0a0", "Texas Instruments MSP-FET"),
    ("04b4:f139", "Cypress FX2 (OpenOCD USB-Blaster)"),
    ("09fb:6001", "Altera USB-Blaster"),
];

pub(super) fn check_jtag_probes() -> (Vec<HardwareFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut detected_names: Vec<String> = Vec::new();

    let Some(lsusb_out) = run_command("lsusb", &[]) else {
        findings.push(HardwareFinding::new(
            t!("jtag.probe.lsusb_missing.title").to_string(),
            t!("jtag.probe.lsusb_missing.desc").to_string(),
            HwSeverity::Informative,
            "hw-jtag",
            None,
            None,
            "lsusb non disponible",
            t!("jtag.probe.lsusb_missing.rem").to_string(),
        ));
        return (findings, detected_names);
    };

    for (vid_pid, name) in KNOWN_JTAG_PROBES {
        if lsusb_out.to_lowercase().contains(&vid_pid.to_lowercase()) {
            detected_names.push(name.to_string());
        }
    }

    if detected_names.is_empty() {
        findings.push(HardwareFinding::new(
            t!("jtag.probe.none_detected.title").to_string(),
            t!("jtag.probe.none_detected.desc").to_string(),
            HwSeverity::Informative,
            "hw-jtag",
            None,
            None,
            "lsusb : aucune sonde JTAG connue détectée",
            t!("jtag.probe.none_detected.rem").to_string(),
        ));
    } else {
        for probe_name in &detected_names {
            findings.push(HardwareFinding::new(
                t!("jtag.probe.detected.title", name = probe_name.as_str()).to_string(),
                t!("jtag.probe.detected.desc", name = probe_name.as_str()).to_string(),
                HwSeverity::High,
                "hw-jtag",
                Some(1191),
                Some(7.5),
                format!("lsusb détecte la sonde : {}", probe_name),
                t!("jtag.probe.detected.rem").to_string(),
            ));
        }
    }

    findings.extend(check_uart_ports());

    (findings, detected_names)
}

fn check_uart_ports() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    let mut uart_ports = Vec::new();

    // Chercher ttyUSB*, ttyACM*, ttyS*
    for pattern in &["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS[0-9]*"] {
        if let Some(out) = run_command("ls", &[pattern]) {
            for line in out.lines() {
                let p = line.trim();
                if !p.is_empty() {
                    uart_ports.push(p.to_string());
                }
            }
        }
    }

    if uart_ports.is_empty() {
        findings.push(HardwareFinding::new(
            t!("jtag.probe.uart_none.title").to_string(),
            t!("jtag.probe.uart_none.desc").to_string(),
            HwSeverity::Informative,
            "hw-jtag",
            None,
            None,
            "Aucun port série /dev/ttyUSB*, /dev/ttyACM*, /dev/ttyS*",
            t!("jtag.probe.uart_none.rem").to_string(),
        ));
    } else {
        let ports_str = uart_ports.join(", ");
        let count = uart_ports.len();
        findings.push(HardwareFinding::new(
            t!("jtag.probe.uart_found.title", ports = ports_str.clone(), count = count.to_string()).to_string(),
            t!("jtag.probe.uart_found.desc", ports = ports_str.clone(), count = count.to_string()).to_string(),
            HwSeverity::Medium,
            "hw-jtag",
            Some(1191),
            Some(5.0),
            format!("Ports série détectés : {}", ports_str),
            t!("jtag.probe.uart_found.rem").to_string(),
        ));
    }

    findings
}

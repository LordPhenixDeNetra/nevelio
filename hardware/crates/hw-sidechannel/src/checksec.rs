use hw_core::{HardwareFinding, HwSeverity, read_sysfs};
use rust_i18n::t;

pub(super) fn check_kernel_hardening() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    findings.extend(check_aslr_entropy());
    findings.extend(check_perf_event_paranoid());
    findings.extend(check_smep_smap());
    findings.extend(check_ptrace_scope());
    findings
}

fn check_aslr_entropy() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if let Some(val) = read_sysfs("/proc/sys/vm/mmap_rnd_bits") {
        if let Ok(bits) = val.trim().parse::<u32>() {
            if bits < 28 {
                findings.push(HardwareFinding::new(
                    t!("side.checksec.aslr_entropy_low.title").to_string(),
                    t!("side.checksec.aslr_entropy_low.desc", bits = bits.to_string()).to_string(),
                    HwSeverity::Medium,
                    "hw-sidechannel",
                    Some(330),
                    Some(5.5),
                    format!("/proc/sys/vm/mmap_rnd_bits = {}", bits),
                    t!("side.checksec.aslr_entropy_low.rem").to_string(),
                ));
            }
        }
    }

    if let Some(val) = read_sysfs("/proc/sys/vm/mmap_rnd_compat_bits") {
        if let Ok(bits) = val.trim().parse::<u32>() {
            if bits < 16 {
                findings.push(HardwareFinding::new(
                    t!("side.checksec.aslr_compat_low.title").to_string(),
                    t!("side.checksec.aslr_compat_low.desc", bits = bits.to_string()).to_string(),
                    HwSeverity::Low,
                    "hw-sidechannel",
                    Some(330),
                    Some(3.5),
                    format!("/proc/sys/vm/mmap_rnd_compat_bits = {}", bits),
                    t!("side.checksec.aslr_compat_low.rem").to_string(),
                ));
            }
        }
    }

    findings
}

fn check_perf_event_paranoid() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(val) = read_sysfs("/proc/sys/kernel/perf_event_paranoid") else {
        return findings;
    };

    let Ok(paranoid) = val.trim().parse::<i32>() else {
        return findings;
    };

    if paranoid < 2 {
        findings.push(HardwareFinding::new(
            t!("side.checksec.perf_permissive.title").to_string(),
            t!("side.checksec.perf_permissive.desc", value = paranoid.to_string()).to_string(),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(1342),
            Some(5.5),
            format!("/proc/sys/kernel/perf_event_paranoid = {}", paranoid),
            t!("side.checksec.perf_permissive.rem").to_string(),
        ));
    } else {
        findings.push(HardwareFinding::new(
            t!("side.checksec.perf_ok.title").to_string(),
            t!("side.checksec.perf_ok.desc", value = paranoid.to_string()).to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            format!("/proc/sys/kernel/perf_event_paranoid = {}", paranoid),
            t!("side.checksec.perf_ok.rem").to_string(),
        ));
    }

    findings
}

fn check_smep_smap() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let cpuinfo = read_sysfs("/proc/cpuinfo").unwrap_or_default();

    if !cpuinfo.contains(" smep ") {
        findings.push(HardwareFinding::new(
            t!("side.checksec.smep_disabled.title").to_string(),
            t!("side.checksec.smep_disabled.desc").to_string(),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(284),
            Some(5.0),
            "Flag 'smep' absent de /proc/cpuinfo",
            t!("side.checksec.smep_disabled.rem").to_string(),
        ));
    }

    if !cpuinfo.contains(" smap ") {
        findings.push(HardwareFinding::new(
            t!("side.checksec.smap_disabled.title").to_string(),
            t!("side.checksec.smap_disabled.desc").to_string(),
            HwSeverity::Low,
            "hw-sidechannel",
            Some(284),
            Some(4.0),
            "Flag 'smap' absent de /proc/cpuinfo",
            t!("side.checksec.smap_disabled.rem").to_string(),
        ));
    }

    findings
}

fn check_ptrace_scope() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(val) = read_sysfs("/proc/sys/kernel/yama/ptrace_scope") else {
        return findings;
    };

    match val.trim() {
        "0" => {
            findings.push(HardwareFinding::new(
                t!("side.checksec.ptrace_unrestricted.title").to_string(),
                t!("side.checksec.ptrace_unrestricted.desc").to_string(),
                HwSeverity::High,
                "hw-sidechannel",
                Some(862),
                Some(7.0),
                "/proc/sys/kernel/yama/ptrace_scope = 0",
                t!("side.checksec.ptrace_unrestricted.rem").to_string(),
            ));
        }
        "1" => {
            findings.push(HardwareFinding::new(
                t!("side.checksec.ptrace_partial.title").to_string(),
                t!("side.checksec.ptrace_partial.desc").to_string(),
                HwSeverity::Low,
                "hw-sidechannel",
                Some(862),
                Some(3.0),
                "/proc/sys/kernel/yama/ptrace_scope = 1",
                t!("side.checksec.ptrace_partial.rem").to_string(),
            ));
        }
        v @ ("2" | "3") => {
            findings.push(HardwareFinding::new(
                t!("side.checksec.ptrace_ok.title").to_string(),
                t!("side.checksec.ptrace_ok.desc", value = v.to_string()).to_string(),
                HwSeverity::Informative,
                "hw-sidechannel",
                None,
                None,
                format!("/proc/sys/kernel/yama/ptrace_scope = {}", v),
                t!("side.checksec.ptrace_ok.rem").to_string(),
            ));
        }
        v => {
            findings.push(HardwareFinding::new(
                t!("side.checksec.ptrace_unknown.title").to_string(),
                t!("side.checksec.ptrace_unknown.desc", value = v.to_string()).to_string(),
                HwSeverity::Informative,
                "hw-sidechannel",
                None,
                None,
                format!("/proc/sys/kernel/yama/ptrace_scope = {}", v),
                t!("side.checksec.ptrace_unknown.rem").to_string(),
            ));
        }
    }

    findings
}

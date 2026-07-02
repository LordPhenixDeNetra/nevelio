use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;
use std::time::Instant;

const SAMPLE_COUNT: usize = 50;
const HIGH_VARIANCE_MS: f64 = 20.0;
const SLOW_P95_MS: f64 = 200.0;

pub(super) fn check_timing_oracle(target_url: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            findings.push(HardwareFinding::new(
                t!("side.timing.http_init_error.title").to_string(),
                t!("side.timing.http_init_error.desc", error = e.to_string()).to_string(),
                HwSeverity::Informative,
                "hw-sidechannel",
                None,
                None,
                format!("reqwest::Client::builder() erreur: {}", e),
                t!("side.timing.http_init_error.rem").to_string(),
            ));
            return findings;
        }
    };

    let mut latencies: Vec<f64> = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let start = Instant::now();
        if client.get(target_url).send().is_ok() {
            latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        }
    }

    if latencies.len() < SAMPLE_COUNT / 2 {
        findings.push(HardwareFinding::new(
            t!("side.timing.unreachable.title").to_string(),
            t!("side.timing.unreachable.desc",
               received = latencies.len().to_string(),
               total    = SAMPLE_COUNT.to_string(),
               url      = target_url.to_string()
            ).to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            format!("URL: {} — {}/{} réponses reçues", target_url, latencies.len(), SAMPLE_COUNT),
            t!("side.timing.unreachable.rem").to_string(),
        ));
        return findings;
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p5  = percentile(&latencies, 5);
    let p95 = percentile(&latencies, 95);
    let variance = p95 - p5;

    if variance > HIGH_VARIANCE_MS {
        findings.push(HardwareFinding::new(
            t!("side.timing.high_variance.title").to_string(),
            t!("side.timing.high_variance.desc",
               variance  = format!("{:.1}", variance),
               threshold = format!("{:.0}", HIGH_VARIANCE_MS)
            ).to_string(),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(208),
            Some(5.3),
            format!("URL: {} — p5={:.1}ms, p95={:.1}ms, Δ={:.1}ms", target_url, p5, p95, variance),
            t!("side.timing.high_variance.rem").to_string(),
        ));
    } else if p95 > SLOW_P95_MS {
        findings.push(HardwareFinding::new(
            t!("side.timing.slow_p95.title").to_string(),
            t!("side.timing.slow_p95.desc",
               p95       = format!("{:.1}", p95),
               threshold = format!("{:.0}", SLOW_P95_MS)
            ).to_string(),
            HwSeverity::Low,
            "hw-sidechannel",
            Some(208),
            Some(3.0),
            format!("URL: {} — p95={:.1}ms (seuil {}ms)", target_url, p95, SLOW_P95_MS),
            t!("side.timing.slow_p95.rem").to_string(),
        ));
    } else {
        findings.push(HardwareFinding::new(
            t!("side.timing.ok.title").to_string(),
            t!("side.timing.ok.desc",
               variance  = format!("{:.1}", variance),
               threshold = format!("{:.0}", HIGH_VARIANCE_MS)
            ).to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            format!("URL: {} — p5={:.1}ms, p95={:.1}ms, Δ={:.1}ms", target_url, p5, p95, variance),
            t!("side.timing.ok.rem").to_string(),
        ));
    }

    findings
}

fn percentile(sorted: &[f64], pct: usize) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((pct * sorted.len()) / 100).min(sorted.len() - 1);
    sorted[idx]
}

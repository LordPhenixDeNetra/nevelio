use hw_core::{HardwareFinding, HwSeverity};
use reqwest::blocking::Client;
use std::time::{Duration, Instant};

const SAMPLE_COUNT: usize = 100;
// Seuil au-delà duquel la variance est suspecte (ms)
const HIGH_VARIANCE_THRESHOLD_MS: u128 = 2_000;
// Seuil p95 : réponses très lentes pouvant indiquer traitement conditionnel
const SLOW_P95_THRESHOLD_MS: u128 = 5_000;

/// Oracle de timing HTTP — CWE-208 (Observable Timing Discrepancy).
///
/// Effectue SAMPLE_COUNT requêtes GET vers `target_url`, mesure le temps de
/// réponse pour chacune, puis signale si la variance (p95 − p5) est anormalement
/// élevée ou si le p95 dépasse le seuil de lenteur.
pub fn check_timing_oracle(target_url: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let client = match Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("nevelio-hw/0.1 (security-audit)")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            findings.push(HardwareFinding::new(
                "Impossible d'initialiser le client HTTP",
                format!("Erreur reqwest : {}", e),
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                target_url,
                "Vérifier la configuration réseau.",
            ));
            return findings;
        }
    };

    let mut samples: Vec<u128> = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let t0 = Instant::now();
        match client.get(target_url).send() {
            Ok(_)  => samples.push(t0.elapsed().as_millis()),
            Err(_) => {} // Ignorer les erreurs réseau transitoires
        }
    }

    if samples.len() < SAMPLE_COUNT / 2 {
        findings.push(HardwareFinding::new(
            "Timing oracle : cible inaccessible ou trop peu de réponses",
            format!(
                "Seulement {}/{} requêtes ont abouti pour {}.",
                samples.len(), SAMPLE_COUNT, target_url
            ),
            HwSeverity::Informative,
            "hw-sidechannel",
            Some(208), None,
            format!("{} réponses sur {}", samples.len(), SAMPLE_COUNT),
            "Vérifier la connectivité et l'URL cible.",
        ));
        return findings;
    }

    samples.sort_unstable();

    let p5  = percentile(&samples, 5.0);
    let p50 = percentile(&samples, 50.0);
    let p95 = percentile(&samples, 95.0);
    let variance = p95.saturating_sub(p5);

    let evidence = format!(
        "URL : {} | n={} | p5={}ms | médiane={}ms | p95={}ms | Δ(p95−p5)={}ms",
        target_url, samples.len(), p5, p50, p95, variance
    );

    if variance > HIGH_VARIANCE_THRESHOLD_MS {
        findings.push(HardwareFinding::new(
            "Timing oracle détecté — variance anormalement élevée (CWE-208)",
            format!(
                "L'écart p95−p5 = {}ms dépasse le seuil de {}ms. Cette dispersion \
                 importante peut indiquer un traitement conditionnel côté serveur \
                 exploitable par un timing attack (énumération d'utilisateurs, \
                 blind SQLi temporel, side-channel cryptographique).",
                variance, HIGH_VARIANCE_THRESHOLD_MS
            ),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(208),
            Some(5.3),
            evidence,
            "Implémenter des délais constants (constant-time comparison) pour les \
             opérations sensibles. Utiliser hmac::verify_slices_are_equal() en Rust, \
             secrets.compare_digest() en Python. Ajouter du jitter aléatoire \
             si la latence variable est inhérente au système.",
        ));
    } else if p95 > SLOW_P95_THRESHOLD_MS {
        findings.push(HardwareFinding::new(
            "Timing oracle : réponses très lentes (CWE-208 potentiel)",
            format!(
                "Le p95 de latence est {}ms > seuil {}ms. Des réponses lentes \
                 peuvent masquer un traitement conditionnel ou indiquer un DoS latent.",
                p95, SLOW_P95_THRESHOLD_MS
            ),
            HwSeverity::Low,
            "hw-sidechannel",
            Some(208),
            Some(3.1),
            evidence,
            "Analyser les chemins de code lents. Ajouter des profils de performance \
             et des timeouts serveur stricts.",
        ));
    } else {
        findings.push(HardwareFinding::new(
            "Timing oracle : aucune anomalie détectée",
            format!(
                "Variance p95−p5 = {}ms sous le seuil de {}ms. \
                 Aucun timing side-channel évident sur cet endpoint.",
                variance, HIGH_VARIANCE_THRESHOLD_MS
            ),
            HwSeverity::Informative,
            "hw-sidechannel",
            None, None,
            evidence,
            "Continuer à monitorer la latence en production.",
        ));
    }

    findings
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic() {
        let data = vec![10u128, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile(&data, 0.0),   10);
        assert_eq!(percentile(&data, 50.0),  60);
        assert_eq!(percentile(&data, 100.0), 100);
    }

    #[test]
    fn percentile_p95() {
        // [1..100] sorted, idx = round(0.95 * 99) = round(94.05) = 94 → data[94] = 95
        let mut data: Vec<u128> = (1..=100).collect();
        data.sort_unstable();
        assert_eq!(percentile(&data, 95.0), 95);
    }
}

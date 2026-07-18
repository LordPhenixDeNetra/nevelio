use anyhow::Result;

use crate::provider::{AiProvider, CompletionOpts, Message};
use crate::triage::FindingContext;

/// Generate a Markdown narrative attack chain report from all findings.
///
/// The narrative describes how an attacker could chain vulnerabilities,
/// the overall risk posture, and key remediation priorities.
pub async fn narrative(
    findings: &[FindingContext],
    target: &str,
    lang: &str,
    provider: &dyn AiProvider,
    opts: &CompletionOpts,
) -> Result<String> {
    if findings.is_empty() {
        return Ok(match lang {
            "en" => "No findings were detected — the target appears secure against tested attack vectors.".to_string(),
            "es" => "No se detectaron hallazgos — el objetivo parece seguro contra los vectores de ataque probados.".to_string(),
            _    => "Aucun finding détecté — la cible semble sécurisée contre les vecteurs d'attaque testés.".to_string(),
        });
    }

    let system = match lang {
        "en" => "You are a senior penetration tester writing an executive and technical report. Use clear, actionable language.",
        "es" => "Eres un pentester senior redactando un informe ejecutivo y técnico. Usa lenguaje claro y accionable.",
        _    => "Tu es un pentester senior rédigeant un rapport exécutif et technique. Utilise un langage clair et actionnable.",
    };

    let severity_counts = count_severities(findings);
    let findings_md: String = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                "{}. **[{}]** {} — `{} {}` (module: {})\n   {}\n",
                i + 1,
                f.severity,
                f.title,
                f.method,
                f.endpoint,
                f.module,
                f.description
            )
        })
        .collect();

    let (instruction, sections) = match lang {
        "en" => (
            "Write in English.",
            "## Executive Summary\n\n## Attack Chain Analysis\n\n## Critical Risk Highlights\n\n## Recommended Remediation Order",
        ),
        "es" => (
            "Escribe en español.",
            "## Resumen Ejecutivo\n\n## Análisis de Cadena de Ataque\n\n## Riesgos Críticos\n\n## Orden de Remediación Recomendado",
        ),
        _ => (
            "Écris en français.",
            "## Résumé Exécutif\n\n## Analyse de la Chaîne d'Attaque\n\n## Points Critiques\n\n## Ordre de Remédiation Recommandé",
        ),
    };

    let user_content = format!(
        r#"{instruction}

Target: {target}
Summary: {critical} Critical · {high} High · {medium} Medium · {low} Low · {info} Informative

Security findings:
{findings_md}

Write a penetration test narrative report with these sections:
{sections}

Use Markdown. Be specific, reference actual endpoints and findings."#,
        instruction = instruction,
        target = target,
        critical = severity_counts.critical,
        high = severity_counts.high,
        medium = severity_counts.medium,
        low = severity_counts.low,
        info = severity_counts.informative,
        findings_md = findings_md,
        sections = sections,
    );

    let messages = vec![Message::system(system), Message::user(user_content)];

    provider.complete(&messages, opts).await
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    informative: usize,
}

fn count_severities(findings: &[FindingContext]) -> SeverityCounts {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informative: 0,
    };
    for f in findings {
        match f.severity.to_uppercase().as_str() {
            "CRITICAL" => counts.critical += 1,
            "HIGH" => counts.high += 1,
            "MEDIUM" => counts.medium += 1,
            "LOW" => counts.low += 1,
            "INFORMATIVE" => counts.informative += 1,
            _ => {}
        }
    }
    counts
}

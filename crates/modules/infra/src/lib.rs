use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

mod cookies;
mod cors_hsts;
mod headers;
mod secrets;
mod tls;

use cookies::check_cookie_flags;
use cors_hsts::{check_cors, check_hsts};
use headers::{
    check_csp, check_referrer_policy, check_security_headers, check_server_disclosure,
    probe_debug_endpoint,
};
use secrets::{check_secrets_in_response, check_stack_traces};
use tls::check_tls;

pub struct InfraModule;

/// Known debug/sensitive paths to probe.
const DEBUG_PATHS: &[(&str, &str, &str, f64)] = &[
    ("/.env", "ENV file exposed", "CRITICAL", 9.8),
    ("/actuator/env", "Spring Actuator /env endpoint", "CRITICAL", 9.1),
    ("/actuator/mappings", "Spring Actuator /mappings endpoint", "HIGH", 7.5),
    ("/actuator/beans", "Spring Actuator /beans endpoint", "HIGH", 7.5),
    ("/actuator/loggers", "Spring Actuator /loggers endpoint", "HIGH", 7.5),
    ("/.git/HEAD", "Git repository exposed", "CRITICAL", 9.8),
    ("/phpinfo.php", "phpinfo() exposed", "HIGH", 7.8),
    ("/debug", "Debug endpoint accessible", "HIGH", 7.5),
    ("/server-status", "Apache server-status exposed", "MEDIUM", 5.3),
    ("/server-info", "Apache server-info exposed", "MEDIUM", 5.3),
    ("/config.json", "Config file exposed", "CRITICAL", 9.1),
];

#[async_trait]
impl AttackModule for InfraModule {
    fn name(&self) -> &str {
        "infra"
    }

    fn description(&self) -> &str {
        "Tests CORS, HSTS, TLS configuration, debug endpoints, and secrets exposure"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = session.config.target.trim_end_matches('/').to_string();

        // --- Header checks on each endpoint ---
        for endpoint in endpoints {
            let url = &endpoint.full_url;
            if let Ok(resp) = client
                .inner()
                .get(url)
                .header("Origin", "https://evil.nevelio.test")
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                let headers = resp.headers().clone();

                // CORS
                if let Some(f) = check_cors(url, &headers) {
                    findings.push(f);
                }
                // HSTS
                if let Some(f) = check_hsts(url, &headers) {
                    findings.push(f);
                }
                // Security headers
                findings.extend(check_security_headers(url, &headers));
                // Server info disclosure
                if let Some(f) = check_server_disclosure(url, &headers) {
                    findings.push(f);
                }
            }
        }

        // --- Debug endpoints (probe from base URL, deduplicate by path) ---
        let mut probed = std::collections::HashSet::new();
        for &(path, label, severity_str, cvss) in DEBUG_PATHS {
            let url = format!("{}{}", base, path);
            if !probed.insert(url.clone()) {
                continue;
            }
            if let Some(f) = probe_debug_endpoint(client, &url, label, severity_str, cvss).await {
                findings.push(f);
            }
        }

        // --- TLS check (once on base target) ---
        findings.extend(check_tls(client, &base).await);

        // --- Per-endpoint extended checks ---
        for endpoint in endpoints {
            let url = &endpoint.full_url;
            if let Ok(resp) = client
                .inner()
                .get(url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                // CSP
                if let Some(f) = check_csp(url, &headers) {
                    findings.push(f);
                }
                // Referrer-Policy
                if let Some(f) = check_referrer_policy(url, &headers) {
                    findings.push(f);
                }
                // Cookie flags
                findings.extend(check_cookie_flags(url, &headers));
                // Secrets in response body
                findings.extend(check_secrets_in_response(url, &body));
                // Stack traces in response body
                if let Some(f) = check_stack_traces(url, &body) {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

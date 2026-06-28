use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

pub(super) async fn check_tls(client: &HttpClient, base: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // If the target is already HTTP — no TLS at all
    if base.starts_with("http://") {
        let mut f = Finding::new(
            "API served over plain HTTP (no TLS)",
            Severity::Critical,
            9.8,
            "infra",
            base,
            "GET",
        );
        f.description =
            "The API is accessible over HTTP without TLS encryption. All traffic \
             (including credentials and tokens) is transmitted in cleartext."
                .to_string();
        f.recommendation =
            "Serve all API traffic exclusively over HTTPS (TLS 1.2+). Redirect HTTP → HTTPS \
             and set HSTS."
                .to_string();
        f.cwe = Some("CWE-319".to_string());
        f.references = vec![
            "https://owasp.org/www-project-api-security/".to_string(),
        ];
        findings.push(f);
        return findings;
    }

    // If HTTPS — check whether HTTP (non-TLS) is also accessible without a redirect
    if let Some(rest) = base.strip_prefix("https://") {
        let http_url = format!("http://{rest}");
        let req = client.inner().get(&http_url).build();
        if let Ok(req) = req {
            // Use inner client directly so we don't follow redirects automatically
            let result = client
                .inner()
                .execute(req)
                .await;
            if let Ok(resp) = result {
                let status = resp.status().as_u16();
                // If the server returns 200 on HTTP instead of redirecting → finding
                if matches!(status, 200..=299) {
                    let mut f = Finding::new(
                        "API accessible over HTTP without HTTPS redirect",
                        Severity::High,
                        7.4,
                        "infra",
                        &http_url,
                        "GET",
                    );
                    f.description = format!(
                        "The HTTP endpoint {} returns HTTP {} without redirecting to HTTPS. \
                         Traffic can be intercepted by a man-in-the-middle attacker.",
                        http_url, status
                    );
                    f.proof = format!("GET {} → HTTP {}", http_url, status);
                    f.recommendation =
                        "Configure your server to return 301/308 for all HTTP requests \
                         and add HSTS to prevent future HTTP access."
                            .to_string();
                    f.cwe = Some("CWE-319".to_string());
                    findings.push(f);
                }
            }
        }
    }

    findings
}

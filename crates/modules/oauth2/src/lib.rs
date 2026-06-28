use async_trait::async_trait;

use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

mod redirect;
mod tokens;
mod flows;
mod clients;
mod referer;

// ---------------------------------------------------------------------------
// OAuth2 endpoint patterns
// ---------------------------------------------------------------------------

const AUTHORIZE_PATHS: &[&str] = &[
    "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
    "/connect/authorize", "/authorize", "/oauth/auth",
    "/login/oauth/authorize", "/api/oauth/authorize",
    "/v1/oauth/authorize", "/v2/oauth/authorize",
];

const TOKEN_PATHS: &[&str] = &[
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/connect/token", "/token", "/api/token",
    "/v1/oauth/token", "/v2/oauth/token",
];

const INTROSPECT_PATHS: &[&str] = &[
    "/oauth/introspect", "/oauth2/introspect", "/introspect",
    "/connect/introspect", "/token/introspect", "/auth/introspect",
];

pub const REVOKE_PATHS: &[&str] = &[
    "/oauth/revoke", "/oauth2/revoke", "/revoke", "/token/revoke",
];

const JWKS_PATHS: &[&str] = &[
    "/.well-known/jwks.json", "/oauth/jwks", "/.well-known/openid-configuration",
];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct OAuth2Module;

#[async_trait]
impl AttackModule for OAuth2Module {
    fn name(&self) -> &str {
        "oauth2"
    }

    fn description(&self) -> &str {
        "Teste les flows OAuth2/OIDC : redirect_uri manipulation, state absent, PKCE bypass, introspection non protégée"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = &session.config.target;

        // ── Discovery: look for OAuth2 endpoints in the spec first ──────────
        let auth_endpoints = collect_matching(endpoints, AUTHORIZE_PATHS);
        let token_endpoints = collect_matching(endpoints, TOKEN_PATHS);
        let introspect_endpoints = collect_matching(endpoints, INTROSPECT_PATHS);

        // ── Also probe well-known paths not in spec ──────────────────────────
        findings.extend(redirect::probe_redirect_uri(client, base, &auth_endpoints).await);
        findings.extend(redirect::probe_missing_state(client, base, &auth_endpoints).await);
        findings.extend(redirect::probe_pkce_bypass(client, base, &auth_endpoints).await);
        findings.extend(tokens::probe_introspect_unauth(client, base, &introspect_endpoints).await);
        findings.extend(tokens::probe_token_endpoint_methods(client, base, &token_endpoints).await);
        findings.extend(tokens::probe_open_jwks(client, base).await);
        findings.extend(flows::probe_implicit_flow(client, base, &auth_endpoints).await);
        findings.extend(flows::probe_code_replay(client, base, &token_endpoints).await);
        findings.extend(clients::probe_client_enumeration(client, base, &auth_endpoints).await);
        findings.extend(referer::probe_token_referer_leak(client, base, &auth_endpoints).await);

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers (pub(super) so sub-modules can call them via super::)
// ---------------------------------------------------------------------------

pub(crate) fn collect_matching<'a>(endpoints: &'a [Endpoint], patterns: &[&str]) -> Vec<&'a Endpoint> {
    endpoints
        .iter()
        .filter(|ep| {
            patterns
                .iter()
                .any(|p| ep.path.to_lowercase().contains(p) || ep.full_url.to_lowercase().contains(p))
        })
        .collect()
}

/// Build a URL by replacing the path in the base target
pub(crate) fn build_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{}{}", base, path)
}

pub(crate) async fn get_text(client: &HttpClient, url: &str) -> Option<(u16, String)> {
    let req = client.inner().get(url).build().ok()?;
    let resp = client.send(req).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some((status, body))
}

// ---------------------------------------------------------------------------
// URL encoding helper
// ---------------------------------------------------------------------------

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

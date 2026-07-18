use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use tokio_tungstenite::tungstenite::Message;

pub struct WebSocketModule;

const WS_PATHS: &[&str] = &[
    "/ws",
    "/websocket",
    "/socket.io/",
    "/socket",
    "/stream",
    "/api/ws",
    "/api/v1/ws",
    "/api/socket",
    "/live",
    "/events",
    "/realtime",
    "/push",
    "/feed",
];

const INJECTION_PAYLOADS: &[(&str, &str)] = &[
    (r#"{"msg":"<script>alert(1)</script>"}"#, "XSS"),
    (r#"{"query":"' OR '1'='1"}"#, "SQLi"),
    (r#"{"input":"{{7*7}}"}"#, "SSTI"),
];

#[async_trait]
impl AttackModule for WebSocketModule {
    fn name(&self) -> &str {
        "websocket"
    }

    fn description(&self) -> &str {
        "WebSocket : validation Origin, auth sur handshake, injection dans les messages, rate-limiting"
    }

    async fn run(
        &self,
        session: &ScanSession,
        _client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let base = session.config.target.trim_end_matches('/');
        let ws_base = to_ws_scheme(base);

        // Probe common WebSocket paths on the target
        for path in WS_PATHS {
            let url = format!("{}{}", ws_base, path);
            if let Some(f) = check_origin_validation(&url).await {
                findings.push(f);
                break;
            }
        }

        // Rate limiting on common WS paths
        for path in &WS_PATHS[..3] {
            let url = format!("{}{}", ws_base, path);
            if let Some(f) = check_ws_rate_limit(&url).await {
                findings.push(f);
                break;
            }
        }

        // Probe endpoints that look like WebSocket upgrade points
        for ep in endpoints {
            let path_lower = ep.path.to_lowercase();
            if looks_like_ws(&path_lower) {
                let ws_url = to_ws_scheme(ep.full_url.trim_end_matches('/'));
                if let Some(f) = check_ws_no_auth(&ws_url).await {
                    findings.push(f);
                }
                if let Some(f) = check_ws_injection(&ws_url).await {
                    findings.push(f);
                }
                if let Some(f) = check_ws_rate_limit(&ws_url).await {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

fn to_ws_scheme(url: &str) -> String {
    if url.starts_with("https://") {
        url.replacen("https://", "wss://", 1)
    } else if url.starts_with("http://") {
        url.replacen("http://", "ws://", 1)
    } else {
        url.to_string()
    }
}

fn looks_like_ws(path: &str) -> bool {
    [
        "ws",
        "websocket",
        "socket",
        "stream",
        "live",
        "events",
        "realtime",
        "push",
        "feed",
    ]
    .iter()
    .any(|kw| path.contains(kw))
}

// ── Checks ────────────────────────────────────────────────────────────────────

async fn check_origin_validation(url: &str) -> Option<Finding> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut req = url.into_client_request().ok()?;
    req.headers_mut()
        .insert("Origin", "https://evil.example.com".parse().ok()?);

    let timeout = std::time::Duration::from_secs(5);
    match tokio::time::timeout(timeout, tokio_tungstenite::connect_async(req)).await {
        Ok(Ok(_)) => {
            let mut f = Finding::new(
                "WebSocket — Origin non validée",
                Severity::High,
                6.5,
                "websocket",
                url,
                "WS-CONNECT",
            );
            f.description =
                "Le serveur WebSocket accepte les connexions depuis une origine arbitraire \
                 (https://evil.example.com). N'importe quel site tiers peut ouvrir une connexion \
                 WebSocket au nom d'un utilisateur authentifié."
                    .to_string();
            f.recommendation =
                "Valider le header `Origin` contre une liste blanche d'origines autorisées \
                 côté serveur. Rejeter les connexions provenant d'origines inconnues."
                    .to_string();
            f.cwe = Some("CWE-346".to_string());
            Some(f)
        }
        _ => None,
    }
}

async fn check_ws_no_auth(url: &str) -> Option<Finding> {
    let timeout = std::time::Duration::from_secs(5);
    match tokio::time::timeout(timeout, tokio_tungstenite::connect_async(url)).await {
        Ok(Ok(_)) => {
            let mut f = Finding::new(
                "WebSocket — Handshake sans authentification",
                Severity::High,
                7.5,
                "websocket",
                url,
                "WS-CONNECT",
            );
            f.description =
                "La connexion WebSocket réussit sans header Authorization ni token de session. \
                 Un attaquant non authentifié peut établir une connexion et interagir avec le service."
                    .to_string();
            f.recommendation =
                "Exiger un token valide (header Authorization ou paramètre `?token=`) \
                 lors du handshake WebSocket. Fermer immédiatement les connexions non authentifiées."
                    .to_string();
            f.cwe = Some("CWE-306".to_string());
            Some(f)
        }
        _ => None,
    }
}

async fn check_ws_injection(url: &str) -> Option<Finding> {
    let timeout = std::time::Duration::from_secs(5);
    let conn = tokio::time::timeout(timeout, tokio_tungstenite::connect_async(url)).await;

    let (mut ws, _) = match conn {
        Ok(Ok(c)) => c,
        _ => return None,
    };

    for (payload, attack_type) in INJECTION_PAYLOADS {
        let _ = ws.send(Message::Text(payload.to_string().into())).await;

        if let Ok(Some(Ok(msg))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await
        {
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                _ => continue,
            };

            if text.contains("<script>") || text.contains("alert(1)") || text.contains("49") {
                let mut f = Finding::new(
                    format!("WebSocket — Injection {} dans les messages", attack_type),
                    Severity::High,
                    7.0,
                    "websocket",
                    url,
                    "WS-MESSAGE",
                );
                f.description = format!(
                    "Le serveur réfléchit le payload {} non filtré dans sa réponse WebSocket.",
                    attack_type
                );
                f.proof = format!(
                    "Payload: {}\nRéponse: {}",
                    payload,
                    &text[..text.len().min(200)]
                );
                f.recommendation =
                    "Valider et échapper toutes les données reçues via WebSocket avant \
                     de les renvoyer ou de les traiter. Utiliser un CSP strict."
                        .to_string();
                f.cwe = Some("CWE-79".to_string());
                return Some(f);
            }
        }
    }

    None
}

async fn check_ws_rate_limit(url: &str) -> Option<Finding> {
    // Open N connections rapidly; if all succeed, no rate limiting is in place.
    const PROBE_COUNT: usize = 10;
    let timeout = std::time::Duration::from_secs(3);
    let mut accepted = 0usize;

    for _ in 0..PROBE_COUNT {
        if let Ok(Ok(_)) =
            tokio::time::timeout(timeout, tokio_tungstenite::connect_async(url)).await
        {
            accepted += 1;
        } else {
            // Server started rejecting — rate limiting likely in place
            return None;
        }
    }

    if accepted >= PROBE_COUNT {
        let mut f = Finding::new(
            format!(
                "WebSocket — Absence de rate limiting sur les connexions — {}",
                url
            ),
            Severity::Medium,
            5.3,
            "websocket",
            url,
            "WS-CONNECT",
        );
        f.description = format!(
            "Le serveur WebSocket a accepté {} connexions consécutives sans rejeter aucune. \
             L'absence de rate limiting expose le service à des attaques par épuisement de \
             connexions (resource exhaustion) ou à du brute force via WebSocket.",
            PROBE_COUNT
        );
        f.proof = format!(
            "{} connexions ouvertes sans aucun refus (HTTP 429 ou fermeture).",
            PROBE_COUNT
        );
        f.recommendation =
            "Implémenter un rate limit sur les connexions WebSocket (ex. max 5 connexions/seconde \
             par IP). Utiliser un reverse proxy (nginx, HAProxy) avec `limit_conn` ou un middleware \
             applicatif."
                .to_string();
        f.cwe = Some("CWE-770".to_string());
        f.references =
            vec!["https://owasp.org/www-community/attacks/Denial_of_Service".to_string()];
        return Some(f);
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_conversion_https() {
        assert_eq!(
            to_ws_scheme("https://api.example.com"),
            "wss://api.example.com"
        );
    }

    #[test]
    fn scheme_conversion_http() {
        assert_eq!(to_ws_scheme("http://localhost:8080"), "ws://localhost:8080");
    }

    #[test]
    fn looks_like_ws_positive() {
        assert!(looks_like_ws("/api/websocket"));
        assert!(looks_like_ws("/live/stream"));
        assert!(looks_like_ws("/events/feed"));
    }

    #[test]
    fn looks_like_ws_negative() {
        assert!(!looks_like_ws("/api/users"));
        assert!(!looks_like_ws("/health"));
    }

    #[test]
    fn module_name() {
        assert_eq!(WebSocketModule.name(), "websocket");
    }
}

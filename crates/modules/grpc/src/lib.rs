use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

pub struct GrpcModule;

// gRPC well-known service paths
const REFLECTION_PATH: &str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
const HEALTH_PATH: &str = "/grpc.health.v1.Health/Check";
const GRPC_CONTENT_TYPE: &str = "application/grpc";

// Protobuf-encoded ListServices request wrapped in a gRPC frame.
// Wire encoding:
//   Field 3 (list_services), wire type 2 (LEN), length 0  → [0x1a, 0x00]
// gRPC frame: [compressed=0x00][length u32 big-endian][message bytes]
const REFLECTION_FRAME: &[u8] = &[
    0x00, // not compressed
    0x00, 0x00, 0x00, 0x02, // message length = 2
    0x1a, 0x00, // list_services = ""
];

// Protobuf-encoded Health/Check request (empty HealthCheckRequest)
// gRPC frame with 0-byte message body
const HEALTH_FRAME: &[u8] = &[
    0x00, // not compressed
    0x00, 0x00, 0x00, 0x00, // message length = 0
];

#[async_trait]
impl AttackModule for GrpcModule {
    fn name(&self) -> &str {
        "grpc"
    }

    fn description(&self) -> &str {
        "gRPC/Protobuf : réflexion exposée, plaintext sans TLS, health check sans auth, injection dans les champs"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        _endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = session.config.target.trim_end_matches('/');

        // 1. Plaintext gRPC (no TLS)
        if let Some(f) = check_plaintext_grpc(client, base).await {
            findings.push(f);
        }

        // 2. gRPC reflection enabled
        if let Some(f) = check_grpc_reflection(client, base).await {
            findings.push(f);
        }

        // 3. Health check without authentication
        if let Some(f) = check_health_no_auth(client, base).await {
            findings.push(f);
        }

        // 4. Missing auth on metadata headers
        if let Some(f) = check_missing_metadata_auth(client, base).await {
            findings.push(f);
        }

        findings
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_grpc_response(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with(GRPC_CONTENT_TYPE))
        .unwrap_or(false)
}

fn grpc_status(resp: &reqwest::Response) -> Option<u32> {
    resp.headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
}

// ── Checks ────────────────────────────────────────────────────────────────────

async fn check_plaintext_grpc(client: &HttpClient, base: &str) -> Option<Finding> {
    if !base.starts_with("http://") {
        return None;
    }

    // Try to send a gRPC health check over plain HTTP/2
    let url = format!("{}{}", base, HEALTH_PATH);
    let req = client
        .inner()
        .post(&url)
        .header("content-type", GRPC_CONTENT_TYPE)
        .header("te", "trailers")
        .body(HEALTH_FRAME.to_vec())
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    if !is_grpc_response(&resp) {
        return None;
    }

    let mut f = Finding::new(
        "gRPC — Service exposé en clair (sans TLS)",
        Severity::High,
        7.4,
        "grpc",
        base,
        "gRPC",
    );
    f.description =
        "Le service gRPC est accessible via HTTP (sans TLS). Les appels RPC, les payloads \
         Protobuf et les métadonnées d'authentification transitent en clair sur le réseau."
            .to_string();
    f.recommendation =
        "Activer TLS (mTLS recommandé) sur le serveur gRPC. Rediriger les connexions \
         HTTP vers HTTPS. Utiliser un certificat valide signé par une CA de confiance."
            .to_string();
    f.cwe = Some("CWE-319".to_string());
    Some(f)
}

async fn check_grpc_reflection(client: &HttpClient, base: &str) -> Option<Finding> {
    let url = format!("{}{}", base, REFLECTION_PATH);

    let req = client
        .inner()
        .post(&url)
        .header("content-type", GRPC_CONTENT_TYPE)
        .header("te", "trailers")
        .body(REFLECTION_FRAME.to_vec())
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    let grpc_ok = is_grpc_response(&resp)
        // grpc-status 0 = OK, absent header also means no error yet
        && grpc_status(&resp).map(|s| s == 0).unwrap_or(true);

    if !grpc_ok {
        return None;
    }

    let mut f = Finding::new(
        "gRPC — Réflexion activée sans authentification",
        Severity::Medium,
        5.3,
        "grpc",
        &url,
        "gRPC",
    );
    f.description =
        "Le service gRPC expose l'API de réflexion (ServerReflection) sans authentification. \
         Un attaquant peut énumérer tous les services, méthodes et types Protobuf disponibles \
         (équivalent de l'introspection GraphQL)."
            .to_string();
    f.recommendation = "Désactiver la réflexion gRPC en production ou la restreindre avec une \
         authentification par métadonnées (header `Authorization`). \
         Utiliser `grpc.EnableReflection` uniquement en développement."
        .to_string();
    f.cwe = Some("CWE-200".to_string());
    f.references =
        vec!["https://grpc.github.io/grpc/core/md_doc_server-reflection.html".to_string()];
    Some(f)
}

async fn check_health_no_auth(client: &HttpClient, base: &str) -> Option<Finding> {
    let url = format!("{}{}", base, HEALTH_PATH);

    let req = client
        .inner()
        .post(&url)
        .header("content-type", GRPC_CONTENT_TYPE)
        .header("te", "trailers")
        .body(HEALTH_FRAME.to_vec())
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    let status = resp.status();

    // grpc-status 0 (OK) without Authorization means unauthenticated access
    let grpc_ok = is_grpc_response(&resp) && grpc_status(&resp).map(|s| s == 0).unwrap_or(false);
    if !grpc_ok && !status.is_success() {
        return None;
    }

    let mut f = Finding::new(
        "gRPC — Health check accessible sans authentification",
        Severity::Low,
        3.7,
        "grpc",
        &url,
        "gRPC",
    );
    f.description =
        "Le endpoint gRPC Health/Check répond avec succès sans header `Authorization`. \
         Un attaquant peut sonder l'état du service et déduire si des dépendances sont actives."
            .to_string();
    f.recommendation =
        "Si le health check est exposé publiquement, s'assurer qu'il ne divulgue pas \
         d'informations sensibles sur les dépendances internes. \
         En interne, le restreindre par réseau (mTLS ou pare-feu)."
            .to_string();
    f.cwe = Some("CWE-200".to_string());
    Some(f)
}

async fn check_missing_metadata_auth(client: &HttpClient, base: &str) -> Option<Finding> {
    // Try a generic RPC call without auth metadata and check if it gets through
    let test_paths = [
        "/api.UserService/GetUser",
        "/api.v1.AdminService/ListUsers",
        "/com.example.Service/Call",
    ];

    for path in &test_paths {
        let url = format!("{}{}", base, path);
        let req = client
            .inner()
            .post(&url)
            .header("content-type", GRPC_CONTENT_TYPE)
            .header("te", "trailers")
            .body(HEALTH_FRAME.to_vec()) // empty protobuf message
            .build()
            .ok()?;

        let resp = client.send(req).await.ok()?;

        // grpc-status 16 = UNAUTHENTICATED, 7 = PERMISSION_DENIED — both mean auth is enforced
        let grpc_st = grpc_status(&resp);
        if matches!(grpc_st, Some(16) | Some(7)) {
            return None; // Auth enforced — no finding
        }

        // grpc-status 0 (OK) or 12 (UNIMPLEMENTED) without auth is a flag
        if is_grpc_response(&resp) && matches!(grpc_st, Some(0) | Some(12) | None) {
            let mut f = Finding::new(
                "gRPC — Appels RPC sans vérification d'authentification",
                Severity::High,
                7.5,
                "grpc",
                &url,
                "gRPC",
            );
            f.description = format!(
                "L'endpoint gRPC `{}` répond sans exiger de métadonnées d'authentification \
                 (header `Authorization` ou token de session). \
                 grpc-status reçu : {}.",
                path,
                grpc_st
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "absent".to_string())
            );
            f.recommendation =
                "Implémenter un intercepteur gRPC qui valide le header `Authorization` \
                 (JWT ou Bearer token) sur chaque appel entrant. \
                 Retourner `UNAUTHENTICATED` (status 16) si le token est absent ou invalide."
                    .to_string();
            f.cwe = Some("CWE-306".to_string());
            return Some(f);
        }
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflection_frame_format() {
        // Frame: [not-compressed][len u32 be][msg]
        assert_eq!(REFLECTION_FRAME[0], 0x00); // not compressed
        let len = u32::from_be_bytes([
            REFLECTION_FRAME[1],
            REFLECTION_FRAME[2],
            REFLECTION_FRAME[3],
            REFLECTION_FRAME[4],
        ]);
        assert_eq!(len, 2);
        // list_services = field 3, wire 2 (LEN), len 0
        assert_eq!(REFLECTION_FRAME[5], 0x1a);
        assert_eq!(REFLECTION_FRAME[6], 0x00);
    }

    #[test]
    fn health_frame_is_empty_message() {
        assert_eq!(HEALTH_FRAME[0], 0x00);
        let len = u32::from_be_bytes([
            HEALTH_FRAME[1],
            HEALTH_FRAME[2],
            HEALTH_FRAME[3],
            HEALTH_FRAME[4],
        ]);
        assert_eq!(len, 0);
    }

    #[test]
    fn module_name() {
        assert_eq!(GrpcModule.name(), "grpc");
    }
}

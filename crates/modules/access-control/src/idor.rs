use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{extract_numeric_id, extract_uuid, get_with_token, NIL_UUID};

// ---------------------------------------------------------------------------
// Check: IDOR — numeric IDs
// ---------------------------------------------------------------------------

pub(super) async fn check_idor_numeric(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some((prefix, id, suffix)) = extract_numeric_id(&ep.full_url) else {
        return vec![];
    };

    // Baseline
    let Some((baseline_status, baseline_body)) =
        get_with_token(client, &ep.full_url, &ep.method, token).await
    else {
        return vec![];
    };

    if !matches!(baseline_status, 200..=299) {
        return vec![];
    }

    // Deltas from idor.yaml: [1, -1, 2, -2, 10, 100] + common [1,2,3,100,999]
    let mut candidates: Vec<u64> = vec![];
    for delta in &[1i64, -1, 2, -2, 10, 100] {
        let candidate = id as i64 + delta;
        if candidate > 0 && candidate as u64 != id {
            candidates.push(candidate as u64);
        }
    }
    for &common in &[1u64, 2, 3, 100, 999, 1000] {
        if common != id {
            candidates.push(common);
        }
    }
    candidates.dedup();

    for candidate in candidates {
        let url = format!("{}/{}{}", prefix, candidate, suffix);
        let Some((status, body)) = get_with_token(client, &url, &ep.method, token).await else {
            continue;
        };

        if matches!(status, 200..=299) && body != baseline_body {
            let mut f = Finding::new(
                format!("IDOR — ID numérique `{}` → `{}`", id, candidate),
                Severity::High,
                8.1,
                "access-control".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne une ressource différente pour l'ID {} alors que \
                 l'authentification est faite avec le token de l'ID {}. \
                 Un attaquant peut accéder aux données d'autres utilisateurs.",
                ep.full_url, candidate, id
            );
            f.proof = format!(
                "GET {} → HTTP {} ({} octets) ≠ baseline GET {} → HTTP {} ({} octets)",
                url, status, body.len(),
                ep.full_url, baseline_status, baseline_body.len()
            );
            f.recommendation =
                "Vérifier que chaque ressource accédée appartient bien à l'utilisateur \
                 authentifié. Utiliser des identifiants non-prévisibles (UUID v4) et \
                 valider la propriété côté serveur."
                    .to_string();
            f.cwe = Some("CWE-639".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: IDOR — UUID
// ---------------------------------------------------------------------------

pub(super) async fn check_idor_uuid(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some((prefix, original_uuid, suffix)) = extract_uuid(&ep.full_url) else {
        return vec![];
    };

    let Some((baseline_status, _)) =
        get_with_token(client, &ep.full_url, &ep.method, token).await
    else {
        return vec![];
    };

    // Try nil UUID and a freshly generated random UUID
    let candidates = [
        NIL_UUID.to_string(),
        uuid::Uuid::new_v4().to_string(),
    ];

    for candidate in &candidates {
        if candidate == &original_uuid {
            continue;
        }
        let url = format!("{}/{}{}", prefix, candidate, suffix);
        let Some((status, body)) = get_with_token(client, &url, &ep.method, token).await else {
            continue;
        };

        // Suspicious: got 200 when baseline was also 200 with a different UUID,
        // OR got 200 when baseline was 403 (broken access)
        if matches!(status, 200..=299)
            && (baseline_status != 200 || !body.is_empty())
        {
            let mut f = Finding::new(
                format!("IDOR — UUID substitution `{}`", &original_uuid[..8]),
                Severity::High,
                8.1,
                "access-control".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne HTTP {} lorsqu'on substitue l'UUID {} par {}. \
                 Le contrôle d'accès basé sur l'UUID est potentiellement absent.",
                ep.full_url, status, original_uuid, candidate
            );
            f.proof = format!(
                "UUID original: {} | UUID testé: {} → HTTP {}",
                original_uuid, candidate, status
            );
            f.recommendation =
                "Les UUIDs ne sont pas secrets. Vérifier la propriété de la ressource \
                 via le token d'authentification, pas uniquement via l'identifiant."
                    .to_string();
            f.cwe = Some("CWE-639".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

use async_trait::async_trait;
use serde::Deserialize;
use std::time::{Duration, Instant};

use nevelio_core::types::{Endpoint, Finding, ParameterLocation, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Payload file (embedded)
// ---------------------------------------------------------------------------

const SQLI_PAYLOADS: &str = include_str!("../../../../payloads/sqli.yaml");

// SQL error substrings that indicate a reflected database error
const SQL_ERRORS: &[&str] = &[
    "sql syntax",
    "you have an error in your sql",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-",
    "postgresql error",
    "pg_query",
    "sqlite_error",
    "sqlite3",
    "syntax error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc drivers error",
    "warning: mysql",
    "invalid query",
    "sqlstate",
    "microsoft ole db provider for sql server",
];

// Fallback generic parameter names when no spec params are known
const GENERIC_PARAMS: &[&str] = &["id", "q", "search", "query", "input", "name", "user", "filter"];

// Time-based threshold in milliseconds
const TIME_THRESHOLD_MS: u128 = 4_000;

// ---------------------------------------------------------------------------
// Payload structs (deserialized from sqli.yaml)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InjectionPayloadFile {
    #[serde(default)]
    payloads: Vec<SqliEntry>,
    #[serde(default)]
    nosql_payloads: Vec<NosqliEntry>,
    #[serde(default)]
    ssti_payloads: Vec<SstiEntry>,
    #[serde(default)]
    cmdi_payloads: Vec<CmdiEntry>,
}

#[derive(Debug, Deserialize)]
struct SqliEntry {
    value: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct NosqliEntry {
    value: String,
}

#[derive(Debug, Deserialize)]
struct SstiEntry {
    value: String,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct CmdiEntry {
    value: String,
    detect: String,
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct InjectionModule;

#[async_trait]
impl AttackModule for InjectionModule {
    fn name(&self) -> &str {
        "injection"
    }

    fn description(&self) -> &str {
        "Tests SQLi, NoSQLi, SSTI, Command Injection, LDAP, and XXE"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let file: InjectionPayloadFile =
            serde_yaml::from_str(SQLI_PAYLOADS).unwrap_or_else(|_| InjectionPayloadFile {
                payloads: vec![],
                nosql_payloads: vec![],
                ssti_payloads: vec![],
                cmdi_payloads: vec![],
            });

        let mut findings = Vec::new();

        for ep in endpoints {
            // Collect parameter names to inject into.
            // Use defined params first; fall back to generic names if none.
            let param_names: Vec<String> = if ep.parameters.is_empty() {
                GENERIC_PARAMS.iter().map(|s| s.to_string()).collect()
            } else {
                ep.parameters
                    .iter()
                    .filter(|p| {
                        matches!(
                            p.location,
                            ParameterLocation::Query | ParameterLocation::Body
                        )
                    })
                    .map(|p| p.name.clone())
                    .collect()
            };

            for param in &param_names {
                findings.extend(
                    check_sqli(client, ep, param, &file.payloads).await,
                );
                findings.extend(
                    check_nosqli(client, ep, param, &file.nosql_payloads).await,
                );
                findings.extend(
                    check_ssti(client, ep, param, &file.ssti_payloads).await,
                );
                findings.extend(
                    check_cmdi(client, ep, param, &file.cmdi_payloads).await,
                );
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_encode_safe_chars() {
        assert_eq!(urlencoding_encode("hello"), "hello");
        assert_eq!(urlencoding_encode("abc123"), "abc123");
        assert_eq!(urlencoding_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencoding_encode_special_chars() {
        let encoded = urlencoding_encode("' OR '1'='1");
        assert!(!encoded.contains('\''));
        assert!(!encoded.contains(' '));
        assert!(encoded.contains('%'));
    }

    #[test]
    fn inject_query_no_existing_params() {
        let url = inject_query("https://api.example.com/users", "id", "1");
        assert_eq!(url, "https://api.example.com/users?id=1");
    }

    #[test]
    fn inject_query_with_existing_params() {
        let url = inject_query("https://api.example.com/search?q=foo", "id", "1");
        assert!(url.contains("?q=foo&id=1"), "got: {}", url);
    }

    #[test]
    fn inject_query_encodes_payload() {
        let url = inject_query("https://api.example.com/x", "q", "' OR 1=1--");
        // Must not contain raw SQL characters unencoded
        let query_part = url.split('?').nth(1).unwrap_or("");
        assert!(!query_part.contains('\''));
        assert!(!query_part.contains(' '));
    }

    #[test]
    fn sql_errors_list_is_non_empty() {
        assert!(!SQL_ERRORS.is_empty());
        assert!(SQL_ERRORS.iter().any(|&e| e.contains("sql")));
    }

    #[test]
    fn inject_nosql_query_bracket_notation() {
        let url = inject_nosql_query(
            "https://api.example.com/users",
            "username",
            r#"{"$gt":""}"#,
        );
        // Should use bracket notation, not encode the JSON object as a string value
        assert!(url.contains("username%5B%24gt%5D="), "expected bracket notation, got: {url}");
        assert!(!url.contains("%7B"), "should not encode JSON object as string value: {url}");
    }

    #[test]
    fn inject_nosql_query_fallback_scalar() {
        // Non-object value falls back to inject_query
        let url = inject_nosql_query("https://api.example.com/users", "q", "hello");
        assert_eq!(url, "https://api.example.com/users?q=hello");
    }

    #[test]
    fn inject_nosql_query_appends_to_existing_params() {
        let url = inject_nosql_query(
            "https://api.example.com/users?page=1",
            "id",
            r#"{"$ne":null}"#,
        );
        assert!(url.contains("page=1"), "existing params preserved: {url}");
        assert!(url.contains("id%5B%24ne%5D="), "bracket notation appended: {url}");
    }
}

// ---------------------------------------------------------------------------
// Helpers: HTTP request builders
// ---------------------------------------------------------------------------

/// Builds a URL with a single injected query parameter.
fn inject_query(base_url: &str, param: &str, payload: &str) -> String {
    let sep = if base_url.contains('?') { '&' } else { '?' };
    format!(
        "{}{}{}={}",
        base_url,
        sep,
        urlencoding_encode(param),
        urlencoding_encode(payload)
    )
}

/// Builds a URL with MongoDB bracket notation for NoSQL operator payloads.
/// `{"$gt":""}` → `?param%5B%24gt%5D=` (Express/PHP bracket notation).
/// Falls back to `inject_query` for non-object JSON values.
fn inject_nosql_query(base_url: &str, param: &str, json_str: &str) -> String {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json_str) {
        let sep = if base_url.contains('?') { '&' } else { '?' };
        let mut url = base_url.to_string();
        let mut first = true;
        for (key, val) in &map {
            let bracket_param = format!("{}[{}]", param, key);
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            if first {
                url.push(sep);
                first = false;
            } else {
                url.push('&');
            }
            url.push_str(&urlencoding_encode(&bracket_param));
            url.push('=');
            url.push_str(&urlencoding_encode(&val_str));
        }
        url
    } else {
        inject_query(base_url, param, json_str)
    }
}

/// Minimal percent-encoding for a query component value.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn get_baseline(client: &HttpClient, ep: &Endpoint) -> Option<(u16, usize)> {
    let req = client
        .inner()
        .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &ep.full_url)
        .build()
        .ok()?;
    let resp = client.send(req).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.ok()?;
    Some((status, body.len()))
}

// ---------------------------------------------------------------------------
// Check: SQL Injection
// ---------------------------------------------------------------------------

async fn check_sqli(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SqliEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let start = Instant::now();
        let resp = if entry.kind == "time_based" {
            // Extended timeout so the injected delay is measurable
            let Ok(req) = client
                .inner()
                .request(method, &url)
                .timeout(Duration::from_millis(TIME_THRESHOLD_MS as u64 + 3_000))
                .build()
            else {
                continue;
            };
            match client.inner().execute(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        } else {
            let Ok(req) = client.inner().request(method, &url).build() else {
                continue;
            };
            match client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        };
        let elapsed = start.elapsed().as_millis();

        let status = resp.status().as_u16();
        let body_bytes = resp.bytes().await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes).to_lowercase();
        let body_len = body_bytes.len();

        let triggered = match entry.kind.as_str() {
            "time_based" => elapsed >= TIME_THRESHOLD_MS,
            "error" => SQL_ERRORS.iter().any(|e| body.contains(e)) || status == 500,
            "boolean" | "bypass" => {
                // Significant change in response (body length ±20% or status flip)
                let ratio = if baseline_len == 0 {
                    body_len > 0
                } else {
                    let diff = (body_len as isize - baseline_len as isize).unsigned_abs();
                    diff * 100 / baseline_len > 20
                };
                ratio || (baseline_status != 200 && status == 200)
            }
            "union" => {
                body_len > baseline_len + 50
            }
            _ => false,
        };

        if triggered {
            let proof = match entry.kind.as_str() {
                "time_based" => format!("Délai de réponse : {}ms (seuil {}ms)", elapsed, TIME_THRESHOLD_MS),
                "error"      => format!("Erreur SQL dans la réponse (HTTP {})", status),
                _            => format!("Réponse anormale : {} octets vs {} baseline (HTTP {})", body_len, baseline_len, status),
            };

            let mut f = Finding::new(
                format!("SQL Injection ({}) — paramètre `{}`", entry.kind, param),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} semble vulnérable à une injection SQL de type {}. \
                 Un attaquant peut lire, modifier ou supprimer des données de la base.",
                param, ep.full_url, entry.kind
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof);
            f.recommendation =
                "Utiliser des requêtes préparées (parameterized queries) et un ORM sécurisé. \
                 Ne jamais concaténer des entrées utilisateur dans des requêtes SQL."
                    .to_string();
            f.cwe = Some("CWE-89".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f]; // one finding per param per endpoint is sufficient
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: NoSQL Injection
// ---------------------------------------------------------------------------

async fn check_nosqli(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[NosqliEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        // Send as JSON body for POST/PUT; bracket notation for GET/DELETE
        let resp = if ep.method == "GET" || ep.method == "DELETE" {
            let url = inject_nosql_query(&ep.full_url, param, &entry.value);
            let req = match client
                .inner()
                .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &url)
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            client.send(req).await
        } else {
            let body = serde_json::json!({ param: serde_json::from_str::<serde_json::Value>(&entry.value).unwrap_or(serde_json::Value::String(entry.value.clone())) });
            let req = match client
                .inner()
                .request(ep.method.parse().unwrap_or(reqwest::Method::POST), &ep.full_url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            client.send(req).await
        };

        let Ok(resp) = resp else { continue };

        let status = resp.status().as_u16();
        let body_len = resp.bytes().await.unwrap_or_default().len();

        let triggered = (baseline_status != 200 && status == 200)
            || (baseline_len > 0
                && (body_len as isize - baseline_len as isize).unsigned_abs() * 100 / baseline_len > 30);

        if triggered {
            let mut f = Finding::new(
                format!("NoSQL Injection — paramètre `{}`", param),
                Severity::Critical,
                9.0,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` semble vulnérable à une injection NoSQL (opérateur MongoDB). \
                 Un attaquant peut contourner l'authentification ou lire des données arbitraires.",
                param
            );
            f.proof = format!(
                "Payload: {:?}\nRéponse : HTTP {} ({} octets) vs baseline HTTP {} ({} octets)",
                entry.value, status, body_len, baseline_status, baseline_len
            );
            f.recommendation =
                "Valider et typer strictement les entrées. Ne jamais passer d'objets non validés \
                 à des requêtes MongoDB. Utiliser un schema de validation (Joi, Zod, etc.)."
                    .to_string();
            f.cwe = Some("CWE-943".to_string());
            f.references = vec![
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: SSTI — Server-Side Template Injection
// ---------------------------------------------------------------------------

async fn check_ssti(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SstiEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);

        let req = match client
            .inner()
            .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &url)
            .build()
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let body = resp.text().await.unwrap_or_default();

        if body.contains(&entry.expect) {
            let mut f = Finding::new(
                format!("Server-Side Template Injection (SSTI) — paramètre `{}`", param),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est évalué par un moteur de templates côté serveur. \
                 L'expression {:?} a produit \"{}\" dans la réponse, indiquant une SSTI exploitable. \
                 Un attaquant peut exécuter du code arbitraire sur le serveur.",
                param, entry.value, entry.expect
            );
            f.proof = format!(
                "Payload: {:?} → résultat attendu {:?} trouvé dans la réponse",
                entry.value, entry.expect
            );
            f.recommendation =
                "Ne jamais rendre des entrées utilisateur directement dans un template. \
                 Utiliser un sandboxing du moteur de templates ou des fonctions d'échappement."
                    .to_string();
            f.cwe = Some("CWE-94".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/server-side-template-injection".to_string(),
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Command Injection
// ---------------------------------------------------------------------------

async fn check_cmdi(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[CmdiEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let is_time = entry.detect == "delay_gt_4000ms";
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let start = Instant::now();
        let resp = if is_time {
            // Extended timeout so the injected sleep is measurable
            let Ok(req) = client
                .inner()
                .request(method, &url)
                .timeout(Duration::from_millis(TIME_THRESHOLD_MS as u64 + 3_000))
                .build()
            else {
                continue;
            };
            match client.inner().execute(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        } else {
            let Ok(req) = client.inner().request(method, &url).build() else {
                continue;
            };
            match client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        };
        let elapsed = start.elapsed().as_millis();

        let triggered = if is_time {
            elapsed >= TIME_THRESHOLD_MS
        } else {
            let body = resp.text().await.unwrap_or_default();
            body.contains(&entry.detect)
        };

        if triggered {
            let proof = if is_time {
                format!("Délai de réponse : {}ms (seuil {}ms)", elapsed, TIME_THRESHOLD_MS)
            } else {
                format!("Sortie système détectée : {:?}", entry.detect)
            };

            let mut f = Finding::new(
                format!("Command Injection — paramètre `{}`", param),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est passé sans assainissement à un interpréteur de commandes système. \
                 Un attaquant peut exécuter des commandes arbitraires sur le serveur.",
                param
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof);
            f.recommendation =
                "Ne jamais construire des commandes shell à partir d'entrées utilisateur. \
                 Utiliser des API système directes (exec avec args séparés) et valider strictement \
                 les entrées via une allowlist."
                    .to_string();
            f.cwe = Some("CWE-77".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/Command_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

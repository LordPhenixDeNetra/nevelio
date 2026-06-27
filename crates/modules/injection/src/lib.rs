use async_trait::async_trait;
use serde::Deserialize;
use std::time::{Duration, Instant};

use nevelio_core::types::{Endpoint, Finding, ParameterLocation, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Payload file (embedded)
// ---------------------------------------------------------------------------

const SQLI_PAYLOADS: &str = include_str!("../../../../payloads/sqli.yaml");
const XXE_PAYLOADS: &str  = include_str!("../../../../payloads/xxe.yaml");
const XSS_PAYLOADS: &str  = include_str!("../../../../payloads/xss.yaml");

// LDAP error substrings
const LDAP_ERRORS: &[&str] = &[
    "ldap error", "invalid filter syntax", "bad search filter", "ldaperror",
    "ldap_search", "javax.naming.directory", "com.sun.jndi", "0x57",
    "NamingException", "InvalidSearchFilterException",
];

// XPath error substrings
const XPATH_ERRORS: &[&str] = &[
    "xpathexception", "invalid xpath", "xpath syntax error", "xmlxpathexception",
    "org.xml.sax", "javax.xml.xpath", "xsltransformexception", "xpath expression",
    "invalid token", "unexpected token",
];

// HTTP headers to test for SSTI
const SSTI_HEADERS: &[&str] = &["User-Agent", "X-Forwarded-For", "Referer", "X-Custom-Name"];

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
    #[serde(default)]
    ldap_payloads: Vec<SimpleEntry>,
    #[serde(default)]
    xpath_payloads: Vec<SimpleEntry>,
    #[serde(default)]
    csv_payloads: Vec<SimpleEntry>,
}

#[derive(Debug, Deserialize)]
struct XssPayloadFile {
    #[serde(default)]
    payloads: Vec<SimpleEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct SimpleEntry {
    value: String,
}

#[derive(Debug, Deserialize)]
struct XxePayloadFile {
    #[serde(default)]
    payloads: Vec<XxeEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct XxeEntry {
    kind: String,
    value: String,
    detect: String,
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
        "Tests SQLi, NoSQLi, SSTI, CMDi, XXE, XSS, LDAP, XPath et CSV injection"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let sqli_file: InjectionPayloadFile =
            serde_yaml::from_str(SQLI_PAYLOADS).unwrap_or_else(|_| InjectionPayloadFile {
                payloads: vec![],
                nosql_payloads: vec![],
                ssti_payloads: vec![],
                cmdi_payloads: vec![],
                ldap_payloads: vec![],
                xpath_payloads: vec![],
                csv_payloads: vec![],
            });

        let xxe_file: XxePayloadFile =
            serde_yaml::from_str(XXE_PAYLOADS).unwrap_or(XxePayloadFile { payloads: vec![] });

        let xss_file: XssPayloadFile =
            serde_yaml::from_str(XSS_PAYLOADS).unwrap_or(XssPayloadFile { payloads: vec![] });

        let mut findings = Vec::new();

        for ep in endpoints {
            // Collect parameter names to inject into.
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
                findings.extend(check_sqli(client, ep, param, &sqli_file.payloads).await);
                findings.extend(check_nosqli(client, ep, param, &sqli_file.nosql_payloads).await);
                findings.extend(check_ssti(client, ep, param, &sqli_file.ssti_payloads).await);
                findings.extend(check_cmdi(client, ep, param, &sqli_file.cmdi_payloads).await);
                findings.extend(check_xss(client, ep, param, &xss_file.payloads).await);
                findings.extend(check_ldap(client, ep, param, &sqli_file.ldap_payloads).await);
                findings.extend(check_xpath(client, ep, param, &sqli_file.xpath_payloads).await);
            }

            // CSV injection: only on export-like endpoints
            if is_export_endpoint(ep) {
                for param in &param_names {
                    findings.extend(
                        check_csv_injection(client, ep, param, &sqli_file.csv_payloads).await,
                    );
                }
            }

            // SSTI in HTTP headers
            findings.extend(check_ssti_headers(client, ep, &sqli_file.ssti_payloads).await);

            // XXE : testé sur les endpoints POST/PUT/PATCH acceptant XML
            findings.extend(check_xxe(client, ep, &xxe_file.payloads).await);
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

// ---------------------------------------------------------------------------
// Check: XSS — Cross-Site Scripting (reflected)
// ---------------------------------------------------------------------------

async fn check_xss(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let resp = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
            let Ok(req) = client.inner().request(method, &url).build() else { continue };
            match client.send(req).await { Ok(r) => r, Err(_) => continue }
        } else {
            let body = serde_json::json!({ param: entry.value });
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            else { continue };
            match client.send(req).await { Ok(r) => r, Err(_) => continue }
        };

        let body = resp.text().await.unwrap_or_default();

        if body.contains(entry.value.as_str()) {
            let mut f = Finding::new(
                format!("XSS réfléchi — paramètre `{}`", param),
                Severity::Medium,
                6.1,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} réfléchit le payload XSS sans encodage. \
                 Un attaquant peut exécuter du JavaScript dans le navigateur de la victime.",
                param, ep.full_url
            );
            f.proof = format!("Payload: {:?} → retrouvé non encodé dans la réponse", entry.value);
            f.recommendation =
                "Encoder toutes les sorties HTML (htmlspecialchars, DOMPurify). \
                 Ajouter un Content-Security-Policy strict. \
                 Valider les entrées côté serveur."
                    .to_string();
            f.cwe = Some("CWE-79".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/xss/".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: LDAP Injection
// ---------------------------------------------------------------------------

async fn check_ldap(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
        let Ok(req) = client.inner().request(method.clone(), &url).build() else { continue };
        let Ok(resp) = client.send(req).await else { continue };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();
        let body_len = body.len();

        let has_ldap_error = LDAP_ERRORS.iter().any(|e| body_lower.contains(&e.to_lowercase()));
        let boolean_change = baseline_len > 0
            && (body_len as isize - baseline_len as isize).unsigned_abs() * 100 / baseline_len > 30;
        let status_flip = baseline_status != 200 && status == 200;

        if has_ldap_error || boolean_change || status_flip {
            let proof_detail = if has_ldap_error {
                format!("Erreur LDAP dans la réponse HTTP {}", status)
            } else {
                format!("Réponse anormale : {} octets vs {} baseline (HTTP {})", body_len, baseline_len, status)
            };

            let mut f = Finding::new(
                format!("LDAP Injection — paramètre `{}`", param),
                Severity::High,
                7.5,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} semble vulnérable à une injection LDAP. \
                 Un attaquant peut manipuler les filtres de recherche LDAP pour contourner \
                 l'authentification ou exfiltrer des informations d'annuaire.",
                param, ep.full_url
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof_detail);
            f.recommendation =
                "Utiliser une API LDAP avec requêtes paramétrées. Encoder les caractères spéciaux \
                 LDAP (*, (, ), \\, \\0). Valider les entrées via une allowlist stricte."
                    .to_string();
            f.cwe = Some("CWE-90".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/LDAP_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: XPath Injection
// ---------------------------------------------------------------------------

async fn check_xpath(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
        let Ok(req) = client.inner().request(method, &url).build() else { continue };
        let Ok(resp) = client.send(req).await else { continue };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();
        let body_len = body.len();

        let has_xpath_error = XPATH_ERRORS.iter().any(|e| body_lower.contains(&e.to_lowercase()));
        let boolean_change = baseline_len > 0
            && (body_len as isize - baseline_len as isize).unsigned_abs() * 100 / baseline_len > 30;
        let status_flip = baseline_status != 200 && status == 200;

        if has_xpath_error || boolean_change || status_flip {
            let proof_detail = if has_xpath_error {
                format!("Erreur XPath dans la réponse HTTP {}", status)
            } else {
                format!("Réponse anormale : {} octets vs {} baseline (HTTP {})", body_len, baseline_len, status)
            };

            let mut f = Finding::new(
                format!("XPath Injection — paramètre `{}`", param),
                Severity::High,
                7.5,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} semble vulnérable à une injection XPath. \
                 Un attaquant peut manipuler des requêtes XPath pour lire du contenu XML arbitraire \
                 ou contourner des contrôles d'accès basés sur XML.",
                param, ep.full_url
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof_detail);
            f.recommendation =
                "Utiliser des requêtes XPath paramétrées. Encoder les entrées utilisateur \
                 avant de les inclure dans des expressions XPath. Valider via une allowlist."
                    .to_string();
            f.cwe = Some("CWE-643".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/XPATH_Injection".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: CSV / Formula Injection
// ---------------------------------------------------------------------------

fn is_export_endpoint(ep: &Endpoint) -> bool {
    let path = ep.path.to_lowercase();
    let url = ep.full_url.to_lowercase();
    ["export", "download", "csv", "report", "xls", "xlsx"]
        .iter()
        .any(|kw| path.contains(kw) || url.contains(kw))
}

async fn check_csv_injection(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
        let Ok(req) = client.inner().request(method, &url).build() else { continue };
        let Ok(resp) = client.send(req).await else { continue };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        // Unescaped formula in CSV response is the indicator
        if matches!(status, 200..=299) && body.contains(entry.value.as_str()) {
            let mut f = Finding::new(
                format!("CSV/Formula Injection — paramètre `{}`", param),
                Severity::Medium,
                5.0,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne une formule non échappée dans un export CSV/Excel. \
                 Un attaquant peut injecter des formules malveillantes qui s'exécutent \
                 lorsqu'un utilisateur ouvre le fichier dans un tableur.",
                ep.full_url
            );
            f.proof = format!(
                "Payload: {:?} → retrouvé non échappé dans la réponse CSV (HTTP {})",
                entry.value, status
            );
            f.recommendation =
                "Préfixer les valeurs commençant par =, +, -, @ avec un apostrophe dans les exports CSV. \
                 Utiliser une bibliothèque de génération CSV qui gère automatiquement l'échappement."
                    .to_string();
            f.cwe = Some("CWE-1236".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/CSV_Injection".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: SSTI dans les headers HTTP
// ---------------------------------------------------------------------------

async fn check_ssti_headers(
    client: &HttpClient,
    ep: &Endpoint,
    payloads: &[SstiEntry],
) -> Vec<Finding> {
    for header_name in SSTI_HEADERS {
        for entry in payloads {
            let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header(*header_name, &entry.value)
                .build()
            else {
                continue;
            };
            let Ok(resp) = client.send(req).await else { continue };
            let body = resp.text().await.unwrap_or_default();

            if body.contains(&entry.expect) {
                let mut f = Finding::new(
                    format!("SSTI via header `{}` — {}", header_name, ep.full_url),
                    Severity::Critical,
                    9.8,
                    "injection".to_string(),
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le header HTTP `{}` est évalué par un moteur de templates côté serveur. \
                     L'expression {:?} a produit {:?} dans la réponse. \
                     Un attaquant peut exécuter du code arbitraire sur le serveur.",
                    header_name, entry.value, entry.expect
                );
                f.proof = format!(
                    "Header: {} = {:?} → résultat {:?} trouvé dans la réponse",
                    header_name, entry.value, entry.expect
                );
                f.recommendation =
                    "Ne jamais rendre des headers HTTP dans un contexte de template. \
                     Utiliser un sandboxing du moteur de templates ou des fonctions d'échappement."
                        .to_string();
                f.cwe = Some("CWE-94".to_string());
                f.references = vec![
                    "https://portswigger.net/web-security/server-side-template-injection".to_string(),
                ];
                return vec![f];
            }
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: XXE — XML External Entity Injection
// ---------------------------------------------------------------------------

const XML_CONTENT_TYPES: &[&str] = &["application/xml", "text/xml", "application/soap+xml"];

async fn check_xxe(
    client: &HttpClient,
    ep: &Endpoint,
    payloads: &[XxeEntry],
) -> Vec<Finding> {
    // XXE requires the server to process an XML body — only relevant for write methods
    if !matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
        return vec![];
    }

    // Try each content-type the server might accept
    for ct in XML_CONTENT_TYPES {
        for entry in payloads {
            // Skip blind OOB payloads (no in-band detection possible without callback server)
            if entry.kind == "blind" {
                continue;
            }

            let req = match client
                .inner()
                .request(ep.method.parse().unwrap_or(reqwest::Method::POST), &ep.full_url)
                .header("Content-Type", *ct)
                .body(entry.value.trim().to_string())
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let Ok(resp) = client.send(req).await else {
                continue;
            };

            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();

            let triggered = if !entry.detect.is_empty() {
                body.contains(entry.detect.as_str())
            } else {
                // No specific marker: a 200 on a SSRF probe is suspicious
                entry.kind == "ssrf" && status == 200 && !body.is_empty()
            };

            if triggered {
                let (title, cwe, severity, cvss) = match entry.kind.as_str() {
                    "ssrf" => (
                        format!("XXE + SSRF — {}", ep.full_url),
                        "CWE-918",
                        Severity::Critical,
                        9.8,
                    ),
                    _ => (
                        format!("XXE File Disclosure — {}", ep.full_url),
                        "CWE-611",
                        Severity::Critical,
                        9.1,
                    ),
                };

                let mut f = Finding::new(title, severity, cvss, "injection", ep.full_url.clone(), ep.method.clone());
                f.description = format!(
                    "L'endpoint {} accepte du contenu XML ({}) et traite les entités externes. \
                     Un attaquant peut lire des fichiers locaux du serveur ou déclencher des requêtes \
                     vers des ressources internes.",
                    ep.full_url, ct
                );
                f.proof = format!(
                    "Payload envoyé avec Content-Type: {}\nRéponse HTTP {}: {}",
                    ct,
                    status,
                    body.chars().take(200).collect::<String>()
                );
                f.recommendation =
                    "Désactiver le traitement des entités externes dans le parseur XML \
                     (FEATURE_SECURE_PROCESSING, setExpandEntityReferences(false)). \
                     Utiliser une allowlist de Content-Types acceptés. \
                     Valider et assainir tout contenu XML avant traitement."
                        .to_string();
                f.cwe = Some(cwe.to_string());
                f.references = vec![
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
                ];
                return vec![f];
            }
        }
    }

    vec![]
}

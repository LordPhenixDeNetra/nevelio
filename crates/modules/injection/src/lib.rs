use async_trait::async_trait;
use serde::Deserialize;

use nevelio_core::types::{Endpoint, Finding, ParameterLocation};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

mod cmdi;
mod csv;
mod ldap;
mod nosqli;
mod sqli;
mod ssti;
mod xss;
mod xpath;
mod xxe;

// ---------------------------------------------------------------------------
// Payload file (embedded)
// ---------------------------------------------------------------------------

const SQLI_PAYLOADS: &str = include_str!("../../../../payloads/sqli.yaml");
const XXE_PAYLOADS: &str  = include_str!("../../../../payloads/xxe.yaml");
const XSS_PAYLOADS: &str  = include_str!("../../../../payloads/xss.yaml");

// LDAP error substrings
pub(crate) const LDAP_ERRORS: &[&str] = &[
    "ldap error", "invalid filter syntax", "bad search filter", "ldaperror",
    "ldap_search", "javax.naming.directory", "com.sun.jndi", "0x57",
    "NamingException", "InvalidSearchFilterException",
];

// XPath error substrings
pub(crate) const XPATH_ERRORS: &[&str] = &[
    "xpathexception", "invalid xpath", "xpath syntax error", "xmlxpathexception",
    "org.xml.sax", "javax.xml.xpath", "xsltransformexception", "xpath expression",
    "invalid token", "unexpected token",
];

// HTTP headers to test for SSTI
pub(crate) const SSTI_HEADERS: &[&str] = &["User-Agent", "X-Forwarded-For", "Referer", "X-Custom-Name"];

// SQL error substrings that indicate a reflected database error
pub(crate) const SQL_ERRORS: &[&str] = &[
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
pub(crate) const TIME_THRESHOLD_MS: u128 = 4_000;

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
pub(crate) struct SimpleEntry {
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
struct XxePayloadFile {
    #[serde(default)]
    payloads: Vec<XxeEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct XxeEntry {
    pub(crate) kind: String,
    pub(crate) value: String,
    pub(crate) detect: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SqliEntry {
    pub(crate) value: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NosqliEntry {
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SstiEntry {
    pub(crate) value: String,
    pub(crate) expect: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CmdiEntry {
    pub(crate) value: String,
    pub(crate) detect: String,
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
                findings.extend(sqli::check_sqli(client, ep, param, &sqli_file.payloads).await);
                findings.extend(nosqli::check_nosqli(client, ep, param, &sqli_file.nosql_payloads).await);
                findings.extend(ssti::check_ssti(client, ep, param, &sqli_file.ssti_payloads).await);
                findings.extend(cmdi::check_cmdi(client, ep, param, &sqli_file.cmdi_payloads).await);
                findings.extend(xss::check_xss(client, ep, param, &xss_file.payloads).await);
                findings.extend(ldap::check_ldap(client, ep, param, &sqli_file.ldap_payloads).await);
                findings.extend(xpath::check_xpath(client, ep, param, &sqli_file.xpath_payloads).await);
            }

            // CSV injection: only on export-like endpoints
            if csv::is_export_endpoint(ep) {
                for param in &param_names {
                    findings.extend(
                        csv::check_csv_injection(client, ep, param, &sqli_file.csv_payloads).await,
                    );
                }
            }

            // SSTI in HTTP headers
            findings.extend(ssti::check_ssti_headers(client, ep, &sqli_file.ssti_payloads).await);

            // XXE : testé sur les endpoints POST/PUT/PATCH acceptant XML
            findings.extend(xxe::check_xxe(client, ep, &xxe_file.payloads).await);

            // XXE via SVG upload (image/svg+xml)
            findings.extend(xxe::check_xxe_svg(client, ep).await);
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers: HTTP request builders
// ---------------------------------------------------------------------------

/// Builds a URL with a single injected query parameter.
pub(crate) fn inject_query(base_url: &str, param: &str, payload: &str) -> String {
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
pub(crate) fn inject_nosql_query(base_url: &str, param: &str, json_str: &str) -> String {
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
pub(crate) fn urlencoding_encode(s: &str) -> String {
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

pub(crate) async fn get_baseline(client: &HttpClient, ep: &Endpoint) -> Option<(u16, usize)> {
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
// Tests
// ---------------------------------------------------------------------------

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

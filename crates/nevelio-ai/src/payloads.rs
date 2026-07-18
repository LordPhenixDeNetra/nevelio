use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::provider::{AiProvider, CompletionOpts, Message};

// ── Context (F.11) ────────────────────────────────────────────────────────────

/// Context about the target endpoint used to generate relevant payloads.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadContext {
    /// Technology stack detected (e.g. "Express.js", "Spring Boot", "Django")
    pub framework: Option<String>,
    /// WAF/protection detected (e.g. "Cloudflare", "ModSecurity", "none")
    pub waf: Option<String>,
    /// Parameter or field to inject into (e.g. "username", "query", "id")
    pub field: Option<String>,
    /// How the field appears in the request (e.g. "JSON body", "query string", "header")
    pub field_type: Option<String>,
    /// Target endpoint path
    pub endpoint: String,
    /// HTTP method
    pub method: String,
}

// ── Vulnerability types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnType {
    SqlInjection,
    NoSqlInjection,
    Xss,
    Ssrf,
    Ssti,
    PathTraversal,
    CommandInjection,
    LdapInjection,
    XxeInjection,
    OpenRedirect,
}

impl VulnType {
    pub fn label(self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL Injection",
            Self::NoSqlInjection => "NoSQL Injection",
            Self::Xss => "Cross-Site Scripting (XSS)",
            Self::Ssrf => "Server-Side Request Forgery (SSRF)",
            Self::Ssti => "Server-Side Template Injection (SSTI)",
            Self::PathTraversal => "Path Traversal",
            Self::CommandInjection => "Command Injection",
            Self::LdapInjection => "LDAP Injection",
            Self::XxeInjection => "XXE Injection",
            Self::OpenRedirect => "Open Redirect",
        }
    }
}

// ── Output (F.11) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPayload {
    /// The payload string itself
    pub value: String,
    /// Brief note on what this payload tests
    pub description: String,
    /// Expected indicator of success (e.g. "SQL error in response", "DNS callback")
    pub indicator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSet {
    pub vuln_type: String,
    pub endpoint: String,
    pub payloads: Vec<GeneratedPayload>,
}

// ── F.11 — generate() ─────────────────────────────────────────────────────────

/// Generate contextually adapted attack payloads via the LLM.
///
/// Returns a `PayloadSet` with validated, deduplicated payloads ready for use.
pub async fn generate(
    context: &PayloadContext,
    vuln_type: VulnType,
    lang: &str,
    provider: &dyn AiProvider,
    opts: &CompletionOpts,
) -> Result<PayloadSet> {
    let system = match lang {
        "en" => "You are a penetration testing payload specialist. Generate precise, context-adapted attack payloads.",
        "es" => "Eres un especialista en payloads de pruebas de penetración. Genera payloads adaptativos y precisos.",
        _    => "Tu es un spécialiste des payloads de pentesting. Génère des payloads précis et adaptés au contexte.",
    };

    let ctx_desc = format!(
        "Endpoint: {} {}\nFramework: {}\nWAF: {}\nField: {} ({})",
        context.method,
        context.endpoint,
        context.framework.as_deref().unwrap_or("unknown"),
        context.waf.as_deref().unwrap_or("none"),
        context.field.as_deref().unwrap_or("generic"),
        context.field_type.as_deref().unwrap_or("unknown"),
    );

    let user_content = match lang {
        "en" => format!(
            r#"Generate 8-12 {vuln} payloads for:
{ctx}

Return JSON:
{{"payloads": [{{"value": "...", "description": "...", "indicator": "..."}}]}}

Rules:
- Payloads MUST be context-aware (WAF evasion if WAF detected, framework-specific syntax)
- Each payload must be different — no duplicates
- Max 500 chars per payload
- Realistic: no lorem ipsum or placeholder content"#,
            vuln = vuln_type.label(),
            ctx = ctx_desc
        ),
        "es" => format!(
            r#"Genera 8-12 payloads de {vuln} para:
{ctx}

Devuelve JSON:
{{"payloads": [{{"value": "...", "description": "...", "indicator": "..."}}]}}

Reglas:
- Payloads DEBEN ser específicos al contexto (evasión WAF si hay WAF, sintaxis del framework)
- Sin duplicados — cada payload diferente
- Máx 500 caracteres por payload"#,
            vuln = vuln_type.label(),
            ctx = ctx_desc
        ),
        _ => format!(
            r#"Génère 8-12 payloads de {vuln} pour :
{ctx}

Retourne du JSON :
{{"payloads": [{{"value": "...", "description": "...", "indicator": "..."}}]}}

Règles :
- Les payloads DOIVENT être adaptés au contexte (évasion WAF si WAF détecté, syntaxe du framework)
- Pas de doublons — chaque payload différent
- Max 500 caractères par payload"#,
            vuln = vuln_type.label(),
            ctx = ctx_desc
        ),
    };

    let messages = vec![Message::system(system), Message::user(user_content)];

    let schema = json!({
        "type": "object",
        "properties": {
            "payloads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "value":       {"type": "string"},
                        "description": {"type": "string"},
                        "indicator":   {"type": "string"}
                    },
                    "required": ["value", "description", "indicator"]
                }
            }
        },
        "required": ["payloads"]
    });

    let raw = provider.complete_json(&messages, schema, opts).await?;

    let items = raw["payloads"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("payload response missing 'payloads' array"))?;

    let raw_payloads: Vec<GeneratedPayload> = items
        .iter()
        .filter_map(|item| {
            let value = item["value"].as_str()?;
            Some(GeneratedPayload {
                value: value.to_string(),
                description: item["description"].as_str().unwrap_or("").to_string(),
                indicator: item["indicator"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    // F.13 — validate generated payloads
    let payloads = validate_payloads(raw_payloads);

    Ok(PayloadSet {
        vuln_type: vuln_type.label().to_string(),
        endpoint: context.endpoint.clone(),
        payloads,
    })
}

// ── F.13 — Validation ─────────────────────────────────────────────────────────

/// Validate and clean generated payloads.
///
/// Rejects obvious hallucinations: empty strings, excessive length, placeholder
/// text patterns. Deduplicates by exact value match.
fn validate_payloads(raw: Vec<GeneratedPayload>) -> Vec<GeneratedPayload> {
    const MAX_LEN: usize = 500;

    // Placeholder patterns that suggest hallucinations
    const BAD_PATTERNS: &[&str] = &[
        "lorem ipsum",
        "<insert",
        "{{", // unresolved template variables
        "your_",
        "example_payload",
    ];

    let mut seen = std::collections::HashSet::new();
    let mut valid = Vec::new();

    for p in raw {
        // Reject empty or oversized payloads
        if p.value.trim().is_empty() || p.value.len() > MAX_LEN {
            continue;
        }

        // Reject placeholder patterns
        let lower = p.value.to_lowercase();
        if BAD_PATTERNS.iter().any(|pat| lower.contains(pat)) {
            tracing::debug!("Payload rejeté (hallucination probable): {:?}", p.value);
            continue;
        }

        // Deduplicate
        if !seen.insert(p.value.clone()) {
            continue;
        }

        valid.push(p);
    }

    valid
}

// ── F.12 — merge_with_static() ────────────────────────────────────────────────

/// Merge LLM-generated payloads with an existing static list, deduplicating.
///
/// Static payloads have priority (LLM ones are appended after).
pub fn merge_with_static(static_payloads: Vec<String>, generated: &PayloadSet) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = static_payloads.iter().cloned().collect();
    let mut merged = static_payloads;

    for p in &generated.payloads {
        if seen.insert(p.value.clone()) {
            merged.push(p.value.clone());
        }
    }

    merged
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty() {
        let raw = vec![
            GeneratedPayload {
                value: "".to_string(),
                description: "".to_string(),
                indicator: "".to_string(),
            },
            GeneratedPayload {
                value: " ".to_string(),
                description: "".to_string(),
                indicator: "".to_string(),
            },
            GeneratedPayload {
                value: "' OR 1=1--".to_string(),
                description: "Classic SQLi".to_string(),
                indicator: "SQL error".to_string(),
            },
        ];
        let valid = validate_payloads(raw);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].value, "' OR 1=1--");
    }

    #[test]
    fn validate_rejects_oversized() {
        let raw = vec![
            GeneratedPayload {
                value: "A".repeat(501),
                description: "too long".to_string(),
                indicator: "".to_string(),
            },
            GeneratedPayload {
                value: "' OR 1=1--".to_string(),
                description: "ok".to_string(),
                indicator: "error".to_string(),
            },
        ];
        let valid = validate_payloads(raw);
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn validate_deduplicates() {
        let raw = vec![
            GeneratedPayload {
                value: "payload".to_string(),
                description: "a".to_string(),
                indicator: "b".to_string(),
            },
            GeneratedPayload {
                value: "payload".to_string(),
                description: "c".to_string(),
                indicator: "d".to_string(),
            },
        ];
        let valid = validate_payloads(raw);
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn merge_deduplicates_with_static() {
        let static_list = vec!["' OR 1=1--".to_string(), "admin' --".to_string()];
        let generated = PayloadSet {
            vuln_type: "SQLi".to_string(),
            endpoint: "/api/login".to_string(),
            payloads: vec![
                GeneratedPayload {
                    value: "' OR 1=1--".to_string(),
                    description: "dup".to_string(),
                    indicator: "".to_string(),
                },
                GeneratedPayload {
                    value: "1' AND SLEEP(5)--".to_string(),
                    description: "time-based".to_string(),
                    indicator: "delay".to_string(),
                },
            ],
        };
        let merged = merge_with_static(static_list, &generated);
        assert_eq!(merged.len(), 3); // no duplicate
        assert_eq!(merged[2], "1' AND SLEEP(5)--");
    }
}

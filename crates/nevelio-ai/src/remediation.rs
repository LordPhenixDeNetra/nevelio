use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::provider::{AiProvider, CompletionOpts, Message};
use crate::triage::FindingContext;

// ── Output ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Immediate,
    ShortTerm,
    LongTerm,
}

impl Priority {
    pub fn label(&self, lang: &str) -> &'static str {
        match (self, lang) {
            (Self::Immediate, "en") => "Immediate",
            (Self::ShortTerm, "en") => "Short term",
            (Self::LongTerm, "en") => "Long term",
            (Self::Immediate, "es") => "Inmediata",
            (Self::ShortTerm, "es") => "Corto plazo",
            (Self::LongTerm, "es") => "Largo plazo",
            (Self::Immediate, _) => "Immédiate",
            (Self::ShortTerm, _) => "Court terme",
            (Self::LongTerm, _) => "Long terme",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub id: String,
    pub explanation: String,
    pub steps: Vec<String>,
    pub priority: Priority,
    pub code_example: Option<String>,
}

// ── Internal JSON shape from LLM ──────────────────────────────────────────────

#[derive(Deserialize)]
struct LlmWrapper {
    findings: Vec<LlmRemediation>,
}

#[derive(Deserialize)]
struct LlmRemediation {
    id: String,
    explanation: String,
    steps: Vec<String>,
    priority: String,
    code_example: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate remediation suggestions for all findings in a single batch call.
pub async fn suggest(
    findings: &[FindingContext],
    lang: &str,
    provider: &dyn AiProvider,
    opts: &CompletionOpts,
) -> Result<Vec<RemediationResult>> {
    if findings.is_empty() {
        return Ok(vec![]);
    }

    let lang_instruction = match lang {
        "en" => "Respond in English.",
        "es" => "Responde en español.",
        _ => "Réponds en français.",
    };

    let finding_list: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id":          f.id,
                "title":       f.title,
                "severity":    f.severity,
                "description": f.description,
                "endpoint":    f.endpoint,
                "method":      f.method,
            })
        })
        .collect();

    let system = match lang {
        "en" => "You are a security architect. Provide actionable, developer-friendly remediation guidance.",
        "es" => "Eres un arquitecto de seguridad. Proporciona orientación de remediación práctica y orientada al desarrollador.",
        _    => "Tu es un architecte sécurité. Fournis des recommandations de remédiation concrètes et adaptées aux développeurs.",
    };

    let user_content = format!(
        r#"{lang_instruction}

For each security finding, provide remediation guidance.

Findings:
{findings_json}

Respond with this exact JSON (nothing else):
{{"findings": [{{"id": "...", "explanation": "1-2 sentence risk explanation", "steps": ["step 1", "step 2"], "priority": "immediate|short_term|long_term", "code_example": "optional code snippet or null"}}]}}"#,
        lang_instruction = lang_instruction,
        findings_json = serde_json::to_string_pretty(&finding_list)?,
    );

    let messages = vec![Message::system(system), Message::user(user_content)];

    let schema = json!({
        "type": "object",
        "required": ["findings"],
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "explanation", "steps", "priority"],
                    "properties": {
                        "id":           {"type": "string"},
                        "explanation":  {"type": "string"},
                        "steps":        {"type": "array", "items": {"type": "string"}},
                        "priority":     {"type": "string", "enum": ["immediate", "short_term", "long_term"]},
                        "code_example": {"type": ["string", "null"]}
                    }
                }
            }
        }
    });

    let raw: Value = provider.complete_json(&messages, schema, opts).await?;

    let wrapper: LlmWrapper = serde_json::from_value(raw)
        .map_err(|e| anyhow::anyhow!("Parsing réponse remédiation : {}", e))?;

    let results = wrapper
        .findings
        .into_iter()
        .map(|r| {
            let priority = match r.priority.as_str() {
                "immediate" => Priority::Immediate,
                "short_term" => Priority::ShortTerm,
                _ => Priority::LongTerm,
            };
            RemediationResult {
                id: r.id,
                explanation: r.explanation,
                steps: r.steps,
                priority,
                code_example: r.code_example,
            }
        })
        .collect();

    Ok(results)
}

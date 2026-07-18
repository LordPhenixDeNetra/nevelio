use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::provider::{AiProvider, CompletionOpts, Message};

// ── Input ─────────────────────────────────────────────────────────────────────

/// Provider-agnostic view of a finding passed to the triage model.
#[derive(Debug, Clone, Serialize)]
pub struct FindingContext {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub module: String,
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub recommendation: String,
    pub proof: String,
}

// ── Output ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    TruePositive,
    FalsePositive,
    Uncertain,
}

impl Verdict {
    pub fn label(&self, lang: &str) -> &'static str {
        match (self, lang) {
            (Self::TruePositive, "en") => "True positive",
            (Self::FalsePositive, "en") => "False positive",
            (Self::Uncertain, "en") => "Uncertain",
            (Self::TruePositive, "es") => "Verdadero positivo",
            (Self::FalsePositive, "es") => "Falso positivo",
            (Self::Uncertain, "es") => "Incierto",
            (Self::TruePositive, _) => "Vrai positif",
            (Self::FalsePositive, _) => "Faux positif",
            (Self::Uncertain, _) => "Incertain",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub id: String,
    pub verdict: Verdict,
    /// 0–100 confidence percentage
    pub confidence: u8,
    pub reason: String,
}

// ── Internal JSON shape from LLM ──────────────────────────────────────────────

#[derive(Deserialize)]
struct LlmWrapper {
    findings: Vec<LlmTriage>,
}

#[derive(Deserialize)]
struct LlmTriage {
    id: String,
    verdict: String,
    confidence: u8,
    reason: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Send all findings in a single batch call and return one `TriageResult` per finding.
/// Findings with no matching result are marked as `Uncertain` with confidence 0.
pub async fn classify_findings(
    findings: &[FindingContext],
    lang: &str,
    provider: &dyn AiProvider,
    opts: &CompletionOpts,
) -> Result<Vec<TriageResult>> {
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
                "id":             f.id,
                "title":          f.title,
                "severity":       f.severity,
                "module":         f.module,
                "endpoint":       f.endpoint,
                "method":         f.method,
                "description":    f.description,
                "recommendation": f.recommendation,
                "proof":          f.proof,
            })
        })
        .collect();

    let system = match lang {
        "en" => "You are a senior penetration tester specializing in API security. Analyze findings and determine which are genuine vulnerabilities.",
        "es" => "Eres un experto en pentesting de APIs. Analiza los hallazgos y determina cuáles son vulnerabilidades reales.",
        _    => "Tu es un expert en pentest d'API. Analyse les findings et détermine lesquels sont de vraies vulnérabilités.",
    };

    let user_content = format!(
        r#"{lang_instruction}

Classify each security finding as: true_positive, false_positive, or uncertain.

Findings:
{findings_json}

Respond with this exact JSON format (nothing else):
{{"findings": [{{"id": "...", "verdict": "true_positive|false_positive|uncertain", "confidence": 0-100, "reason": "..."}}]}}"#,
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
                    "required": ["id", "verdict", "confidence", "reason"],
                    "properties": {
                        "id":         {"type": "string"},
                        "verdict":    {"type": "string", "enum": ["true_positive", "false_positive", "uncertain"]},
                        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                        "reason":     {"type": "string"}
                    }
                }
            }
        }
    });

    let raw: Value = provider.complete_json(&messages, schema, opts).await?;

    let wrapper: LlmWrapper = serde_json::from_value(raw)
        .map_err(|e| anyhow::anyhow!("Parsing réponse triage : {}", e))?;

    let results: Vec<TriageResult> = wrapper
        .findings
        .into_iter()
        .map(|t| {
            let verdict = match t.verdict.as_str() {
                "true_positive" => Verdict::TruePositive,
                "false_positive" => Verdict::FalsePositive,
                _ => Verdict::Uncertain,
            };
            TriageResult {
                id: t.id,
                verdict,
                confidence: t.confidence,
                reason: t.reason,
            }
        })
        .collect();

    // Fill in any missing IDs with Uncertain
    let mut final_results = results;
    for f in findings {
        if !final_results.iter().any(|r| r.id == f.id) {
            final_results.push(TriageResult {
                id: f.id.clone(),
                verdict: Verdict::Uncertain,
                confidence: 0,
                reason: "Pas de réponse du modèle".to_string(),
            });
        }
    }

    Ok(final_results)
}

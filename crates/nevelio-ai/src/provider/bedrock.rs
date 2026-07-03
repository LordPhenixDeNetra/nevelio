/// AWS Bedrock Runtime provider — Converse API with manual SigV4 signing.
///
/// Credentials are read from the standard AWS environment variables:
///   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional)
///
/// Compiled only when the `bedrock` Cargo feature is enabled.
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};

use super::{AiProvider, CompletionOpts, Message, Role, ToolCall, ToolCallResponse, ToolDefinition};

type HmacSha256 = Hmac<Sha256>;

// SigV4 service name for Bedrock Runtime
const SIGV4_SERVICE: &str = "bedrock";

// ── Public struct ─────────────────────────────────────────────────────────────

pub struct BedrockProvider {
    model:       String,
    region:      String,
    max_tokens:  u32,
    temperature: f32,
    client:      reqwest::Client,
}

impl BedrockProvider {
    pub fn new(model: String, region: String, max_tokens: u32, temperature: f32) -> Self {
        Self { model, region, max_tokens, temperature, client: reqwest::Client::new() }
    }

    pub fn default_opts(&self) -> CompletionOpts {
        CompletionOpts { max_tokens: self.max_tokens, temperature: self.temperature, model: None }
    }

    fn resolve_model<'a>(&'a self, opts: &'a CompletionOpts) -> &'a str {
        opts.model.as_deref().unwrap_or(&self.model)
    }

    async fn post(&self, body: Value, model: &str) -> Result<Value> {
        let creds = AwsCreds::from_env()?;
        let host = format!("bedrock-runtime.{}.amazonaws.com", self.region);

        let now = Utc::now();
        let amzdate   = now.format("%Y%m%dT%H%M%SZ").to_string();
        let datestamp = now.format("%Y%m%d").to_string();

        let body_bytes = serde_json::to_vec(&body).context("Sérialisation body Bedrock")?;

        // Raw (unencoded) path — encoding is done inside build_authorization
        let raw_path = format!("/model/{}/converse", model);
        let authorization = build_authorization(
            &host, &raw_path, &amzdate, &datestamp, &self.region, &body_bytes, &creds,
        );

        // Percent-encode the path for the actual HTTP request
        let encoded_path = encode_path(&raw_path);
        let url = format!("https://{}{}", host, encoded_path);

        let mut req_builder = self.client
            .post(&url)
            .header("content-type", "application/json")
            .header("host", &host)
            .header("x-amz-date", &amzdate)
            .header("authorization", &authorization);

        if let Some(ref token) = creds.session_token {
            req_builder = req_builder.header("x-amz-security-token", token);
        }

        let resp = req_builder
            .body(body_bytes)
            .send()
            .await
            .context("Requête AWS Bedrock échouée")?;

        let status = resp.status();
        let bytes  = resp.bytes().await.context("Lecture réponse Bedrock")?;

        if !status.is_success() {
            let err: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
            anyhow::bail!(
                "Bedrock API {} : {}",
                status,
                err.get("message").and_then(Value::as_str)
                    .or_else(|| err.get("Message").and_then(Value::as_str))
                    .unwrap_or("erreur inconnue")
            );
        }

        serde_json::from_slice(&bytes).context("Parsing réponse Bedrock")
    }

    fn build_converse_body(&self, messages: &[Message], opts: &CompletionOpts) -> Value {
        let mut system: Option<String> = None;
        let chat: Vec<Value> = messages.iter().filter_map(|m| match m.role {
            Role::System    => { system = Some(m.content.clone()); None }
            Role::User      => Some(json!({ "role": "user",      "content": [{"text": m.content}] })),
            Role::Assistant => Some(json!({ "role": "assistant", "content": [{"text": m.content}] })),
        }).collect();

        let mut body = json!({
            "messages": chat,
            "inferenceConfig": {
                "maxTokens":   opts.max_tokens,
                "temperature": opts.temperature,
            }
        });

        if let Some(sys) = system {
            body["system"] = json!([{"text": sys}]);
        }

        body
    }
}

#[async_trait]
impl AiProvider for BedrockProvider {
    fn name(&self)  -> &str { "bedrock" }
    fn model(&self) -> &str { &self.model }

    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String> {
        let model = self.resolve_model(opts).to_string();
        let body  = self.build_converse_body(messages, opts);
        let resp  = self.post(body, &model).await?;
        extract_text(&resp)
    }

    async fn complete_json(
        &self,
        messages: &[Message],
        _schema:  Value,
        opts:     &CompletionOpts,
    ) -> Result<Value> {
        let mut msgs = messages.to_vec();
        msgs.push(Message::user(
            "Réponds UNIQUEMENT avec un objet JSON valide, sans texte avant ou après.",
        ));

        let model = self.resolve_model(opts).to_string();
        let body  = self.build_converse_body(&msgs, opts);
        let resp  = self.post(body, &model).await?;
        let text  = extract_text(&resp)?;

        let clean = text.trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        serde_json::from_str(clean).context("Parsing JSON réponse Bedrock")
    }

    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools:    &[ToolDefinition],
        opts:     &CompletionOpts,
    ) -> Result<ToolCallResponse> {
        let model = self.resolve_model(opts).to_string();
        let mut body = self.build_converse_body(messages, opts);

        let tool_list: Vec<Value> = tools.iter().map(|t| json!({
            "toolSpec": {
                "name":        t.name,
                "description": t.description,
                "inputSchema": { "json": t.parameters }
            }
        })).collect();

        body["toolConfig"] = json!({ "tools": tool_list });

        let resp = self.post(body, &model).await?;
        parse_tool_response(&resp)
    }
}

// ── AWS credentials ────────────────────────────────────────────────────────────

struct AwsCreds {
    access_key_id:     String,
    secret_access_key: String,
    session_token:     Option<String>,
}

impl AwsCreds {
    fn from_env() -> Result<Self> {
        Ok(Self {
            access_key_id:     std::env::var("AWS_ACCESS_KEY_ID")
                                   .context("AWS_ACCESS_KEY_ID non défini")?,
            secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY")
                                   .context("AWS_SECRET_ACCESS_KEY non défini")?,
            session_token:     std::env::var("AWS_SESSION_TOKEN").ok(),
        })
    }
}

// ── SigV4 signing ─────────────────────────────────────────────────────────────

/// Returns the value of the `Authorization` header for an AWS SigV4 request.
fn build_authorization(
    host:      &str,
    raw_path:  &str,   // unencoded path, e.g. "/model/anthropic.claude-3-5.../converse"
    amzdate:   &str,   // "20240101T120000Z"
    datestamp: &str,   // "20240101"
    region:    &str,
    body:      &[u8],
    creds:     &AwsCreds,
) -> String {
    let has_token = creds.session_token.is_some();

    // Canonical URI: percent-encode each path segment
    let canonical_uri = encode_path(raw_path);

    // Canonical headers (sorted alphabetically, each ending with \n)
    let mut canonical_headers = format!(
        "content-type:application/json\nhost:{host}\nx-amz-date:{amzdate}",
    );
    if has_token {
        let token = creds.session_token.as_deref().unwrap_or("");
        canonical_headers.push_str(&format!("\nx-amz-security-token:{token}"));
    }
    canonical_headers.push('\n'); // required trailing newline

    let signed_headers = if has_token {
        "content-type;host;x-amz-date;x-amz-security-token"
    } else {
        "content-type;host;x-amz-date"
    };

    let body_hash = sha256_hex(body);

    // Canonical request
    // Format: method\nuri\nquery\nheaders\nsigned_headers\nbody_hash
    // canonical_headers already ends with \n, so "{headers}\n{signed}" produces the
    // required blank line between headers block and signed-headers list.
    let canonical_request = format!(
        "POST\n{canonical_uri}\n\n{canonical_headers}{signed_headers}\n{body_hash}"
    );

    let credential_scope = format!("{datestamp}/{region}/{SIGV4_SERVICE}/aws4_request");

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // Derive signing key
    let k_date    = hmac_sha256(format!("AWS4{}", creds.secret_access_key).as_bytes(), datestamp.as_bytes());
    let k_region  = hmac_sha256(&k_date,    region.as_bytes());
    let k_service = hmac_sha256(&k_region,  SIGV4_SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        access_key = creds.access_key_id,
    )
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Percent-encodes every byte except RFC-3986 unreserved characters.
/// Applied per-segment (split on '/' before calling this function).
fn percent_encode_segment(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
            (b as char).to_string()
        }
        _ => format!("%{b:02X}"),
    }).collect()
}

/// Encodes a full path, preserving '/' separators between segments.
fn encode_path(path: &str) -> String {
    path.split('/').map(percent_encode_segment).collect::<Vec<_>>().join("/")
}

// ── Response parsing ──────────────────────────────────────────────────────────

fn extract_text(resp: &Value) -> Result<String> {
    resp["output"]["message"]["content"]
        .as_array()
        .and_then(|arr| arr.iter().find(|b| b["text"].is_string()))
        .and_then(|b| b["text"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!(
            "Champ 'output.message.content[].text' manquant dans réponse Bedrock"
        ))
}

fn parse_tool_response(resp: &Value) -> Result<ToolCallResponse> {
    let mut text       = None;
    let mut tool_calls = Vec::new();

    if let Some(content) = resp["output"]["message"]["content"].as_array() {
        for block in content {
            if let Some(t) = block["text"].as_str() {
                text = Some(t.to_string());
            } else if block["toolUse"].is_object() {
                let tu = &block["toolUse"];
                tool_calls.push(ToolCall {
                    id:        tu["toolUseId"].as_str().map(|s| s.to_string()),
                    tool_name: tu["name"].as_str().unwrap_or("").to_string(),
                    arguments: tu["input"].clone(),
                });
            }
        }
    }

    Ok(ToolCallResponse { text, tool_calls })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_colon_in_model_id() {
        let id = "anthropic.claude-3-5-sonnet-20241022-v2:0";
        let encoded = percent_encode_segment(id);
        assert_eq!(encoded, "anthropic.claude-3-5-sonnet-20241022-v2%3A0");
    }

    #[test]
    fn encode_path_preserves_slashes() {
        let path = "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse";
        let encoded = encode_path(path);
        assert_eq!(encoded, "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse");
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA256("") = e3b0c44...
        let empty = sha256_hex(b"");
        assert_eq!(&empty[..8], "e3b0c442");
    }

    #[test]
    fn extract_text_from_converse_response() {
        let resp = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello from Bedrock"}]
                }
            }
        });
        assert_eq!(extract_text(&resp).unwrap(), "Hello from Bedrock");
    }

    #[test]
    fn parse_tool_response_extracts_tool_call() {
        let resp = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Using tool"},
                        {
                            "toolUse": {
                                "toolUseId": "abc123",
                                "name": "get_weather",
                                "input": {"city": "Paris"}
                            }
                        }
                    ]
                }
            }
        });
        let result = parse_tool_response(&resp).unwrap();
        assert_eq!(result.text, Some("Using tool".to_string()));
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].tool_name, "get_weather");
        assert_eq!(result.tool_calls[0].id, Some("abc123".to_string()));
        assert_eq!(result.tool_calls[0].arguments["city"], "Paris");
    }
}

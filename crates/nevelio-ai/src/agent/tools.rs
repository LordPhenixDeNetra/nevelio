use serde_json::json;

use crate::provider::ToolDefinition;

/// Return the four tools exposed by the Nevelio agent to the LLM.
pub fn nevelio_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "list_endpoints".to_string(),
            description:
                "List all API endpoints discovered during reconnaissance. \
                 Call this first to understand the attack surface before probing."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "probe_endpoint".to_string(),
            description:
                "Send an HTTP request to an API endpoint to test for vulnerabilities. \
                 Analyze the response (status code, headers, body) for security issues."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                        "description": "HTTP method"
                    },
                    "url": {
                        "type": "string",
                        "description": "Full URL to request (must be in scope)"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers as key-value string pairs",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "type": "string",
                        "description": "Optional request body — JSON string, form data, etc."
                    }
                },
                "required": ["method", "url"]
            }),
        },
        ToolDefinition {
            name: "report_finding".to_string(),
            description:
                "Report a confirmed, exploitable security vulnerability. \
                 Only use this for real issues backed by proof — not theoretical vulnerabilities."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short, descriptive vulnerability title"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIVE"],
                        "description": "CVSS-based severity"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Vulnerable endpoint path (e.g. /api/users/{id})"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method used to trigger the vulnerability"
                    },
                    "description": {
                        "type": "string",
                        "description": "Technical description: what the vulnerability is and what impact it has"
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "Specific, actionable remediation advice"
                    },
                    "proof": {
                        "type": "string",
                        "description": "Evidence of exploitability — exact request/response snippet"
                    }
                },
                "required": ["title", "severity", "endpoint", "method", "description", "recommendation", "proof"]
            }),
        },
        ToolDefinition {
            name: "finish".to_string(),
            description:
                "Signal that the security assessment is complete. \
                 Call this when all relevant endpoints have been tested or the request/iteration limit is near."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Brief summary: what was tested, what was found, overall security posture"
                    }
                },
                "required": ["summary"]
            }),
        },
    ]
}

use anyhow::{Context, Result};
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};

/// Parse an OpenAPI 3.x spec (local file or remote URL) and return all endpoints.
pub async fn parse_spec(
    spec_path_or_url: &str,
    base_url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Endpoint>> {
    let content = fetch_spec(spec_path_or_url, client).await?;
    let spec = load_spec(&content)
        .with_context(|| format!("Failed to parse OpenAPI spec: {}", spec_path_or_url))?;

    // Warn if spec version is not 3.1.x (oas3 0.21 targets 3.1.x, but 3.0.x usually parses)
    if let Err(e) = spec.validate_version() {
        tracing::warn!("Spec version may not be fully supported: {}", e);
    }

    let base = effective_base_url(&spec, base_url);
    tracing::info!(
        "Spec '{}' loaded — {} path(s), base: {}",
        spec_path_or_url,
        spec.paths.as_ref().map_or(0, |p| p.len()),
        base
    );

    let endpoints = spec
        .operations()
        .map(|(path, method, operation)| {
            let parameters = operation
                .parameters(&spec)
                .unwrap_or_default()
                .into_iter()
                .map(|p| Parameter {
                    name: p.name,
                    location: oas_location_to_core(p.location),
                    required: p.required.unwrap_or(false),
                    schema: None,
                })
                .collect();

            let full_url = format!("{}{}", base.trim_end_matches('/'), path);
            let auth_required = !operation.security.is_empty();

            Endpoint {
                method: method.to_string(),
                path,
                full_url,
                parameters,
                auth_required,
            }
        })
        .collect::<Vec<_>>();

    tracing::info!("Extracted {} endpoint(s) from spec", endpoints.len());
    Ok(endpoints)
}

fn effective_base_url(spec: &oas3::OpenApiV3Spec, override_url: &str) -> String {
    if !override_url.is_empty() {
        return override_url.to_string();
    }
    spec.primary_server()
        .map(|s| s.url.clone())
        .unwrap_or_else(|| "/".to_string())
}

async fn fetch_spec(source: &str, client: &reqwest::Client) -> Result<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        tracing::info!("Fetching remote spec: {}", source);
        let content = client
            .get(source)
            .send()
            .await
            .context("Failed to fetch remote spec")?
            .text()
            .await
            .context("Failed to read spec response body")?;
        Ok(content)
    } else {
        std::fs::read_to_string(source)
            .with_context(|| format!("Cannot read spec file: {}", source))
    }
}

fn load_spec(content: &str) -> Result<oas3::OpenApiV3Spec> {
    // JSON if it starts with '{', otherwise try YAML
    if content.trim_start().starts_with('{') {
        oas3::from_json(content).context("Failed to parse spec as JSON")
    } else {
        oas3::from_yaml(content).context("Failed to parse spec as YAML")
    }
}

fn oas_location_to_core(loc: oas3::spec::ParameterIn) -> ParameterLocation {
    match loc {
        oas3::spec::ParameterIn::Path => ParameterLocation::Path,
        oas3::spec::ParameterIn::Query => ParameterLocation::Query,
        oas3::spec::ParameterIn::Header => ParameterLocation::Header,
        oas3::spec::ParameterIn::Cookie => ParameterLocation::Cookie,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nevelio_core::types::ParameterLocation;

    #[test]
    fn load_spec_parses_minimal_yaml() {
        let yaml = r#"
openapi: "3.1.0"
info:
  title: Test API
  version: "1.0"
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: OK
  /users/{id}:
    delete:
      summary: Delete user
      responses:
        "204":
          description: No Content
"#;
        let spec = load_spec(yaml).expect("should parse valid YAML spec");
        let ops: Vec<_> = spec.operations().collect();
        assert_eq!(ops.len(), 2, "expected 2 operations");
        let methods: Vec<String> = ops.iter().map(|(_, m, _)| format!("{}", m).to_uppercase()).collect();
        assert!(methods.contains(&"GET".to_string()));
        assert!(methods.contains(&"DELETE".to_string()));
    }

    #[test]
    fn load_spec_parses_minimal_json() {
        let json = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/ping": {
                    "get": {"summary": "Ping", "responses": {"200": {"description": "OK"}}}
                }
            }
        }"#;
        let spec = load_spec(json).expect("should parse valid JSON spec");
        let ops: Vec<_> = spec.operations().collect();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn effective_base_url_uses_override_when_provided() {
        let yaml = r#"
openapi: "3.1.0"
info:
  title: T
  version: "1"
servers:
  - url: https://prod.example.com
paths: {}
"#;
        let spec = load_spec(yaml).unwrap();
        let base = effective_base_url(&spec, "https://staging.example.com");
        assert_eq!(base, "https://staging.example.com");
    }

    #[test]
    fn effective_base_url_falls_back_to_spec_server() {
        let yaml = r#"
openapi: "3.1.0"
info:
  title: T
  version: "1"
servers:
  - url: https://api.example.com
paths: {}
"#;
        let spec = load_spec(yaml).unwrap();
        let base = effective_base_url(&spec, "");
        assert_eq!(base, "https://api.example.com");
    }

    #[test]
    fn oas_location_mapping_is_exhaustive() {
        assert!(matches!(
            oas_location_to_core(oas3::spec::ParameterIn::Query),
            ParameterLocation::Query
        ));
        assert!(matches!(
            oas_location_to_core(oas3::spec::ParameterIn::Path),
            ParameterLocation::Path
        ));
        assert!(matches!(
            oas_location_to_core(oas3::spec::ParameterIn::Header),
            ParameterLocation::Header
        ));
        assert!(matches!(
            oas_location_to_core(oas3::spec::ParameterIn::Cookie),
            ParameterLocation::Cookie
        ));
    }
}

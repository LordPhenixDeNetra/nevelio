use std::collections::HashMap;
use anyhow::Result;

/// Summary of HTTP headers observed on a target endpoint.
#[derive(Debug, Default)]
pub struct HeaderProfile {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub cors_origin: Option<String>,
    pub hsts: Option<String>,
    pub csp: Option<String>,
    pub x_content_type: Option<String>,
    pub x_frame_options: Option<String>,
    pub referrer_policy: Option<String>,
    pub auth_type: Option<String>,
    pub api_version: Option<String>,
    pub all: HashMap<String, String>,
}

/// Probe a single URL and return its header profile.
pub async fn analyze(url: &str, client: &reqwest::Client) -> Result<HeaderProfile> {
    tracing::debug!("[headers] probing {}", url);

    let resp = client
        .get(url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    let mut profile = HeaderProfile::default();

    for (name, value) in resp.headers() {
        let key = name.as_str().to_lowercase();
        let val = value.to_str().unwrap_or("").to_string();

        profile.all.insert(key.clone(), val.clone());

        match key.as_str() {
            "server" => profile.server = Some(val),
            "x-powered-by" => profile.powered_by = Some(val),
            "access-control-allow-origin" => profile.cors_origin = Some(val),
            "strict-transport-security" => profile.hsts = Some(val),
            "content-security-policy" => profile.csp = Some(val),
            "x-content-type-options" => profile.x_content_type = Some(val),
            "x-frame-options" => profile.x_frame_options = Some(val),
            "referrer-policy" => profile.referrer_policy = Some(val),
            "www-authenticate" => profile.auth_type = Some(val),
            "x-api-version" | "api-version" => profile.api_version = Some(val),
            _ => {}
        }
    }

    tracing::debug!(
        "[headers] {} — server={:?} cors={:?} hsts={}",
        url,
        profile.server,
        profile.cors_origin,
        profile.hsts.is_some()
    );

    Ok(profile)
}

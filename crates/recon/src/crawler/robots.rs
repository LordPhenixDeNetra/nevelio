use std::collections::HashSet;

/// Fetch and parse `robots.txt`, returning all `Disallow:` paths.
pub(super) async fn load_robots_disallowed(
    base: &str,
    client: &reqwest::Client,
) -> HashSet<String> {
    let url = format!("{}/robots.txt", base);
    let mut disallowed = HashSet::new();

    let text = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return disallowed,
    };

    for line in text.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_prefix("Disallow:") {
            let path = path.split_whitespace().next().unwrap_or("").trim();
            if !path.is_empty() {
                disallowed.insert(path.to_string());
            }
        }
    }

    tracing::debug!("[crawler] robots.txt: {} disallowed paths", disallowed.len());
    disallowed
}

pub(super) fn is_disallowed(path: &str, disallowed: &HashSet<String>) -> bool {
    disallowed.iter().any(|d| {
        if d.ends_with('/') {
            path.starts_with(d.as_str())
        } else {
            path == d.as_str() || path.starts_with(&format!("{}/", d))
        }
    })
}

/// If `/api/v1/...` was found, generate variants for v2–v4.
pub(super) fn expand_versioned_paths(paths: &[String]) -> Vec<String> {
    let mut extra = Vec::new();
    for path in paths {
        if path.contains("/v1") {
            for v in &["2", "3", "4"] {
                let candidate = path.replacen("/v1", &format!("/v{}", v), 1);
                if !paths.contains(&candidate) && !extra.contains(&candidate) {
                    extra.push(candidate);
                }
            }
        }
    }
    extra
}

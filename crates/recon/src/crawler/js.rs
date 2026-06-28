/// Fetch the root page, find `<script src>` tags, download local JS files,
/// and extract API-looking paths from `fetch()`, `axios.*()`, and string literals.
pub(super) async fn extract_js_urls(base: &str, client: &reqwest::Client) -> Vec<String> {
    let html = match client
        .get(base)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    let script_srcs = extract_script_srcs(&html);
    let mut api_paths: Vec<String> = Vec::new();

    for src in script_srcs.iter().take(10) {
        if src.starts_with("http://") || src.starts_with("https://") {
            continue; // skip CDN scripts
        }
        let js_url = format!("{}/{}", base, src.trim_start_matches('/'));

        let content = match client
            .get(&js_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            _ => continue,
        };

        api_paths.extend(extract_api_paths_from_js(&content));
    }

    api_paths.sort();
    api_paths.dedup();
    api_paths
}

/// Extract `src` attribute values from `<script>` tags.
pub(super) fn extract_script_srcs(html: &str) -> Vec<String> {
    let mut srcs = Vec::new();
    let mut search = html;

    while let Some(tag_pos) = search.to_lowercase().find("<script") {
        let after = &search[tag_pos..];
        let tag_end = after.find('>').unwrap_or(after.len());
        let tag_content = &after[..tag_end];

        if let Some(src) = extract_attr(tag_content, "src") {
            if !src.is_empty() {
                srcs.push(src);
            }
        }

        search = &search[tag_pos + 7..]; // advance past "<script"
    }

    srcs
}

/// Extract an HTML attribute value (single or double quotes).
pub(super) fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let search_dq = format!("{}=\"", attr);
    let search_sq = format!("{}='", attr);

    if let Some(pos) = tag.to_lowercase().find(&search_dq) {
        let after = &tag[pos + search_dq.len()..];
        let end = after.find('"').unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    if let Some(pos) = tag.to_lowercase().find(&search_sq) {
        let after = &tag[pos + search_sq.len()..];
        let end = after.find('\'').unwrap_or(after.len());
        return Some(after[..end].to_string());
    }

    None
}

/// Extract API-looking paths from JS source code.
pub(super) fn extract_api_paths_from_js(js: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Patterns: fetch("PATH"), axios.METHOD("PATH")
    let call_prefixes: &[&str] = &[
        "fetch(\"",
        "fetch('",
        "axios.get(\"",
        "axios.post(\"",
        "axios.put(\"",
        "axios.delete(\"",
        "axios.patch(\"",
        "axios.get('",
        "axios.post('",
        "axios.put('",
        "axios.delete('",
        "axios.patch('",
    ];

    for &prefix in call_prefixes {
        let quote = if prefix.ends_with('"') { '"' } else { '\'' };
        let mut search = js;
        while let Some(pos) = search.find(prefix) {
            search = &search[pos + prefix.len()..];
            if let Some(end) = search.find(quote) {
                let candidate = &search[..end];
                if is_api_path_candidate(candidate) {
                    paths.push(candidate.to_string());
                }
                search = &search[end..];
            }
        }
    }

    // String literals: "/api/...", "/v1/...", "/v2/..."
    let path_prefixes: &[(&str, char)] = &[
        ("\"/api/", '"'),
        ("'/api/", '\''),
        ("\"/v1/", '"'),
        ("'/v1/", '\''),
        ("\"/v2/", '"'),
        ("'/v2/", '\''),
        ("\"/v3/", '"'),
        ("'/v3/", '\''),
    ];

    for &(prefix, quote) in path_prefixes {
        let mut search = js;
        while let Some(pos) = search.find(prefix) {
            // The path starts after the opening quote
            search = &search[pos + 1..];
            if let Some(end) = search.find(quote) {
                let candidate = &search[..end];
                if is_api_path_candidate(candidate) {
                    paths.push(candidate.to_string());
                }
                search = &search[end + 1..];
            }
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

pub(super) fn is_api_path_candidate(s: &str) -> bool {
    s.starts_with('/')
        && s.len() > 2
        && !s.contains(' ')
        && !s.contains('\n')
        && !s.ends_with(".js")
        && !s.ends_with(".css")
        && !s.ends_with(".html")
}

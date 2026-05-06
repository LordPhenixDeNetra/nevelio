/// Detects the locale in priority order:
/// 1. --lang CLI flag
/// 2. NEVELIO_LANG environment variable
/// 3. LANGUAGE / LANG system variables (e.g. "fr_FR.UTF-8" → "fr")
/// 4. Default: "en"
pub fn detect(lang_flag: Option<&str>) -> String {
    if let Some(l) = lang_flag {
        let n = normalize(l);
        if is_supported(&n) { return n; }
    }
    if let Ok(v) = std::env::var("NEVELIO_LANG") {
        let n = normalize(&v);
        if is_supported(&n) { return n; }
    }
    for var in &["LANGUAGE", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            let n = normalize(&v);
            if is_supported(&n) { return n; }
        }
    }
    "en".to_string()
}

pub fn is_supported(locale: &str) -> bool {
    matches!(locale, "fr" | "en" | "es")
}

fn normalize(raw: &str) -> String {
    raw.split(['_', '-', '.'])
        .next()
        .unwrap_or("en")
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(2)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_fr_fr_utf8() {
        assert_eq!(normalize("fr_FR.UTF-8"), "fr");
    }

    #[test]
    fn normalize_en_us() {
        assert_eq!(normalize("en-US"), "en");
    }

    #[test]
    fn normalize_es() {
        assert_eq!(normalize("es"), "es");
    }

    #[test]
    fn unsupported_falls_to_en() {
        assert_eq!(detect(Some("de")), "en");
    }
}

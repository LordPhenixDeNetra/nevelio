use rust_i18n::t;
use sha2::{Digest, Sha256};
use std::fmt::Write as FmtWrite;

/// Entrée d'audit — action + résumé + chaîne SHA-256.
#[derive(Debug)]
pub struct AuditEntry {
    pub timestamp:   String,
    pub action:      String,
    pub findings:    usize,
    pub max_sev:     String,
    pub elapsed_ms:  u64,
    /// SHA-256(prev_hash || timestamp || action || findings || max_sev)
    pub hash:        String,
}

/// Journaliste d'audit avec chaînage de hachages.
pub struct AuditLogger {
    entries:   Vec<AuditEntry>,
    prev_hash: String,
    log_path:  String,
}

impl AuditLogger {
    pub fn new(log_path: impl Into<String>) -> Self {
        Self {
            entries:   Vec::new(),
            prev_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            log_path:  log_path.into(),
        }
    }

    /// Enregistre une action dans le journal.
    pub fn record(
        &mut self,
        action:     impl Into<String>,
        findings:   usize,
        max_sev:    impl Into<String>,
        elapsed_ms: u64,
    ) {
        let action  = action.into();
        let max_sev = max_sev.into();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let input = format!(
            "{}{}{}{}{}",
            self.prev_hash, timestamp, action, findings, max_sev
        );
        let hash = sha256_hex(input.as_bytes());

        let entry = AuditEntry {
            timestamp,
            action,
            findings,
            max_sev,
            elapsed_ms,
            hash: hash.clone(),
        };

        self.prev_hash = hash;
        self.entries.push(entry);
    }

    /// Sauvegarde le journal dans le fichier configuré.
    pub fn save(&self) -> std::io::Result<()> {
        let mut buf = String::new();
        writeln!(buf, "{}", t!("audit.header_title")).ok();
        writeln!(buf, "{}", t!("audit.header_chain")).ok();
        writeln!(buf, "{}", t!("audit.header_format")).ok();
        writeln!(buf, "# ---").ok();
        for e in &self.entries {
            writeln!(
                buf,
                "{}|{}|{}|{}|{}|{}",
                e.timestamp, e.action, e.findings, e.max_sev, e.elapsed_ms, e.hash
            ).ok();
        }
        std::fs::write(&self.log_path, buf)
    }

    /// Vérifie l'intégrité de la chaîne de hachages.
    #[allow(dead_code)]
    pub fn verify(&self) -> bool {
        let mut prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        for e in &self.entries {
            let input = format!(
                "{}{}{}{}{}",
                prev, e.timestamp, e.action, e.findings, e.max_sev
            );
            let expected = sha256_hex(input.as_bytes());
            if expected != e.hash {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    #[allow(dead_code)]
    pub fn entries(&self) -> &[AuditEntry] { &self.entries }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().fold(String::new(), |mut acc, b| {
        write!(acc, "{:02x}", b).ok();
        acc
    })
}

/// Retourne le chemin du fichier de log selon la plateforme.
pub fn default_log_path() -> String {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        format!("{}/nevelio-hw/audit.log", xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.local/share/nevelio-hw/audit.log", home)
    } else {
        "/tmp/nevelio-hw-audit.log".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_chain_integrity() {
        let mut log = AuditLogger::new("/dev/null");
        log.record("scan --dry-run", 5, "HIGH", 1200);
        log.record("scan --active", 12, "CRITICAL", 8450);
        assert!(log.verify());
    }

    #[test]
    fn audit_chain_tampered() {
        let mut log = AuditLogger::new("/dev/null");
        log.record("scan", 3, "MEDIUM", 500);
        // Modification frauduleuse du premier hash
        if let Some(e) = log.entries.first_mut() {
            e.hash = "tampered".into();
        }
        assert!(!log.verify());
    }

    #[test]
    fn default_log_path_non_empty() {
        let p = default_log_path();
        assert!(!p.is_empty());
        assert!(p.contains("nevelio-hw"));
    }
}

use anyhow::{bail, Result};

// ── Guardrail ─────────────────────────────────────────────────────────────────

pub struct Guardrail {
    allowed_hosts: Vec<String>,
    pub max_requests: u32,
    pub ai_budget:    Option<u32>,
    pub dry_run:      bool,
    requests_made:    u32,
    tokens_spent:     u32,
}

impl Guardrail {
    pub fn new(
        target:       &str,
        max_requests: u32,
        ai_budget:    Option<u32>,
        dry_run:      bool,
    ) -> Self {
        Self {
            allowed_hosts: extract_allowed_hosts(target),
            max_requests,
            ai_budget,
            dry_run,
            requests_made: 0,
            tokens_spent:  0,
        }
    }

    /// Check that the URL's host is within the allowed scope (exact match or subdomain).
    pub fn check_scope(&self, url: &str) -> Result<()> {
        let host = extract_host(url);
        let in_scope = self.allowed_hosts.iter().any(|allowed| {
            host == *allowed
                || host.ends_with(&format!(".{}", allowed))
                || allowed.ends_with(&format!(".{}", host))
        });
        if !in_scope {
            bail!(
                "Out-of-scope request blocked: {} (host: {}) is not in {:?}",
                url,
                host,
                self.allowed_hosts
            );
        }
        Ok(())
    }

    /// Fail if the HTTP request count has reached the configured limit.
    pub fn check_requests(&self) -> Result<()> {
        if self.requests_made >= self.max_requests {
            bail!(
                "Request limit reached ({}/{})",
                self.requests_made,
                self.max_requests
            );
        }
        Ok(())
    }

    /// Fail if adding `additional_estimate` tokens would exceed the budget.
    pub fn check_budget(&self, additional_estimate: u32) -> Result<()> {
        if let Some(max) = self.ai_budget {
            let projected = self.tokens_spent.saturating_add(additional_estimate);
            if projected >= max {
                bail!(
                    "Token budget exhausted ({}/{})",
                    projected,
                    max
                );
            }
        }
        Ok(())
    }

    pub fn record_request(&mut self) {
        self.requests_made += 1;
    }

    pub fn record_tokens(&mut self, tokens: u32) {
        self.tokens_spent = self.tokens_spent.saturating_add(tokens);
    }

    pub fn requests_made(&self) -> u32 { self.requests_made }
    pub fn tokens_spent(&self)  -> u32 { self.tokens_spent  }
}

// ── Host extraction helpers ────────────────────────────────────────────────────

fn extract_allowed_hosts(target: &str) -> Vec<String> {
    let host = extract_host(target);
    if host.is_empty() { vec![] } else { vec![host] }
}

pub fn extract_host(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')   // strip port
        .next()
        .unwrap_or("")
        .to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_allows_exact_host() {
        let g = Guardrail::new("https://api.example.com", 100, None, false);
        assert!(g.check_scope("https://api.example.com/v1/users").is_ok());
    }

    #[test]
    fn scope_allows_subdomain() {
        let g = Guardrail::new("https://example.com", 100, None, false);
        assert!(g.check_scope("https://api.example.com/users").is_ok());
    }

    #[test]
    fn scope_blocks_foreign_host() {
        let g = Guardrail::new("https://api.example.com", 100, None, false);
        assert!(g.check_scope("https://evil.com/steal").is_err());
    }

    #[test]
    fn requests_limit_enforced() {
        let mut g = Guardrail::new("https://api.example.com", 2, None, false);
        g.record_request();
        g.record_request();
        assert!(g.check_requests().is_err());
    }

    #[test]
    fn budget_limit_enforced() {
        let g = Guardrail::new("https://api.example.com", 100, Some(1000), false);
        assert!(g.check_budget(1001).is_err());
        assert!(g.check_budget(999).is_ok());
    }
}

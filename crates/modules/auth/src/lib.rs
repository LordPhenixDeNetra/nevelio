use async_trait::async_trait;
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_core::types::{Endpoint, Finding};

pub struct AuthModule;

#[async_trait]
impl AttackModule for AuthModule {
    fn name(&self) -> &str {
        "auth"
    }

    fn description(&self) -> &str {
        "Tests JWT flaws, OAuth, Basic Auth, and API key vulnerabilities"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        _client: &HttpClient,
        _endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        tracing::info!("[auth] Phase 1 stub — no tests implemented yet");
        vec![]
    }
}

use async_trait::async_trait;
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_core::types::{Endpoint, Finding};

pub struct AccessControlModule;

#[async_trait]
impl AttackModule for AccessControlModule {
    fn name(&self) -> &str {
        "access-control"
    }

    fn description(&self) -> &str {
        "Tests IDOR, privilege escalation (horizontal/vertical), BFLA, and mass assignment"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        _client: &HttpClient,
        _endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        tracing::info!("[access-control] Phase 1 stub — no tests implemented yet");
        vec![]
    }
}

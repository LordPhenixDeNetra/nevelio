use async_trait::async_trait;
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_core::types::{Endpoint, Finding};

pub struct InjectionModule;

#[async_trait]
impl AttackModule for InjectionModule {
    fn name(&self) -> &str {
        "injection"
    }

    fn description(&self) -> &str {
        "Tests SQLi, NoSQLi, SSTI, Command Injection, LDAP, and XXE"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        _client: &HttpClient,
        _endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        tracing::info!("[injection] Phase 1 stub — no tests implemented yet");
        vec![]
    }
}

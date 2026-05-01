use async_trait::async_trait;
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_core::types::{Endpoint, Finding};

pub struct BusinessLogicModule;

#[async_trait]
impl AttackModule for BusinessLogicModule {
    fn name(&self) -> &str {
        "business-logic"
    }

    fn description(&self) -> &str {
        "Tests rate limit bypass, race conditions, negative values, and workflow bypass"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        _client: &HttpClient,
        _endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        tracing::info!("[business-logic] Phase 1 stub — no tests implemented yet");
        vec![]
    }
}

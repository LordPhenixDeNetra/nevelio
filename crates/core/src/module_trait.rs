use async_trait::async_trait;
use crate::http_client::HttpClient;
use crate::session::ScanSession;
use crate::types::{Endpoint, Finding};

#[async_trait]
pub trait AttackModule: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding>;
}

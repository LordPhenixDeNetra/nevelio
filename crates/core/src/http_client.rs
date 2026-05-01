use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::types::ScanConfig;

pub struct HttpClient {
    inner: reqwest::Client,
    semaphore: Arc<Semaphore>,
}

impl HttpClient {
    pub fn new(config: &ScanConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .user_agent("Nevelio/0.1.0 (Security Scanner)");

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        let semaphore = Arc::new(Semaphore::new(config.concurrency));

        Ok(Self { inner: client, semaphore })
    }

    pub async fn send(&self, request: reqwest::Request) -> Result<reqwest::Response> {
        let _permit = self.semaphore.acquire().await?;
        let response = self.inner.execute(request).await?;
        Ok(response)
    }

    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

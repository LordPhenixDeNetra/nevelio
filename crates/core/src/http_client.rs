use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use crate::types::ScanConfig;

pub struct HttpClient {
    inner: reqwest::Client,
    semaphore: Arc<Semaphore>,
    last_send: Arc<Mutex<Instant>>,
    min_interval: Duration,
}

fn compute_min_interval(rate_limit: u64) -> Duration {
    1_000_000u64
        .checked_div(rate_limit)
        .map(Duration::from_micros)
        .unwrap_or(Duration::ZERO)
}

impl HttpClient {
    pub fn new(config: &ScanConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .user_agent("Nevelio/0.1.0 (Security Scanner)");

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let min_interval = compute_min_interval(config.rate_limit);

        Ok(Self {
            inner: client,
            semaphore,
            last_send: Arc::new(Mutex::new(Instant::now() - min_interval)),
            min_interval,
        })
    }

    pub async fn send(&self, request: reqwest::Request) -> Result<reqwest::Response> {
        let _permit = self.semaphore.acquire().await?;
        if self.min_interval > Duration::ZERO {
            let mut last = self.last_send.lock().await;
            let elapsed = last.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
            *last = Instant::now();
        }
        let response = self.inner.execute(request).await?;
        Ok(response)
    }

    /// Like `send`, but retries transient network failures with exponential backoff.
    /// Only connection/timeout errors are retried; HTTP 4xx/5xx responses are returned as-is.
    pub async fn send_with_retry(
        &self,
        build: impl Fn() -> reqwest::Result<reqwest::Request>,
    ) -> Result<reqwest::Response> {
        const BACKOFF_MS: &[u64] = &[500, 1_000, 2_000];

        for (attempt, &backoff) in BACKOFF_MS.iter().enumerate() {
            let req = build().map_err(anyhow::Error::from)?;
            match self.send(req).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    let is_transient = e
                        .downcast_ref::<reqwest::Error>()
                        .map(|re| re.is_connect() || re.is_timeout())
                        .unwrap_or(false);

                    if is_transient && attempt + 1 < BACKOFF_MS.len() {
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!()
    }

    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_interval_computed() {
        assert_eq!(compute_min_interval(50), Duration::from_micros(20_000));
    }

    #[test]
    fn zero_rate_limit_means_no_throttle() {
        assert_eq!(compute_min_interval(0), Duration::ZERO);
    }

    #[test]
    fn aggressive_profile_rate_limit() {
        assert_eq!(compute_min_interval(200), Duration::from_micros(5_000));
    }

    #[test]
    fn stealth_profile_rate_limit() {
        assert_eq!(compute_min_interval(10), Duration::from_micros(100_000));
    }
}

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

pub(crate) struct UploadThrottle(Mutex<HashMap<u32, (Instant, f64)>>);

impl UploadThrottle {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// Throttle an upload chunk for the given IP, blocking until the token
    /// bucket allows it. `rate_bps` is the max bytes per second for this IP.
    pub(crate) async fn throttle(&self, ip: u32, bytes: usize, rate_bps: f64) {
        let sleep_dur = {
            let mut map = self.0.lock().await;

            let now = Instant::now();

            // Evict entries idle for longer than 1 bucket-refill period.
            map.retain(|_, (last, _)| now.duration_since(*last) < Duration::from_secs(60));

            let (last_refill, tokens) = map.entry(ip).or_insert((now, rate_bps));

            let elapsed = now.duration_since(*last_refill).as_secs_f64();
            *tokens = (*tokens + elapsed * rate_bps).min(rate_bps);
            *last_refill = now;

            let bytes_f = bytes as f64;
            if *tokens >= bytes_f {
                *tokens -= bytes_f;
                None
            } else {
                let deficit = bytes_f - *tokens;
                *tokens = 0.0;
                Some(Duration::from_secs_f64(deficit / rate_bps))
            }
        };

        if let Some(dur) = sleep_dur {
            tokio::time::sleep(dur).await;
        }
    }
}

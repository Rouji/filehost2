use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

pub(crate) struct KeyedTtlCache<K, V> {
    ttl: Duration,
    state: RwLock<HashMap<K, (Instant, V)>>,
}

impl<K: Eq + Hash + Clone, V: Clone> KeyedTtlCache<K, V> {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) async fn get_or_refresh<F, Fut>(&self, key: K, fetch: F) -> Result<V, sqlx::Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, sqlx::Error>>,
    {
        if let Some((fetched_at, value)) = self.state.read().await.get(&key)
            && fetched_at.elapsed() < self.ttl
        {
            return Ok(value.clone());
        }

        let mut guard = self.state.write().await;
        if let Some((fetched_at, value)) = guard.get(&key)
            && fetched_at.elapsed() < self.ttl
        {
            return Ok(value.clone());
        }

        let fresh = fetch().await?;
        guard.insert(key, (Instant::now(), fresh.clone()));
        // opportunistic cleanup so keys that stop showing up don't linger forever
        let ttl = self.ttl;
        guard.retain(|_, (fetched_at, _)| fetched_at.elapsed() < ttl);
        Ok(fresh)
    }

    /// Inserts a value directly, bypassing `fetch` — for call sites that just
    /// learned the fresh value as a side effect (e.g. just wrote it to the DB)
    /// and want the cache to reflect it immediately rather than waiting out the TTL.
    pub(crate) async fn set(&self, key: K, value: V) {
        self.state
            .write()
            .await
            .insert(key, (Instant::now(), value));
    }

    /// Forces the next `get_or_refresh` for any key to hit the DB.
    pub(crate) async fn invalidate(&self) {
        self.state.write().await.clear();
    }
}

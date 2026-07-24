use std::collections::HashSet;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::db;
use crate::db_pool::DbPool;
use crate::model::BanType;

struct TtlCell<T> {
    ttl: Duration,
    state: RwLock<Option<(Instant, Arc<T>)>>,
}

impl<T> TtlCell<T> {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: RwLock::new(None),
        }
    }

    async fn get_or_refresh<F, Fut>(&self, fetch: F) -> Result<Arc<T>, sqlx::Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, sqlx::Error>>,
    {
        if let Some((fetched_at, data)) = self.state.read().await.as_ref()
            && fetched_at.elapsed() < self.ttl
        {
            return Ok(data.clone());
        }

        let mut guard = self.state.write().await;
        if let Some((fetched_at, data)) = guard.as_ref()
            && fetched_at.elapsed() < self.ttl
        {
            return Ok(data.clone());
        }

        let fresh = Arc::new(fetch().await?);
        *guard = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    async fn invalidate(&self) {
        *self.state.write().await = None;
    }
}

struct KeyedTtlCache<K, V> {
    ttl: Duration,
    state: RwLock<std::collections::HashMap<K, (Instant, V)>>,
}

impl<K: Eq + Hash + Clone, V: Clone> KeyedTtlCache<K, V> {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: RwLock::new(std::collections::HashMap::new()),
        }
    }

    async fn get_or_refresh<F, Fut>(&self, key: K, fetch: F) -> Result<V, sqlx::Error>
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
        // opportunistic cleanup so IPs that stop showing up don't linger forever
        let ttl = self.ttl;
        guard.retain(|_, (fetched_at, _)| fetched_at.elapsed() < ttl);
        Ok(fresh)
    }

    /// Forces the next `get_or_refresh` for any key to hit the DB.
    async fn invalidate(&self) {
        self.state.write().await.clear();
    }
}

pub(crate) struct BanCache {
    ip_bans: KeyedTtlCache<(u32, BanType), bool>,
    extensions: TtlCell<HashSet<String>>,
    mimes: TtlCell<HashSet<String>>,
    hashes: TtlCell<HashSet<Vec<u8>>>,
    user_agent_patterns: TtlCell<Vec<String>>,
}

impl BanCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ip_bans: KeyedTtlCache::new(ttl),
            extensions: TtlCell::new(ttl),
            mimes: TtlCell::new(ttl),
            hashes: TtlCell::new(ttl),
            user_agent_patterns: TtlCell::new(ttl),
        }
    }

    pub(crate) async fn is_ip_banned(
        &self,
        db: &DbPool,
        ip: u32,
        ban_type: BanType,
    ) -> Result<bool, sqlx::Error> {
        self.ip_bans
            .get_or_refresh((ip, ban_type), || db::is_ip_banned(db, ip, ban_type))
            .await
    }

    pub(crate) async fn is_extension_banned(
        &self,
        db: &DbPool,
        ext: &str,
    ) -> Result<bool, sqlx::Error> {
        let extensions = self
            .extensions
            .get_or_refresh(|| async {
                Ok(db::list_banned_extensions(db)
                    .await?
                    .into_iter()
                    .map(|e| e.extension)
                    .collect())
            })
            .await?;
        Ok(extensions.contains(ext))
    }

    pub(crate) async fn is_mime_banned(
        &self,
        db: &DbPool,
        mime: &str,
    ) -> Result<bool, sqlx::Error> {
        let mimes = self
            .mimes
            .get_or_refresh(|| async {
                Ok(db::list_banned_mimes(db)
                    .await?
                    .into_iter()
                    .map(|m| m.mime)
                    .collect())
            })
            .await?;
        Ok(mimes.contains(mime))
    }

    pub(crate) async fn is_hash_banned(
        &self,
        db: &DbPool,
        hash: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let hashes = self
            .hashes
            .get_or_refresh(|| async {
                Ok(db::list_banned_hashes(db)
                    .await?
                    .into_iter()
                    .map(|h| h.hash)
                    .collect())
            })
            .await?;
        Ok(hashes.contains(hash))
    }

    pub(crate) async fn is_user_agent_banned(
        &self,
        db: &DbPool,
        user_agent: &str,
    ) -> Result<bool, sqlx::Error> {
        let patterns = self
            .user_agent_patterns
            .get_or_refresh(|| async {
                Ok(db::list_banned_user_agents(db)
                    .await?
                    .into_iter()
                    .map(|u| u.pattern)
                    .collect())
            })
            .await?;
        let ua_lower = user_agent.to_lowercase();
        Ok(patterns
            .iter()
            .any(|p| ua_lower.contains(&p.to_lowercase())))
    }

    pub(crate) async fn invalidate_ip_ranges(&self) {
        self.ip_bans.invalidate().await;
    }

    pub(crate) async fn invalidate_extensions(&self) {
        self.extensions.invalidate().await;
    }

    pub(crate) async fn invalidate_mimes(&self) {
        self.mimes.invalidate().await;
    }

    pub(crate) async fn invalidate_hashes(&self) {
        self.hashes.invalidate().await;
    }

    pub(crate) async fn invalidate_user_agents(&self) {
        self.user_agent_patterns.invalidate().await;
    }
}

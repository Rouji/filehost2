use std::collections::HashSet;
use std::future::Future;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::db;
use crate::db_pool::DbPool;
use crate::model::BanType;
use crate::ttl_cache::KeyedTtlCache;

/// `KeyedTtlCache` with `K = ()`; the `Arc` means a cache hit clones a pointer rather
/// than the whole `HashSet`/`Vec`.
type TtlCell<T> = KeyedTtlCache<(), Arc<T>>;

/// `is_user_agent_banned` needs substring matching, not exact lookup, so it doesn't go
/// through here.
async fn is_in_cached_set<T, Q, F, Fut>(
    cell: &TtlCell<HashSet<T>>,
    fetch: F,
    needle: &Q,
) -> Result<bool, sqlx::Error>
where
    T: Eq + Hash + std::borrow::Borrow<Q>,
    Q: Eq + Hash + ?Sized,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<HashSet<T>, sqlx::Error>>,
{
    let set = cell
        .get_or_refresh((), || async { Ok(Arc::new(fetch().await?)) })
        .await?;
    Ok(set.contains(needle))
}

pub(crate) struct BanCache {
    ip_bans: KeyedTtlCache<(IpAddr, BanType), bool>,
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
        ip: IpAddr,
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
        let ext_lower = ext.to_lowercase();
        is_in_cached_set(
            &self.extensions,
            || async {
                Ok(db::list_banned_extensions(db)
                    .await?
                    .into_iter()
                    .map(|e| e.extension)
                    .collect())
            },
            &ext_lower,
        )
        .await
    }

    pub(crate) async fn is_mime_banned(
        &self,
        db: &DbPool,
        mime: &str,
    ) -> Result<bool, sqlx::Error> {
        let mime_lower = mime.to_lowercase();
        is_in_cached_set(
            &self.mimes,
            || async {
                Ok(db::list_banned_mimes(db)
                    .await?
                    .into_iter()
                    .map(|m| m.mime)
                    .collect())
            },
            &mime_lower,
        )
        .await
    }

    pub(crate) async fn is_hash_banned(
        &self,
        db: &DbPool,
        hash: &[u8],
    ) -> Result<bool, sqlx::Error> {
        is_in_cached_set(
            &self.hashes,
            || async {
                Ok(db::list_banned_hashes(db)
                    .await?
                    .into_iter()
                    .map(|h| h.hash)
                    .collect())
            },
            hash,
        )
        .await
    }

    pub(crate) async fn is_user_agent_banned(
        &self,
        db: &DbPool,
        user_agent: &str,
    ) -> Result<bool, sqlx::Error> {
        let patterns = self
            .user_agent_patterns
            .get_or_refresh((), || async {
                Ok(Arc::new(
                    db::list_banned_user_agents(db)
                        .await?
                        .into_iter()
                        .map(|u| u.pattern.to_lowercase())
                        .collect(),
                ))
            })
            .await?;
        let ua_lower = user_agent.to_lowercase();
        Ok(patterns.iter().any(|p| ua_lower.contains(p)))
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

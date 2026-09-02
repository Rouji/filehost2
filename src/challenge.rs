use std::net::IpAddr;
use std::time::Duration;

use crate::db;
use crate::db_pool::DbPool;
use crate::ttl_cache::KeyedTtlCache;

pub(crate) struct ChallengeCache {
    verified_ips: KeyedTtlCache<IpAddr, bool>,
}

impl ChallengeCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            verified_ips: KeyedTtlCache::new(ttl),
        }
    }

    pub(crate) async fn is_ip_verified(
        &self,
        db: &DbPool,
        ip: IpAddr,
    ) -> Result<bool, sqlx::Error> {
        self.verified_ips
            .get_or_refresh(ip, || db::is_ip_challenge_verified(db, ip))
            .await
    }

    /// Persists the IP as verified and updates the cache immediately, so a
    /// retried upload right after solving the challenge doesn't have to wait
    /// out the cache TTL.
    pub(crate) async fn mark_ip_verified(
        &self,
        db: &DbPool,
        ip: IpAddr,
        ttl_seconds: u64,
    ) -> Result<(), sqlx::Error> {
        db::upsert_challenge_verified_ip(db, ip, ttl_seconds).await?;
        self.verified_ips.set(ip, true).await;
        Ok(())
    }
}

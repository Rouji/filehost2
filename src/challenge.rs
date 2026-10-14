use std::net::IpAddr;
use std::time::Duration;

use crate::db;
use crate::db_pool::DbPool;
use crate::ttl_cache::KeyedTtlCache;

pub(crate) struct ChallengeCache {
    verified_ips: KeyedTtlCache<IpAddr, bool>,
    suspect_ips: KeyedTtlCache<IpAddr, bool>,
}

impl ChallengeCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            verified_ips: KeyedTtlCache::new(ttl),
            suspect_ips: KeyedTtlCache::new(ttl),
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

    async fn is_ip_suspect(
        &self,
        db: &DbPool,
        ip: IpAddr,
        nsfw_threshold: f32,
    ) -> Result<bool, sqlx::Error> {
        self.suspect_ips
            .get_or_refresh(ip, || db::has_nsfw_upload_last_week(db, ip, nsfw_threshold))
            .await
    }

    pub(crate) async fn needs_challenge(
        &self,
        db: &DbPool,
        ip: IpAddr,
        nsfw_threshold: f32,
    ) -> Result<bool, sqlx::Error> {
        if self.is_ip_verified(db, ip).await? {
            return Ok(false);
        }
        self.is_ip_suspect(db, ip, nsfw_threshold).await
    }

    pub(crate) async fn mark_ip_suspect(&self, ip: IpAddr) {
        self.suspect_ips.set(ip, true).await;
    }

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

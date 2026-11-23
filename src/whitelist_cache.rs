use std::net::IpAddr;
use std::time::Duration;

use crate::db;
use crate::db_pool::DbPool;
use crate::ttl_cache::KeyedTtlCache;

/// TTL cache for IP whitelist membership; same invalidation contract as
/// [`crate::ban_cache::BanCache`] — admin writes bump it so management
/// changes take effect without waiting out the TTL.
pub(crate) struct WhitelistCache {
    ip_whitelist: KeyedTtlCache<IpAddr, bool>,
}

impl WhitelistCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ip_whitelist: KeyedTtlCache::new(ttl),
        }
    }

    pub(crate) async fn is_ip_whitelisted(
        &self,
        db: &DbPool,
        ip: IpAddr,
    ) -> Result<bool, sqlx::Error> {
        self.ip_whitelist
            .get_or_refresh(ip, || db::is_ip_whitelisted(db, ip))
            .await
    }

    pub(crate) async fn invalidate(&self) {
        self.ip_whitelist.invalidate().await;
    }
}

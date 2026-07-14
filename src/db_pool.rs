use std::time::Duration;

use deadpool::managed::{self, Metrics, RecycleResult};
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection};
use sqlx::{ConnectOptions, Connection};

pub(crate) struct Manager {
    options: MySqlConnectOptions,
}

impl managed::Manager for Manager {
    type Type = MySqlConnection;
    type Error = sqlx::Error;

    async fn create(&self) -> Result<MySqlConnection, sqlx::Error> {
        self.options.connect().await
    }

    async fn recycle(&self, conn: &mut MySqlConnection, _: &Metrics) -> RecycleResult<sqlx::Error> {
        if let Err(e) = conn.ping().await {
            log::warn!("db_pool: dropping dead connection ({e})");
            return Err(e.into());
        }
        Ok(())
    }
}

pub(crate) type DbPool = managed::Pool<Manager>;
pub(crate) type DbConn = managed::Object<Manager>;

pub(crate) fn build_pool(options: MySqlConnectOptions, max_size: u32) -> anyhow::Result<DbPool> {
    let pool = DbPool::builder(Manager { options })
        .max_size(max_size as usize)
        .runtime(deadpool::Runtime::Tokio1)
        .timeouts(managed::Timeouts {
            wait: Some(Duration::from_secs(30)),
            create: Some(Duration::from_secs(30)),
            recycle: Some(Duration::from_secs(5)),
        })
        .build()?;
    Ok(pool)
}

/// checks out a connection, mapping deadpool's `PoolError` into `sqlx::Error` so every
/// existing `Result<_, sqlx::Error>` signature in the app is unaffected by the pool swap.
pub(crate) async fn conn(pool: &DbPool) -> Result<DbConn, sqlx::Error> {
    pool.get().await.map_err(|e| match e {
        managed::PoolError::Backend(e) => e,
        e => sqlx::Error::Io(std::io::Error::other(e.to_string())),
    })
}

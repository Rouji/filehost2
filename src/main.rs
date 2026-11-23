mod admin;
mod app;
mod asn;
mod ban_cache;
mod challenge;
mod clamd;
mod cli;
mod db;
mod db_pool;
mod dedup;
mod handlers;
mod ip;
mod model;
mod nsfw;
mod pow;
mod rate_limit;
mod settings;
mod sync;
mod templates;
mod ttl_cache;
mod upload;
mod util;
mod whitelist_cache;

#[cfg(test)]
mod tests;

use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, http::header, middleware::Logger, web,
};
use clap::Parser;
use futures_util::StreamExt;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use settings::Settings;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    dotenvy::dotenv().ok();

    let cli = cli::Cli::parse();

    let settings =
        Settings::from_env().expect("Failed to load settings from environment variables");

    let db_connect_options: sqlx::mysql::MySqlConnectOptions = settings
        .database_url
        .parse()
        .expect("Failed to parse DATABASE_URL");
    let db = db_pool::build_pool(db_connect_options, settings.db_max_connections)
        .expect("Failed to build database pool");

    if let Some(command) = cli.command {
        let result = match command {
            cli::Command::Migrate => cli::migrate(&db).await,
            cli::Command::DeleteExpired => cli::delete_expired(&db, &settings).await,
            cli::Command::Delete { target } => cli::delete(&db, &settings, target).await,
            cli::Command::Dedup { dry_run } => cli::dedup(&db, &settings, dry_run).await,
            cli::Command::Rehash => cli::rehash(&db, &settings).await,
            cli::Command::Rensfw { all, dry_run } => {
                cli::rensfw(&db, &settings, all, dry_run).await
            }
            cli::Command::Blacklist { command } => cli::blacklist(&db, command).await,
            cli::Command::AsnSync { path } => cli::asn_sync(&db, path.as_deref()).await,
            cli::Command::Ban { target } => cli::ban(&db, target).await,
            cli::Command::Whitelist { command } => cli::whitelist(&db, command).await,
        };
        if let Err(e) = result {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Server path only: subcommands like `migrate` never store files, so a
    // MAX_FILESIZE that only matters for uploads shouldn't block them.
    if let Err(e) = settings.validate() {
        log::error!("{e}");
        return Err(std::io::Error::other(e));
    }

    if let Err(e) = db::run_migrations(&db).await {
        log::error!("failed to run database migrations: {e}");
        return Err(std::io::Error::other("migration failure"));
    }

    let acme_domains = app::parse_acme_domains(settings.acme_domains.as_deref());

    let state = web::Data::new(app::AppState::new(db.clone(), settings.clone()));
    let xff_credible = state.xff_trust.proxy_count() > 0;

    let log_format = if xff_credible {
        "%{r}a %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T"
    } else {
        "%a %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T"
    };

    let tls_config = acme_domains.map(|domains| setup_acme(&settings, domains));

    let http_server = HttpServer::new(move || {
        App::new()
            .configure(|cfg| app::configure(cfg, state.clone()))
            .wrap(rate_limit::RequestRateLimiter)
            .wrap(Logger::new(log_format))
    });
    let server = match tls_config {
        Some(config) => http_server
            .bind_rustls_0_23((settings.listen_addr.clone(), settings.listen_port), config)?,
        None => http_server.bind_auto_h2c((settings.listen_addr, settings.listen_port))?,
    };
    server.run().await
}

/// Builds the ACME state, spawns its event loop and the port-80 redirect
/// listener, and returns the rustls config for the TLS listener.
fn setup_acme(settings: &Settings, domains: Vec<String>) -> rustls_acme::rustls::ServerConfig {
    let cache_dir = settings
        .acme_cache_dir
        .clone()
        .unwrap_or_else(|| "acme-cache".to_string());
    let mut config = AcmeConfig::new(domains.iter())
        .contact_push(format!("mailto:{}", settings.admin_email))
        .cache(DirCache::new(cache_dir));
    config = match settings.acme_directory_url.as_deref() {
        Some(url) => config.directory(url),
        _ => config.directory_lets_encrypt(true),
    };
    let mut state = config.state();
    let challenge_rustls_config =
        Arc::into_inner(state.challenge_rustls_config()).expect("acme: challenge rustls config");

    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(event)) => log::info!("acme: {event:?}"),
                Some(Err(err)) => log::error!("acme: {err:?}"),
                _ => break,
            }
        }
    });

    spawn_http_redirect(&settings.listen_addr, settings.listen_port);
    challenge_rustls_config
}

/// Plain HTTP on port 80 only redirects to HTTPS — unless the TLS listener
/// itself is on port 80 (TLS-ALPN-01 needs 443 anyway, so that would be a
/// misconfiguration).
fn spawn_http_redirect(listen_addr: &str, tls_port: u16) {
    if tls_port == 80 {
        return;
    }
    match HttpServer::new(|| {
        App::new().default_service(web::to(|req: HttpRequest| async move {
            let host = req.connection_info().host().to_string();
            Ok::<HttpResponse, Error>(
                HttpResponse::PermanentRedirect()
                    .insert_header((header::LOCATION, format!("https://{host}{}", req.uri())))
                    .finish(),
            )
        }))
    })
    .bind((listen_addr.to_string(), 80))
    {
        Ok(srv) => {
            log::info!("listening on port 80 to redirect to https");
            let srv_run = srv.run();
            tokio::spawn(async move {
                if let Err(err) = srv_run.await {
                    log::error!("http redirect server error: {err}");
                }
            });
        }
        Err(err) => log::error!("failed to bind http redirect listener on port 80: {err}"),
    }
}

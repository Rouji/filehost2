mod admin;
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

#[cfg(test)]
mod tests;

use actix_cors::Cors;
use actix_multipart::{MultipartError, form::MultipartFormConfig};
use actix_web::{App, Error, HttpRequest, HttpServer, http::header, middleware::Logger, web};
use clap::Parser;
use futures_util::StreamExt;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use settings::Settings;
use std::sync::Arc;

fn handle_multipart_error(err: MultipartError, _req: &HttpRequest) -> Error {
    match err {
        MultipartError::Payload(inner) => inner.into(),
        _ => Error::from(err),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    dotenvy::dotenv().ok();

    let cli = cli::Cli::parse();

    let mut settings =
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
            cli::Command::Ban { target } => cli::ban(&db, target).await,
        };
        if let Err(e) = result {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    let acme_domains: Option<Vec<String>> = settings
        .acme_domains
        .as_deref()
        .map(|domains| {
            domains
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .filter(|domains: &Vec<String>| !domains.is_empty());

    if settings.base_url.is_none() {
        let scheme = if acme_domains.is_some() {
            "https"
        } else {
            "http"
        };
        settings.base_url = Some(format!(
            "{scheme}://{}:{}/",
            settings.listen_addr, settings.listen_port
        ));
    }

    let rendered_templates = templates::render(&settings);
    let throttle = web::Data::new(rate_limit::UploadThrottle::new());
    let ban_cache = web::Data::new(ban_cache::BanCache::new(std::time::Duration::from_secs(
        settings.ban_cache_ttl_seconds,
    )));
    let challenge_cache = web::Data::new(challenge::ChallengeCache::new(
        std::time::Duration::from_secs(settings.ban_cache_ttl_seconds),
    ));
    let pow_secret = web::Data::new(pow::PowSecret::generate());

    let nsfw_model = web::Data::new(match settings.nsfw_model_path() {
        Some(path) => match nsfw::NsfwModel::load(path) {
            Ok(model) => {
                log::info!("nsfw: loaded model from {}", path.display());
                Some(std::sync::Arc::new(model))
            }
            Err(e) => {
                log::error!("nsfw: failed to load model from {}: {e:#}", path.display());
                None
            }
        },
        None => None,
    });

    // `%a` is the raw peer address, which is the reverse proxy's IP rather
    // than the client's whenever trust_xff is set; `%{r}a` resolves the
    // client IP from X-Forwarded-For/Forwarded instead, matching the
    // XFF-aware IP resolution already used for the DB access log.
    let log_format = if settings.trust_xff {
        "%{r}a %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T"
    } else {
        "%a %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T"
    };

    let s = settings.clone();
    let acme = acme_domains.map(|domains| {
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
        let state = config.state();
        let challenge_rustls_config = Arc::into_inner(state.challenge_rustls_config())
            .expect("acme: challenge rustls config");
        (state, challenge_rustls_config)
    });

    let http_server = HttpServer::new(move || {
        App::new()
            .service(handlers::index)
            .service(handlers::upload)
            .service(handlers::captcha_page)
            .service(handlers::captcha_js)
            .service(handlers::captcha_challenge)
            .service(handlers::captcha_verify)
            .service(handlers::get_file)
            .service(
                web::scope("/admin")
                    .wrap(
                        Cors::default()
                            .allow_any_origin()
                            .allowed_methods([
                                actix_web::http::Method::GET,
                                actix_web::http::Method::POST,
                                actix_web::http::Method::DELETE,
                            ])
                            .allowed_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
                    )
                    .configure(admin::configure),
            )
            .wrap(Logger::new(log_format))
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(s.clone()))
            .app_data(web::Data::new(rendered_templates.clone()))
            .app_data(throttle.clone())
            .app_data(ban_cache.clone())
            .app_data(challenge_cache.clone())
            .app_data(pow_secret.clone())
            .app_data(nsfw_model.clone())
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(s.max_filesize * 1024 * 1024)
                    .error_handler(handle_multipart_error),
            )
    });
    let server = match acme {
        Some((mut state, challenge_rustls_config)) => {
            tokio::spawn(async move {
                loop {
                    match state.next().await {
                        Some(Ok(event)) => log::info!("acme: {event:?}"),
                        Some(Err(err)) => log::error!("acme: {err:?}"),
                        _ => break,
                    }
                }
            });
            http_server.bind_rustls_0_23(
                (settings.listen_addr.clone(), settings.listen_port),
                challenge_rustls_config,
            )?
        }
        _ => http_server.bind_auto_h2c((settings.listen_addr, settings.listen_port))?,
    };
    server.run().await
}

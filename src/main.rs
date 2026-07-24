mod admin;
mod ban_cache;
mod clamd;
mod cli;
mod db;
mod db_pool;
mod dedup;
mod handlers;
mod import;
mod model;
mod rate_limit;
mod settings;
mod sync;
mod templates;
mod upload;

#[cfg(test)]
mod tests;

use actix_multipart::{MultipartError, form::MultipartFormConfig};
use actix_web::{App, Error, HttpRequest, HttpServer, middleware::Logger, web};
use clap::Parser;
use settings::Settings;

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
            cli::Command::ImportPhp { files, log } => {
                cli::import_php(&db, &settings, files, log).await
            }
            cli::Command::Dedup { dry_run } => cli::dedup(&db, &settings, dry_run).await,
            cli::Command::Rehash => cli::rehash(&db, &settings).await,
            cli::Command::Blacklist { command } => cli::blacklist(&db, command).await,
        };
        if let Err(e) = result {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if settings.base_url.is_none() {
        settings.base_url = Some(format!(
            "http://{}:{}/",
            settings.listen_addr, settings.listen_port
        ));
    }

    let rendered_templates = templates::render(&settings);
    let throttle = web::Data::new(rate_limit::UploadThrottle::new());
    let ban_cache = web::Data::new(ban_cache::BanCache::new(std::time::Duration::from_secs(
        settings.ban_cache_ttl_seconds,
    )));

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
    HttpServer::new(move || {
        App::new()
            .service(handlers::index)
            .service(handlers::get_file)
            .service(handlers::upload)
            .service(web::scope("/admin").configure(admin::configure))
            .wrap(Logger::new(log_format))
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(s.clone()))
            .app_data(web::Data::new(rendered_templates.clone()))
            .app_data(throttle.clone())
            .app_data(ban_cache.clone())
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(s.max_filesize * 1024 * 1024)
                    .error_handler(handle_multipart_error),
            )
    })
    .bind_auto_h2c((settings.listen_addr, settings.listen_port))?
    .run()
    .await
}

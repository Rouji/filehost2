mod cli;
mod handlers;
mod model;
mod settings;
mod templates;
mod upload;

#[cfg(test)]
mod tests;

use actix_multipart::{MultipartError, form::MultipartFormConfig};
use actix_web::{App, Error, HttpRequest, HttpServer, middleware::Logger, web};
use clap::Parser;
use settings::Settings;
use sqlx::mysql::MySqlPool;

fn handle_multipart_error(err: MultipartError, _req: &HttpRequest) -> Error {
    match err {
        MultipartError::Payload(inner) => inner.into(),
        _ => Error::from(err),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = cli::Cli::parse();

    let mut settings =
        Settings::from_env().expect("Failed to load settings from environment variables");

    let db = MySqlPool::connect(&settings.database_url)
        .await
        .expect("Failed to connect to database");

    if let Some(command) = cli.command {
        let result = match command {
            cli::Command::Migrate => cli::migrate(&db).await,
            cli::Command::DeleteExpired => cli::delete_expired(&db, &settings).await,
            cli::Command::Delete { target } => cli::delete(&db, &settings, target).await,
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

    let s = settings.clone();
    HttpServer::new(move || {
        App::new()
            .service(handlers::index)
            .service(handlers::get_file)
            .service(handlers::upload)
            .wrap(Logger::default())
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(s.clone()))
            .app_data(web::Data::new(rendered_templates.clone()))
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(s.max_filesize * 1024 * 1024)
                    .error_handler(handle_multipart_error),
            )
    })
    .bind((settings.listen_addr, settings.listen_port))?
    .run()
    .await
}

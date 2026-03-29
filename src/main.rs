mod model;
mod settings;
use model::Upload;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use actix_files::NamedFile;
use actix_multipart::{
    MultipartError,
    form::{MultipartForm, MultipartFormConfig, tempfile::TempFile},
};
use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder, get,
    http::header::{ContentDisposition, ContentType},
    middleware::Logger,
    post, web,
};
use rand::distr::{Alphanumeric, SampleString};
use serde::Deserialize;
use settings::Settings;
use sqlx::{Connection, mysql::MySqlPool, query, query_as};
use tinytemplate::TinyTemplate;

#[derive(Debug, Deserialize)]
enum Config {
    Hupl,
    ShareX,
}

#[derive(Debug, Deserialize)]
struct IndexQuery {
    config: Option<Config>,
}

#[get("/")]
async fn index(
    rendered_templates: web::Data<RenderedTemplates>,
    settings: web::Data<Settings>,
    query: web::Query<IndexQuery>,
) -> impl Responder {
    //    let blah = n
    match query.config {
        Some(Config::Hupl) => HttpResponse::Ok()
            .content_type(ContentType::json())
            .insert_header(ContentDisposition::attachment(
                settings.name.clone() + ".hupl",
            ))
            .body(rendered_templates.hupl.clone()),
        Some(Config::ShareX) => HttpResponse::Ok()
            .content_type(ContentType::json())
            .insert_header(ContentDisposition::attachment(
                settings.name.clone() + ".sxcu",
            ))
            .body(rendered_templates.sharex.clone()),
        None => HttpResponse::Ok().body(rendered_templates.index.clone()),
    }
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<TempFile>,
}

fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

fn uuid_to_path(root: &Path, uuid: &Uuid) -> PathBuf {
    let folder = format!("{:04x}", uuid.as_u128() >> 112);
    root.join(folder).join(uuid.to_string())
}

#[post("/")]
async fn upload(
    MultipartForm(form): MultipartForm<UploadForm>,
    db: web::Data<MySqlPool>,
    settings: web::Data<Settings>,
) -> impl Responder {
    let uuid = Uuid::new_v4();
    let mut response = String::new();
    for f in form.files {
        let slug = random_string(5);
        let save_path = uuid_to_path(Path::new(&settings.store_path), &uuid);

        f.file.persist(&save_path).unwrap();

        let link = format!(
            "{}{}\n",
            settings.base_url.as_ref().unwrap(),
            save_path.file_name().unwrap().to_str().unwrap(),
        );
        response.push_str(&link);
    }

    let query = query_as!(
        Upload,
        "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size) VALUES (?, ?, ?, ?, ?)",
        uuid,
        "test",
        "2024-01-01 00:00:00",
        "abcde",
        0,
    );

    query.execute(db.get_ref()).await.unwrap();

    //let query = query_as!(String, "SELECT slug FROM uploads;",);
    //query.fetch_one(db.get_ref()).await.unwrap();

    HttpResponse::Ok().body(response)
}

#[get("/{id}")]
async fn file(
    path: web::Path<(String,)>,
    settings: web::Data<Settings>,
) -> actix_web::Result<NamedFile> {
    let path = Path::new(&settings.store_path).join(&path.0);
    Ok(NamedFile::open(path)?.use_last_modified(true))
}

fn handle_multipart_error(err: MultipartError, _req: &HttpRequest) -> Error {
    match err {
        MultipartError::Payload(inner) => inner.into(),
        _ => Error::from(err),
    }
}

#[derive(Clone)]
struct RenderedTemplates {
    index: String,
    hupl: String,
    sharex: String,
}

fn render_templates(settings: &Settings) -> RenderedTemplates {
    let mut tt = TinyTemplate::new();
    tt.add_template("index", include_str!("../templates/index.html"))
        .expect("Failed to add template");
    tt.add_template("hupl", include_str!("../templates/hupl.json"))
        .expect("Failed to add template");
    tt.add_template("sharex", include_str!("../templates/sharex.sxcu"))
        .expect("Failed to add template");

    RenderedTemplates {
        index: tt
            .render("index", &settings)
            .expect("Failed to render index template"),
        hupl: tt
            .render("hupl", &settings)
            .expect("Failed to render hupl template"),
        sharex: tt
            .render("sharex", &settings)
            .expect("Failed to render sharex template"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut settings =
        Settings::from_env().expect("Failed to load settings from environment variables");

    if settings.base_url.is_none() {
        settings.base_url = Some(format!(
            "{}://{}:{}/",
            "http", settings.listen_addr, settings.listen_port
        ));
    }

    let rendered_templates = render_templates(&settings);

    let db = MySqlPool::connect(&settings.database_url)
        .await
        .expect("Failed to connect to database");

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let s = settings.clone();
    HttpServer::new(move || {
        App::new()
            .service(index)
            .service(file)
            .service(upload)
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

use std::path::Path;

use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile, text::Text};
use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    http::header::{ContentDisposition, ContentType},
    post, web,
};
use serde::Deserialize;
use sqlx::mysql::MySqlPool;
use uuid::Uuid;

use crate::model::Upload;
use crate::settings::Settings;
use crate::templates::RenderedTemplates;
use crate::upload::{build_slug, calculate_expiry, md5_file, uuid_to_path};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Config {
    Hupl,
    ShareX,
}

#[derive(Debug, Deserialize)]
struct IndexQuery {
    config: Option<Config>,
}

#[get("/")]
pub(crate) async fn index(
    rendered_templates: web::Data<RenderedTemplates>,
    settings: web::Data<Settings>,
    query: web::Query<IndexQuery>,
) -> impl Responder {
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
pub(crate) struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<TempFile>,
    id_length: Option<Text<usize>>,
}

#[post("/")]
pub(crate) async fn upload(
    req: HttpRequest,
    MultipartForm(form): MultipartForm<UploadForm>,
    db: web::Data<MySqlPool>,
    settings: web::Data<Settings>,
) -> impl Responder {
    let id_len = form
        .id_length
        .as_ref()
        .map(|t| t.0.clamp(settings.min_id_length, settings.max_id_length))
        .unwrap_or(settings.min_id_length);

    let uploader_ip: Option<u32> = req
        .peer_addr()
        .and_then(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => Some(u32::from(ip)),
            std::net::IpAddr::V6(_) => None,
        });

    let mut response = String::new();
    for file in form.files {
        let uuid = Uuid::new_v4();
        let original_name = file.file_name.as_deref().unwrap_or("unknown").to_string();
        let mime_str = match file.content_type {
            Some(ref ct) => Some(ct.to_string()),
            None => None,
        };
        let ct_subtype = match file.content_type {
            Some(ref ct) => Some(ct.subtype().to_string()),
            None => None,
        };

        let slug = build_slug(
            &original_name,
            ct_subtype.as_deref(),
            id_len,
            settings.auto_file_ext,
            settings.max_ext_len,
        );
        let expiry = calculate_expiry(file.size, &settings);
        let save_path = uuid_to_path(Path::new(&settings.store_path), &uuid);

        if let Some(ref mime) = mime_str {
            let banned = sqlx::query!(
                "SELECT 1 as banned FROM banned_file_mimes WHERE mime = ?",
                mime,
            )
            .fetch_optional(db.get_ref())
            .await;
            match banned {
                Ok(Some(_)) => return HttpResponse::Forbidden().finish(),
                Err(e) => {
                    log::error!("DB banned mime check failed: {e}");
                    return HttpResponse::InternalServerError().finish();
                }
                Ok(None) => {}
            }
        } else {
            log::warn!(
                "No content type provided for file {}, skipping MIME type check",
                original_name
            );
        }

        // TODO: maybe move this into some background process to avoid blocking the request?
        let hash = match md5_file(file.file.path().to_path_buf()).await {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to hash file: {e}");
                return HttpResponse::InternalServerError().finish();
            }
        };

        // Reject if the hash is banned.
        let banned = sqlx::query!(
            "SELECT 1 as banned FROM banned_file_hashes WHERE hash = ?",
            hash.as_slice(),
        )
        .fetch_optional(db.get_ref())
        .await;
        match banned {
            Ok(Some(_)) => return HttpResponse::Forbidden().finish(),
            Err(e) => {
                log::error!("DB banned hash check failed: {e}");
                return HttpResponse::InternalServerError().finish();
            }
            Ok(None) => {}
        }

        if let Err(e) = std::fs::create_dir_all(save_path.parent().unwrap()) {
            log::error!("Failed to create directory: {e}");
            return HttpResponse::InternalServerError().finish();
        }

        if let Err(e) = file.file.persist(&save_path) {
            if e.error.kind() == std::io::ErrorKind::CrossesDevices {
                if let Err(copy_err) = std::fs::copy(e.file.path(), &save_path) {
                    log::error!("Failed to copy file: {copy_err}");
                    return HttpResponse::InternalServerError().finish();
                }
            } else {
                log::error!("Failed to persist file: {}", e.error);
                return HttpResponse::InternalServerError().finish();
            }
        }

        let result = sqlx::query!(
            "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
            uuid,
            original_name,
            expiry,
            slug,
            file.size as i64,
            hash.as_slice(),
            uploader_ip,
        )
        .execute(db.get_ref())
        .await;

        if let Err(e) = result {
            log::error!("DB insert failed: {e}");
            return HttpResponse::InternalServerError().finish();
        }

        let link = format!("{}{}\n", settings.base_url.as_ref().unwrap(), slug);
        response.push_str(&link);
    }

    HttpResponse::Ok().body(response)
}

#[get("/{slug}")]
pub(crate) async fn get_file(
    path: web::Path<(String,)>,
    db: web::Data<MySqlPool>,
    settings: web::Data<Settings>,
) -> actix_web::Result<NamedFile> {
    let slug = &path.0;

    let row = sqlx::query_as!(
        Upload,
        "SELECT id as `id: Uuid`, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, slug, file_size, hash as `hash: Vec<u8>`, uploader_ip FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
        slug
    )
    .fetch_optional(db.get_ref())
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?
    .ok_or_else(|| actix_web::error::ErrorNotFound("File not found"))?;

    let file_path = uuid_to_path(Path::new(&settings.store_path), &row.id);
    Ok(NamedFile::open(file_path)?
        .use_last_modified(true)
        .set_content_disposition(ContentDisposition {
            disposition: actix_web::http::header::DispositionType::Attachment,
            parameters: vec![actix_web::http::header::DispositionParam::Filename(
                row.original_name,
            )],
        }))
}

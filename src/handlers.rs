use std::path::Path;

use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile, text::Text};
use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    http::header::{ContentDisposition, ContentType, DispositionParam, DispositionType},
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

    let uploader_ip: Option<u32> = req.peer_addr().and_then(|addr| match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(u32::from(ip)),
        std::net::IpAddr::V6(_) => None,
    });

    let mut response = String::new();
    for file in form.files {
        let uuid = Uuid::new_v4();
        let original_name = file.file_name.as_deref().unwrap_or("unknown").to_string();
        // Use client-provided Content-Type; fall back to guessing from filename.
        let content_type_str: String = file
            .content_type
            .as_ref()
            .map(|ct| ct.to_string())
            .unwrap_or_else(|| {
                mime_guess::from_path(&original_name)
                    .first_or_octet_stream()
                    .to_string()
            });
        let mime_str = Some(content_type_str.clone());
        let ct_subtype: Option<String> = file
            .content_type
            .as_ref()
            .map(|ct| ct.subtype().to_string())
            .or_else(|| {
                mime_guess::from_path(&original_name)
                    .first()
                    .map(|m| m.subtype().as_str().to_string())
            });

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
            "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            uuid,
            original_name,
            expiry,
            slug,
            file.size as i64,
            hash.as_slice(),
            uploader_ip,
            content_type_str,
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
        "SELECT id as `id: Uuid`, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, slug, file_size, hash as `hash: Vec<u8>`, uploader_ip, content_type FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
        slug
    )
    .fetch_optional(db.get_ref())
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?
    .ok_or_else(|| actix_web::error::ErrorNotFound("File not found"))?;

    let mime: mime_guess::Mime = row
        .content_type
        .as_deref()
        .and_then(|s| s.parse::<mime_guess::Mime>().ok())
        .unwrap_or(mime_guess::mime::APPLICATION_OCTET_STREAM);

    let disposition = match mime.type_().as_str() {
        "image" | "video" | "audio" => DispositionType::Inline,
        "text" if mime.subtype().as_str() == "plain" => DispositionType::Inline,
        "application" if matches!(mime.subtype().as_str(), "json" | "pdf") => {
            DispositionType::Inline
        }
        _ => DispositionType::Attachment,
    };

    // Serve non-plain text types (html, js, css, …) as text/plain so browsers don't execute them
    let serve_mime = match mime.type_().as_str() {
        "text" if mime.subtype().as_str() != "plain" => mime_guess::mime::TEXT_PLAIN,
        _ => mime,
    };

    let file_path = uuid_to_path(Path::new(&settings.store_path), &row.id);
    Ok(NamedFile::open(file_path)?
        .use_last_modified(true)
        .set_content_type(serve_mime)
        .set_content_disposition(ContentDisposition {
            disposition,
            parameters: vec![DispositionParam::Filename(row.original_name)],
        }))
}

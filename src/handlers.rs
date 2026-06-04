use std::path::Path;

use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile, text::Text};
use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    http::{StatusCode, header::{ContentDisposition, ContentType, DispositionParam, DispositionType}},
    post, web,
};
use serde::Deserialize;
use sqlx::mysql::MySqlPool;
use uuid::Uuid;

use crate::db;
use crate::model::Upload;
use crate::settings::Settings;
use crate::templates::RenderedTemplates;
use crate::upload::{build_slug, calculate_expiry, md5_file, uuid_to_path};

fn error_page(status: StatusCode, message: &str) -> HttpResponse {
    let body = format!("{status} {message}");
    HttpResponse::build(status)
        .content_type(ContentType::plaintext())
        .body(body)
}

fn determine_content_type(file: &TempFile, original_name: &str) -> (String, Option<String>) {
    let content_type_str = file
        .content_type
        .as_ref()
        .map(|ct| ct.to_string())
        .unwrap_or_else(|| {
            mime_guess::from_path(original_name)
                .first_or_octet_stream()
                .to_string()
        });
    let ct_subtype = file
        .content_type
        .as_ref()
        .map(|ct| ct.subtype().to_string())
        .or_else(|| {
            mime_guess::from_path(original_name)
                .first()
                .map(|m| m.subtype().as_str().to_string())
        });
    (content_type_str, ct_subtype)
}

fn save_file(tmp: tempfile::NamedTempFile, dest: &Path) -> std::io::Result<()> {
    match tmp.persist(dest) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == std::io::ErrorKind::CrossesDevices => {
            std::fs::copy(e.file.path(), dest)?;
            Ok(())
        }
        Err(e) => Err(e.error),
    }
}

async fn process_file(
    db: &MySqlPool,
    settings: &Settings,
    file: TempFile,
    uploader_ip: Option<u32>,
    id_len: usize,
) -> Result<String, HttpResponse> {
    let uuid = Uuid::new_v4();
    let original_name = file.file_name.as_deref().unwrap_or("unknown").to_string();
    let file_size = file.size;

    let internal_err = || error_page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.");

    if let Some(ext) = Path::new(&original_name).extension().and_then(|e| e.to_str()) {
        match db::is_extension_banned(db, ext).await {
            Ok(true) => return Err(error_page(StatusCode::FORBIDDEN, "File type not allowed.")),
            Err(e) => {
                log::error!("banned extension check failed: {e}");
                return Err(internal_err());
            }
            Ok(false) => {}
        }
    }

    let (content_type_str, ct_subtype) = determine_content_type(&file, &original_name);

    let slug = build_slug(
        &original_name,
        ct_subtype.as_deref(),
        id_len,
        settings.auto_file_ext,
        settings.max_ext_len,
    );
    let expiry = calculate_expiry(file_size, settings);
    let save_path = uuid_to_path(Path::new(&settings.store_path), &uuid);

    match db::is_mime_banned(db, &content_type_str).await {
        Ok(true) => return Err(error_page(StatusCode::FORBIDDEN, "Your upload was rejected.")),
        Err(e) => {
            log::error!("banned mime check failed: {e}");
            return Err(internal_err());
        }
        Ok(false) => {}
    }

    // TODO: maybe move this into some background process to avoid blocking the request?
    let hash = match md5_file(file.file.path().to_path_buf()).await {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to hash file: {e}");
            return Err(internal_err());
        }
    };

    match db::is_hash_banned(db, hash.as_slice()).await {
        Ok(true) => return Err(error_page(StatusCode::FORBIDDEN, "Your upload was rejected.")),
        Err(e) => {
            log::error!("banned hash check failed: {e}");
            return Err(internal_err());
        }
        Ok(false) => {}
    }

    if let Err(e) = std::fs::create_dir_all(save_path.parent().unwrap()) {
        log::error!("Failed to create directory: {e}");
        return Err(internal_err());
    }

    if let Err(e) = save_file(file.file, &save_path) {
        log::error!("Failed to save file: {e}");
        return Err(internal_err());
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        uuid, original_name, expiry, slug, file_size as i64, hash.as_slice(), uploader_ip, content_type_str,
    )
    .execute(db)
    .await
    {
        log::error!("insert failed: {e}");
        return Err(internal_err());
    }

    Ok(format!("{}{}\n", settings.base_url.as_ref().unwrap(), slug))
}

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
    let id_len = if let Some(ref t) = form.id_length {
        t.0.clamp(settings.min_id_length, settings.max_id_length)
    } else {
        settings.min_id_length
    };

    let uploader_ip: Option<u32> = req.peer_addr().and_then(|addr| match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(u32::from(ip)),
        std::net::IpAddr::V6(_) => None,
    });

    if let Some(ip) = uploader_ip {
        match db::is_ip_banned(db.get_ref(), ip).await {
            Ok(true) => {
                return error_page(StatusCode::FORBIDDEN, "Your IP is banned from uploading.")
            }
            Err(e) => {
                log::error!("banned IP check failed: {e}");
                return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.");
            }
            Ok(false) => {}
        }
    }

    let mut response = String::new();
    for file in form.files {
        match process_file(db.get_ref(), &settings, file, uploader_ip, id_len).await {
            Ok(link) => response.push_str(&link),
            Err(resp) => return resp,
        }
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

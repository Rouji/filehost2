use core::iter::IntoIterator;
use std::path::Path;
use std::sync::Arc;

use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, text::Text};
use actix_web::{
    FromRequest, HttpRequest, HttpResponse, Responder, get,
    http::{
        StatusCode,
        header::{ContentDisposition, ContentType, DispositionParam, DispositionType},
    },
    post, web,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use uuid::Uuid;

use crate::ban_cache::BanCache;
use crate::clamd;
use crate::db;
use crate::db_pool::DbPool;
use crate::model::BanType;
use crate::nsfw::NsfwModel;
use crate::settings::Settings;
use crate::templates::RenderedTemplates;
use crate::upload::{HashedTempFile, build_slug, calculate_expiry, extract_ip, uuid_to_path};

/// Characters that don't need percent-encoding in a URL path segment,
/// on top of what `NON_ALPHANUMERIC` already leaves alone.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn error_page(status: StatusCode, message: &str) -> HttpResponse {
    let body = format!("{status} {message}");
    HttpResponse::build(status)
        .content_type(ContentType::plaintext())
        .body(body)
}

fn format_ip(ip: Option<std::net::IpAddr>) -> String {
    ip.map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn respond_to_check(
    condition: Result<bool, sqlx::Error>,
    ip: Option<std::net::IpAddr>,
    check_name: &str,
    fail_status: StatusCode,
    fail_message: &str,
) -> Result<(), HttpResponse> {
    match condition {
        Ok(true) => {
            log::info!("upload rejected: {check_name} (ip={})", format_ip(ip));
            Err(error_page(fail_status, fail_message))
        }
        Ok(false) => Ok(()),
        Err(e) => {
            log::error!("{check_name} check failed: {e}");
            Err(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong.",
            ))
        }
    }
}

/// Runs a `db::is_*_banned` check and turns it into a response: forbidden if
/// banned, a logged 500 if the check itself failed, otherwise `Ok(())`.
async fn check_not_banned(
    check: impl std::future::Future<Output = Result<bool, sqlx::Error>>,
    ip: Option<std::net::IpAddr>,
    check_name: &str,
    forbidden_message: &str,
) -> Result<(), HttpResponse> {
    respond_to_check(
        check.await,
        ip,
        check_name,
        StatusCode::FORBIDDEN,
        forbidden_message,
    )
}

async fn check_under_limit(
    limit: Option<i64>,
    check: impl std::future::Future<Output = Result<i64, sqlx::Error>>,
    ip: Option<std::net::IpAddr>,
    check_name: &str,
    too_many_message: &str,
) -> Result<(), HttpResponse> {
    let Some(limit) = limit else {
        return Ok(());
    };
    respond_to_check(
        check.await.map(|n| n >= limit),
        ip,
        check_name,
        StatusCode::TOO_MANY_REQUESTS,
        too_many_message,
    )
}

/// get content_type from the file
/// or guess from file name, if it's octet-stream or not set at all
fn determine_content_type(file: &HashedTempFile, original_name: &str) -> (String, Option<String>) {
    if let Some(ref ct) = file.content_type
        && *ct != mime_guess::mime::APPLICATION_OCTET_STREAM
    {
        return (ct.to_string(), Some(ct.subtype().to_string()));
    }

    let guess = mime_guess::from_path(original_name).first();
    (
        guess
            .as_ref()
            .map(|m| m.to_string())
            .unwrap_or_else(|| mime_guess::mime::APPLICATION_OCTET_STREAM.to_string()),
        guess.map(|m| m.subtype().as_str().to_string()),
    )
}

fn save_file(tmp: tempfile::NamedTempFile, dest: &Path) -> std::io::Result<()> {
    match tmp.persist(dest) {
        Ok(_) => Ok(()),
        Err(e) => {
            std::fs::copy(e.file.path(), dest)?;
            Ok(())
        }
    }
}

/// Slug space grows exponentially with `id_len`, so bumping it after a few collisions
/// always converges in practice.
async fn allocate_unique_slug(
    db: &DbPool,
    original_name: &str,
    ct_subtype: Option<&str>,
    settings: &Settings,
    keep_name: bool,
    mut id_len: usize,
) -> Result<String, HttpResponse> {
    const MAX_SLUG_ATTEMPTS: u32 = 3;
    loop {
        for _ in 0..MAX_SLUG_ATTEMPTS {
            let candidate = build_slug(
                original_name,
                ct_subtype,
                id_len,
                settings.auto_file_ext,
                settings.max_ext_len,
                keep_name,
            );
            match db::is_slug_taken(db, &candidate).await {
                Ok(true) => continue,
                Ok(false) => return Ok(candidate),
                Err(e) => {
                    log::error!("failed to check slug availability: {e}");
                    return Err(error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Something went wrong.",
                    ));
                }
            }
        }
        id_len += 1;
    }
}

fn reconcile_content_type_for_db(
    detected_content_type: Option<&mime::Mime>,
    content_type_str: String,
) -> String {
    let Some(detected) = detected_content_type else {
        return content_type_str;
    };

    // "text" and "octet-stream" are just fallbacks the sniffer reports when it couldn't
    // identify anything more specific, so they're not meaningful enough to override
    // whatever the client/guessed type already said.
    let sniffer_found_something_specific =
        detected.type_() != "text" && *detected != mime_guess::mime::APPLICATION_OCTET_STREAM;
    if sniffer_found_something_specific {
        return detected.to_string();
    }

    // The other direction: the client/guessed type was a meaningless "octet-stream", but
    // the sniffer at least confirmed the content is text. Normalize to `text/plain`
    // rather than keeping the uninformative fallback.
    let client_type_was_octet_stream = content_type_str == "application/octet-stream";
    if detected.type_() == "text" && client_type_was_octet_stream {
        return "text/plain".to_string();
    }

    content_type_str
}

/// Takes ownership of everything since it outlives `process_file`'s return.
fn spawn_clamd_scan(
    db: DbPool,
    settings: Settings,
    uuid: Uuid,
    slug: String,
    save_path: std::path::PathBuf,
) {
    let Some(addr) = settings.clamd_addr.clone() else {
        return;
    };
    tokio::spawn(async move {
        match clamd::scan_file(&addr, &save_path).await {
            Ok(clamd::ScanResult::Clean) => log::info!("clamd: {uuid} ({slug}) clean"),
            Ok(clamd::ScanResult::Infected(name)) => {
                log::warn!("clamd: {uuid} ({slug}) infected with {name:?}, deleting");
                if let Err(e) = db::delete_by_id(&db, &settings, uuid).await {
                    log::error!("clamd: failed to delete infected file {uuid}: {e}");
                }
            }
            Err(e) => log::error!("clamd: scan failed for {uuid} ({slug}): {e}"),
        }
    });
}

fn spawn_nsfw_scan(
    nsfw_model: Option<Arc<NsfwModel>>,
    db: DbPool,
    uuid: Uuid,
    slug: String,
    save_path: std::path::PathBuf,
) {
    let Some(model) = nsfw_model else {
        return;
    };
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || model.classify(&save_path)).await {
            Ok(Ok(c)) => {
                log::info!("nsfw: {uuid} ({slug}) score={:.3}", c.score);
                if let Err(e) = db::update_nsfw_score(&db, uuid, c.score).await {
                    log::error!("nsfw: failed to update score for {uuid}: {e}");
                }
            }
            Ok(Err(e)) => log::error!("nsfw: classification failed for {uuid} ({slug}): {e:#}"),
            Err(e) => log::error!("nsfw: scan task panicked for {uuid} ({slug}): {e}"),
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn process_file(
    db: &DbPool,
    ban_cache: &BanCache,
    settings: &Settings,
    nsfw_model: Option<Arc<NsfwModel>>,
    file: HashedTempFile,
    uploader_ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
    id_len: usize,
    keep_name: bool,
) -> Result<String, HttpResponse> {
    let original_name = file.file_name.as_deref().unwrap_or("unknown").to_string();
    let file_size = file.size;

    let internal_err = || error_page(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.");

    if let Some(ext) = Path::new(&original_name)
        .extension()
        .and_then(|e| e.to_str())
    {
        check_not_banned(
            ban_cache.is_extension_banned(db, ext),
            uploader_ip,
            "banned extension",
            "File type not allowed.",
        )
        .await?;
    }

    let (content_type_str, ct_subtype) = determine_content_type(&file, &original_name);

    for ct in [&file.content_type, &file.detected_content_type]
        .into_iter()
        .flatten()
    {
        check_not_banned(
            ban_cache.is_mime_banned(db, ct.as_ref()),
            uploader_ip,
            "banned mime",
            "Your upload was rejected.",
        )
        .await?;
    }

    let hash = file.hash;

    check_not_banned(
        ban_cache.is_hash_banned(db, hash.as_slice()),
        uploader_ip,
        "banned hash",
        "Your upload was rejected.",
    )
    .await?;

    if settings.dedup
        && let Some((existing_id, existing_slug)) =
            db::find_active_upload_by_hash(db, hash.as_slice())
                .await
                .map_err(|e| {
                    log::error!("failed to check dedup: {e}");
                    internal_err()
                })?
    {
        log::info!("dedup: {existing_id} ({existing_slug}) already exists");
        let encoded = utf8_percent_encode(&existing_slug, PATH_SEGMENT).to_string();
        return Ok(format!("{}{encoded}", settings.base_url.as_ref().unwrap()));
    }

    let uuid = Uuid::new_v4();

    let slug = allocate_unique_slug(
        db,
        &original_name,
        ct_subtype.as_deref(),
        settings,
        keep_name,
        id_len,
    )
    .await?;
    let expiry = calculate_expiry(file_size, settings);
    let save_path = uuid_to_path(Path::new(&settings.store_path), &uuid);

    if let Err(e) = std::fs::create_dir_all(save_path.parent().unwrap()) {
        log::error!("Failed to create directory: {e}");
        return Err(internal_err());
    }

    if let Err(e) = save_file(file.file, &save_path) {
        log::error!("Failed to save file: {e}");
        return Err(internal_err());
    }

    let content_type_for_db =
        reconcile_content_type_for_db(file.detected_content_type.as_ref(), content_type_str);

    if let Err(e) = db::insert_upload_row(
        db,
        uuid,
        &original_name,
        expiry,
        &slug,
        file_size as i64,
        hash.as_slice(),
        uploader_ip,
        &content_type_for_db,
        user_agent,
    )
    .await
    {
        log::error!("insert failed: {e}");
        return Err(internal_err());
    }

    spawn_clamd_scan(
        db.clone(),
        settings.clone(),
        uuid,
        slug.clone(),
        save_path.clone(),
    );

    if content_type_for_db.starts_with("image/") {
        spawn_nsfw_scan(nsfw_model, db.clone(), uuid, slug.clone(), save_path);
    }

    let encoded_slug = utf8_percent_encode(&slug, PATH_SEGMENT).to_string();
    let base_url = settings.base_url.as_ref().unwrap();
    Ok(format!("{base_url}{encoded_slug}"))
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
        None => HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(rendered_templates.index.clone()),
    }
}

#[derive(MultipartForm)]
pub(crate) struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<HashedTempFile>,
    id_length: Option<Text<usize>>,
    keep_name: Option<Text<String>>,
    formatted: Option<Text<String>>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#039;")
}

/// Run before the multipart body is even read.
async fn enforce_upload_gates(
    db: &DbPool,
    ban_cache: &BanCache,
    settings: &Settings,
    uploader_ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<(), HttpResponse> {
    if let Some(ip) = uploader_ip {
        check_not_banned(
            ban_cache.is_ip_banned(db, ip, BanType::ReadOnly),
            uploader_ip,
            "banned IP",
            "Your IP is banned from uploading.",
        )
        .await?;
    }

    if let Some(ua) = user_agent {
        check_not_banned(
            ban_cache.is_user_agent_banned(db, ua),
            uploader_ip,
            "banned user agent",
            "Your client is banned from uploading.",
        )
        .await?;
    }

    if let Some(ip) = uploader_ip {
        check_under_limit(
            settings.max_uploads_per_day.map(|n| n as i64),
            db::uploads_count_last_day(db, ip),
            uploader_ip,
            "upload count rate limit",
            "Upload limit reached.",
        )
        .await?;
        check_under_limit(
            settings.max_bytes_per_day.map(|n| n as i64),
            db::uploads_bytes_last_day(db, ip),
            uploader_ip,
            "byte quota rate limit",
            "Daily byte quota reached.",
        )
        .await?;
    }

    Ok(())
}

fn format_links(links: &[String], formatted: bool) -> HttpResponse {
    if formatted {
        let body: String = links
            .iter()
            .map(|url| {
                format!(
                    "<pre>Access your file here: <a href=\"{url}\">{}</a></pre>\n",
                    escape_html(url)
                )
            })
            .collect();
        HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(body)
    } else {
        let body: String = links.iter().map(|url| format!("{url}\n")).collect();
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(body)
    }
}

#[post("/")]
pub(crate) async fn upload(
    req: HttpRequest,
    payload: web::Payload,
    db: web::Data<DbPool>,
    settings: web::Data<Settings>,
    ban_cache: web::Data<BanCache>,
    nsfw_model: web::Data<Option<Arc<NsfwModel>>>,
) -> impl Responder {
    let uploader_ip = extract_ip(&req, settings.trust_xff);
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok());

    // ban + rate-limit checks before the multipart body is read
    if let Err(resp) = enforce_upload_gates(
        db.get_ref(),
        ban_cache.get_ref(),
        &settings,
        uploader_ip,
        user_agent,
    )
    .await
    {
        return resp;
    }

    let mut dev_payload = payload.into_inner();
    let MultipartForm(form) =
        match MultipartForm::<UploadForm>::from_request(&req, &mut dev_payload).await {
            Ok(form) => form,
            Err(e) => {
                log::info!(
                    "upload rejected: malformed request ({e}) (ip={})",
                    format_ip(uploader_ip)
                );
                return HttpResponse::from_error(e);
            }
        };

    let id_len = if let Some(ref t) = form.id_length {
        t.0.clamp(settings.min_id_length, settings.max_id_length)
    } else {
        settings.min_id_length
    };
    let keep_name = form.keep_name.is_some();
    let formatted = form.formatted.is_some();

    let mut links = Vec::new();
    for file in form.files {
        match process_file(
            db.get_ref(),
            ban_cache.get_ref(),
            &settings,
            nsfw_model.get_ref().clone(),
            file,
            uploader_ip,
            user_agent,
            id_len,
            keep_name,
        )
        .await
        {
            Ok(link) => links.push(link),
            Err(resp) => return resp,
        }
    }

    format_links(&links, formatted)
}

#[get("/{slug}")]
pub(crate) async fn get_file(
    req: HttpRequest,
    path: web::Path<(String,)>,
    db: web::Data<DbPool>,
    settings: web::Data<Settings>,
    ban_cache: web::Data<BanCache>,
) -> actix_web::Result<HttpResponse> {
    let slug = &path.0;

    if let Some(ip) = extract_ip(&req, settings.trust_xff)
        && ban_cache
            .is_ip_banned(db.get_ref(), ip, BanType::Full)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
    {
        return Ok(error_page(StatusCode::FORBIDDEN, "Your IP is banned."));
    }

    let row = db::get_upload_by_slug(db.get_ref(), slug)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .ok_or_else(|| actix_web::error::ErrorNotFound("File not found"))?;

    let ip = extract_ip(&req, settings.trust_xff);
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let upload_id = row.id;
    let db_log = db.clone();
    tokio::spawn(async move {
        if let Err(e) = db::log_access(db_log.get_ref(), upload_id, ip, user_agent.as_deref()).await
        {
            log::warn!("Failed to log file access: {e}");
        }
    });

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
    let mut res = NamedFile::open(file_path)?
        .use_last_modified(true)
        .use_etag(true)
        .set_content_type(serve_mime)
        .set_content_disposition(ContentDisposition {
            disposition,
            parameters: vec![DispositionParam::Filename(row.original_name)],
        })
        .into_response(&req);

    // workaround for actix-files bug: https://github.com/actix/actix-web/issues/3191
    // TODO: remove once actix-files > 0.6.10 is released.
    let is_identity = res
        .headers()
        .get(actix_web::http::header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if is_identity {
        res.headers_mut()
            .remove(actix_web::http::header::CONTENT_ENCODING);
    }

    Ok(res)
}

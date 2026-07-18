use std::net::Ipv4Addr;

use actix_web::{
    FromRequest, HttpRequest, HttpResponse, Responder, delete, dev::Payload, get, http::StatusCode,
    post, web,
};
use futures_util::future::{Ready, ready};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::db;
use crate::db_pool::DbPool;
use crate::model::{
    BannedFileExtension, BannedFileHash, BannedFileMime, BannedIpv4Range, BannedUserAgent, Upload,
};
use crate::settings::Settings;

/// Registers every `/admin/*` route. Shared by the real app (main.rs) and the test
/// app (tests.rs) so the two can't drift out of sync — a route added to one but not
/// the other used to be a silent gap rather than a compile error.
pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(stats)
        .service(list_uploads)
        .service(delete_upload)
        .service(delete_upload_by_slug)
        .service(list_banned_ips)
        .service(add_banned_ip)
        .service(remove_banned_ip)
        .service(list_banned_extensions)
        .service(add_banned_extension)
        .service(remove_banned_extension)
        .service(list_banned_mimes)
        .service(add_banned_mime)
        .service(remove_banned_mime)
        .service(list_banned_hashes)
        .service(add_banned_hash)
        .service(remove_banned_hash)
        .service(list_banned_user_agents)
        .service(add_banned_user_agent)
        .service(remove_banned_user_agent);
}

/// Extractor-as-guard for `/admin/*` routes: checks `Authorization: Bearer <admin_token>`
/// against `Settings::admin_token`. Absent config -> 404 (route pretends not to exist).
pub(crate) struct AdminAuth;

impl FromRequest for AdminAuth {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let configured_token = req
            .app_data::<web::Data<Settings>>()
            .and_then(|s| s.admin_token.as_deref())
            .map(|t| t.to_string());

        let Some(configured_token) = configured_token else {
            return ready(Err(actix_web::error::ErrorNotFound("Not found")));
        };

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let Some(token) = token else {
            return ready(Err(actix_web::error::ErrorUnauthorized(
                "Missing or malformed Authorization header",
            )));
        };

        if constant_time_eq(token.as_bytes(), configured_token.as_bytes()) {
            ready(Ok(AdminAuth))
        } else {
            ready(Err(actix_web::error::ErrorForbidden("Invalid admin token")))
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn parse_rfc3339(s: &str) -> Option<PrimitiveDateTime> {
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    Some(PrimitiveDateTime::new(odt.date(), odt.time()))
}

fn format_ts(ts: PrimitiveDateTime) -> String {
    ts.assume_utc().format(&Rfc3339).unwrap_or_default()
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

fn json_error(status: StatusCode, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(ErrorBody { error: message })
}

fn internal_err(e: impl std::fmt::Display, context: &str) -> HttpResponse {
    log::error!("admin: {context} failed: {e}");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.")
}

#[derive(Serialize)]
struct DeleteResult {
    deleted: usize,
}

#[derive(Serialize)]
struct IdResult {
    id: i64,
}

// ---- uploads ----

#[derive(Serialize)]
struct UploadDto {
    id: String,
    upload_timestamp: String,
    expiry_timestamp: String,
    deleted: bool,
    original_name: String,
    slug: String,
    file_size: i64,
    hash: Option<String>,
    uploader_ip: Option<String>,
    content_type: Option<String>,
    user_agent: Option<String>,
}

impl From<Upload> for UploadDto {
    fn from(u: Upload) -> Self {
        UploadDto {
            id: u.id.to_string(),
            upload_timestamp: format_ts(u.upload_timestamp),
            expiry_timestamp: format_ts(u.expiry_timestamp),
            deleted: u.deleted_timestamp.is_some(),
            original_name: u.original_name,
            slug: u.slug,
            file_size: u.file_size,
            hash: u.hash.map(|h| hex_encode(&h)),
            uploader_ip: u.uploader_ip.map(|ip| Ipv4Addr::from(ip).to_string()),
            content_type: u.content_type,
            user_agent: u.user_agent,
        }
    }
}

#[get("/stats")]
pub(crate) async fn stats(_auth: AdminAuth, db: web::Data<DbPool>) -> impl Responder {
    match db::global_stats(db.get_ref()).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => internal_err(e, "global_stats"),
    }
}

#[derive(Deserialize)]
pub(crate) struct ListUploadsQuery {
    ip: Option<String>,
    slug: Option<String>,
    include_deleted: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[get("/uploads")]
pub(crate) async fn list_uploads(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    query: web::Query<ListUploadsQuery>,
) -> impl Responder {
    let ip = match query.ip.as_deref().map(str::parse::<Ipv4Addr>) {
        Some(Ok(ip)) => Some(u32::from(ip)),
        Some(Err(_)) => return json_error(StatusCode::BAD_REQUEST, "Invalid ip"),
        None => None,
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0).max(0);

    match db::list_uploads(
        db.get_ref(),
        ip,
        query.slug.as_deref(),
        query.include_deleted.unwrap_or(false),
        limit,
        offset,
    )
    .await
    {
        Ok(rows) => {
            HttpResponse::Ok().json(rows.into_iter().map(UploadDto::from).collect::<Vec<_>>())
        }
        Err(e) => internal_err(e, "list_uploads"),
    }
}

#[delete("/uploads/{id}")]
pub(crate) async fn delete_upload(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    settings: web::Data<Settings>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let Ok(id) = Uuid::parse_str(&path.into_inner().0) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid id");
    };
    match db::delete_by_id(db.get_ref(), &settings, id).await {
        Ok(deleted) => {
            log::info!("admin: deleted upload {id} ({deleted} row(s))");
            HttpResponse::Ok().json(DeleteResult { deleted })
        }
        Err(e) => internal_err(e, "delete_by_id"),
    }
}

#[delete("/uploads/slug/{slug}")]
pub(crate) async fn delete_upload_by_slug(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    settings: web::Data<Settings>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let slug = path.into_inner().0;
    match db::delete_by_slug(db.get_ref(), &settings, &slug).await {
        Ok(deleted) => {
            log::info!("admin: deleted upload by slug {slug} ({deleted} row(s))");
            HttpResponse::Ok().json(DeleteResult { deleted })
        }
        Err(e) => internal_err(e, "delete_by_slug"),
    }
}

// ---- banned IP ranges ----

#[derive(Serialize)]
struct BannedIpRangeDto {
    id: i64,
    start_ip: String,
    end_ip: String,
    reason: Option<String>,
    banned_timestamp: String,
    expires_timestamp: Option<String>,
}

impl From<BannedIpv4Range> for BannedIpRangeDto {
    fn from(b: BannedIpv4Range) -> Self {
        BannedIpRangeDto {
            id: b.id,
            start_ip: Ipv4Addr::from(b.start_ip).to_string(),
            end_ip: Ipv4Addr::from(b.end_ip).to_string(),
            reason: b.reason,
            banned_timestamp: format_ts(b.banned_timestamp),
            expires_timestamp: b.expires_timestamp.map(format_ts),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct BannedIpRangeCreate {
    start_ip: String,
    end_ip: String,
    reason: Option<String>,
    expires_timestamp: Option<String>,
}

#[get("/bans/ips")]
pub(crate) async fn list_banned_ips(_auth: AdminAuth, db: web::Data<DbPool>) -> impl Responder {
    match db::list_banned_ips(db.get_ref()).await {
        Ok(rows) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(BannedIpRangeDto::from)
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_err(e, "list_banned_ips"),
    }
}

#[post("/bans/ips")]
pub(crate) async fn add_banned_ip(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    body: web::Json<BannedIpRangeCreate>,
) -> impl Responder {
    let Ok(start_ip) = body.start_ip.parse::<Ipv4Addr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid start_ip");
    };
    let Ok(end_ip) = body.end_ip.parse::<Ipv4Addr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid end_ip");
    };
    let expires_timestamp = match body.expires_timestamp.as_deref() {
        Some(s) => match parse_rfc3339(s) {
            Some(ts) => Some(ts),
            None => return json_error(StatusCode::BAD_REQUEST, "Invalid expires_timestamp"),
        },
        None => None,
    };

    match db::insert_banned_ip(
        db.get_ref(),
        u32::from(start_ip),
        u32::from(end_ip),
        body.reason.as_deref(),
        expires_timestamp,
    )
    .await
    {
        Ok(id) => {
            log::info!("admin: banned ip range {start_ip}-{end_ip} (id {id})");
            HttpResponse::Created().json(IdResult { id })
        }
        Err(e) => internal_err(e, "insert_banned_ip"),
    }
}

#[delete("/bans/ips/{id}")]
pub(crate) async fn remove_banned_ip(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    path: web::Path<(i64,)>,
) -> impl Responder {
    let id = path.into_inner().0;
    match db::delete_banned_ip(db.get_ref(), id).await {
        Ok(true) => {
            log::info!("admin: removed banned ip range {id}");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, "delete_banned_ip"),
    }
}

// ---- banned file extensions ----

#[derive(Deserialize)]
pub(crate) struct ExtensionCreate {
    extension: String,
}

#[get("/bans/extensions")]
pub(crate) async fn list_banned_extensions(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
) -> impl Responder {
    match db::list_banned_extensions(db.get_ref()).await {
        Ok(rows) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(|r: BannedFileExtension| r.extension)
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_err(e, "list_banned_extensions"),
    }
}

#[post("/bans/extensions")]
pub(crate) async fn add_banned_extension(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    body: web::Json<ExtensionCreate>,
) -> impl Responder {
    match db::insert_banned_extension(db.get_ref(), &body.extension).await {
        Ok(()) => {
            log::info!("admin: banned extension {}", body.extension);
            HttpResponse::Created().finish()
        }
        Err(e) => internal_err(e, "insert_banned_extension"),
    }
}

#[delete("/bans/extensions/{extension}")]
pub(crate) async fn remove_banned_extension(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let ext = path.into_inner().0;
    match db::delete_banned_extension(db.get_ref(), &ext).await {
        Ok(true) => {
            log::info!("admin: removed banned extension {ext}");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, "delete_banned_extension"),
    }
}

// ---- banned mime types ----

#[derive(Deserialize)]
pub(crate) struct MimeCreate {
    mime: String,
}

#[get("/bans/mimes")]
pub(crate) async fn list_banned_mimes(_auth: AdminAuth, db: web::Data<DbPool>) -> impl Responder {
    match db::list_banned_mimes(db.get_ref()).await {
        Ok(rows) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(|r: BannedFileMime| r.mime)
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_err(e, "list_banned_mimes"),
    }
}

#[post("/bans/mimes")]
pub(crate) async fn add_banned_mime(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    body: web::Json<MimeCreate>,
) -> impl Responder {
    match db::insert_banned_mime(db.get_ref(), &body.mime).await {
        Ok(()) => {
            log::info!("admin: banned mime {}", body.mime);
            HttpResponse::Created().finish()
        }
        Err(e) => internal_err(e, "insert_banned_mime"),
    }
}

// mime types contain a `/` (e.g. "image/png"), hence the greedy path match.
#[delete("/bans/mimes/{mime:.*}")]
pub(crate) async fn remove_banned_mime(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let mime = path.into_inner().0;
    match db::delete_banned_mime(db.get_ref(), &mime).await {
        Ok(true) => {
            log::info!("admin: removed banned mime {mime}");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, "delete_banned_mime"),
    }
}

// ---- banned file hashes ----

#[derive(Serialize)]
struct BannedHashDto {
    hash: String,
    reason: Option<String>,
}

impl From<BannedFileHash> for BannedHashDto {
    fn from(b: BannedFileHash) -> Self {
        BannedHashDto {
            hash: hex_encode(&b.hash),
            reason: b.reason,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct HashCreate {
    hash: String,
    reason: Option<String>,
}

#[get("/bans/hashes")]
pub(crate) async fn list_banned_hashes(_auth: AdminAuth, db: web::Data<DbPool>) -> impl Responder {
    match db::list_banned_hashes(db.get_ref()).await {
        Ok(rows) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(BannedHashDto::from)
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_err(e, "list_banned_hashes"),
    }
}

#[post("/bans/hashes")]
pub(crate) async fn add_banned_hash(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    body: web::Json<HashCreate>,
) -> impl Responder {
    let Some(hash) = hex_decode(&body.hash) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Invalid hash (expected lowercase hex)",
        );
    };
    if hash.len() != 32 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Invalid hash length (expected 32-byte BLAKE3)",
        );
    }
    match db::insert_banned_hash(db.get_ref(), &hash, body.reason.as_deref()).await {
        Ok(()) => {
            log::info!("admin: banned hash {}", body.hash);
            HttpResponse::Created().finish()
        }
        Err(e) => internal_err(e, "insert_banned_hash"),
    }
}

#[delete("/bans/hashes/{hash}")]
pub(crate) async fn remove_banned_hash(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let hex = path.into_inner().0;
    let Some(hash) = hex_decode(&hex) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Invalid hash (expected lowercase hex)",
        );
    };
    match db::delete_banned_hash(db.get_ref(), &hash).await {
        Ok(true) => {
            log::info!("admin: removed banned hash {hex}");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, "delete_banned_hash"),
    }
}

#[derive(Serialize)]
struct BannedUserAgentDto {
    pattern: String,
    reason: Option<String>,
}

impl From<BannedUserAgent> for BannedUserAgentDto {
    fn from(b: BannedUserAgent) -> Self {
        BannedUserAgentDto {
            pattern: b.pattern,
            reason: b.reason,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct UserAgentCreate {
    pattern: String,
    reason: Option<String>,
}

#[get("/bans/user-agents")]
pub(crate) async fn list_banned_user_agents(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
) -> impl Responder {
    match db::list_banned_user_agents(db.get_ref()).await {
        Ok(rows) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(BannedUserAgentDto::from)
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_err(e, "list_banned_user_agents"),
    }
}

#[post("/bans/user-agents")]
pub(crate) async fn add_banned_user_agent(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    body: web::Json<UserAgentCreate>,
) -> impl Responder {
    match db::insert_banned_user_agent(db.get_ref(), &body.pattern, body.reason.as_deref()).await {
        Ok(()) => {
            log::info!("admin: banned user agent pattern {:?}", body.pattern);
            HttpResponse::Created().finish()
        }
        Err(e) => internal_err(e, "insert_banned_user_agent"),
    }
}

// User agent patterns can contain '/', hence the greedy path match.
#[delete("/bans/user-agents/{pattern:.*}")]
pub(crate) async fn remove_banned_user_agent(
    _auth: AdminAuth,
    db: web::Data<DbPool>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let pattern = path.into_inner().0;
    match db::delete_banned_user_agent(db.get_ref(), &pattern).await {
        Ok(true) => {
            log::info!("admin: removed banned user agent pattern {pattern:?}");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, "delete_banned_user_agent"),
    }
}

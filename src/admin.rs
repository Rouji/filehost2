use std::future::Future;
use std::net::IpAddr;

use actix_web::{
    FromRequest, HttpRequest, HttpResponse, Responder, delete, dev::Payload, get, http::StatusCode,
    post, web,
};
use futures_util::future::{Ready, ready};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::db;
use crate::ip;
use crate::model::{BanType, BannedFileHash, BannedFileMime, BannedIpRange, Upload};
use crate::util::{format_ts, hex_decode, hex_encode, parse_rfc3339};

/// Registers every `/admin/*` route. Shared by the real app (main.rs) and the test
/// app (tests.rs) so the two can't drift out of sync — a route added to one but not
/// the other used to be a silent gap rather than a compile error.
pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(stats)
        .service(list_uploads)
        .service(delete_upload)
        .service(delete_upload_by_slug)
        .service(delete_upload_by_ip)
        .service(ip_stats)
        .service(list_banned_ips)
        .service(add_banned_ip)
        .service(remove_banned_ip)
        .service(list_banned_filenames)
        .service(add_banned_filename)
        .service(remove_banned_filename)
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
            .app_data::<web::Data<AppState>>()
            .and_then(|s| s.settings.admin_token.as_deref())
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

fn respond_list<T, U: Serialize>(
    result: Result<Vec<T>, sqlx::Error>,
    map: impl Fn(T) -> U,
    err_context: &str,
) -> HttpResponse {
    match result {
        Ok(rows) => HttpResponse::Ok().json(rows.into_iter().map(map).collect::<Vec<_>>()),
        Err(e) => internal_err(e, err_context),
    }
}

async fn respond_created<Fut: Future<Output = ()>>(
    result: Result<(), sqlx::Error>,
    invalidate: impl FnOnce() -> Fut,
    ok_log: impl FnOnce() -> String,
    err_context: &str,
) -> HttpResponse {
    match result {
        Ok(()) => {
            log::info!("{}", ok_log());
            invalidate().await;
            HttpResponse::Created().finish()
        }
        Err(e) => internal_err(e, err_context),
    }
}

async fn respond_removed<Fut: Future<Output = ()>>(
    result: Result<bool, sqlx::Error>,
    invalidate: impl FnOnce() -> Fut,
    ok_log: impl FnOnce() -> String,
    err_context: &str,
) -> HttpResponse {
    match result {
        Ok(true) => {
            log::info!("{}", ok_log());
            invalidate().await;
            HttpResponse::NoContent().finish()
        }
        Ok(false) => json_error(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => internal_err(e, err_context),
    }
}

#[derive(Serialize)]
struct DeleteResult {
    deleted: usize,
}

#[derive(Serialize)]
struct IdResult {
    id: i64,
}

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
    nsfw_score: Option<f32>,
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
            uploader_ip: u
                .uploader_ip
                .and_then(|b| ip::from_db_bytes(&b))
                .map(|ip| ip.to_string()),
            content_type: u.content_type,
            user_agent: u.user_agent,
            nsfw_score: u.nsfw_score,
        }
    }
}

const TOP_UPLOADERS_LIMIT: i64 = 10;

#[derive(Serialize)]
struct TopUploaderDto {
    ip: String,
    count: i64,
    bytes: i64,
}

#[derive(Serialize)]
struct TopNsfwUploaderDto {
    ip: String,
    count: i64,
    avg_score: f64,
}

#[derive(Serialize)]
struct StatsDto {
    #[serde(flatten)]
    global: db::GlobalStats,
    top_uploaders: Vec<TopUploaderDto>,
    top_nsfw_uploaders: Vec<TopNsfwUploaderDto>,
}

#[get("/stats")]
pub(crate) async fn stats(_auth: AdminAuth, state: web::Data<AppState>) -> impl Responder {
    let stats = match db::global_stats(&state.db).await {
        Ok(s) => s,
        Err(e) => return internal_err(e, "global_stats"),
    };
    let top_uploaders = match db::top_uploader_ips(&state.db, TOP_UPLOADERS_LIMIT).await {
        Ok(rows) => rows,
        Err(e) => return internal_err(e, "top_uploader_ips"),
    };
    let top_nsfw_uploaders = match db::top_nsfw_uploader_ips(
        &state.db,
        state.settings.nsfw_threshold,
        TOP_UPLOADERS_LIMIT,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => return internal_err(e, "top_nsfw_uploader_ips"),
    };

    HttpResponse::Ok().json(StatsDto {
        global: stats,
        top_uploaders: top_uploaders
            .into_iter()
            .map(|u| TopUploaderDto {
                ip: ip::display_db_bytes(&u.ip),
                count: u.count,
                bytes: u.bytes,
            })
            .collect(),
        top_nsfw_uploaders: top_nsfw_uploaders
            .into_iter()
            .map(|u| TopNsfwUploaderDto {
                ip: ip::display_db_bytes(&u.ip),
                count: u.count,
                avg_score: u.avg_score,
            })
            .collect(),
    })
}

#[derive(Deserialize)]
pub(crate) struct ListUploadsQuery {
    ip: Option<String>,
    slug: Option<String>,
    include_deleted: Option<bool>,
    min_nsfw_score: Option<f32>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[get("/uploads")]
pub(crate) async fn list_uploads(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    query: web::Query<ListUploadsQuery>,
) -> impl Responder {
    let ip = match query.ip.as_deref().map(str::parse::<IpAddr>) {
        Some(Ok(ip)) => Some(ip),
        Some(Err(_)) => return json_error(StatusCode::BAD_REQUEST, "Invalid ip"),
        None => None,
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0).max(0);

    respond_list(
        db::list_uploads(
            &state.db,
            ip,
            query.slug.as_deref(),
            query.include_deleted.unwrap_or(false),
            query.min_nsfw_score,
            limit,
            offset,
        )
        .await,
        UploadDto::from,
        "list_uploads",
    )
}

#[delete("/uploads/{id}")]
pub(crate) async fn delete_upload(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let Ok(id) = Uuid::parse_str(&path.into_inner().0) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid id");
    };
    match db::delete_by_id(&state.db, &state.settings, id).await {
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
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let slug = path.into_inner().0;
    match db::delete_by_slug(&state.db, &state.settings, &slug).await {
        Ok(deleted) => {
            log::info!("admin: deleted upload by slug {slug} ({deleted} row(s))");
            HttpResponse::Ok().json(DeleteResult { deleted })
        }
        Err(e) => internal_err(e, "delete_by_slug"),
    }
}

#[delete("/uploads/ip/{ip}")]
pub(crate) async fn delete_upload_by_ip(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let Ok(ip) = path.into_inner().0.parse::<IpAddr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid ip");
    };
    match db::delete_by_ip(&state.db, &state.settings, ip).await {
        Ok(deleted) => {
            log::info!("admin: deleted uploads by ip {ip} ({deleted} row(s))");
            HttpResponse::Ok().json(DeleteResult { deleted })
        }
        Err(e) => internal_err(e, "delete_by_ip"),
    }
}

#[derive(Serialize)]
struct IpStatsDto {
    hourly: Vec<db::HourlyUploadCount>,
    top_mimes: Vec<db::MimeUploadCount>,
}

const IP_STATS_HOURS: i64 = 24 * 7;

#[get("/ip-stats/{ip}")]
pub(crate) async fn ip_stats(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let Ok(ip) = path.into_inner().0.parse::<IpAddr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid ip");
    };

    let hourly = match db::uploads_hourly_counts(&state.db, ip, IP_STATS_HOURS).await {
        Ok(rows) => rows,
        Err(e) => return internal_err(e, "uploads_hourly_counts"),
    };
    let top_mimes = match db::uploads_top_mimes(&state.db, ip, 5).await {
        Ok(rows) => rows,
        Err(e) => return internal_err(e, "uploads_top_mimes"),
    };

    HttpResponse::Ok().json(IpStatsDto { hourly, top_mimes })
}

#[derive(Serialize)]
struct BannedIpRangeDto {
    id: i64,
    start_ip: String,
    end_ip: String,
    reason: Option<String>,
    banned_timestamp: String,
    expires_timestamp: Option<String>,
    blacklist_id: Option<i32>,
    type_: u32,
}

impl From<BannedIpRange> for BannedIpRangeDto {
    fn from(b: BannedIpRange) -> Self {
        BannedIpRangeDto {
            id: b.id,
            start_ip: ip::display_db_bytes(&b.start_ip),
            end_ip: ip::display_db_bytes(&b.end_ip),
            reason: b.reason,
            banned_timestamp: format_ts(b.banned_timestamp),
            expires_timestamp: b.expires_timestamp.map(format_ts),
            blacklist_id: b.blacklist_id,
            type_: b.type_ as u32,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct BannedIpRangeCreate {
    start_ip: String,
    end_ip: String,
    reason: Option<String>,
    expires_timestamp: Option<String>,
    blacklist_id: Option<i32>,
    /// Defaults to ReadOnly when omitted.
    type_: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct ListBannedIpsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[get("/bans/ips")]
pub(crate) async fn list_banned_ips(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    query: web::Query<ListBannedIpsQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0).max(0);

    respond_list(
        db::list_banned_ips(&state.db, limit, offset).await,
        BannedIpRangeDto::from,
        "list_banned_ips",
    )
}

#[post("/bans/ips")]
pub(crate) async fn add_banned_ip(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    body: web::Json<BannedIpRangeCreate>,
) -> impl Responder {
    let Ok(start_ip) = body.start_ip.parse::<IpAddr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid start_ip");
    };
    let Ok(end_ip) = body.end_ip.parse::<IpAddr>() else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid end_ip");
    };
    if !ip::same_family(start_ip, end_ip) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "start_ip and end_ip must be the same IP version",
        );
    }
    let expires_timestamp = match body.expires_timestamp.as_deref() {
        Some(s) => match parse_rfc3339(s) {
            Some(ts) => Some(ts),
            None => return json_error(StatusCode::BAD_REQUEST, "Invalid expires_timestamp"),
        },
        None => None,
    };
    let Ok(ban_type) = BanType::try_from(body.type_.unwrap_or(BanType::ReadOnly as u32)) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid type (expected 1 or 2)");
    };

    match db::insert_banned_ip(
        &state.db,
        start_ip,
        end_ip,
        body.reason.as_deref(),
        expires_timestamp,
        body.blacklist_id,
        ban_type,
    )
    .await
    {
        Ok(id) => {
            log::info!("admin: banned ip range {start_ip}-{end_ip} (id {id})");
            state.ban_cache.invalidate_ip_ranges().await;
            HttpResponse::Created().json(IdResult { id })
        }
        Err(e) => internal_err(e, "insert_banned_ip"),
    }
}

#[delete("/bans/ips/{id}")]
pub(crate) async fn remove_banned_ip(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(i64,)>,
) -> impl Responder {
    let id = path.into_inner().0;
    respond_removed(
        db::delete_banned_ip(&state.db, id).await,
        || state.ban_cache.invalidate_ip_ranges(),
        || format!("admin: removed banned ip range {id}"),
        "delete_banned_ip",
    )
    .await
}

#[derive(Deserialize)]
pub(crate) struct FilenameCreate {
    pattern: String,
    reason: Option<String>,
}

#[get("/bans/filenames")]
pub(crate) async fn list_banned_filenames(
    _auth: AdminAuth,
    state: web::Data<AppState>,
) -> impl Responder {
    respond_list(
        db::list_banned_filenames(&state.db).await,
        std::convert::identity,
        "list_banned_filenames",
    )
}

#[post("/bans/filenames")]
pub(crate) async fn add_banned_filename(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    body: web::Json<FilenameCreate>,
) -> impl Responder {
    if let Err(e) = regex::Regex::new(&body.pattern) {
        return json_error(StatusCode::BAD_REQUEST, &format!("Invalid regex: {e}"));
    }
    respond_created(
        db::insert_banned_filename(&state.db, &body.pattern, body.reason.as_deref()).await,
        || state.ban_cache.invalidate_filenames(),
        || format!("admin: banned filename pattern {:?}", body.pattern),
        "insert_banned_filename",
    )
    .await
}

// Filename patterns can contain '/', hence the greedy path match.
#[delete("/bans/filenames/{pattern:.*}")]
pub(crate) async fn remove_banned_filename(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let pattern = path.into_inner().0;
    respond_removed(
        db::delete_banned_filename(&state.db, &pattern).await,
        || state.ban_cache.invalidate_filenames(),
        || format!("admin: removed banned filename pattern {pattern:?}"),
        "delete_banned_filename",
    )
    .await
}

#[derive(Deserialize)]
pub(crate) struct MimeCreate {
    mime: String,
}

#[get("/bans/mimes")]
pub(crate) async fn list_banned_mimes(
    _auth: AdminAuth,
    state: web::Data<AppState>,
) -> impl Responder {
    respond_list(
        db::list_banned_mimes(&state.db).await,
        |r: BannedFileMime| r.mime,
        "list_banned_mimes",
    )
}

#[post("/bans/mimes")]
pub(crate) async fn add_banned_mime(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    body: web::Json<MimeCreate>,
) -> impl Responder {
    let mime = body.mime.to_lowercase();
    respond_created(
        db::insert_banned_mime(&state.db, &mime).await,
        || state.ban_cache.invalidate_mimes(),
        || format!("admin: banned mime {mime}"),
        "insert_banned_mime",
    )
    .await
}

// mime types contain a `/` (e.g. "image/png"), hence the greedy path match.
#[delete("/bans/mimes/{mime:.*}")]
pub(crate) async fn remove_banned_mime(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let mime = path.into_inner().0.to_lowercase();
    respond_removed(
        db::delete_banned_mime(&state.db, &mime).await,
        || state.ban_cache.invalidate_mimes(),
        || format!("admin: removed banned mime {mime}"),
        "delete_banned_mime",
    )
    .await
}

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
pub(crate) async fn list_banned_hashes(
    _auth: AdminAuth,
    state: web::Data<AppState>,
) -> impl Responder {
    respond_list(
        db::list_banned_hashes(&state.db).await,
        BannedHashDto::from,
        "list_banned_hashes",
    )
}

#[post("/bans/hashes")]
pub(crate) async fn add_banned_hash(
    _auth: AdminAuth,
    state: web::Data<AppState>,
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
    respond_created(
        db::insert_banned_hash(&state.db, &hash, body.reason.as_deref()).await,
        || state.ban_cache.invalidate_hashes(),
        || format!("admin: banned hash {}", body.hash),
        "insert_banned_hash",
    )
    .await
}

#[delete("/bans/hashes/{hash}")]
pub(crate) async fn remove_banned_hash(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let hex = path.into_inner().0;
    let Some(hash) = hex_decode(&hex) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Invalid hash (expected lowercase hex)",
        );
    };
    respond_removed(
        db::delete_banned_hash(&state.db, &hash).await,
        || state.ban_cache.invalidate_hashes(),
        || format!("admin: removed banned hash {hex}"),
        "delete_banned_hash",
    )
    .await
}

#[derive(Deserialize)]
pub(crate) struct UserAgentCreate {
    pattern: String,
    reason: Option<String>,
}

#[get("/bans/user-agents")]
pub(crate) async fn list_banned_user_agents(
    _auth: AdminAuth,
    state: web::Data<AppState>,
) -> impl Responder {
    respond_list(
        db::list_banned_user_agents(&state.db).await,
        std::convert::identity,
        "list_banned_user_agents",
    )
}

#[post("/bans/user-agents")]
pub(crate) async fn add_banned_user_agent(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    body: web::Json<UserAgentCreate>,
) -> impl Responder {
    respond_created(
        db::insert_banned_user_agent(&state.db, &body.pattern, body.reason.as_deref()).await,
        || state.ban_cache.invalidate_user_agents(),
        || format!("admin: banned user agent pattern {:?}", body.pattern),
        "insert_banned_user_agent",
    )
    .await
}

// User agent patterns can contain '/', hence the greedy path match.
#[delete("/bans/user-agents/{pattern:.*}")]
pub(crate) async fn remove_banned_user_agent(
    _auth: AdminAuth,
    state: web::Data<AppState>,
    path: web::Path<(String,)>,
) -> impl Responder {
    let pattern = path.into_inner().0;
    respond_removed(
        db::delete_banned_user_agent(&state.db, &pattern).await,
        || state.ban_cache.invalidate_user_agents(),
        || format!("admin: removed banned user agent pattern {pattern:?}"),
        "delete_banned_user_agent",
    )
    .await
}

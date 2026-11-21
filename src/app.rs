use std::sync::Arc;
use std::time::Duration;

use actix_cors::Cors;
use actix_multipart::{MultipartError, form::MultipartFormConfig};
use actix_web::{Error, HttpRequest, http::header, web};

use crate::ban_cache::BanCache;
use crate::challenge::ChallengeCache;
use crate::db_pool::DbPool;
use crate::ip::XffTrust;
use crate::nsfw::NsfwModel;
use crate::pow::PowSecret;
use crate::rate_limit::{DownloadThrottle, MissTracker, RequestTracker, UploadThrottle};
use crate::settings::Settings;
use crate::templates::{self, RenderedTemplates};
use crate::{admin, handlers};

/// Everything request handlers need, registered as a single `web::Data`.
/// Built once at startup; each worker's `App` gets a cheap `Arc` clone.
pub(crate) struct AppState {
    pub db: DbPool,
    pub settings: Settings,
    pub templates: RenderedTemplates,
    pub ban_cache: BanCache,
    pub challenge_cache: ChallengeCache,
    pub pow_secret: PowSecret,
    pub nsfw_model: Option<Arc<NsfwModel>>,
    pub xff_trust: XffTrust,
    pub upload_throttle: Arc<UploadThrottle>,
    pub download_throttle: Arc<DownloadThrottle>,
    pub miss_tracker: MissTracker,
    pub request_tracker: RequestTracker,
}

impl AppState {
    pub(crate) fn new(db: DbPool, settings: Settings) -> Self {
        let ttl = Duration::from_secs(settings.ban_cache_ttl_seconds);

        let (xff_trust, invalid_proxies) = settings.xff_trust();
        for entry in &invalid_proxies {
            log::error!("TRUSTED_PROXIES: ignoring unparsable entry {entry:?}");
        }
        if xff_trust.proxy_count() == 0 {
            log::warn!(
                "TRUSTED_PROXIES is unset or empty; X-Forwarded-For headers will be ignored"
            );
        } else {
            log::info!(
                "trusting X-Forwarded-For from {} proxy range(s), \
                 taking the client from {} hop(s) back",
                xff_trust.proxy_count(),
                settings.xff_hops,
            );
        }

        let nsfw_model = match settings.nsfw_model_path() {
            Some(path) => match NsfwModel::load(path) {
                Ok(model) => {
                    log::info!("nsfw: loaded model from {}", path.display());
                    Some(Arc::new(model))
                }
                Err(e) => {
                    log::error!("nsfw: failed to load model from {}: {e:#}", path.display());
                    None
                }
            },
            None => None,
        };

        Self {
            db,
            templates: templates::render(&settings),
            ban_cache: BanCache::new(ttl),
            challenge_cache: ChallengeCache::new(ttl),
            pow_secret: PowSecret::generate(),
            nsfw_model,
            xff_trust,
            upload_throttle: Arc::new(UploadThrottle::new()),
            download_throttle: Arc::new(DownloadThrottle::new()),
            miss_tracker: MissTracker::new(),
            request_tracker: RequestTracker::new(),
            settings,
        }
    }
}

fn handle_multipart_error(err: MultipartError, _req: &HttpRequest) -> Error {
    match err {
        MultipartError::Payload(inner) => inner.into(),
        _ => Error::from(err),
    }
}

/// Registers every route and the shared app data. Used by both the real
/// server (main.rs) and the test app (tests.rs) so the wiring can't drift
/// out of sync — the test app used to silently lack the upload throttle,
/// the request tracker and the multipart error handler.
pub(crate) fn configure(cfg: &mut web::ServiceConfig, state: web::Data<AppState>) {
    cfg.service(handlers::index)
        .service(handlers::upload)
        .service(handlers::captcha_page)
        .service(handlers::captcha_js)
        .service(handlers::captcha_challenge)
        .service(handlers::captcha_verify)
        .service(handlers::favicon)
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
        .app_data(state.clone())
        .app_data(
            MultipartFormConfig::default()
                .total_limit(state.settings.max_filesize * 1024 * 1024)
                .error_handler(handle_multipart_error),
        );
}

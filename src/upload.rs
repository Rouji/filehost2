use std::path::{Path, PathBuf};
use std::pin::Pin;
use uuid::Uuid;

use actix_multipart::form::{FieldReader, Limits};
use actix_multipart::{Field, MultipartError};
use actix_web::{HttpRequest, error::ErrorInternalServerError};
use futures_util::TryStreamExt as _;
use rand::distr::{Alphanumeric, SampleString};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use tokio::io::AsyncWriteExt as _;

use crate::rate_limit::UploadThrottle;
use crate::settings::Settings;

use file_type::FileType;
use file_type::format::SourceType;

pub(crate) fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

pub(crate) fn uuid_to_path(root: &Path, uuid: &Uuid) -> PathBuf {
    let folder = format!("{:04x}", uuid.as_u128() >> 112);
    root.join(folder).join(uuid.to_string())
}

/// Resolves the client's IP address (v4 or v6) for a request, honoring
/// `trust_xff` so every consumer (ban checks, quotas, throttling, access
/// logs) agrees on the same notion of "client IP" behind a reverse proxy.
pub(crate) fn extract_ip(req: &HttpRequest, trust_xff: bool) -> Option<std::net::IpAddr> {
    if trust_xff {
        req.headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
    } else {
        req.peer_addr().map(|addr| addr.ip())
    }
}

/// A multipart field reader that writes the upload to a temp file and
/// simultaneously feeds every chunk to a BLAKE3 hasher, so no second
/// disk pass is needed after the upload completes.
pub(crate) struct HashedTempFile {
    pub file: tempfile::NamedTempFile,
    pub content_type: Option<mime::Mime>,
    pub detected_content_type: Option<mime::Mime>,
    pub file_name: Option<String>,
    pub size: usize,
    pub hash: [u8; 32],
}

/// Keeps the original extension on the temp file's name, since `detect_content_type`
/// sniffs by path.
fn make_tempfile(ext_suffix: Option<&str>) -> std::io::Result<tempfile::NamedTempFile> {
    match ext_suffix {
        Some(suffix) => tempfile::Builder::new().suffix(suffix).tempfile(),
        _ => tempfile::NamedTempFile::new(),
    }
}

/// longest signature in `file_type`'s db needs 594 bytes
const SNIFF_LIMIT: u64 = 1024;

/// webp/webm/mp4 have a variable-length field within their first 8 bytes,
/// which breaks `file_type`'s signature lookup when there's no extension hint.
fn sniff_well_known(bytes: &[u8]) -> Option<mime::Mime> {
    let mime = if bytes.starts_with(b"RIFF") && bytes.get(8..12).is_some_and(|w| w == b"WEBP") {
        "image/webp"
    } else if bytes.starts_with(b"\x1a\x45\xdf\xa3") && bytes.windows(4).any(|w| w == b"webm") {
        "video/webm"
    } else if bytes.get(4..8).is_some_and(|w| w == b"ftyp") {
        "video/mp4"
    } else {
        return None;
    };
    mime.parse().ok()
}

/// `media_types` is unreliable (empty, or multiple with the wrong one first),
/// so prefer `mime_guess` on the matched extensions over it.
fn resolve_mime(ft: &FileType) -> Option<mime::Mime> {
    ft.extensions()
        .iter()
        .find_map(|ext| mime_guess::from_ext(ext).first())
        .or_else(|| {
            ft.media_types()
                .first()
                .and_then(|s| s.parse::<mime::Mime>().ok())
                .filter(|m| *m != mime_guess::mime::APPLICATION_OCTET_STREAM)
        })
}

/// Content wins over extension: try a pure signature match first, and only
/// consult the extension (no I/O, just a table lookup) if that found nothing.
async fn detect_content_type(path: PathBuf) -> Option<mime::Mime> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read as _;

        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .ok()?
            .take(SNIFF_LIMIT)
            .read_to_end(&mut bytes)
            .ok()?;

        let by_content = FileType::from_bytes(&bytes);
        if *by_content.source_type() != SourceType::Default {
            return resolve_mime(by_content);
        }

        sniff_well_known(&bytes).or_else(|| {
            let by_extension = path
                .extension()
                .and_then(|e| e.to_str())
                .and_then(|ext| FileType::from_extension(ext).first())
                .copied()
                .unwrap_or(by_content);
            resolve_mime(by_extension)
        })
    })
    .await
    .ok()
    .flatten()
}

impl<'t> FieldReader<'t> for HashedTempFile {
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self, MultipartError>> + 't>>;

    fn read_field(_req: &'t HttpRequest, mut field: Field, limits: &'t mut Limits) -> Self::Future {
        Box::pin(async move {
            let content_type = field.content_type().map(ToOwned::to_owned);
            let file_name = field
                .content_disposition()
                .expect("multipart form fields should have a content-disposition header")
                .get_filename()
                .map(ToOwned::to_owned);
            let field_name = field.name().unwrap_or("file").to_owned();

            let throttle = _req
                .app_data::<actix_web::web::Data<UploadThrottle>>()
                .cloned();
            let (rate, burst, trust_xff) = _req
                .app_data::<actix_web::web::Data<Settings>>()
                .map(|s| {
                    (
                        s.max_upload_bytes_per_sec,
                        s.max_upload_burst_bytes,
                        s.trust_xff,
                    )
                })
                .unwrap_or((None, None, false));
            let ip: Option<std::net::IpAddr> = extract_ip(_req, trust_xff);

            let to_field_err = |e: std::io::Error| MultipartError::Field {
                name: field_name.clone(),
                source: ErrorInternalServerError(e),
            };

            let ext_suffix = file_name
                .as_deref()
                .and_then(|n| Path::new(n).extension())
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"));

            let file = make_tempfile(ext_suffix.as_deref()).map_err(to_field_err)?;

            let mut file_async = tokio::fs::File::from_std(file.reopen().map_err(to_field_err)?);

            let mut hasher = blake3::Hasher::new();
            let mut size = 0usize;

            while let Some(chunk) = field.try_next().await? {
                limits.try_consume_limits(chunk.len(), false)?;
                if let (Some(t), Some(r), Some(ip)) = (&throttle, rate, ip) {
                    t.throttle(
                        crate::ip::normalize_for_quota(ip),
                        chunk.len(),
                        r,
                        burst.unwrap_or(r),
                    )
                    .await;
                }
                size += chunk.len();
                hasher.update(&chunk);
                file_async
                    .write_all(chunk.as_ref())
                    .await
                    .map_err(to_field_err)?;
            }

            file_async.flush().await.map_err(to_field_err)?;

            let detected = detect_content_type(file.path().to_path_buf()).await;

            Ok(HashedTempFile {
                file,
                content_type,
                detected_content_type: detected,
                file_name,
                size,
                hash: hasher.finalize().into(),
            })
        })
    }
}

pub(crate) fn life_expectancy_days(file_size: u64, settings: &Settings) -> f64 {
    let max_bytes = (settings.max_filesize * 1024 * 1024) as f64;
    let ratio = (file_size as f64 / max_bytes).min(1.0);
    settings.min_fileage as f64
        + (settings.max_fileage - settings.min_fileage) as f64
            * (1.0 - ratio).powi(settings.decay_exp as i32)
}

pub(crate) fn calculate_expiry(file_size: usize, settings: &Settings) -> PrimitiveDateTime {
    let expiry = OffsetDateTime::now_utc()
        + Duration::days(life_expectancy_days(file_size as u64, settings) as i64);
    PrimitiveDateTime::new(expiry.date(), expiry.time())
}

/// Sanitises the extension-less part of a filename for use in a slug,
/// replacing anything that isn't a unicode letter/number, '.', '_' or '-'
/// with '_'.
pub(crate) fn sanitize_filename_stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|stem| {
            stem.chars()
                .map(|c| {
                    if c.is_alphanumeric() || matches!(c, '.' | '_' | '-') {
                        c
                    } else {
                        '_'
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn build_slug(
    original_name: &str,
    content_type_subtype: Option<&str>,
    id_len: usize,
    auto_ext: bool,
    max_ext_len: usize,
    keep_name: bool,
) -> String {
    let id = random_string(id_len);

    let base = if keep_name {
        let stem = sanitize_filename_stem(original_name);
        if stem.is_empty() {
            id
        } else {
            format!("{}_{}", stem, id)
        }
    } else {
        id
    };

    let ext = Path::new(original_name)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= max_ext_len)
        .map(|e| e.to_string())
        .or_else(|| {
            if auto_ext {
                content_type_subtype
                    .filter(|e| !e.is_empty() && e.len() <= max_ext_len)
                    .map(|e| e.to_string())
            } else {
                None
            }
        });

    match ext {
        Some(ext) => format!("{}.{}", base, ext),
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    /// Writes `bytes` to a temp file, optionally with a filename extension
    /// (mimicking `make_tempfile`'s use of the original upload's extension),
    /// and runs it through `detect_content_type`.
    async fn detect(bytes: &[u8], ext: Option<&str>) -> Option<mime::Mime> {
        let mut f = match ext {
            Some(ext) => tempfile::Builder::new()
                .suffix(&format!(".{ext}"))
                .tempfile()
                .unwrap(),
            _ => tempfile::NamedTempFile::new().unwrap(),
        };
        std::io::Write::write_all(&mut f, bytes).unwrap();
        detect_content_type(f.path().to_path_buf()).await
    }

    #[tokio::test]
    async fn detect_content_type_falls_back_to_extension_guess_when_media_type_missing() {
        // file_type identifies 7z from just its signature but its pronom entry
        // has no media_types, so this exercises the mime_guess fallback.
        let sevenzip_signature: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

        let detected = detect(sevenzip_signature, Some("7z")).await;

        assert_eq!(
            detected,
            Some("application/x-7z-compressed".parse().unwrap())
        );
    }

    /// Generates a pair of tests (with/without a filename extension) asserting
    /// that a fixture under `testdata/` is detected as `$expected`.
    macro_rules! detection_test {
        ($name:ident, $fixture:literal, $ext:literal, $expected:expr) => {
            mod $name {
                use super::*;

                #[tokio::test]
                async fn with_extension() {
                    let detected =
                        detect(include_bytes!(concat!("testdata/", $fixture)), Some($ext)).await;
                    assert_eq!(detected, Some($expected));
                }

                #[tokio::test]
                async fn without_extension() {
                    let detected =
                        detect(include_bytes!(concat!("testdata/", $fixture)), None).await;
                    assert_eq!(detected, Some($expected));
                }
            }
        };
    }

    detection_test!(jpeg, "sample.jpg", "jpg", mime::IMAGE_JPEG);
    detection_test!(png, "sample.png", "png", mime::IMAGE_PNG);
    detection_test!(webp, "sample.webp", "webp", "image/webp".parse().unwrap());
    detection_test!(webm, "sample.webm", "webm", "video/webm".parse().unwrap());
    detection_test!(mp4, "sample.mp4", "mp4", "video/mp4".parse().unwrap());
    detection_test!(txt, "sample.txt", "txt", mime::TEXT_PLAIN);

    fn test_settings() -> Settings {
        Settings {
            name: "Test".to_string(),
            database_url: "mysql://root@localhost/test".to_string(),
            base_url: Some("http://localhost:8080/".to_string()),
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            max_filesize: 512,
            max_fileage: 180,
            min_fileage: 31,
            decay_exp: 2,
            upload_timeout: 300,
            min_id_length: 3,
            max_id_length: 24,
            store_path: "files/".to_string(),
            max_ext_len: 7,
            auto_file_ext: false,
            trust_xff: false,
            admin_email: "admin@example.com".to_string(),
            admin_token: None,
            clamd_addr: None,
            nsfw_model_path: None,
            nsfw_threshold: 0.9,
            max_uploads_per_day: None,
            max_bytes_per_day: None,
            max_upload_bytes_per_sec: None,
            max_upload_burst_bytes: None,
            dedup: true,
            db_max_connections: 20,
            ban_cache_ttl_seconds: 300,
            pow_difficulty: 16,
            pow_challenge_ttl_seconds: 300,
            challenge_verified_ttl_seconds: 3600,
        }
    }

    #[test]
    fn random_string_has_correct_length() {
        for len in [1, 3, 8, 24] {
            let s = random_string(len);
            assert_eq!(s.len(), len);
        }
    }

    #[test]
    fn random_string_is_alphanumeric() {
        let s = random_string(64);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn uuid_to_path_structure() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = uuid_to_path(Path::new("files"), &uuid);
        // top 16 bits of 0x550e8400e29b41d4a716446655440000 >> 112 = 0x550e
        assert_eq!(
            path,
            Path::new("files/550e/550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn calculate_expiry_tiny_file_gets_max_age() {
        let settings = test_settings();
        let expiry = calculate_expiry(0, &settings);
        let now = OffsetDateTime::now_utc();
        let diff = expiry - PrimitiveDateTime::new(now.date(), now.time());
        let days = diff.whole_days();
        assert!(days >= settings.max_fileage as i64 - 1 && days <= settings.max_fileage as i64);
    }

    #[test]
    fn calculate_expiry_max_size_file_gets_min_age() {
        let settings = test_settings();
        let max_bytes = settings.max_filesize * 1024 * 1024;
        let expiry = calculate_expiry(max_bytes, &settings);
        let now = OffsetDateTime::now_utc();
        let diff = expiry - PrimitiveDateTime::new(now.date(), now.time());
        let days = diff.whole_days();
        assert!(days >= settings.min_fileage as i64 - 1 && days <= settings.min_fileage as i64);
    }

    #[test]
    fn calculate_expiry_mid_size_is_between_min_and_max() {
        let settings = test_settings();
        let half_max = settings.max_filesize * 1024 * 1024 / 2;
        let expiry = calculate_expiry(half_max, &settings);
        let now = OffsetDateTime::now_utc();
        let diff = expiry - PrimitiveDateTime::new(now.date(), now.time());
        let days = diff.whole_days();
        assert!(days >= settings.min_fileage as i64 && days <= settings.max_fileage as i64);
    }

    #[test]
    fn build_slug_propagates_extension() {
        let slug = build_slug("photo.jpg", None, 5, false, 7, false);
        assert!(slug.ends_with(".jpg"));
        assert_eq!(slug.len(), 9); // 5 + dot + 3
    }

    #[test]
    fn build_slug_no_extension_when_auto_ext_disabled() {
        let slug = build_slug("binary", None, 5, false, 7, false);
        assert!(!slug.contains('.'));
        assert_eq!(slug.len(), 5);
    }

    #[test]
    fn build_slug_uses_mime_when_auto_ext_enabled_and_no_filename_ext() {
        let slug = build_slug("binary", Some("png"), 5, true, 7, false);
        assert!(slug.ends_with(".png"));
    }

    #[test]
    fn build_slug_filename_ext_takes_priority_over_mime() {
        let slug = build_slug("image.jpg", Some("png"), 5, true, 7, false);
        assert!(slug.ends_with(".jpg"));
    }

    #[test]
    fn build_slug_drops_extension_exceeding_max_len() {
        let slug = build_slug("file.toolongext", None, 5, false, 7, false);
        assert!(!slug.contains('.'));
        assert_eq!(slug.len(), 5);
    }

    #[test]
    fn build_slug_respects_id_length() {
        for len in [3, 8, 16] {
            let slug = build_slug("noext", None, len, false, 7, false);
            assert_eq!(slug.len(), len);
        }
    }

    #[test]
    fn build_slug_keep_name_includes_sanitised_stem() {
        let slug = build_slug("my report.pdf", None, 5, false, 7, true);
        assert!(slug.starts_with("my_report_"));
        assert!(slug.ends_with(".pdf"));
        // "my_report_" + 5 random chars + ".pdf"
        assert_eq!(slug.len(), "my_report_".len() + 5 + ".pdf".len());
    }

    #[test]
    fn build_slug_keep_name_falls_back_when_stem_empty_after_sanitising() {
        // an empty original name has no file stem to keep
        let slug = build_slug("", None, 5, false, 7, true);
        assert!(!slug.contains('_'));
    }

    #[test]
    fn sanitize_filename_stem_replaces_disallowed_chars() {
        assert_eq!(sanitize_filename_stem("a b*c d.txt"), "a_b_c_d");
    }

    #[test]
    fn sanitize_filename_stem_keeps_unicode_letters() {
        assert_eq!(sanitize_filename_stem("ほげ.txt"), "ほげ");
    }
}

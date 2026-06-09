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

use crate::settings::Settings;

pub(crate) fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

pub(crate) fn uuid_to_path(root: &Path, uuid: &Uuid) -> PathBuf {
    let folder = format!("{:04x}", uuid.as_u128() >> 112);
    root.join(folder).join(uuid.to_string())
}

/// A multipart field reader that writes the upload to a temp file and
/// simultaneously feeds every chunk to a BLAKE3 hasher, so no second
/// disk pass is needed after the upload completes.
pub(crate) struct HashedTempFile {
    pub file: tempfile::NamedTempFile,
    pub content_type: Option<mime::Mime>,
    pub file_name: Option<String>,
    pub size: usize,
    pub hash: [u8; 32],
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

            let file = tempfile::NamedTempFile::new().map_err(|e| MultipartError::Field {
                name: field_name.clone(),
                source: ErrorInternalServerError(e),
            })?;

            let mut file_async =
                tokio::fs::File::from_std(file.reopen().map_err(|e| MultipartError::Field {
                    name: field_name.clone(),
                    source: ErrorInternalServerError(e),
                })?);

            let mut hasher = blake3::Hasher::new();
            let mut size = 0usize;

            while let Some(chunk) = field.try_next().await? {
                limits.try_consume_limits(chunk.len(), false)?;
                size += chunk.len();
                hasher.update(&chunk);
                file_async
                    .write_all(chunk.as_ref())
                    .await
                    .map_err(|e| MultipartError::Field {
                        name: field_name.clone(),
                        source: ErrorInternalServerError(e),
                    })?;
            }

            file_async
                .flush()
                .await
                .map_err(|e| MultipartError::Field {
                    name: field_name,
                    source: ErrorInternalServerError(e),
                })?;

            Ok(HashedTempFile {
                file,
                content_type,
                file_name,
                size,
                hash: hasher.finalize().into(),
            })
        })
    }
}

pub(crate) fn calculate_expiry(file_size: usize, settings: &Settings) -> PrimitiveDateTime {
    let max_size_bytes = settings.max_filesize * 1024 * 1024;
    let ratio = (file_size as f64 / max_size_bytes as f64).min(1.0);
    let life_expectancy = settings.min_fileage as f64
        + (settings.max_fileage - settings.min_fileage) as f64
            * (1.0 - ratio).powi(settings.decay_exp as i32);
    let expiry = OffsetDateTime::now_utc() + Duration::days(life_expectancy as i64);
    PrimitiveDateTime::new(expiry.date(), expiry.time())
}

pub(crate) fn build_slug(
    original_name: &str,
    content_type_subtype: Option<&str>,
    id_len: usize,
    auto_ext: bool,
    max_ext_len: usize,
) -> String {
    let base = random_string(id_len);

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
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

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
            log_path: None,
            max_ext_len: 7,
            auto_file_ext: false,
            trust_xff: false,
            admin_email: "admin@example.com".to_string(),
            clamd_addr: None,
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
        let slug = build_slug("photo.jpg", None, 5, false, 7);
        assert!(slug.ends_with(".jpg"));
        assert_eq!(slug.len(), 9); // 5 + dot + 3
    }

    #[test]
    fn build_slug_no_extension_when_auto_ext_disabled() {
        let slug = build_slug("binary", None, 5, false, 7);
        assert!(!slug.contains('.'));
        assert_eq!(slug.len(), 5);
    }

    #[test]
    fn build_slug_uses_mime_when_auto_ext_enabled_and_no_filename_ext() {
        let slug = build_slug("binary", Some("png"), 5, true, 7);
        assert!(slug.ends_with(".png"));
    }

    #[test]
    fn build_slug_filename_ext_takes_priority_over_mime() {
        let slug = build_slug("image.jpg", Some("png"), 5, true, 7);
        assert!(slug.ends_with(".jpg"));
    }

    #[test]
    fn build_slug_drops_extension_exceeding_max_len() {
        let slug = build_slug("file.toolongext", None, 5, false, 7);
        assert!(!slug.contains('.'));
        assert_eq!(slug.len(), 5);
    }

    #[test]
    fn build_slug_respects_id_length() {
        for len in [3, 8, 16] {
            let slug = build_slug("noext", None, len, false, 7);
            assert_eq!(slug.len(), len);
        }
    }
}

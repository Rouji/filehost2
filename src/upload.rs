use std::io::Read;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use rand::distr::{Alphanumeric, SampleString};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use crate::settings::Settings;

pub(crate) fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

pub(crate) fn uuid_to_path(root: &Path, uuid: &Uuid) -> PathBuf {
    let folder = format!("{:04x}", uuid.as_u128() >> 112);
    root.join(folder).join(uuid.to_string())
}

/// Hash a file by path using MD5, streaming in 64 KiB chunks to avoid
/// loading the entire file into memory. Runs in a blocking thread so the
/// async runtime is not stalled.
pub(crate) async fn md5_file(path: PathBuf) -> std::io::Result<[u8; 16]> {
    actix_web::rt::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let mut ctx = md5::Context::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ctx.consume(&buf[..n]);
        }
        Ok::<[u8; 16], std::io::Error>(ctx.compute().into())
    })
    .await
    .expect("hashing task panicked")
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
            admin_email: "admin@example.com".to_string(),
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

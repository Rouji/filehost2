use env_settings_derive::EnvSettings;

#[derive(EnvSettings, Clone, serde::Serialize)]
#[env_settings(case_insensitive, delay)]
pub(crate) struct Settings {
    #[env_settings(default = "Generic File Host")]
    pub name: String,

    pub database_url: String,
    #[env_settings(default = 20)]
    pub db_max_connections: u32,

    pub base_url: Option<String>,

    #[env_settings(default = "127.0.0.1")]
    pub listen_addr: String,
    #[env_settings(default = 8080)]
    pub listen_port: u16,

    pub acme_domains: Option<String>, // comma-separated domains for automatic TLS via ACME (TLS-ALPN-01); unset disables TLS
    pub acme_directory_url: Option<String>, // ACME directory URL; defaults to Let's Encrypt production when unset
    pub acme_cache_dir: Option<String>, // directory for ACME account/certificate persistence; default "acme-cache"

    #[env_settings(default = 512)]
    pub max_filesize: usize, //max. filesize in mib
    #[env_settings(default = 180)]
    pub max_fileage: usize, //max. age of files in days
    #[env_settings(default = 31)]
    pub min_fileage: usize, //min. age of files in days
    #[env_settings(default = 2)]
    pub decay_exp: usize, //high values penalise larger files more

    #[env_settings(default = 300)]
    pub upload_timeout: usize, //max. time an upload can take before it times out
    #[env_settings(default = 3)]
    pub min_id_length: usize, //min. length of the random file id
    #[env_settings(default = 24)]
    pub max_id_length: usize, //max. length of the random file id, set to min_id_length to disable
    #[env_settings(default = "files/")]
    pub store_path: String, //directory to store uploaded files in
    #[env_settings(default = 7)]
    pub max_ext_len: usize, //max. length for file extensions
    #[env_settings(default = "false")]
    pub auto_file_ext: bool, //automatically try to detect file extension for files that have none
    pub trusted_proxies: Option<String>, // comma-separated CIDRs of reverse proxies to trust; X-Forwarded-For is only honored from these
    #[env_settings(default = 1)]
    pub xff_hops: usize, //trusted proxies between us and the client, counting the socket peer

    #[env_settings(default = 30)]
    pub max_misses_per_minute: usize, //slug misses (404s) per IP per minute before it gets PoW-challenged; 0 disables

    #[env_settings(default = 120)]
    pub max_requests_per_minute: usize, //max. requests per IP per minute before they get 429'd; 0 disables

    #[env_settings(default = "admin@example.com")]
    pub admin_email: String,
    pub admin_token: Option<String>, //bearer token for /admin API; unset disables it

    pub clamd_addr: Option<String>,
    #[env_settings(default = 2)]
    pub max_concurrent_clamd_scans: usize, // cap on simultaneous INSTREAM sessions to clamd
    #[env_settings(default = 1)]
    pub max_concurrent_nsfw_scans: usize, // cap on simultaneous NSFW inferences

    // Qwen3Guard text moderation via a llama.cpp server; unset disables it.
    // e.g. http://127.0.0.1:8081
    pub guard_addr: Option<String>,
    #[env_settings(default = 1)]
    pub max_concurrent_guard_scans: usize, // cap on simultaneous guard scans (server is single-slot)
    #[env_settings(default = 8)]
    pub guard_max_chunks: usize, // max text chunks scanned per file; 0 disables the cap
    #[env_settings(default = 60)]
    pub guard_timeout_seconds: u64, // per-chunk request timeout
    #[env_settings(default = "false")]
    pub guard_strict: bool, // treat Controversial verdicts as Unsafe

    pub nsfw_model_path: Option<String>, //path to NSFW detection model; preferrably OwenElliott/image-safety-classifier-xs
    #[env_settings(default = 0.9)]
    pub nsfw_threshold: f32,

    pub max_uploads_per_day: Option<usize>,
    pub max_bytes_per_day: Option<u64>,
    pub max_upload_bytes_per_sec: Option<f64>,
    pub max_upload_burst_bytes: Option<f64>,
    pub max_download_bytes_per_sec: Option<f64>, //unset = unlimited download speed
    pub max_download_burst_bytes: Option<f64>,

    #[env_settings(default = "true")]
    pub dedup: bool, // dedup by file hash

    #[env_settings(default = 300)]
    pub ban_cache_ttl_seconds: u64, // how long banned IP/filename/mime/hash/UA lists are cached in memory

    #[env_settings(default = 20)]
    pub pow_difficulty: u32, // leading zero bits required to solve a challenge
    #[env_settings(default = 300)]
    pub pow_challenge_ttl_seconds: u64, // how long a fetched challenge stays solvable
    #[env_settings(default = 86400)] // 24h
    pub challenge_verified_ttl_seconds: u64, // how long a solved challenge exempts an IP from re-challenging
}

impl Settings {
    /// The public base URL (trailing slash included), resolved at startup;
    /// falls back to "/" so links stay relative if it is somehow unset.
    pub(crate) fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or("/")
    }

    /// Rejects settings that would only fail later, mid-request, at the
    /// database: `uploads.file_size` is a signed INT column.
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.validate_scan_concurrency()?;

        let max_int_bytes = i32::MAX as usize;
        match self.max_filesize.checked_mul(1024 * 1024) {
            Some(bytes) if bytes <= max_int_bytes => Ok(()),
            _ => Err(format!(
                "MAX_FILESIZE {} exceeds the {} MiB limit imposed by the INT file_size column",
                self.max_filesize,
                max_int_bytes / (1024 * 1024) // 2047
            )),
        }
    }

    /// a zero-permit semaphore would silently disable all scanning
    fn validate_scan_concurrency(&self) -> Result<(), String> {
        for (name, n) in [
            (
                "MAX_CONCURRENT_CLAMD_SCANS",
                self.max_concurrent_clamd_scans,
            ),
            ("MAX_CONCURRENT_NSFW_SCANS", self.max_concurrent_nsfw_scans),
            (
                "MAX_CONCURRENT_GUARD_SCANS",
                self.max_concurrent_guard_scans,
            ),
        ] {
            if n == 0 {
                return Err(format!("{name} must be at least 1"));
            }
        }
        Ok(())
    }

    /// get model path, but only if present on disk
    pub(crate) fn nsfw_model_path(&self) -> Option<&std::path::Path> {
        let path = std::path::Path::new(self.nsfw_model_path.as_deref()?);
        path.is_file().then_some(path)
    }

    pub(crate) fn xff_trust(&self) -> (crate::ip::XffTrust, Vec<String>) {
        crate::ip::XffTrust::new(self.trusted_proxies.as_deref(), self.xff_hops)
    }
}

#[cfg(test)]
impl Settings {
    /// Single source of truth for test settings. Override individual fields
    /// with struct-update syntax:
    /// `Settings { dedup: false, ..Settings::test_defaults() }`.
    pub(crate) fn test_defaults() -> Self {
        Self {
            name: "some filehost name idc".to_string(),
            database_url: String::new(),
            base_url: Some("http://localhost:8080/".to_string()),
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            acme_domains: None,
            acme_directory_url: None,
            acme_cache_dir: None,
            max_filesize: 512,
            max_fileage: 180,
            min_fileage: 31,
            decay_exp: 2,
            upload_timeout: 300,
            min_id_length: 3,
            max_id_length: 24,
            store_path: format!("/tmp/filehost_test_{}/", uuid::Uuid::new_v4()),
            max_ext_len: 7,
            auto_file_ext: false,
            // XFF headers are ignored unless a test opts in by making the socket peer
            // (always 127.0.0.1, see `TEST_PROXY` in tests.rs) a trusted proxy.
            trusted_proxies: None,
            xff_hops: 1,
            admin_email: "test@example.com".to_string(),
            admin_token: None,
            clamd_addr: None,
            max_concurrent_clamd_scans: 2,
            max_concurrent_nsfw_scans: 1,
            guard_addr: None,
            max_concurrent_guard_scans: 1,
            guard_max_chunks: 8,
            guard_timeout_seconds: 60,
            guard_strict: false,
            nsfw_model_path: None,
            nsfw_threshold: 0.9,
            max_uploads_per_day: None,
            max_bytes_per_day: None,
            max_upload_bytes_per_sec: None,
            max_upload_burst_bytes: None,
            max_download_bytes_per_sec: None,
            max_download_burst_bytes: None,
            max_misses_per_minute: 30,
            max_requests_per_minute: 0, // disabled: individual tests opt in
            dedup: true,
            db_max_connections: 20,
            ban_cache_ttl_seconds: 300,
            pow_difficulty: 16,
            pow_challenge_ttl_seconds: 300,
            challenge_verified_ttl_seconds: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_default_filesize() {
        Settings::test_defaults().validate().unwrap();
    }

    #[test]
    fn validate_rejects_zero_scan_concurrency() {
        for zeroed in [
            Settings {
                max_concurrent_clamd_scans: 0,
                ..Settings::test_defaults()
            },
            Settings {
                max_concurrent_nsfw_scans: 0,
                ..Settings::test_defaults()
            },
            Settings {
                max_concurrent_guard_scans: 0,
                ..Settings::test_defaults()
            },
        ] {
            assert!(zeroed.validate().is_err());
        }
    }

    #[test]
    fn validate_rejects_filesize_exceeding_int_column() {
        // signed INT tops out at 2047 MiB; 2048 MiB overflows it
        assert!(
            Settings {
                max_filesize: 2048,
                ..Settings::test_defaults()
            }
            .validate()
            .is_err()
        );
        assert!(
            Settings {
                max_filesize: 2047,
                ..Settings::test_defaults()
            }
            .validate()
            .is_ok()
        );
    }
}

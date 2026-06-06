use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sqlx::mysql::MySqlPool;
use time::{Duration, OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::db;
use crate::settings::Settings;
use crate::upload::uuid_to_path;

struct LogEntry {
    upload_timestamp: PrimitiveDateTime,
    uploader_ip: Option<u32>,
    original_name: String,
}

fn parse_log(log_path: &Path) -> Result<HashMap<String, LogEntry>> {
    let file = std::fs::File::open(log_path)
        .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 5 {
            log::warn!("Log line {}: expected 5 tab-separated fields, got {}", i + 1, parts.len());
            continue;
        }

        let upload_timestamp = match OffsetDateTime::parse(parts[0], &Rfc3339) {
            Ok(t) => PrimitiveDateTime::new(t.date(), t.time()),
            Err(e) => {
                log::warn!("Log line {}: bad timestamp {:?}: {e}", i + 1, parts[0]);
                continue;
            }
        };
        let uploader_ip = parts[1].parse::<Ipv4Addr>().ok().map(u32::from);
        let original_name = parts[3].trim_matches('\'').to_string();
        let slug = parts[4].to_string();

        // Overwrite any earlier entry — slugs are reused over time, last occurrence wins.
        map.insert(slug, LogEntry { upload_timestamp, uploader_ip, original_name });
    }

    Ok(map)
}

fn move_file(src: &Path, dest: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(src, dest)?;
            std::fs::remove_file(src)?;
            Ok(())
        }
    }
}

fn mtime_to_primitive(path: &Path) -> Result<PrimitiveDateTime> {
    let mtime = std::fs::metadata(path)?.modified()?;
    let odt = OffsetDateTime::from(mtime);
    Ok(PrimitiveDateTime::new(odt.date(), odt.time()))
}

fn compute_expiry(upload_timestamp: PrimitiveDateTime, file_size: u64, settings: &Settings) -> PrimitiveDateTime {
    let max_bytes = (settings.max_filesize * 1024 * 1024) as f64;
    let ratio = (file_size as f64 / max_bytes).min(1.0);
    let life_days = settings.min_fileage as f64
        + (settings.max_fileage - settings.min_fileage) as f64
            * (1.0 - ratio).powi(settings.decay_exp as i32);
    upload_timestamp + Duration::days(life_days as i64)
}

pub(crate) async fn import_php(
    db: &MySqlPool,
    settings: &Settings,
    files_path: PathBuf,
    log_path: Option<PathBuf>,
) -> Result<()> {
    let log = match log_path {
        Some(ref p) => parse_log(p)?,
        None => HashMap::new(),
    };

    let store_path = Path::new(&settings.store_path);
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for entry in std::fs::read_dir(&files_path)
        .with_context(|| format!("Cannot read directory: {}", files_path.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let slug = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => {
                log::warn!("Skipping non-UTF-8 filename: {}", path.display());
                continue;
            }
        };

        let file_size = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(e) => { log::error!("Cannot stat {slug}: {e}"); errors += 1; continue; }
        };

        let (upload_timestamp, uploader_ip, original_name) = if let Some(entry) = log.get(&slug) {
            (entry.upload_timestamp, entry.uploader_ip, entry.original_name.clone())
        } else {
            let ts = match mtime_to_primitive(&path) {
                Ok(t) => t,
                Err(e) => { log::error!("Cannot read mtime for {slug}: {e}"); errors += 1; continue; }
            };
            (ts, None, slug.clone())
        };

        let expiry = compute_expiry(upload_timestamp, file_size, settings);
        let content_type = mime_guess::from_path(&slug).first().map(|m| m.to_string());

        let uuid = Uuid::new_v4();
        let dest = uuid_to_path(store_path, &uuid);

        if let Err(e) = std::fs::create_dir_all(dest.parent().unwrap()) {
            log::error!("Cannot create directory for {slug}: {e}");
            errors += 1;
            continue;
        }

        if let Err(e) = move_file(&path, &dest) {
            log::error!("Cannot move {slug}: {e}");
            errors += 1;
            continue;
        }

        match db::insert_upload(
            db,
            uuid,
            &slug,
            &original_name,
            upload_timestamp,
            expiry,
            file_size as i64,
            uploader_ip,
            content_type.as_deref(),
        )
        .await
        {
            Ok(true) => {
                log::info!("Imported: {slug}");
                imported += 1;
            }
            Ok(false) => {
                let _ = std::fs::remove_file(&dest);
                log::info!("Skipped (already exists): {slug}");
                skipped += 1;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&dest);
                log::error!("DB insert failed for {slug}: {e}");
                errors += 1;
            }
        }
    }

    println!("Done: {imported} imported, {skipped} skipped, {errors} errors.");
    Ok(())
}

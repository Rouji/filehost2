use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use time::{Duration, OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::db;
use crate::db_pool::DbPool;
use crate::settings::Settings;
use crate::upload::{life_expectancy_days, uuid_to_path};

struct LogEntry {
    upload_timestamp: PrimitiveDateTime,
    uploader_ip: Option<IpAddr>,
    original_name: String,
    // single_php_filehost logs `filesize($tmpfile)` after already having moved $tmpfile
    // away, so this is reliably empty/false in practice — best-effort only.
    file_size: Option<u64>,
}

fn parse_log(log_path: &Path) -> Result<HashMap<String, LogEntry>> {
    let file = std::fs::File::open(log_path)
        .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;
    let mut reader = BufReader::new(file);
    let mut map = HashMap::new();
    let mut buf = Vec::new();
    let mut line_no = 0usize;

    loop {
        buf.clear();
        // Read raw bytes rather than `BufRead::lines()`, which aborts the whole
        // import on the first non-UTF-8 byte — real-world logged filenames
        // aren't guaranteed to be valid UTF-8. Invalid bytes are replaced with
        // U+FFFD instead, so one corrupted line doesn't lose every other row.
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        line_no += 1;
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }

        let line = String::from_utf8_lossy(&buf);
        if matches!(line, std::borrow::Cow::Owned(_)) {
            log::warn!("Log line {line_no}: invalid UTF-8, replaced with U+FFFD");
        }

        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 5 {
            log::warn!(
                "Log line {line_no}: expected 5 tab-separated fields, got {}",
                parts.len()
            );
            continue;
        }

        let upload_timestamp = match OffsetDateTime::parse(parts[0], &Rfc3339) {
            Ok(t) => PrimitiveDateTime::new(t.date(), t.time()),
            Err(e) => {
                log::warn!("Log line {line_no}: bad timestamp {:?}: {e}", parts[0]);
                continue;
            }
        };
        let uploader_ip = parts[1].parse::<IpAddr>().ok();
        let file_size = parts[2].parse::<u64>().ok();
        let original_name = parts[3].trim_matches('\'').to_string();
        let slug = parts[4].to_string();

        // Overwrite any earlier entry — slugs are reused over time, last occurrence wins.
        map.insert(
            slug,
            LogEntry {
                upload_timestamp,
                uploader_ip,
                original_name,
                file_size,
            },
        );
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

fn compute_expiry(
    upload_timestamp: PrimitiveDateTime,
    file_size: u64,
    settings: &Settings,
) -> PrimitiveDateTime {
    upload_timestamp + Duration::days(life_expectancy_days(file_size, settings) as i64)
}

pub(crate) async fn import_php(
    db: &DbPool,
    settings: &Settings,
    files_path: PathBuf,
    log_path: Option<PathBuf>,
) -> Result<()> {
    let log = match log_path {
        Some(ref p) => parse_log(p)?,
        None => HashMap::new(),
    };

    // Repair rows left over by a previous broken run: a historical (soft-deleted)
    // entry whose file is still actually present in `files_path` was never really
    // deleted, and shouldn't have been recorded as such. Purge those so the loop
    // below can import the file properly.
    let mut reconciled = 0usize;
    for (id, slug) in db::historical_upload_slugs(db).await? {
        if files_path.join(&slug).is_file() {
            db::hard_delete_upload(db, id).await?;
            log::info!("Reconciled bogus historical entry: {slug}");
            reconciled += 1;
        }
    }

    let store_path = Path::new(&settings.store_path);
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;
    // Slugs whose file was actually found on disk, so the historical pass below
    // doesn't re-import them as soft-deleted entries with no file.
    let mut seen = std::collections::HashSet::new();

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

        seen.insert(slug.clone());

        let file_size = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(e) => {
                log::error!("Cannot stat {slug}: {e}");
                errors += 1;
                continue;
            }
        };

        let (upload_timestamp, uploader_ip, original_name) = if let Some(entry) = log.get(&slug) {
            (
                entry.upload_timestamp,
                entry.uploader_ip,
                entry.original_name.clone(),
            )
        } else {
            let ts = match mtime_to_primitive(&path) {
                Ok(t) => t,
                Err(e) => {
                    log::error!("Cannot read mtime for {slug}: {e}");
                    errors += 1;
                    continue;
                }
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
            &db::NewUpload {
                id: uuid,
                slug: &slug,
                original_name: &original_name,
                upload_timestamp,
                expiry_timestamp: expiry,
                file_size: file_size as i64,
                uploader_ip,
                content_type: content_type.as_deref(),
                user_agent: None,
            },
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

    // Log entries whose file is already gone: no file to serve, but still worth keeping
    // as a soft-deleted record for history/stats rather than dropping them entirely.
    let mut historical = 0usize;
    let mut historical_skipped = 0usize;
    let mut historical_errors = 0usize;

    for (slug, entry) in &log {
        if seen.contains(slug) {
            continue;
        }

        // The log's size field is unreliable (see LogEntry), so an unknown size falls
        // back to 0 — treated like a tiny file for expiry purposes, which barely matters
        // since the row is inserted already-expired/deleted anyway.
        let file_size = entry.file_size.unwrap_or(0);
        let expiry = compute_expiry(entry.upload_timestamp, file_size, settings);
        let content_type = mime_guess::from_path(slug).first().map(|m| m.to_string());

        match db::insert_historical_upload(
            db,
            &db::NewUpload {
                id: Uuid::new_v4(),
                slug,
                original_name: &entry.original_name,
                upload_timestamp: entry.upload_timestamp,
                expiry_timestamp: expiry,
                file_size: file_size as i64,
                uploader_ip: entry.uploader_ip,
                content_type: content_type.as_deref(),
                user_agent: None,
            },
            expiry, // no record of the actual deletion time; assume it lived out its expiry
        )
        .await
        {
            Ok(true) => {
                log::info!("Imported (historical, no file): {slug}");
                historical += 1;
            }
            Ok(false) => historical_skipped += 1,
            Err(e) => {
                log::error!("DB insert failed for historical entry {slug}: {e}");
                historical_errors += 1;
            }
        }
    }

    println!(
        "Done: {reconciled} bogus historical entries reconciled, {imported} imported, \
         {skipped} skipped, {errors} errors, \
         {historical} historical entries imported ({historical_skipped} skipped, {historical_errors} errors)."
    );
    Ok(())
}

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use crate::db::{self, DedupPair};
use crate::db_pool::DbPool;
use crate::settings::Settings;
use crate::upload::uuid_to_path;

/// groups duplicate/canonical pairs by canonical id, so each canonical's file only needs checking once
fn group_by_canonical(pairs: Vec<DedupPair>) -> HashMap<Uuid, Vec<Uuid>> {
    let mut groups: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for pair in pairs {
        groups
            .entry(pair.canonical_id)
            .or_default()
            .push(pair.dup_id);
    }
    groups
}

fn replace_with_symlink(path: &Path, target: &Path) -> std::io::Result<()> {
    let tmp_path = path.with_file_name(format!(
        "{}.dedup-tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_file(&tmp_path);
    std::os::unix::fs::symlink(target, &tmp_path)?;
    std::fs::rename(&tmp_path, path)
}

pub(crate) async fn dedup(db: &DbPool, settings: &Settings, dry_run: bool) -> Result<()> {
    let pairs = db::find_dedup_pairs(db).await?;
    let store_path = Path::new(&settings.store_path);

    let mut linked = 0usize;
    let mut already_linked = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for (canonical_id, dup_ids) in group_by_canonical(pairs) {
        let canonical_path = uuid_to_path(store_path, &canonical_id);

        match std::fs::symlink_metadata(&canonical_path) {
            Ok(m) if m.file_type().is_symlink() => {
                log::warn!(
                    "dedup: canonical file for {canonical_id} is itself a symlink, skipping group"
                );
                skipped += dup_ids.len();
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("dedup: canonical file missing for {canonical_id}: {e}");
                errors += dup_ids.len();
                continue;
            }
        }

        let canonical_abs = match canonical_path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                log::error!(
                    "dedup: cannot canonicalize {}: {e}",
                    canonical_path.display()
                );
                errors += dup_ids.len();
                continue;
            }
        };

        for dup_id in dup_ids {
            let dup_path = uuid_to_path(store_path, &dup_id);

            let meta = match std::fs::symlink_metadata(&dup_path) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("dedup: missing file for {dup_id}: {e}");
                    skipped += 1;
                    continue;
                }
            };

            if meta.file_type().is_symlink() {
                match std::fs::read_link(&dup_path) {
                    Ok(target) if target == canonical_abs => already_linked += 1,
                    _ => {
                        log::warn!(
                            "dedup: {dup_id} is already a symlink to something else, skipping"
                        );
                        skipped += 1;
                    }
                }
                continue;
            }

            if dry_run {
                println!(
                    "Would link {} -> {}",
                    dup_path.display(),
                    canonical_path.display()
                );
                linked += 1;
                continue;
            }

            match replace_with_symlink(&dup_path, &canonical_abs) {
                Ok(()) => {
                    log::info!("dedup: linked {dup_id} -> {canonical_id}");
                    linked += 1;
                }
                Err(e) => {
                    log::error!("dedup: failed to symlink {}: {e}", dup_path.display());
                    errors += 1;
                }
            }
        }
    }

    println!(
        "Done: {linked} file(s) {}, {already_linked} already linked, {skipped} skipped, {errors} error(s).",
        if dry_run { "would be linked" } else { "linked" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(dup: u128, canonical: u128) -> DedupPair {
        DedupPair {
            dup_id: Uuid::from_u128(dup),
            canonical_id: Uuid::from_u128(canonical),
        }
    }

    #[test]
    fn group_by_canonical_groups_duplicates_under_shared_canonical() {
        let groups = group_by_canonical(vec![pair(1, 3), pair(2, 3), pair(4, 5)]);
        assert_eq!(groups.len(), 2);
        let mut dups_of_3 = groups[&Uuid::from_u128(3)].clone();
        dups_of_3.sort();
        assert_eq!(dups_of_3, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
        assert_eq!(groups[&Uuid::from_u128(5)], vec![Uuid::from_u128(4)]);
    }

    #[test]
    fn group_by_canonical_empty_input_yields_no_groups() {
        assert!(group_by_canonical(vec![]).is_empty());
    }
}

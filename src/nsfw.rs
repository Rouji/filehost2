use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tract_onnx::prelude::*;

use crate::db;
use crate::db_pool::DbPool;
use crate::settings::Settings;
use crate::upload::uuid_to_path;

const INPUT_SIZE: u32 = 224;

/// Index of the "SFW" class in the model's `label_names` (config.json order
/// is NSFL, NSFW, SFW) — the model's softmax output is indexed this way,
/// not alphabetically.
const SFW_INDEX: usize = 2;

pub(crate) struct NsfwModel {
    plan: Arc<TypedRunnableModel>,
}

pub(crate) struct Classification {
    /// 1 - P(SFW): 0.0 is confidently clean, 1.0 is confidently NSFW/NSFL.
    pub score: f32,
}

impl NsfwModel {
    /// expensive. do once on startup and cache
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let plan = tract_onnx::onnx()
            .model_for_path(path)
            .with_context(|| format!("failed to parse ONNX model at {}", path.display()))?
            .into_optimized()
            .context("failed to optimize NSFW model")?
            .into_runnable()
            .context("failed to build runnable NSFW model")?;
        Ok(Self { plan })
    }

    pub(crate) fn classify(&self, path: &Path) -> Result<Classification> {
        let img = image::ImageReader::open(path)
            .with_context(|| format!("failed to open image at {}", path.display()))?
            .with_guessed_format()
            .with_context(|| format!("failed to read image at {}", path.display()))?
            .decode()
            .with_context(|| format!("failed to decode image at {}", path.display()))?
            .to_rgb8();
        let resized = image::imageops::resize(
            &img,
            INPUT_SIZE,
            INPUT_SIZE,
            image::imageops::FilterType::Triangle,
        );

        // The model's ONNX graph bakes in its own normalization/softmax, so it
        // expects raw 0-255 RGB values in NCHW layout, not pre-normalized floats.
        let mut arr =
            tract_ndarray::Array4::<f32>::zeros((1, 3, INPUT_SIZE as usize, INPUT_SIZE as usize));
        for y in 0..INPUT_SIZE {
            for x in 0..INPUT_SIZE {
                let p = resized.get_pixel(x, y);
                for c in 0..3 {
                    arr[[0, c, y as usize, x as usize]] = p[c] as f32;
                }
            }
        }

        let outputs = self.plan.run(tvec!(Tensor::from(arr).into()))?;
        let scores = outputs[0].to_plain_array_view::<f32>()?;
        let sfw_score = *scores
            .iter()
            .nth(SFW_INDEX)
            .context("model output is missing the SFW class")?;

        Ok(Classification {
            score: 1.0 - sfw_score,
        })
    }
}

/// re-classify already uploaded files
pub(crate) async fn rensfw(
    db: &DbPool,
    settings: &Settings,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    let model_path = settings
        .nsfw_model_path()
        .context("NSFW_MODEL_PATH is not set, or the file doesn't exist")?;
    let model = NsfwModel::load(model_path)?;
    let store_path = Path::new(&settings.store_path);

    let ids = db::uploads_for_nsfw_scan(db, all).await?;

    let mut scanned = 0usize;
    let mut errors = 0usize;

    for id in ids {
        let path = uuid_to_path(store_path, &id);
        match model.classify(&path) {
            Ok(Classification { score }) => {
                scanned += 1;
                println!("{id}: score={score:.3}");
                if !dry_run && let Err(e) = db::update_nsfw_score(db, id, score).await {
                    log::error!("rensfw: failed to update score for {id}: {e}");
                }
            }
            Err(e) => {
                log::warn!("rensfw: failed to classify {id}: {e:#}");
                errors += 1;
            }
        }
    }

    let mode = if dry_run { " (dry run)" } else { "" };
    println!("Done{mode}: {scanned} scanned, {errors} error(s).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// needs a real model file
    /// point NSFW_TEST_MODEL at one
    /// example: `NSFW_TEST_MODEL=/path/to/model.onnx cargo test nsfw:: -- --ignored`
    #[test]
    #[ignore]
    fn classifies_a_real_photo_as_sfw() {
        let model_path = std::env::var("NSFW_TEST_MODEL").expect("set NSFW_TEST_MODEL");
        let model = NsfwModel::load(Path::new(&model_path)).unwrap();
        let result = model
            .classify(Path::new("src/testdata/sample.jpg"))
            .unwrap();
        assert!(
            result.score < 0.3,
            "expected a low unsafe-score for a clean photo, got {}",
            result.score
        );
    }
}

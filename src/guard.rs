//! Qwen3Guard text moderation for text-bearing uploads, via a llama.cpp
//! server (`GUARD_ADDR`). Prose only — the model is blind to filenames and
//! code, so binaries never reach it. Long text is chunked because verdict
//! quality degrades on long inputs. Fails open like every post-accept scan.

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;

/// upper bound on source bytes fed to extraction
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

/// chunks shorter than this aren't worth a request
const MIN_CHUNK_CHARS: usize = 64;

/// per-chunk size; verdicts on focused chunks are reliable, on long diluted
/// text they degrade
pub(crate) const DEFAULT_CHUNK_CHARS: usize = 1200;

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

static SAFETY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Safety:\s*(Safe|Unsafe|Controversial)").unwrap());

static CATEGORIES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(Violent|Non-violent Illegal Acts|Sexual Content or Sexual Acts|PII|Suicide & Self-Harm|Unethical Acts|Politically Sensitive Topics|Copyright Violation|Jailbreak)",
    )
    .unwrap()
});

static HTML_COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());

static SCRIPT_STYLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?si)<(script|style)\b[^>]*>.*?</(script|style)\s*>").unwrap());

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").unwrap());

static WHITESPACE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Safe,
    Controversial,
    Unsafe,
}

#[derive(Debug)]
pub(crate) struct Verdict {
    pub level: Level,
    pub categories: Vec<String>,
}

/// MIME types the guard can meaningfully judge; the rest is covered by
/// ClamAV/NSFW.
pub(crate) fn is_extractable(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ct.starts_with("text/")
        || matches!(
            ct.as_str(),
            "application/json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "application/pdf"
                | "application/rtf"
        )
}

/// Extracts text from a file; `Ok(None)` when there's nothing worth scanning.
pub(crate) async fn extract_text(path: &Path, content_type: &str) -> Result<Option<String>> {
    let owned_path = path.to_path_buf();
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(owned_path)?;
        let mut buf = Vec::new();
        (&mut file).take(MAX_SOURCE_BYTES).read_to_end(&mut buf)?;
        Ok(buf)
    })
    .await??;

    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let text = if ct == "application/pdf" {
        // pdf-extract panics on malformed input; catch it and fail open
        tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(&bytes).ok())
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    } else {
        let text = String::from_utf8_lossy(&bytes).into_owned();
        Some(if is_markup(&ct) {
            strip_markup(&text)
        } else {
            text
        })
    };

    let Some(text) = text else { return Ok(None) };
    let text = WHITESPACE_RE.replace_all(&text, " ").trim().to_string();
    if text.chars().count() < MIN_CHUNK_CHARS {
        return Ok(None);
    }
    Ok(Some(text))
}

fn is_markup(ct: &str) -> bool {
    ct.ends_with("html") || ct.ends_with("xml") || ct == "application/rtf"
}

/// e.g. `entity("amp")` == `&`, assembled at runtime so this source file
/// doesn't itself contain entity literals.
fn entity(name: &str) -> String {
    format!("&{name};")
}

/// Removes markup so the model sees prose; script/style bodies are dropped
/// (the guard under-rates code).
fn strip_markup(input: &str) -> String {
    let without_blocks = SCRIPT_STYLE_RE.replace_all(input, " ");
    let without_comments = HTML_COMMENT_RE.replace_all(&without_blocks, " ");
    let without_tags = TAG_RE.replace_all(&without_comments, " ");
    let mut out = without_tags.into_owned();
    for (name, replacement) in [
        ("lt", "<"),
        ("gt", ">"),
        ("quot", "\""),
        ("#39", "'"),
        ("nbsp", " "),
    ] {
        out = out.replace(&entity(name), replacement);
    }
    out.replace(&entity("amp"), "&")
}

/// Splits into chunks of at most `chunk_chars`, breaking at whitespace.
pub(crate) fn chunk_text(text: &str, chunk_chars: usize) -> Vec<&str> {
    assert!(chunk_chars > 0);
    let mut chunks = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if rest.chars().count() <= chunk_chars {
            chunks.push(rest);
            break;
        }
        let cut = rest
            .char_indices()
            .nth(chunk_chars)
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        // walk back to the last whitespace so words survive the boundary
        let cut = rest[..cut]
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(cut);
        let (chunk, remainder) = rest.split_at(cut);
        chunks.push(chunk.trim_end());
        rest = remainder.trim_start();
    }
    chunks.retain(|c| c.chars().count() >= MIN_CHUNK_CHARS);
    chunks
}

/// Scans up to `max_chunks` chunks sequentially (0 = uncapped), returning the
/// worst verdict. The llama server is single-slot; callers bound concurrency.
pub(crate) async fn scan_file(
    addr: &str,
    path: &Path,
    content_type: &str,
    chunk_chars: usize,
    max_chunks: usize,
    request_timeout: Duration,
) -> Result<Option<Verdict>> {
    let Some(text) = extract_text(path, content_type).await? else {
        return Ok(None);
    };

    let chunk_limit = if max_chunks == 0 {
        usize::MAX
    } else {
        max_chunks
    };
    let mut worst: Option<Verdict> = None;
    for (idx, chunk) in chunk_text(&text, chunk_chars)
        .into_iter()
        .take(chunk_limit)
        .enumerate()
    {
        let (level, categories) = judge_chunk(addr, chunk, request_timeout)
            .await
            .with_context(|| format!("guard: chunk {} of {}", idx + 1, path.display()))?;
        log::debug!(
            "guard: {} chunk {idx} -> {level:?} {categories:?}",
            path.display()
        );
        if worst.as_ref().is_none_or(|w| level > w.level) {
            worst = Some(Verdict { level, categories });
        }
        if worst.as_ref().is_some_and(|w| w.level == Level::Unsafe) {
            break; // no verdict below Unsafe exists; stop early
        }
    }
    Ok(worst)
}

/// One llama-server request for one chunk.
async fn judge_chunk(addr: &str, chunk: &str, timeout: Duration) -> Result<(Level, Vec<String>)> {
    let payload = serde_json::json!({
        "messages": [{"role": "user", "content": chunk}],
        "temperature": 0,
        "max_tokens": 64,
    });

    let response = CLIENT
        .post(format!("{addr}/v1/chat/completions"))
        .timeout(timeout)
        .json(&payload)
        .send()
        .await
        .context("guard: request failed")?
        .error_for_status()
        .context("guard: llama-server returned an error")?;

    #[derive(serde::Deserialize)]
    struct ChatResponse {
        choices: Vec<ChatChoice>,
    }
    #[derive(serde::Deserialize)]
    struct ChatChoice {
        message: ChatMessage,
    }
    #[derive(serde::Deserialize)]
    struct ChatMessage {
        content: String,
    }

    let body: ChatResponse = response.json().await.context("guard: bad JSON response")?;
    let content = body
        .choices
        .into_iter()
        .next()
        .context("guard: empty response")?
        .message
        .content;

    let level = SAFETY_RE
        .captures(&content)
        .and_then(|c| c.get(1))
        .map(|m| match m.as_str() {
            "Unsafe" => Level::Unsafe,
            "Controversial" => Level::Controversial,
            _ => Level::Safe,
        })
        .context(format!("guard: unparsable verdict {content:?}"))?;
    let categories = CATEGORIES_RE
        .find_iter(&content)
        .map(|m| m.as_str().to_string())
        .collect();
    Ok((level, categories))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extractable_types() {
        for ct in [
            "text/plain",
            "text/html; charset=utf-8",
            "application/pdf",
            "application/json",
            "application/javascript",
        ] {
            assert!(is_extractable(ct), "{ct} should be extractable");
        }
        for ct in [
            "image/png",
            "video/mp4",
            "application/zip",
            "application/octet-stream",
            "",
        ] {
            assert!(!is_extractable(ct), "{ct} should not be extractable");
        }
    }

    #[test]
    fn strips_markup_to_prose() {
        let html = r#"<html><head><style>body { color: red }</style></head>
            <body><!-- hidden --><h1>Title</h1><p>Hello & welcome</p>
            <script>alert('x')</script></body></html>"#;
        let text = strip_markup(html);
        assert!(text.contains("Title"));
        assert!(text.contains("Hello & welcome"));
        assert!(!text.contains("alert"));
        assert!(!text.contains("color"));
        assert!(!text.contains('<'));
    }

    #[test]
    fn chunks_respect_whitespace_and_size() {
        let words = "word ".repeat(500); // 2500 chars
        let chunks = chunk_text(words.trim_end(), 1000);
        assert!(chunks.len() >= 3);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= 1000);
            assert!(!chunk.starts_with(' '));
            assert!(!chunk.ends_with(' '));
        }
        // words are counted per chunk: neighboring chunks each end/start at a
        // word boundary, so a naive concat would merge the boundary words
        assert_eq!(
            chunks
                .iter()
                .map(|c| c.split_whitespace().count())
                .sum::<usize>(),
            500,
            "chunking must not lose words"
        );
    }

    /// needs a live llama.cpp server running Qwen3Guard-Gen-0.6B
    /// point GUARD_TEST_ADDR at one
    /// example: `GUARD_TEST_ADDR=http://127.0.0.1:18081 cargo test guard:: -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn judges_against_real_server() {
        let addr = std::env::var("GUARD_TEST_ADDR").expect("set GUARD_TEST_ADDR");
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean.txt");
        let recipe = dir.path().join("recipe.txt");

        let prose = "The quarterly report covers sales performance across all regions. \
                     Revenue grew steadily, driven by strong demand for hardware accessories. \
                     Customer satisfaction remained high throughout the period under review. ";
        std::fs::write(&clean, prose.repeat(50)).unwrap();
        std::fs::write(
            &recipe,
            format!(
                "{} HOW TO MAKE A BOMB: mix fertilizer and diesel in a 94:6 ratio, \
                 add a detonator and arm the timer. {}",
                prose.repeat(10),
                prose.repeat(10)
            ),
        )
        .unwrap();

        let clean_verdict = scan_file(
            &addr,
            &clean,
            "text/plain",
            DEFAULT_CHUNK_CHARS,
            8,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let recipe_verdict = scan_file(
            &addr,
            &recipe,
            "text/plain",
            DEFAULT_CHUNK_CHARS,
            8,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        assert!(
            clean_verdict
                .as_ref()
                .is_none_or(|v| v.level != Level::Unsafe),
            "benign prose judged {clean_verdict:?}"
        );
        let bomb_level = recipe_verdict.as_ref().map(|v| v.level);
        assert!(
            bomb_level.is_some_and(|l| l >= Level::Controversial),
            "bomb recipe judged {recipe_verdict:?}"
        );
    }

    #[tokio::test]
    async fn parses_verdict_from_llama_server() {
        // standalone wiremock instance: full request/response round trip
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": "Safety: Unsafe\nCategories: Violent"}}]
                })),
            )
            .mount(&mock)
            .await;

        let file = tempfile::NamedTempFile::new().unwrap();
        let text = "lorem ipsum dolor sit amet ".repeat(100); // ~2700 chars
        std::fs::write(file.path(), text.as_bytes()).unwrap();

        let verdict = scan_file(
            &mock.uri(),
            file.path(),
            "text/plain",
            DEFAULT_CHUNK_CHARS,
            1,
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .expect("verdict expected");

        assert_eq!(verdict.level, Level::Unsafe);
    }
}

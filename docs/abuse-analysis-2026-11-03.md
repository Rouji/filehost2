# Abuse analysis & automated detection design — filehost2

**Analysed:** 2026-11-03
**Data source:** `prod.sql.gz` (production dump), imported into a local MariaDB 13.0.2 instance
**Window analysed:** 2026-09-03 00:01 → 2026-11-03 18:16 (2 months)

> The dump also contained ~1.03M uploads from 2022-09 → 2026-08 imported from a *previous*
> filehost. That history is incomplete (53.6% of those rows are 0-byte, no `hash`, no
> `uploader_ip`, no `user_agent`, no NSFW scores) and was **excluded** — it is not
> representative of real traffic and would have produced entirely bogus signals. The
> `accesses` table only exists from 2026-07-04, so no download-side data predates it.

## 0. Dataset shape

| | count | notes |
|---|---|---|
| uploads | 267,570 | 1,537.9 GB ingress |
| distinct uploader IPs | 23,660 | |
| uploads with **NULL** uploader_ip | 68,715 (25.7%) | 178.2 GB — see §1 |
| accesses | 4,300,114 | 64.5 TB egress |
| distinct downloader IPs | 370,429 | |
| self-downloads (downloader == uploader) | 1,297,367 (30.2% of hits) | |
| re-uploaded hashes | 232 hashes / 490 uploads | low |
| uploads with nsfw_score ≥ 0.9 | 11,397 | + 1,044 in 0.8–0.9 |

Production limits in effect (`.env`): `MAX_UPLOADS_PER_DAY=100`,
`MAX_BYTES_PER_DAY=10 GiB`, `MAX_UPLOAD_BYTES_PER_SEC=10000` (10 KB/s),
`MAX_UPLOAD_BURST_BYTES=10 MB`, `nsfw_threshold=0.9`.

Upload-volume distribution per IP (whole window): p50 = 2 files, p90 = 13, p99 = 100
(the cap), max = 5,725. Bytes per IP: p50 = 0.5 MB, p90 = 55 MB, p99 = 869 MB, max = 48.3 GB.
Download-side per IP: p50 = 2 hits, p90 = 5, p99 = 72, max = 1,060,354. Served bytes per IP:
p99 = 0.3 GB, max = **41.9 TB** (one IP = 65% of all egress in 2 months).

---

## 1. P0 — enforcement was silently disabled for 4 days (fail-open IP extraction)

Between **2026-10-20 21:06** and **2026-10-23 21:58**, 68,715 uploads (178.2 GB, 576 distinct
user agents, 50,450 distinct sizes) were recorded with `uploader_ip = NULL`.

| day | uploads | GB |
|---|---|---|
| 2026-10-20 | 1,897 | 6.7 |
| 2026-10-21 | 21,039 | 50.6 |
| 2026-10-22 | 21,915 | 65.9 |
| 2026-10-23 | 23,864 | 54.9 |

**Root cause.** `git log` shows `e9a27d1 add tls + acme` and `2233611 add port 80 listener to
redir to tls port`, both dated **2026-10-20** — exactly when the NULLs start. The app moved
from behind a reverse proxy to terminating TLS itself, but `TRUST_XFF` evidently stayed
enabled, so `extract_ip` looked for an `X-Forwarded-For` header that direct clients never send:

```rust
// src/upload.rs:31
pub(crate) fn extract_ip(req: &HttpRequest, trust_xff: bool) -> Option<std::net::IpAddr> {
    if trust_xff {
        req.headers().get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())     // leftmost = client-controlled
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
    } else {
        req.peer_addr().map(|addr| addr.ip())
    }
}
```

**Why it matters — every gate is `if let Some(ip)`, i.e. fail-open.** With no IP:

- `enforce_upload_gates` (`src/handlers.rs:559`) skips the IP ban check, the upload-count
  limit, the byte quota, *and* the PoW challenge check.
- `get_file` (`src/handlers.rs:745`) skips the IP ban check and the challenge check.
- `UploadThrottle::throttle` is keyed by `IpAddr`, so the byte-rate limit never engages.
- The rows are permanently unattributable: no ban, no purge-by-IP, no NSFW-suspect marking,
  no future detection can ever act on those 68,715 uploads.

**Second, worse issue: XFF is spoofable as written.** `s.split(',').next()` takes the
*leftmost* value, which the client fully controls. Whenever `TRUST_XFF=true`, any abuser can
send `X-Forwarded-For: 8.8.8.8` and get a fresh, unbanned, un-rate-limited identity per
request — a complete bypass of every per-IP control, including the blacklist feeds. Worth
verifying the production setting; it should be `false` now that TLS is terminated in-app.

**Fixes (small, high value):**
1. Never return `None` silently: fall back to `req.peer_addr()`, and if that also fails,
   reject the upload (`400`/`500`) rather than accepting an unattributable file.
2. If XFF trust is genuinely required, add a `TRUSTED_PROXIES` CIDR allowlist, verify
   `peer_addr` is in it, and parse XFF **right-to-left**, dropping exactly N trusted hops.
3. Emit a metric/log for `uploads_with_null_ip` and alert on any non-zero value — this
   incident was invisible for 4 days and would still be invisible today.
4. Make `uploader_ip` `NOT NULL` in the schema once (1) lands, so the failure mode becomes a
   loud insert error instead of silent data loss.

---

## 2. Confirmed abuse cases

### 2.1 Botnet dead-drop / C2 beaconing (Sep 3–4 burst)

- **692** `.dat` files, 800–2000 B, avg 1,471 B, but only **20 distinct file sizes** —
  i.e. a handful of templates re-uploaded with fresh random content.
- Filenames: random base62, 10–20 chars (`06Syg4QnPRk.dat`, `0HnP0d198.dat`, …).
- **45 uploader IPs**, all residential/mobile, spread across PH, US, BR, IT, IS
  (top: `112.198.163.157`, `138.84.155.3`, `151.21.242.101`, `180.190.197.90`,
  `112.198.162.37`, `172.59.77.2`, …). Two IPs share a /24 (`112.198.162-163`), two share
  `172.59.77/79` (T-Mobile CGNAT).
- **All 45 use one identical, truncated browser UA**:
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` — real Chrome always
  continues `(KHTML, like Gecko) Chrome/x.y.z.z Safari/537.36`. Forged and malformed.
- Buried inside that same fake-UA cohort: **171 distinct IPs**, 16,024 files, 101.5 GB,
  including 1,204 more small `.dat` files — the fleet is far larger than the Sep burst.
- **Collector: `200.232.208.225`** (BR residential, unbanned). 1,076 accesses to 1,075
  distinct files between 2026-09-03 00:01 and 2026-09-04 20:35 — each file fetched exactly
  once, minutes after upload, **with a different random User-Agent on every single request**
  (1,076 hits / 1,076 distinct UAs). Textbook harvest-and-relay.
- Response taken at the time: 2 of the 45 IPs manually banned (`type=1` ReadOnly), 663 of the
  692 files purged. The collector was not banned, and no rule now prevents a re-run.

### 2.2 Persistent KV dead-drop from cloud (`immortal-store/0.1`)

- `129.213.177.56` (Oracle Cloud), UA `immortal-store/0.1`.
- **1,144 files**, every one exactly **1,287 bytes**, **1,144 distinct hashes**, 38 distinct
  sizes overall, names `<32-hex-md5>_0_<3|4>` (`73b08affaba75171949c2c8911399b04_0_4`).
- Content type `application/octet-stream`, detected as `application/vnd.ms-tnef` in places.
- **4,711 self-downloads** of its own 813 files — the uploader reads its own values back.
- Still active at the end of the window (last upload 2026-11-03 18:01). Not banned.
- Interpretation: a key/value store or task queue using the filehost as free persistent
  backend, with hash-uniqueness deliberately defeated (unique hash per write ⇒ dedup never
  fires, every write costs storage).

### 2.3 Parasitic CDN / self-CDN applications — the dominant bandwidth abuse

**30.2% of all 4.3M accesses are an uploader re-downloading its own file.** 64.5 TB egress in
2 months; 41.9 TB of it (65%) came from a single IP.

| actor | evidence |
|---|---|
| **Telegram mirror bot** `92.246.137.156` (KZ) | uploads TG media via `Python/3.14 aiohttp/3.14.x` (filenames are literal Telegram file IDs: `BAACAgQAAxkDA3Muv2rNR5LedUtGlVxHUYyEJ8JrP0alAAInDAACFidsUrVn_2dV6v05PQQ.mp4`, `oENVjAeqkCRAIRjwITAygJLIfxUyNUQ5GkHCCf.mp4`), then serves it to end users: **1,053,328 self-downloads of 148 files ≈ 2.3 TB**, running continuously for the full 2 months. Top file: `photo.jpg` 300,386 hits. |
| **AI companion app** | Azure KR `20.247.1.229` uploads exactly 10 character assets (`ref_1_angry.png`, `ref_sheet.png`, `voice_main_ref.wav`, `stand_first.png`, …, 8 MB total) via `curl/8.19.0`; Tencent HK GPU worker `43.128.76.178` pulls them **397,523 times**. Asset fetch per inference. Same worker: 433,926 total hits / 207 GB. |
| **42 TB in 5 days** | one 605 MB video (`경애하는 김정은동지를 모시고…mp4`, slug `enSj`) uploaded by `149.34.243.75` (banned 2026-09-25, type=1) and downloaded **69,219 times by a single UK residential IP `31.104.150.45`** = **41,916 GB**. The ban came after the flood; the downloader was never actioned and the file's slug no longer resolves (row purged). |
| **Game/app manifest polling** | `172.233.121.77` (Linode) polls `meta.json` (338 B, uploaded by `64.34.85.71` with UA `launcher/1.0`) **26,351 times** over 2 months ≈ every 4 minutes. Also probes 16 other `metadata.json`-shaped files from 6 other uploaders — a launcher doing update checks against a filehost. |
| **Beaconing** | `103.135.15.56` hits `inj.mp4` (1,965 B, uploaded by Alibaba `8.222.32.133` via `curl/7.88.1`) **158,288 times over 19 days** ≈ every 10 seconds. Also `170.210.81.54` (25,360 hits/1 file), `101.95.105.6` (12,398 hits in **25 minutes**), `108.170.12.10`, `94.245.106.65` (single-file, month-long polling). |
| **Marketplace image tooling** | `icanpares-ozon/1.0` — 8,516 uploads from 8 IPs, Turkish Ozon listing photos (`HT-SYP-MDT0001X2_uyumluluk.jpg`, `04_komplekt.jpg`), 25,776 self-downloads by the uploader `95.10.203.252` (4,223 files). |
| **Discord Rich-Presence clients** | `AIMP-DiscordRPC/1.5.4` (5,431 files, 254 IPs), `AIMP-DiscordRPC/1.6.4` (3,165, 295 IPs), `discord-nowcast/1.4.12` (5,220 files, **all with NULL uploader_ip** — §1) — album-cover hosting read back on every track change, from hundreds of end-user machines. |
| **Bulk file mover** | `47.252.13.147` (Alibaba US) pulled `xd.bin`/`dxgamer.bin` (16 MB each, from two adjacent Iranian IPs `94.183.156.20/.29`) 14,011 times = **223.6 GB in 3 days**. |

### 2.4 Cap-surfing: clients that saturate the configured limits

Measured per-IP per-day upload counts against `MAX_UPLOADS_PER_DAY=100`:

| IP | active days | days ≥90 | days ≥95 | max in a day | avg/day |
|---|---|---|---|---|---|
| `72.62.10.126` | 60 | **53** | **46** | 100 | 95.4 |
| `2.27.41.83` | 52 | **47** | **47** | 100 | 96.1 |
| `95.10.203.252` | 50 | 36 | 32 | 100 | 84.5 |
| `8.212.10.159` | 59 | 22 | 20 | 100 | 78.8 |
| `47.57.242.119` | 49 | 16 | 14 | 100 | 71.4 |

Globally 369 (IP,day) pairs reached ≥90 uploads and 292 reached ≥99, out of 42,532 pairs
(0.87%). Hitting *exactly* 100 repeatedly is not organic behaviour: these clients upload until
the server refuses, then resume at UTC midnight. `72.62.10.126` did this on 46 of 60 days
(5,725 files of `print.png` screenshots, one UA, 3.1 GB); `2.27.41.83` on 47 of 52 days
(4,996 `chart.png` files via `python-requests/2.33.1`).

The byte-rate throttle shows the same signature: `8.212.10.159` moved 48.33 GB over 61.75 days
= **9,059 B/s sustained**, i.e. 91% of `MAX_UPLOAD_BYTES_PER_SEC=10000` — it is riding the
token bucket continuously for two months. The daily *byte* quota (10 GiB) is essentially never
binding (4 (IP,day) pairs came within 10% of it), so count-cap and rate-throttle are the only
effective ingress controls.

### 2.5 UA-rotating bulk uploaders (cloud)

`8.212.10.159` and `47.57.242.119` (both Alibaba Cloud) uploaded 4,651 and 3,498 files
(48.3 GB and 32.0 GB) with **185 and 147 distinct User-Agents respectively** — `curl/8.14.1`
interleaved with forged full Chrome/Firefox strings. Their content-type histograms are
near-identical (zip ≈ 50%, then text/plain, pdf, octet-stream, html, png, docx, jpeg,
markdown, gzip, pptx, mp4 …), including the same oddities (`application/x-authorware-bin` for
`.zip`, `application/x-pif`, `application/x-pkcs7-certificates`, `video/x-ivf`, `audio/mid`).
Two hosts, one workload, rotating UA to defeat UA-based bans. `47.57.242.119` was finally
caught by the `stopforumspam_7d` feed (blacklist_id 9) on **2026-11-03 17:00** — two months
and 32 GB after it started.

### 2.6 Proxy-pool / IP-farming fleets (all unbanned)

Aggregating by /24 (IPv4):

| /24 | IPs | files | GB | signature |
|---|---|---|---|---|
| `140.248.50.0/24` + `140.248.52.0/24` | **253** | 1,554 | 6.5 | custom app UAs (`clipbot-test/1.0`, `eservice24-poster/1.1`, `inj-weekly-stats-uploader`, `jianren-report/1.0`), ~4 files/IP — spreading to stay under the per-IP cap |
| `160.79.106.0/24` | 33 | 7,313 | 26.7 | `apex-upload/1.0`, `breiboetiek/1.0`, `gonk-agent/1.0`, `curl/8.x` |
| `207.166.160.0/24` | 74 | 853 | ~0 | `exploit-test/1.0`, tiny files, curl + forged Mozilla |
| `206.223.225.0/24` | 49 | 352 | 3.7 | curl 7.81–8.14 mix + Android Mozilla |
| `95.143.47.0/24` | 56 | 327 | 1.5 | curl + Mac Mozilla |
| `43.162.199.0/24` | 8 | 337 | 0.1 | `curl/7.68.0 architecture-research…` |
| `1.53.255.0/24` | 4 | 722 | 27.0 | `HaniTool-Transfer/1.0` |

`140.248.50/52` is the clearest farming case: 253 IPs × ~4 uploads each is exactly the shape
you get when a client rotates source addresses to multiply a per-IP quota. Per-IP limits are
useless against it; per-/24 limits are not.

### 2.7 Content-policy load

11,397 uploads scored ≥ 0.9 NSFW (4.3% of scored files) and a further 1,044 sit in the
0.8–0.9 band just under the threshold. The score distribution is bimodal (121,700 files at
0.0–0.2, 10,042 at 1.0), so there is little evidence of deliberate threshold-surfing — the
0.8–0.9 band is roughly what you'd expect from classifier noise. The existing
NSFW → `mark_ip_suspect` → PoW challenge path is the right design; the problem is that the
suspect marking is not persisted (§4.2).

---

## 3. Why the current defenses missed all of this

`banned_ip_ranges` holds 97,846 ranges from **17 external reputation feeds**
(projecthoneypot, tor exits, bruteforceblocker, spamhaus DROP, cinsscore, blocklist.de,
greensnow, firehol level1, stopforumspam, GPTBot/searchbot, DigitalOcean ASN, AWS ranges,
MaxMind anonymous proxies, plus country zones cn/ru/uz) and 22,780 manual/type-1 entries.

Of the **18 most abusive IPs identified above, exactly 1 was ever blocked** (`47.57.242.119`,
by stopforumspam, two months late). `149.34.243.75` and 2 C2 bots were banned manually, after
the fact. Everything else — the KZ Telegram mirror, the 42 TB downloader, the manifest poller,
the C2 collector, `immortal-store`, all proxy pools — is unbanned.

Structural reasons:

1. **Reputation feeds answer the wrong question.** They list IPs known for spam, brute force,
   scanning and Tor. Real filehost abuse comes from clean residential (KZ, UK, BR, PH) and
   legitimate cloud (Alibaba, Oracle, Azure, Tencent, Linode) addresses with no bad history.
   237 of 23,660 uploader IPs (1.0%) matched any ban range, accounting for 8,607 files / 76 GB.
2. **No egress accounting at all.** `accesses` records `(upload_id, timestamp, ip, user_agent)`
   — no bytes, no status. The single largest abuse vector (64.5 TB served, 65% of it to one IP)
   is invisible to every control, and there is no per-file or per-IP download limit.
3. **All rate limits are per-IP**, and IPv4 is matched exactly (`ip::quota_range` returns
   `(ip, ip)` for v4). A /24 pool multiplies every quota by 253×.
4. **No behavioural signal is used.** Filename grammar, file-size uniformity, UA↔IP
   consistency, content-type fingerprinting and upload/download ratios are all present in the
   data and completely unused.
5. **Suspect marking is in-memory only.** `ChallengeCache::mark_ip_suspect` sets a TTL cache
   entry; once it expires, `is_ip_suspect` re-derives suspicion *solely* from
   `has_nsfw_upload_last_week`. Any non-NSFW suspicion evaporates after `pow_challenge_ttl`.
6. **404s are not logged.** `get_file` returns `ErrorNotFound` before `log_access`, so slug
   enumeration/brute-force discovery is a total blind spot (slugs are only 3 chars by default,
   `min_id_length=3` — 62³ ≈ 238k combinations vs 267k live files, so enumeration is viable).
7. **Fail-open IP extraction** (§1) — and XFF spoofing when enabled.

---

## 4. Detection rules, with measured selectivity

Thresholds below are calibrated on this dataset (23,660 uploader IPs, 370,429 downloader IPs).
"Flags" = how many subjects the rule would have caught in 2 months — all are ≪1% of the
population, so a challenge-first (not ban-first) response is safe.

### Upload-side

| # | Rule | Signal | Threshold | Flags | Catches |
|---|---|---|---|---|---|
| U1 | **Cap surfing** | per-IP uploads/day ≥ 0.9 × `max_uploads_per_day`, on ≥3 distinct days | ≥90/day ×3d | ~10 IPs | §2.4 (all five) |
| U2 | **Throttle surfing** | sustained ingress rate ≥ 0.8 × `max_upload_bytes_per_sec` over ≥1 h | 8 KB/s for 1 h | few | `8.212.10.159` (9.06 KB/s for 62 days) |
| U3 | **Size-uniform bulk** | ≥20 files whose sizes take ≤5 distinct values | as stated | **18 IPs** | §2.1 C2 fleet, §2.2 `immortal-store` |
| U4 | **Tiny bulk** | ≥20 files, avg < 3 KB | as stated | **94 IPs** | §2.1, §2.6 `207.166.160/24` |
| U5 | **Filename grammar** | `^[A-Za-z0-9_-]{10,20}\.(dat|bin)$`, or `^[0-9a-f]{32}_\d+_\d+$`, or high-entropy stem + generic ext | regex | 692 + 1,144 files | §2.1, §2.2 |
| U6 | **UA rotation** | distinct UAs per IP ≥ 20/day | ≥20 | **13 IPs** (≥100: **2 IPs**) | §2.5 Alibaba pair |
| U7 | **Shared-UA fleet** | one exact UA string across ≥20 distinct IPs | ≥20 IPs | few UAs | §2.1 (45 IPs, 1 UA), §2.6 |
| U8 | **Malformed/forged browser UA** | matches `^Mozilla/5\.0 \(.*\) AppleWebKit/537\.36$` (no version tail), or browser UA from a client that also sends curl-style headers | regex | 171-IP cohort | §2.1 |
| U9 | **/24 aggregation** | sum(files), sum(bytes), or shared UA/filename grammar across a /24 (v6: /64, matching existing `quota_range`) | ≥5 IPs and ≥100 files/24h | ~15 /24s | §2.6 all fleets |
| U10 | **Content-type fingerprint match** | cosine similarity of the per-IP content-type histogram vs a known-abusive profile ≥ 0.9 | 0.9 | 2 IPs (the Alibaba pair) | links rotated infra |
| U11 | **Dedup evasion** | same hash re-uploaded after deletion/expiry, or ≥5 near-identical sizes from one IP within 1 h | — | 232 hashes | §2.2 (hash-per-write KV store) |
| U12 | **Egress-free uploader** | IP uploads ≥50 files and never downloads any of them, while a *different* IP downloads them ≥1,000× | — | ~10 pairs | §2.3 AI app, `enSj` |

### Download-side

| # | Rule | Signal | Threshold | Flags | Catches |
|---|---|---|---|---|---|
| D1 | **Egress volume per IP** | served bytes / 24 h (needs new `accesses.bytes`) | >10 GB → challenge, >100 GB → throttle+challenge | 293 IPs ≥10 GB, **26 ≥100 GB** (2 months) | 42 TB video, §2.3 |
| D2 | **Egress per file** | served bytes per upload_id / 24 h | >5 GB/day | handful | `enSj` (8.4 TB/day), `xd.bin` |
| D3 | **Hit-count outlier** | hits per IP / 24 h | p99 = 72 per *2 months*; >1,000/24 h is ~4σ | 145 IPs ≥1k, 11 ≥10k | §2.3 pollers |
| D4 | **Polling regularity** | ≥100 hits on one file with low inter-arrival variance (CV < 0.3) | as stated | ~15 IPs | `launcher/1.0` (every 4 min), `inj.mp4` (every 10 s) |
| D5 | **Harvester sweep** | ≥50 distinct files from ≥20 distinct uploaders in 24 h, each fetched once, median (fetch − upload) < 1 h | as stated | **400 IPs** (2 mo, looser form) | §2.1 collector |
| D6 | **UA uniqueness ratio** | distinct UAs / requests ≈ 1.0 over ≥50 requests | ≥0.95 | **1 IP** (zero false positives measured) | §2.1 collector (1,076/1,076) |
| D7 | **Self-download dominance** | self_hits/hits > 0.8 with ≥100 hits | as stated | **230 IPs** | every parasitic CDN in §2.3 |
| D8 | **Slug enumeration** | 404s on `/{slug}` per IP (needs new logging) | >50/h | unknown (blind spot) | §3.6 |

### Cross-cutting

| # | Rule | Signal |
|---|---|---|
| X1 | **Bipartite clustering** | build IP↔file download graph nightly; a tight component where one downloader IP touches files from many uploaders with identical timing = redistribution service |
| X2 | **Upload→download latency** | median < 60 s across many files = machine relay, not human sharing |
| X3 | **Blacklist miss rate** | weekly report: what fraction of flagged IPs appear in any feed. Currently ~5% — proves feeds are not a substitute for behavioural detection |

### Escalation ladder (reuse existing machinery)

`log finding` → `mark_ip_suspect` (PoW challenge, already wired for both upload and download)
→ `insert_banned_ip(type=ReadOnly)` (upload-only ban, auto-expiring after 7 d)
→ `insert_banned_ip(type=Full)` → `delete_by_ip` + `insert_banned_hash` (purge, for confirmed
C2/malware). Every step already exists in `src/db.rs` and `src/cli.rs`; only the *decision*
layer is missing.

---

## 5. Reproducing this analysis

Local MariaDB (not systemd-managed, container has no init):

```bash
sudo pacman -S mariadb
mkdir -p tmp/mariadb/data
mariadb-install-db --datadir=$PWD/tmp/mariadb/data --user=$(id -un)
mariadbd --datadir=$PWD/tmp/mariadb/data --socket=$PWD/tmp/mariadb/m.sock \
  --bind-address=127.0.0.1 --port=3307 --innodb-buffer-pool-size=512M \
  --skip-name-resolve --max-allowed-packet=64M \
  --log-error=$PWD/tmp/mariadb/err.log &
mariadb --socket=$PWD/tmp/mariadb/m.sock -e "CREATE DATABASE filehost2;"
# --binary-mode=1 is required: _sqlx_migrations blob rows contain literal NUL bytes
zcat prod.sql.gz | mariadb --binary-mode=1 --socket=$PWD/tmp/mariadb/m.sock filehost2
```

Import took ~50 min (1.4 GB dump, 6 secondary indexes on `uploads` rebuilt during load,
512 MB buffer pool, I/O-bound). Trimming to the analysis window (fresh tables + `INSERT…SELECT`
+ atomic `RENAME`, `FOREIGN_KEY_CHECKS=0`) took 4m50s; a plain `DELETE` of 1.03M rows took
9m55s, and `OPTIMIZE TABLE` on the 7M-row `accesses` was abandoned as slower than the rebuild.

```sql
-- trim to the last 2 months (uploads first would break the FK; accesses references uploads)
SET FOREIGN_KEY_CHECKS=0;
CREATE TABLE uploads_new LIKE uploads;  CREATE TABLE accesses_new LIKE accesses;
INSERT INTO uploads_new  SELECT * FROM uploads  WHERE upload_timestamp >= '2026-09-03';
INSERT INTO accesses_new SELECT a.* FROM accesses a JOIN uploads_new u ON a.upload_id=u.id
                          WHERE a.timestamp >= '2026-09-03';
RENAME TABLE uploads TO uploads_old, accesses TO accesses_old,
             uploads_new TO uploads, accesses_new TO accesses;
DROP TABLE accesses_old, uploads_old;  SET FOREIGN_KEY_CHECKS=1;
ANALYZE TABLE uploads, accesses;
```

Gotchas for anyone re-running this:
- IPs are `VARBINARY(16)`, IPv4 stored as `::ffff:a.b.c.d`. `INET6_ATON('1.2.3.4')` returns
  **4** bytes and will never match — use `INET6_ATON('::ffff:1.2.3.4')`, or compare with
  `INET6_NTOA(uploader_ip) = '::ffff:1.2.3.4'`.
- `OFFSET (subquery)` is not allowed in MariaDB; use `PERCENT_RANK() OVER (ORDER BY …)`.
- The ban-range lookup is `WHERE ? BETWEEN start_ip AND end_ip`; for bulk work build a temp
  table of subject IPs and use the `(start_ip, end_ip)` index with a correlated
  `ORDER BY start_ip DESC LIMIT 1` instead of a join, or it will not finish.
- `accesses` has no `bytes` and no status column — egress figures above are
  `COUNT(*) × uploads.file_size`, which over-counts ranged/cached requests and under-counts
  nothing, but is exact only for full-body downloads.

---

## 6. Implementation plan

Ordered by value/effort. Phases 1–2 are small, self-contained and stop the worst bleeding;
phases 3–5 build the detection layer.

### Phase 1 — close the fail-open holes (½ day, no schema change)

**1a. `extract_ip` must not silently return `None`** (`src/upload.rs:31`) — *implemented*

```rust
pub(crate) fn extract_ip(req: &HttpRequest, xff_trust: &XffTrust) -> Option<IpAddr> {
    crate::ip::client_ip(
        req.headers().get("X-Forwarded-For").and_then(|v| v.to_str().ok()),
        req.peer_addr().map(|addr| addr.ip()),
        xff_trust,
    )
}
```

`ip::client_ip` consults `X-Forwarded-For` only when the socket peer is inside the configured
proxy allowlist, then takes the entry `xff_hops` places from the **right** — the leftmost
entries are whatever the client typed. A missing header, an unparsable entry at the expected
position, or a header shorter than the trusted chain each fall back to the peer and log a
warning, so a request is never left unattributable. `None` now means only "no socket peer",
which a TCP listener should never produce.

Settings gained `trusted_proxies` (comma-separated addresses/CIDRs) and `xff_hops` (default 1).
(The later `trust_xff` master switch has since been removed again; `TRUSTED_PROXIES` is the
only knob — an empty allowlist means headers are ignored.) An allowlist
that resolves to nothing is not fatal at startup — every client becomes the socket peer, which
is noisy but correct — so it logs a prominent `log::error!` naming the variable to fix, and
unparsable allowlist entries are reported individually instead of silently narrowing trust to
nothing. The access-log format switches to actix's `%{r}a` only when XFF is credible, since
`%{r}a` resolves XFF without consulting the allowlist.

**1b. Fail closed when there is no IP.** — *implemented*

In `upload()` and `get_file()`, if `extract_ip` returns `None`, respond `500` (upload) / `403`
(download) and `log::error!`. An unattributable upload is worse than a rejected one: it can
never be banned, purged, or detected. `captcha_verify` already rejected in that case and now
logs. `get_file` resolved the address three separate times per request; it resolves once now
and shares it across the ban check, the challenge gate and the access-log insert.

What this exposes operationally: the address is always resolvable for a real TCP connection,
so if these errors ever fire it means a listener that isn't TCP (or a very broken socket) —
worth wiring a counter to before it silently becomes the only signal.

**Deploying Phase 1 needs one config decision.** With no `TRUSTED_PROXIES`,
`X-Forwarded-For` is ignored, so every client is attributed to the
socket peer — behind a local nginx that means `127.0.0.1` for everyone, which collapses every
per-IP control onto one identity. That is strictly safer than the spoofable default, but it is
not deployable. Set `TRUSTED_PROXIES` to the addresses the app actually sits behind (usually
`127.0.0.1`, or the docker/k8s bridge CIDR) when this ships. `XFF_HOPS` defaults to 1; raise it
only for a genuine proxy chain, since a too-high value silently degrades to "closest proxy".

**1c. Persist `uploader_ip NOT NULL`** — *implemented* (migration
`20261104000000_uploads_uploader_ip_not_null.sql`, plus `insert_upload_row`/`process_file`
now take a non-optional IP so the schema invariant lives in the type). The migration does
**not** touch existing NULL rows: it fails loudly until prod data is resolved by hand —
either delete the 68,715 incident rows (and ideally the ~500k incomplete legacy-import
NULLs), or backfill a sentinel first.

**1d. Log 404s on the slug route.** — *implemented as in-memory detection only*. Every miss
logs an info line with slug + IP, and a per-IP miss counter (`rate_limit::MissTracker`,
fixed 60 s window) marks IPs suspect via the PoW gate once they cross
`MAX_MISSES_PER_MINUTE` (default 30, 0 disables). A `misses` table was briefly shipped and
dropped again the same day (`20261107000000` / `20261107010000_drop_misses`): brute-force
detection needs the *count*, not the rows, and the stdout access log already records every
miss for forensics.

### Phase 2 — egress accounting (½ day, 1 migration)

The single biggest blind spot: 64.5 TB served with zero visibility. — *2a/2b implemented*
(migration `20261105000000_accesses_bytes_status.sql`; `log_access` carries `bytes`/`status`,
taken in `get_file` from the built response's status and body size hint — range requests
report their range length, HEAD leaves `bytes` NULL. `bytes` is BIGINT UNSIGNED rather than
the sketched INT so files over 4 GiB fit.)

**2a. Migration**

```sql
ALTER TABLE accesses ADD COLUMN bytes INT UNSIGNED NULL;      -- actual body size sent
ALTER TABLE accesses ADD COLUMN status SMALLINT UNSIGNED NULL; -- 200/206/404…
ALTER TABLE accesses ADD INDEX idx_accesses_ip_ts (ip, timestamp);
ALTER TABLE accesses ADD INDEX idx_accesses_upload_ts (upload_id, timestamp);
```

`idx_accesses_ip_ts` is what every download-side rule needs; today the only usable index is
the FK on `upload_id`, so per-IP scans are full-table (that is why the analysis queries above
took minutes).

**2b. Populate it for free.** — *implemented* as described, except the value comes from the
response's body size hint rather than `row.file_size`, which makes range requests accurate
for free.

**2c. Download throttle.** — *implemented*. `UploadThrottle` was generalised into
`ByteThrottle` with `UploadThrottle`/`DownloadThrottle` aliases; `get_file` paces the
response body chunk-by-chunk through the same token bucket after the ban/challenge checks,
so bytes flow immediately, range requests are charged for what they actually serve, and a
hot file degrades into slow serving instead of unlimited drain.
`MAX_DOWNLOAD_BYTES_PER_SEC` unset (the default) means unlimited, matching the upload
settings' shape.

**2d. Per-file egress cap.** New setting `max_file_egress_per_day` (e.g. 5 GB). Counter keyed
by `upload_id` in a TTL cache; on breach, require a challenge rather than hard-block, so a
legit viral file degrades to "solve PoW" instead of 403. This is the rule that catches
`enSj` (8.4 TB/day) within hours instead of never.

**2e. Retention + rollup.** `accesses` grows ~70k rows/day (~26M/yr). Nightly job: insert into
`access_rollup_daily (day DATE, ip VARBINARY(16), upload_id BINARY(16), hits INT, bytes BIGINT,
PRIMARY KEY(day, ip, upload_id))` via `INSERT … SELECT … ON DUPLICATE KEY UPDATE`, then delete
raw rows older than `access_retention_days` (e.g. 90). Rules run against the rollup for
anything longer than a day, against raw `accesses` for burst detection.

### Phase 3 — the detection layer (2–3 days)

**3a. New module `src/abuse.rs`** — a pure rule engine, no HTTP:

```rust
pub(crate) struct Finding {
    pub rule: RuleId,
    pub subject: Subject,        // Ip(IpAddr) | Prefix(IpAddr, u8) | Upload(Uuid)
    pub severity: Severity,      // Info | Challenge | BanReadOnly | BanFull | Purge
    pub evidence: serde_json::Value,
}

pub(crate) enum RuleId { CapSurfing, ThrottleSurfing, SizeUniformBulk, TinyBulk,
    FilenameGrammar, UaRotation, SharedUaFleet, ForgedBrowserUa, PrefixAggregate,
    MimeFingerprint, DedupEvasion, EgressVolumeIp, EgressVolumeFile, HitOutlier,
    PollingRegularity, HarvesterSweep, UaUniqueness, SelfDownloadDominance, SlugEnumeration }
```

Two evaluation modes, because the rules have very different latency needs:

- **Inline** (in `process_file`, which already has hash/size/name/content_type/ua/ip in hand —
  no extra I/O): U3, U4, U5, U6, U8, U11. State lives in an in-memory per-IP ring buffer
  (`VecDeque<(size, name_grammar, ts)>`, cap ~200 entries), same pattern as `UploadThrottle`'s
  `Mutex<HashMap<IpAddr, _>>` with idle eviction. This is what stops a C2 burst *during* the
  burst instead of two months later.
- **Batch** (nightly / every 15 min via CLI, mirroring the existing `blacklist sync` cron):
  U1, U2, U7, U9, U10, U12, D1–D7, X1–X3. Pure SQL over `uploads`, `accesses`,
  `access_rollup_daily`.

**3b. Findings table**

```sql
CREATE TABLE abuse_findings (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rule VARCHAR(48) NOT NULL,
  severity TINYINT UNSIGNED NOT NULL,
  dedupe_key VARCHAR(191) NOT NULL,     -- 'rule|subject|bucket', UNIQUE so re-fires collapse
  ip VARBINARY(16) NULL,
  ip_prefix_len TINYINT UNSIGNED NULL,
  upload_id BINARY(16) NULL,
  evidence JSON NOT NULL,
  action VARCHAR(24) NULL,              -- NULL = shadow mode, no action taken
  acted_on DATETIME NULL,
  UNIQUE KEY uniq_finding (dedupe_key),
  INDEX idx_findings_rule_time (rule, detected_at)
);
```

`INSERT IGNORE` on `dedupe_key` makes the scanner idempotent — important because a persistent
abuser (e.g. `immortal-store`, active for 2 months) re-fires on every run. Bucket by day for
slow rules, by hour for burst rules.

**3c. Persist suspicion — fixes a real bug.** `ChallengeCache::mark_ip_suspect` only writes the
in-memory TTL cache; `is_ip_suspect` re-derives from `db::has_nsfw_upload_last_week`. So any
suspicion raised by abuse detection silently disappears after `pow_challenge_ttl_seconds`
(default 300 s). Add:

```sql
CREATE TABLE suspect_ips (
  ip VARBINARY(16) NOT NULL PRIMARY KEY,
  reason VARCHAR(48) NOT NULL,          -- RuleId as string
  first_flagged DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_timestamp DATETIME NOT NULL,
  INDEX idx_suspect_expires (expires_timestamp)
);
```

and make `db::is_ip_suspect(db, ip) = has_nsfw_upload_last_week(..) OR row_exists(suspect_ips)`,
with `ChallengeCache::mark_ip_suspect` doing an upsert + cache set (exactly the shape of the
existing `mark_ip_verified`, which already upserts `challenge_verified_ips`). Default TTL 7 d,
configurable. Now the PoW gate — already enforced on **both** upload and download paths
(`a72672a apply the sus check to downloads too`) — becomes the universal soft action for every
rule, with zero new enforcement code.

**3d. Policy engine + shadow mode.** New settings:

```
ABUSE_SCAN_ENABLED=true
ABUSE_SCAN_INTERVAL_SECONDS=900
ABUSE_AUTO_ACTION=false          # shadow: log findings, take no action
ABUSE_AUTO_ACTION_RULES=         # comma-separated allowlist once confident
ABUSE_CHALLENGE_TTL_SECONDS=604800
```

`abuse::act(finding)`: `Info` → log only; `Challenge` → upsert `suspect_ips`; `BanReadOnly` →
`db::insert_banned_ip(.., BanType::ReadOnly, reason=rule, expires=+7d)`; `BanFull` →
`BanType::Full`; `Purge` → `db::delete_by_ip` + `db::insert_banned_hash`. All five functions
already exist. Always invalidate `ban_cache` after writes (the handlers already call
`ban_cache.invalidate_hashes()` after clamd bans — same pattern).

Ship with `ABUSE_AUTO_ACTION=false` for a week, compare findings against this report's ground
truth, then enable per rule starting with the zero-FP ones (D6, U8, U3).

**3e. /24 and /64 scoping** (`src/ip.rs`). `quota_range` already collapses IPv6 to /64; add the
IPv4 counterpart and a scope enum:

```rust
pub(crate) enum Scope { Host, Prefix }           // Prefix = /24 for v4, /64 for v6
pub(crate) fn scope_range(ip: IpAddr, scope: Scope) -> (IpAddr, IpAddr)
```

Then `db::uploads_count_last_day` / `uploads_bytes_last_day` take a `Scope` and pass the range
into their existing `BETWEEN ? AND ?` — the SQL doesn't change at all, and
`idx_uploads_uploader_ip_upload_timestamp` already covers it. `enforce_upload_gates` calls each
limit twice (Host, then Prefix) with a separate, larger `max_uploads_per_day_prefix` setting.
That single change neutralises the `140.248.50/52` 253-IP farm.

**3f. CLI + admin surface** (mirror existing patterns exactly):

- `src/cli.rs`: `Command::Abuse { command: AbuseCommand }` with `Scan { rule, dry_run, since }`,
  `Findings { list, rule, limit }`, `Act { id, action }`, `Rules { list }`.
  `AbuseCommand::Scan` is what cron calls, next to `blacklist sync`.
- `src/admin.rs`: add `abuse_findings`, `abuse_act`, `top_egress_ips`, `top_egress_files` to
  `configure()`, reusing `AdminGuard` and the existing `top_uploader_ips` shape. `ip_stats`
  already exists — extend it with egress numbers.
- The Elm admin (`elm-admin/`) gets a findings table with an "act" button per row.

### Phase 4 — the specific rules as SQL (all validated against this dataset)

```sql
-- U1 cap surfing: ≥90% of the daily cap on ≥3 days
SELECT uploader_ip, COUNT(*) days, MAX(files) peak FROM (
  SELECT uploader_ip, DATE(upload_timestamp) d, COUNT(*) files
  FROM uploads WHERE upload_timestamp > NOW() - INTERVAL 14 DAY
  GROUP BY uploader_ip, d HAVING files >= 0.9 * :max_uploads_per_day
) t GROUP BY uploader_ip HAVING days >= 3;

-- U3/U4 size-uniform tiny bulk (inline equivalent keeps a ring buffer per IP)
SELECT uploader_ip, COUNT(*) files, COUNT(DISTINCT file_size) sizes, AVG(file_size) avg_sz
FROM uploads WHERE upload_timestamp > NOW() - INTERVAL 1 DAY AND uploader_ip IS NOT NULL
GROUP BY uploader_ip
HAVING files >= 20 AND (sizes <= 5 OR avg_sz < 3000);

-- U6 UA rotation / U7 shared-UA fleet
SELECT uploader_ip, COUNT(DISTINCT user_agent) uas, COUNT(*) files
FROM uploads WHERE upload_timestamp > NOW() - INTERVAL 1 DAY
GROUP BY uploader_ip HAVING uas >= 20;

SELECT user_agent, COUNT(DISTINCT uploader_ip) ips, COUNT(*) files
FROM uploads WHERE upload_timestamp > NOW() - INTERVAL 1 DAY AND user_agent IS NOT NULL
GROUP BY user_agent HAVING ips >= 20 AND files >= 50;

-- U9 /24 aggregation (v4 only here; v6 uses the existing /64 quota range)
SELECT INET6_NTOA(uploader_ip) sample_ip,
       SUBSTRING_INDEX(SUBSTRING(INET6_NTOA(uploader_ip), 8), '.', 3) net24,
       COUNT(DISTINCT uploader_ip) ips, COUNT(*) files, SUM(file_size) bytes
FROM uploads
WHERE upload_timestamp > NOW() - INTERVAL 1 DAY
  AND INET6_NTOA(uploader_ip) LIKE '::ffff:%'
GROUP BY net24 HAVING ips >= 5 AND files >= 100;

-- D1/D2 egress per IP and per file (needs Phase 2 `bytes`)
SELECT ip, SUM(bytes) served, COUNT(*) hits, COUNT(DISTINCT upload_id) files
FROM accesses WHERE timestamp > NOW() - INTERVAL 1 DAY AND ip IS NOT NULL
GROUP BY ip HAVING served > :max_ip_egress_per_day;

-- D4 polling regularity: many hits on one file, tight inter-arrival spread
SELECT a.ip, a.upload_id, COUNT(*) hits,
       STDDEV_POP(TIMESTAMPDIFF(SECOND, MIN(a.timestamp), a.timestamp)) sd,
       TIMESTAMPDIFF(SECOND, MIN(a.timestamp), MAX(a.timestamp)) / NULLIF(COUNT(*)-1,0) mean_gap
FROM accesses a WHERE a.timestamp > NOW() - INTERVAL 1 DAY
GROUP BY a.ip, a.upload_id HAVING hits >= 100 AND mean_gap < 600;

-- D5/D6 harvester sweep + UA uniqueness (the zero-false-positive pair)
SELECT a.ip, COUNT(*) hits, COUNT(DISTINCT a.upload_id) files,
       COUNT(DISTINCT u.uploader_ip) uploaders, COUNT(DISTINCT a.user_agent) uas,
       AVG(TIMESTAMPDIFF(SECOND, u.upload_timestamp, a.timestamp)) mean_lag
FROM accesses a JOIN uploads u ON u.id = a.upload_id
WHERE a.timestamp > NOW() - INTERVAL 1 DAY AND a.ip IS NOT NULL
GROUP BY a.ip
HAVING (files >= 50 AND uploaders >= 20 AND mean_lag < 3600)   -- D5
    OR (hits >= 50 AND uas / hits >= 0.95);                    -- D6

-- D7 self-download dominance (parasitic CDN)
SELECT a.ip, COUNT(*) hits, SUM(a.ip = u.uploader_ip) self_hits, SUM(a.bytes) served
FROM accesses a JOIN uploads u ON u.id = a.upload_id
WHERE a.timestamp > NOW() - INTERVAL 7 DAY AND a.ip IS NOT NULL
GROUP BY a.ip HAVING hits >= 100 AND self_hits / hits > 0.8;

-- U5 filename grammar: cheap enough to run inline as a regex, but the batch form is
SELECT uploader_ip, COUNT(*) n FROM uploads
WHERE upload_timestamp > NOW() - INTERVAL 1 DAY
  AND (original_name REGEXP '^[A-Za-z0-9_-]{10,20}\\.(dat|bin)$'
    OR original_name REGEXP '^[0-9a-f]{32}_[0-9]+_[0-9]+$')
GROUP BY uploader_ip HAVING n >= 5;
```

`U8` forged-UA regex (inline, no query needed):
`^Mozilla/5\.0 \([^)]*\)( AppleWebKit/[\d.]+)?$` — a real browser UA always continues with
`(KHTML, like Gecko) Chrome/<ver> Safari/<ver>` or `Gecko/… Firefox/<ver>`. Matched 171 IPs
here, all of them in the C2 cohort.

### Phase 5 — nice-to-haves

- **X1 bipartite clustering**: nightly job building IP↔file edges from the rollup, then
  connected components / label propagation. Catches redistribution services that no
  single-subject threshold sees. Needs the rollup (2e) to be tractable.
- **U10 MIME fingerprint**: store a per-rule content-type histogram in `evidence` JSON when
  banning, then cosine-compare new IPs against stored abusive profiles. This is how you catch
  the *next* Alibaba pair after they rotate IPs and UAs.
- **Metrics endpoint**: `/metrics` (or a periodic structured log line) exporting
  `uploads_null_ip_total`, `egress_bytes_total{ip_class}`, `challenge_issued_total`,
  `findings_total{rule,severity}`, `throttled_bytes_total`. Without these, thresholds cannot
  be tuned and a repeat of §1 stays invisible.
- **Honeypot slugs**: publish a few never-linked slugs; any access is a scanner. Free,
  zero-FP enumeration detector to complement D8.
- **Extend `src/sync.rs` to IPv6** (it still has `// TODO: ipv6` and an IPv4-only regex) —
  `2a06:98c0:3600::103` (1,230 files, Cloudflare-ish range) is currently unblockable by feed.

### Suggested build order

| step | work | effort | stops |
|---|---|---|---|
| 1 | 1a–1d fail-closed IP + 404 log | ½ d | §1 outage class, XFF spoofing, D8 blind spot |
| 2 | 2a–2d egress accounting + download throttle + per-file cap | ½ d | 42 TB video, all of §2.3 |
| 3 | 3c `suspect_ips` persistence | 2 h | suspect-marking bug; prerequisite for everything |
| 4 | 3a/3b/3d engine + findings table + shadow mode | 1–2 d | — |
| 5 | Phase 4 rules U1,U3,U5,U6,U8,D1,D4,D5,D6,D7 | 1 d | §2.1, §2.2, §2.4, §2.5 |
| 6 | 3e /24 scoping + U9 | ½ d | §2.6 proxy pools |
| 7 | 2e rollup + retention, admin UI, CLI | 1 d | table growth, operability |
| 8 | Phase 5 | later | — |

Everything in steps 1–6 reuses existing machinery (`BanCache`, `ChallengeCache`, `UploadThrottle`,
`db::insert_banned_ip`, `db::delete_by_ip`, the PoW gate on both paths, the CLI/admin patterns),
so the new surface is one module, three tables, four settings groups and ~15 SQL queries.

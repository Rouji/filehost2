// these tests need a DB
// go steal one at the database store
#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use actix_http::Request;
    use actix_web::{App, Error, dev::ServiceResponse, test, web};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use sqlx::MySqlPool;

    use crate::app::{self, AppState};
    use crate::db;
    use crate::db_pool;
    use crate::handlers;
    use crate::settings::Settings;
    use crate::upload::uuid_to_path;

    // `#[sqlx::test]` only knows how to hand back a real `sqlx::MySqlPool` (it's what
    // creates/migrates/tears down the isolated per-test database), but application code
    // runs on a deadpool-backed pool in production — so point a deadpool pool at that same
    // per-test database instead of handing the raw sqlx pool to app/CLI code under test.
    fn to_db_pool(pool: &MySqlPool) -> db_pool::DbPool {
        db_pool::build_pool((*pool.connect_options()).clone(), 5)
            .expect("Failed to build test database pool")
    }

    fn peer(req: test::TestRequest) -> test::TestRequest {
        req.peer_addr(TEST_PROXY)
    }

    const TEST_PROXY: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 54321);

    async fn full_app(
        settings: Settings,
        pool: MySqlPool,
    ) -> impl actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error> {
        std::fs::create_dir_all(&settings.store_path).unwrap();
        let state = web::Data::new(AppState::new(to_db_pool(&pool), settings));
        test::init_service(App::new().configure(|cfg| app::configure(cfg, state.clone()))).await
    }

    #[sqlx::test]
    async fn index_returns_200(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;
        let resp =
            test::call_service(&app, peer(test::TestRequest::get()).uri("/").to_request()).await;
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn hupl_config_download(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/?config=hupl")
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        let ct = hdr(&resp, "content-type");
        assert!(ct.contains("application/json"), "expected JSON, got: {ct}");
    }

    #[sqlx::test]
    async fn unknown_slug_returns_404(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/doesntexist")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    /// `get_file`'s `/{slug}` catch-all must be registered after `/captcha`,
    /// or it silently swallows the route and this 404s as "File not found"
    /// instead of serving the challenge page.
    #[sqlx::test]
    async fn captcha_page_is_not_shadowed_by_the_slug_route(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get()).uri("/captcha").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert!(hdr(&resp, "content-type").contains("text/html"));
    }

    /// Same shadowing hazard as above, for the external script the challenge
    /// page loads instead of an inline `<script>` (which a strict CSP blocks).
    #[sqlx::test]
    async fn captcha_js_is_not_shadowed_by_the_slug_route(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/captcha.js")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert!(hdr(&resp, "content-type").contains("javascript"));
    }

    static BOUNDARY: &str = "----TestBoundary";

    fn multipart_body(name: &str, body: &str) -> String {
        multipart_body_with_type(name, "text/plain", body)
    }

    fn multipart_body_with_type(name: &str, content_type: &str, body: &str) -> String {
        format!(
            "--{BOUNDARY}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: {content_type}\r\n\
             \r\n\
             {body}\r\n"
        )
    }

    /// Builds a POST / multipart request, optionally with extra headers (e.g. User-Agent,
    /// X-Forwarded-For) — shared by every test that needs to twiddle upload request headers.
    fn upload_req(content: &str, headers: &[(&str, &str)]) -> actix_http::Request {
        let mut req = peer(test::TestRequest::post()).uri("/").insert_header((
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        ));
        for (k, v) in headers {
            req = req.insert_header((*k, *v));
        }
        req.set_payload(format!("{content}--{BOUNDARY}--\r\n"))
            .to_request()
    }

    fn multipart_request(content: &str) -> actix_http::Request {
        upload_req(content, &[])
    }

    fn hdr(resp: &ServiceResponse, name: &str) -> String {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    fn slug(url: &str) -> &str {
        url.trim().trim_start_matches("http://localhost:8080/")
    }

    fn ip_bytes(s: &str) -> Vec<u8> {
        crate::ip::to_db_vec(s.parse().unwrap())
    }

    #[sqlx::test]
    async fn upload_body_timeout_returns_408(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.upload_timeout = 1;
        let app = full_app(settings, pool).await;

        let (head, _) = upload_req(&multipart_body("f.txt", "hello"), &[]).into_parts();
        let stalled: std::pin::Pin<
            Box<
                dyn futures_util::Stream<
                        Item = Result<actix_web::web::Bytes, actix_http::error::PayloadError>,
                    >,
            >,
        > = Box::pin(futures_util::stream::once(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Ok::<_, actix_http::error::PayloadError>(actix_web::web::Bytes::new())
        }));
        let req = Request::from(head)
            .replace_payload(actix_http::Payload::Stream { payload: stalled })
            .0;

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 408);
    }

    #[sqlx::test]
    async fn upload_and_retrieve(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let file_content = "hello ima test";
        let file_name = "hello.txt";

        let req = multipart_request(&multipart_body(file_name, file_content));
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            url.trim().starts_with("http://"),
            "expected URL, got: {url}"
        );
        let slug = slug(&url);
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        assert_eq!(
            hdr(&resp, "content-disposition"),
            format!("inline; filename=\"{file_name}\"")
        );
        assert_eq!(&test::read_body(resp).await[..], file_content.as_bytes());
    }

    /// Column-width limits (20261121000000's sibling fix): an overlong
    /// filename or User-Agent header must be truncated, not fail the insert
    /// after the file is already saved to disk.
    #[sqlx::test]
    async fn upload_truncates_overlong_name_and_user_agent(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;

        let long_name = format!("{}.txt", "a".repeat(300));
        let long_ua = "x".repeat(600);
        let req = upload_req(
            &multipart_body(&long_name, "hello"),
            &[("User-Agent", long_ua.as_str())],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let row: (String, Option<String>) =
            sqlx::query_as("SELECT original_name, user_agent FROM uploads WHERE slug = ?")
                .bind(slug(&url))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0.chars().count(), crate::db::MAX_NAME_LEN);
        assert_eq!(row.1.as_deref().map(str::len), Some(crate::db::MAX_UA_LEN));
    }

    #[sqlx::test]
    async fn html_served_as_plaintext_attachment(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = multipart_request(&multipart_body_with_type(
            "page.html",
            "text/html",
            "<h1>hi</h1>",
        ));
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&url);

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let cd = hdr(&resp, "content-disposition");
        assert!(
            cd.starts_with("attachment"),
            "expected attachment disposition, got: {cd}"
        );

        let ct = hdr(&resp, "content-type");
        assert!(
            !ct.contains("text/html"),
            "expected non-HTML content type, got: {ct}"
        );
    }

    #[sqlx::test]
    async fn octet_stream_upload_falls_back_to_extension_guess(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = multipart_request(&multipart_body_with_type(
            "clip.mp4",
            "application/octet-stream",
            "fake mp4 bytes",
        ));
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&url);

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let ct = hdr(&resp, "content-type");
        assert!(
            ct.contains("video/mp4"),
            "expected extension-based guess of video/mp4, got: {ct}"
        );

        let cd = hdr(&resp, "content-disposition");
        assert!(
            cd.starts_with("inline"),
            "expected inline disposition, got: {cd}"
        );
    }

    #[sqlx::test]
    async fn duplicate_slug_insert_is_a_unique_violation(pool: MySqlPool) {
        // uploads.slug is UNIQUE (20261121000000). The upload handler relies on
        // this: a lost check-then-insert race surfaces as a unique violation,
        // which its retry loop answers with a longer id.
        let db = to_db_pool(&pool);
        let settings = Settings::test_defaults();
        let name = "row.txt";
        let expiry = crate::upload::calculate_expiry(1, &settings);
        let slug = "the-same-slug";
        let size = 1i64;
        let hash: &[u8] = &[0u8; 32];
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let ct = "text/plain";
        let ua = None;

        db::insert_upload_row(
            &db,
            uuid::Uuid::new_v4(),
            name,
            expiry,
            slug,
            size,
            hash,
            ip,
            ct,
            ua,
        )
        .await
        .unwrap();

        let err = db::insert_upload_row(
            &db,
            uuid::Uuid::new_v4(),
            name,
            expiry,
            slug,
            size,
            hash,
            ip,
            ct,
            ua,
        )
        .await
        .unwrap_err();
        assert!(
            db::is_unique_violation(&err),
            "expected a unique violation, got: {err}"
        );
    }

    #[sqlx::test]
    async fn unrecognised_binary_keeps_extension_guess(pool: MySqlPool) {
        // Binary bytes (contain control chars) that match no magic-byte signature make the
        // sniffer fall back to application/octet-stream. That default must not clobber a valid
        // extension-based guess.
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = multipart_request(&multipart_body_with_type(
            "clip.mp4",
            "application/octet-stream",
            "\x01\x02\x03 not a real mp4 \x00\x1f",
        ));
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&url);

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let ct = hdr(&resp, "content-type");
        assert!(
            ct.contains("video/mp4"),
            "expected extension-based guess of video/mp4, got: {ct}"
        );
    }

    #[sqlx::test]
    async fn detected_plaintext_without_extension_is_served_as_text(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = multipart_request(&multipart_body_with_type(
            "noext",
            "application/octet-stream",
            "hello ima plaintext file",
        ));
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&url);

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let ct = hdr(&resp, "content-type");
        assert!(
            ct.contains("text/plain"),
            "expected text/plain for detected plaintext, got: {ct}"
        );

        let cd = hdr(&resp, "content-disposition");
        assert!(
            cd.starts_with("inline"),
            "expected inline disposition for text, got: {cd}"
        );
    }

    #[sqlx::test]
    async fn formatted_upload_returns_html_link(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let ct = hdr(&resp, "content-type");
        assert!(
            ct.contains("text/html"),
            "expected html content-type, got: {ct}"
        );

        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            body.contains("<a href=\"http://localhost:8080/"),
            "expected formatted link in body, got: {body}"
        );
    }

    async fn ban_ip(pool: &MySqlPool, ip: std::net::IpAddr, ban_type: u32) {
        let ip_bytes = crate::ip::to_db_vec(ip);
        sqlx::query(
            "INSERT INTO banned_ip_ranges (start_ip, end_ip, banned_timestamp, type) VALUES (?, ?, NOW(), ?)",
        )
        .bind(&ip_bytes)
        .bind(&ip_bytes)
        .bind(ban_type)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn xff_used_when_peer_is_trusted_proxy(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await;

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn ipv6_xff_banned_ip_rejected(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await;

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "2001:db8::1")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn ipv6_xff_non_banned_ip_uploads_fine(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await;

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "2001:db8::2")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "expected success, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn xff_ignored_when_no_trusted_proxies(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await;

        let app = full_app(Settings::test_defaults(), pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "XFF should be ignored without TRUSTED_PROXIES, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn xff_from_untrusted_peer_is_not_believed(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 2).await; // Full ban

        let mut settings = Settings::test_defaults();
        // a proxy that isn't us: the header arrives, but the peer never vouches for it
        settings.trusted_proxies = Some("10.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "X-Forwarded-For from a peer outside TRUSTED_PROXIES must not be believed, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn xff_rightmost_entry_is_the_client_not_the_leftmost(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 2).await; // Full ban

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        // the client tries to hide behind a clean first entry; the trusted hop appended the
        // real address to the right of it, and that's the one we act on
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "8.8.8.8, 1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn xff_missing_falls_back_to_banned_peer(pool: MySqlPool) {
        // the Oct 2026 case: TLS/ACME edge dropped the header, every request became
        // unattributable, and the fail-open path let a banned client keep going.
        let banned_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        ban_ip(&pool, banned_ip, 2).await; // Full ban, on the socket peer itself

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(&multipart_body("test.txt", "hello"), &[]);
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn upload_without_client_address_is_rejected(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let mut req = test::TestRequest::post().uri("/").insert_header((
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        ));
        req = req.set_payload(format!(
            "{}--{BOUNDARY}--\r\n",
            multipart_body("test.txt", "hello")
        ));
        let resp = test::call_service(&app, req.to_request()).await;
        assert_eq!(resp.status(), 500);
    }

    #[sqlx::test]
    async fn get_without_client_address_is_rejected(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = upload_req(&multipart_body("test.txt", "hello"), &[]);
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let url = std::str::from_utf8(&body).unwrap().trim().to_string();

        let req = test::TestRequest::get().uri(&url).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn full_ban_blocks_get(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 2).await; // Full ban

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "5.6.7.8")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let url = std::str::from_utf8(&body).unwrap().trim().to_string();

        let req = peer(test::TestRequest::get())
            .uri(&url)
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn read_only_ban_does_not_block_get(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await; // ReadOnly ban

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "5.6.7.8")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let url = std::str::from_utf8(&body).unwrap().trim().to_string();

        let req = peer(test::TestRequest::get())
            .uri(&url)
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    /// Seeds a whitelist range via raw SQL, mirroring `ban_ip` above.
    async fn whitelist_range(pool: &MySqlPool, start: &str, end: &str) {
        sqlx::query(
            "INSERT INTO whitelisted_ip_ranges (start_ip, end_ip, created_timestamp) VALUES (?, ?, NOW())",
        )
        .bind(ip_bytes(start))
        .bind(ip_bytes(end))
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn whitelisted_ip_upload_overrides_ban(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await; // ReadOnly ban
        whitelist_range(&pool, "1.2.3.0", "1.2.3.255").await;

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "whitelisted IP must upload despite the ban covering it, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn whitelisted_ip_download_overrides_full_ban(pool: MySqlPool) {
        let banned_ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip, 2).await; // Full ban
        whitelist_range(&pool, "1.2.3.0", "1.2.3.255").await;

        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        // clean uploader so we have a file to fetch
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "5.6.7.8")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let url = std::str::from_utf8(&body).unwrap().trim().to_string();

        let req = peer(test::TestRequest::get())
            .uri(&url)
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "whitelisted IP must download despite the Full ban covering it, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn whitelisted_ip_skips_challenge_gate(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;
        whitelist_range(&pool, "198.51.100.0", "198.51.100.255").await;

        let req = upload_req(
            &multipart_body("b.txt", "hello"),
            &[("X-Forwarded-For", "198.51.100.7")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "whitelisted IP must not be sent through the challenge, got: {}",
            resp.status()
        );
    }

    #[sqlx::test]
    async fn ipv6_daily_quota_shared_within_64_prefix(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        settings.max_uploads_per_day = Some(1);
        let app = full_app(settings, pool).await;

        let req = upload_req(
            &multipart_body("a.txt", "hello"),
            &[("X-Forwarded-For", "2001:db8:1234:5678::1")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "first upload should succeed");

        // Different address, but same /64 as above -- should share the quota bucket.
        let req = upload_req(
            &multipart_body("b.txt", "hello"),
            &[("X-Forwarded-For", "2001:db8:1234:5678:ffff::2")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            429,
            "second address in the same /64 should be rate-limited"
        );

        // Different /64 entirely -- should have its own, unspent quota.
        let req = upload_req(
            &multipart_body("c.txt", "hello"),
            &[("X-Forwarded-For", "2001:db8:1234:9999::1")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "a different /64 should not share the exhausted quota"
        );
    }

    /// Seeds an NSFW upload by `ip`, `age_days` old, and returns its slug. Uploads from
    /// a throwaway IP and reassigns it, so `ip`'s "not suspect" answer doesn't get cached
    /// by the upload gate (there's no NSFW model in tests to mark it suspect afterwards).
    async fn seed_nsfw_upload(
        app: &impl actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
        pool: &MySqlPool,
        ip: &str,
        age_days: u32,
    ) -> String {
        let req = upload_req(
            &multipart_body("a.png", "hello"),
            &[("X-Forwarded-For", "192.0.2.1")],
        );
        let resp = test::call_service(app, req).await;
        assert!(resp.status().is_success(), "seed upload should succeed");
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&body).to_string();
        sqlx::query(
            "UPDATE uploads SET nsfw_score = 0.99, upload_timestamp = NOW() - INTERVAL ? DAY, \
             uploader_ip = ? WHERE slug = ?",
        )
        .bind(age_days)
        .bind(ip_bytes(ip))
        .bind(&slug)
        .execute(pool)
        .await
        .unwrap();
        slug
    }

    async fn mark_verified(pool: &MySqlPool, ip: &str) {
        sqlx::query(
            "INSERT INTO challenge_verified_ips (ip, expires_timestamp) \
             VALUES (?, NOW() + INTERVAL 1 HOUR)",
        )
        .bind(ip_bytes(ip))
        .execute(pool)
        .await
        .unwrap();
    }

    fn download_req(slug: &str, ip: &str, accept: Option<&str>) -> actix_http::Request {
        let mut req = peer(test::TestRequest::get())
            .uri(&format!("/{slug}"))
            .insert_header(("X-Forwarded-For", ip));
        if let Some(accept) = accept {
            req = req.insert_header(("Accept", accept));
        }
        req.to_request()
    }

    const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

    #[sqlx::test]
    async fn suspect_browser_download_redirects_to_captcha(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        let slug = seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;

        let resp = test::call_service(
            &app,
            download_req(&slug, "198.51.100.7", Some(BROWSER_ACCEPT)),
        )
        .await;
        assert_eq!(resp.status(), 302);
        assert_eq!(
            hdr(&resp, "location"),
            format!("http://localhost:8080/captcha?next={slug}")
        );
    }

    #[sqlx::test]
    async fn suspect_script_download_gets_428(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        let slug = seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;

        let resp = test::call_service(&app, download_req(&slug, "198.51.100.7", None)).await;
        assert_eq!(resp.status(), 428);
        assert!(hdr(&resp, "content-type").contains("text/plain"));
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            body.contains("http://localhost:8080/captcha"),
            "expected captcha URL, got: {body}"
        );
    }

    #[sqlx::test]
    async fn verified_suspect_can_download(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        let slug = seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;
        mark_verified(&pool, "198.51.100.7").await;

        let resp = test::call_service(&app, download_req(&slug, "198.51.100.7", None)).await;
        assert!(resp.status().is_success(), "got {}", resp.status());

        // and a non-suspect IP was never gated in the first place
        let resp = test::call_service(&app, download_req(&slug, "198.51.100.8", None)).await;
        assert!(resp.status().is_success(), "got {}", resp.status());
    }

    #[sqlx::test]
    async fn recent_nsfw_uploader_must_solve_challenge(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;

        let req = upload_req(
            &multipart_body("b.txt", "hello"),
            &[("X-Forwarded-For", "198.51.100.7")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 428);

        let req = upload_req(
            &multipart_body("c.txt", "hello"),
            &[("X-Forwarded-For", "198.51.100.8")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "other IPs should not be affected"
        );
    }

    #[sqlx::test]
    async fn challenge_link_is_clickable_for_web_form(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        seed_nsfw_upload(&app, &pool, "198.51.100.7", 0).await;

        let req = peer(test::TestRequest::post())
            .uri("/")
            .insert_header(("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"))
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            ))
            .insert_header(("X-Forwarded-For", "198.51.100.7"))
            .set_payload(format!(
                "{}--{BOUNDARY}--\r\n",
                multipart_body("b.txt", "hello")
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 428);
        assert!(hdr(&resp, "content-type").contains("text/html"));
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            body.contains("<a href=\"http://localhost:8080/captcha\">"),
            "expected captcha link, got: {body}"
        );
    }

    #[sqlx::test]
    async fn old_nsfw_upload_does_not_make_ip_suspect(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        seed_nsfw_upload(&app, &pool, "198.51.100.7", 8).await;

        let req = upload_req(
            &multipart_body("b.txt", "hello"),
            &[("X-Forwarded-For", "198.51.100.7")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "NSFW upload older than 7 days should be ignored"
        );
    }

    async fn ban_user_agent(pool: &MySqlPool, pattern: &str) {
        sqlx::query("INSERT INTO banned_user_agents (pattern, banned_timestamp) VALUES (?, NOW())")
            .bind(pattern)
            .execute(pool)
            .await
            .unwrap();
    }

    #[sqlx::test]
    async fn banned_user_agent_rejected_at_upload(pool: MySqlPool) {
        ban_user_agent(&pool, "curl").await;
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("User-Agent", "curl/8.0.1")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn non_banned_user_agent_upload_succeeds(pool: MySqlPool) {
        ban_user_agent(&pool, "curl").await;
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("User-Agent", "Mozilla/5.0")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "expected success, got: {}",
            resp.status()
        );
    }

    async fn upload_and_get_slug<S>(app: &S, filename: &str) -> String
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        let req = multipart_request(&multipart_body(filename, "content"));
        let resp = test::call_service(app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );
        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        slug(&url).to_string()
    }

    // since log_access is a background task ...
    async fn wait_for_accesses_count(pool: &MySqlPool, expected: i64) {
        for _ in 0..100 {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses")
                .fetch_one(pool)
                .await
                .unwrap();
            if count >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("accesses row did not appear within timeout");
    }

    #[sqlx::test]
    async fn miss_returns_404(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/no-such-slug")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[sqlx::test]
    async fn banned_user_agent_cannot_download(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        db::insert_banned_user_agent(&to_db_pool(&pool), "python-requests", Some("scraper"))
            .await
            .unwrap();

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .insert_header(("User-Agent", "python-requests/2.31.0"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 403);

        // an unbanned client is unaffected
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .insert_header(("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn request_rate_limit_429s_after_threshold(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.max_requests_per_minute = 2;
        let state = web::Data::new(AppState::new(to_db_pool(&pool), settings));
        let app = test::init_service(
            App::new()
                .service(handlers::index)
                .app_data(state)
                .wrap(crate::rate_limit::RequestRateLimiter),
        )
        .await;

        for i in 1..=2 {
            let resp =
                test::call_service(&app, peer(test::TestRequest::get()).uri("/").to_request())
                    .await;
            assert!(resp.status().is_success(), "request {i} should pass");
        }

        let resp =
            test::call_service(&app, peer(test::TestRequest::get()).uri("/").to_request()).await;
        assert_eq!(resp.status(), 429);
    }

    #[sqlx::test]
    async fn miss_brute_force_marks_ip_suspect(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.max_misses_per_minute = 2;
        let app = full_app(settings, pool).await;
        // upload while the IP is still clean: once suspect, uploads need PoW too
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let miss = |i: usize| {
            let app = &app;
            async move {
                test::call_service(
                    app,
                    peer(test::TestRequest::get())
                        .uri(&format!("/no-such-{i}"))
                        .to_request(),
                )
                .await
            }
        };
        assert_eq!(miss(1).await.status(), 404);
        assert_eq!(miss(2).await.status(), 404);

        // threshold crossed: the IP now faces the PoW challenge everywhere
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 428);
    }

    #[sqlx::test]
    async fn favicon_is_served(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/favicon.ico").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("image/x-icon")
        );
        assert!(!test::read_body(resp).await.is_empty());
    }

    #[sqlx::test]
    async fn head_requests_hit_the_file_route(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        // HEAD used to fall through to the router's bare 404 (#[get] doesn't
        // match HEAD), breaking HEAD-first download clients
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::default())
                .method(actix_http::Method::HEAD)
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::default())
                .method(actix_http::Method::HEAD)
                .uri("/no-such-slug")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[sqlx::test]
    async fn download_is_logged(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        wait_for_accesses_count(&pool, 1).await;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test]
    async fn download_logs_xff_ip(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .insert_header(("X-Forwarded-For", "10.0.0.1"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        wait_for_accesses_count(&pool, 1).await;
        let (ip, bytes, status): (Option<Vec<u8>>, Option<u64>, Option<u16>) =
            sqlx::query_as("SELECT ip, bytes, status FROM accesses LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(ip, Some(ip_bytes("10.0.0.1")));
        // the uploaded file is 7 bytes of body, served whole
        assert_eq!(bytes, Some(7), "served byte count should be logged");
        assert_eq!(status, Some(200), "response status should be logged");
    }

    #[sqlx::test]
    async fn download_throttle_paces_hot_clients(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        // 10 B/s with a 5 B burst: the first download drains the burst, the
        // immediate second one has to wait for the bucket to refill
        settings.max_download_bytes_per_sec = Some(10.0);
        settings.max_download_burst_bytes = Some(5.0);
        let app = full_app(settings, pool).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let get = || async {
            test::call_service(
                &app,
                peer(test::TestRequest::get())
                    .uri(&format!("/{slug}"))
                    .to_request(),
            )
            .await
        };
        let start = std::time::Instant::now();
        let resp = get().await;
        assert!(resp.status().is_success());
        // pacing happens in the body stream, so it must be drained to be timed
        test::read_body(resp).await;
        let unthrottled = start.elapsed();

        let resp = get().await;
        assert!(resp.status().is_success());
        test::read_body(resp).await;
        let gap = start.elapsed() - unthrottled;
        assert!(
            gap >= std::time::Duration::from_millis(400),
            "second download should wait for the bucket to refill, waited {gap:?}"
        );
    }

    #[sqlx::test]
    async fn upload_multiple(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await;

        let req = multipart_request(
            [
                multipart_body("file 1", "blah"),
                multipart_body("file 2", "indeed"),
            ]
            .join("")
            .as_str(),
        );

        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );

        let body = test::read_body(resp).await;
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str.lines().count(), 2);
    }

    fn admin_settings() -> Settings {
        let mut settings = Settings::test_defaults();
        settings.admin_token = Some("secret".to_string());
        settings
    }

    struct MockClamd {
        addr: std::net::SocketAddr,
        /// total connections accepted so far (one per scan)
        connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    /// minimal clamd INSTREAM mock; tracks peak concurrency and delays each
    /// response briefly so overlapping scans are measurable
    async fn spawn_mock_clamd() -> MockClamd {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connections, current, peak) = (
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let (conn_task, cur_task, peak_task) = (connections.clone(), current.clone(), peak.clone());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                conn_task.fetch_add(1, Ordering::SeqCst);
                let now = cur_task.fetch_add(1, Ordering::SeqCst) + 1;
                peak_task.fetch_max(now, Ordering::SeqCst);
                let cur_task = cur_task.clone();
                tokio::spawn(async move {
                    let mut window = [255u8; 4];
                    let mut buf = [0u8; 4096];
                    'read: loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                for &b in &buf[..n] {
                                    window = [window[1], window[2], window[3], b];
                                    if window == [0u8; 4] {
                                        break 'read;
                                    }
                                }
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let _ = sock.write_all(b"stream: OK\0").await;
                    let _ = sock.flush().await;
                    cur_task.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        MockClamd {
            addr,
            connections,
            peak,
        }
    }

    /// scans must wait for a permit (never skip) and never exceed the limit
    #[sqlx::test]
    async fn clamd_scans_wait_for_a_permit(pool: MySqlPool) {
        use std::sync::atomic::Ordering;

        const N: usize = 6;
        let clamd = spawn_mock_clamd().await;
        let settings = Settings {
            clamd_addr: Some(clamd.addr.to_string()),
            max_concurrent_clamd_scans: 1,
            ..Settings::test_defaults()
        };
        let app = full_app(settings, pool).await;

        // unique content per upload so dedup can't collapse them into one scan
        let reqs: Vec<_> = (0..N)
            .map(|i| {
                multipart_request(&multipart_body(
                    &format!("f{i}.txt"),
                    &format!("unique-content-{i}"),
                ))
            })
            .collect();
        let responses =
            futures_util::future::join_all(reqs.into_iter().map(|r| test::call_service(&app, r)))
                .await;
        for resp in responses {
            assert!(
                resp.status().is_success(),
                "upload failed: {}",
                resp.status()
            );
        }

        // scans run in spawned tasks: wait until all N have hit the mock
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while clamd.connections.load(Ordering::SeqCst) < N {
            assert!(
                std::time::Instant::now() < deadline,
                "only {} of {N} uploads were scanned in time",
                clamd.connections.load(Ordering::SeqCst)
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            clamd.peak.load(Ordering::SeqCst) == 1,
            "clamd scans overlapped: peak={} (limit 1)",
            clamd.peak.load(Ordering::SeqCst)
        );
    }

    fn admin_req(method: test::TestRequest, uri: &str) -> test::TestRequest {
        method
            .uri(uri)
            .insert_header(("Authorization", "Bearer secret"))
    }

    async fn admin_get<S>(app: &S, path: &str) -> ServiceResponse
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        test::call_service(
            app,
            admin_req(peer(test::TestRequest::get()), path).to_request(),
        )
        .await
    }

    async fn admin_post<S>(app: &S, path: &str, body: &impl Serialize) -> ServiceResponse
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        test::call_service(
            app,
            admin_req(peer(test::TestRequest::post()), path)
                .set_json(body)
                .to_request(),
        )
        .await
    }

    async fn admin_delete<S>(app: &S, path: &str) -> ServiceResponse
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        test::call_service(
            app,
            admin_req(peer(test::TestRequest::delete()), path).to_request(),
        )
        .await
    }

    /// GETs `path` as admin and decodes the JSON body — used for every "list" endpoint.
    async fn admin_list<S, T: DeserializeOwned>(app: &S, path: &str) -> Vec<T>
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        test::read_body_json(admin_get(app, path).await).await
    }

    #[derive(Deserialize)]
    struct StatsResponse {
        active_uploads: i64,
    }

    #[sqlx::test]
    async fn admin_no_token_configured_returns_404(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool).await; // admin_token defaults to None
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/admin/stats")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[sqlx::test]
    async fn admin_missing_header_returns_401(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/admin/stats")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 401);
    }

    #[sqlx::test]
    async fn admin_wrong_token_returns_403(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri("/admin/stats")
                .insert_header(("Authorization", "Bearer wrong"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn admin_correct_token_returns_stats(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let resp = admin_get(&app, "/admin/stats").await;
        assert!(resp.status().is_success());
        let body: StatsResponse = test::read_body_json(resp).await;
        assert_eq!(body.active_uploads, 0);
    }

    #[derive(Deserialize)]
    struct TopUploaderResponse {
        ip: String,
        count: i64,
        bytes: i64,
    }

    #[derive(Deserialize)]
    struct StatsWithTopUploadersResponse {
        top_uploaders: Vec<TopUploaderResponse>,
    }

    #[sqlx::test]
    async fn admin_stats_includes_top_uploaders(pool: MySqlPool) {
        let mut settings = admin_settings();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        for (ip, bodies) in [
            ("5.5.5.5", vec!["one", "two", "three"]),
            ("6.6.6.6", vec!["four"]),
        ] {
            let xff = &[("X-Forwarded-For", ip)];
            for body in bodies {
                let req = upload_req(&multipart_body("f.txt", body), xff);
                assert!(test::call_service(&app, req).await.status().is_success());
            }
        }

        let stats: StatsWithTopUploadersResponse =
            test::read_body_json(admin_get(&app, "/admin/stats").await).await;

        assert_eq!(stats.top_uploaders.len(), 2);
        assert_eq!(stats.top_uploaders[0].ip, "5.5.5.5");
        assert_eq!(stats.top_uploaders[0].count, 3);
        assert!(stats.top_uploaders[0].bytes > 0);
        assert_eq!(stats.top_uploaders[1].ip, "6.6.6.6");
        assert_eq!(stats.top_uploaders[1].count, 1);
    }

    #[derive(Deserialize)]
    struct TopNsfwUploaderResponse {
        ip: String,
        count: i64,
        avg_score: f64,
    }

    #[derive(Deserialize)]
    struct StatsWithTopNsfwUploadersResponse {
        top_nsfw_uploaders: Vec<TopNsfwUploaderResponse>,
    }

    #[sqlx::test]
    async fn admin_stats_includes_top_nsfw_uploaders(pool: MySqlPool) {
        let mut settings = admin_settings();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let db_pool = to_db_pool(&pool);
        let app = full_app(settings, pool).await;

        let nsfw_resp = test::call_service(
            &app,
            upload_req(
                &multipart_body("nsfw.txt", "nsfw"),
                &[("X-Forwarded-For", "7.7.7.7")],
            ),
        )
        .await;
        assert!(nsfw_resp.status().is_success());
        let nsfw_slug =
            slug(core::str::from_utf8(&test::read_body(nsfw_resp).await).unwrap()).to_string();

        // Below the top-uploaders threshold, so this uploader shouldn't show up.
        let sfw_resp = test::call_service(
            &app,
            upload_req(
                &multipart_body("sfw.txt", "sfw"),
                &[("X-Forwarded-For", "8.8.8.8")],
            ),
        )
        .await;
        assert!(sfw_resp.status().is_success());
        let sfw_slug =
            slug(core::str::from_utf8(&test::read_body(sfw_resp).await).unwrap()).to_string();

        let uploads: Vec<UploadResponse> = admin_list(&app, "/admin/uploads").await;
        let nsfw_id = uploads
            .iter()
            .find(|u| u.slug == nsfw_slug)
            .unwrap()
            .id
            .parse()
            .unwrap();
        let sfw_id = uploads
            .iter()
            .find(|u| u.slug == sfw_slug)
            .unwrap()
            .id
            .parse()
            .unwrap();
        crate::db::update_nsfw_score(&db_pool, nsfw_id, 0.9)
            .await
            .unwrap();
        crate::db::update_nsfw_score(&db_pool, sfw_id, 0.1)
            .await
            .unwrap();

        let stats: StatsWithTopNsfwUploadersResponse =
            test::read_body_json(admin_get(&app, "/admin/stats").await).await;

        assert_eq!(stats.top_nsfw_uploaders.len(), 1);
        assert_eq!(stats.top_nsfw_uploaders[0].ip, "7.7.7.7");
        assert_eq!(stats.top_nsfw_uploaders[0].count, 1);
        assert!((stats.top_nsfw_uploaders[0].avg_score - 0.9).abs() < 0.01);
    }

    #[derive(Deserialize)]
    struct UploadResponse {
        id: String,
        slug: String,
        deleted: bool,
    }

    #[sqlx::test]
    async fn admin_lists_and_deletes_upload_by_id(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let uploads: Vec<UploadResponse> = admin_list(&app, "/admin/uploads").await;
        let upload = uploads
            .iter()
            .find(|u| u.slug == slug)
            .expect("uploaded file should be listed");
        assert!(!upload.deleted);

        let resp = admin_delete(&app, &format!("/admin/uploads/{}", upload.id)).await;
        assert!(resp.status().is_success());

        // Deleted uploads are excluded from the default listing...
        let uploads: Vec<UploadResponse> = admin_list(&app, "/admin/uploads").await;
        assert!(!uploads.iter().any(|u| u.slug == slug));

        // ...but included by the archive query, with the deleted flag set.
        let uploads: Vec<UploadResponse> =
            admin_list(&app, "/admin/uploads?include_deleted=true").await;
        let deleted = uploads
            .iter()
            .find(|u| u.slug == slug)
            .expect("deleted upload should be listed with include_deleted");
        assert!(deleted.deleted);

        // And the file is no longer servable.
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[sqlx::test]
    async fn admin_deletes_upload_by_slug(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let resp = admin_delete(&app, &format!("/admin/uploads/slug/{slug}")).await;
        assert!(resp.status().is_success());

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[derive(Deserialize)]
    struct DeleteResultResponse {
        deleted: usize,
    }

    #[sqlx::test]
    async fn admin_deletes_uploads_by_ip(pool: MySqlPool) {
        let mut settings = admin_settings();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let ip = "6.6.6.6";
        let xff = &[("X-Forwarded-For", ip)];

        for body in ["one", "two"] {
            let req = upload_req(&multipart_body("f.txt", body), xff);
            assert!(test::call_service(&app, req).await.status().is_success());
        }
        // Uploaded without an XFF header, so it lands on a different IP (127.0.0.1) and
        // should be unaffected by the ip-scoped delete below.
        let other_slug = upload_and_get_slug(&app, "other.txt").await;

        let resp = admin_delete(&app, &format!("/admin/uploads/ip/{ip}")).await;
        assert!(resp.status().is_success());
        let body: DeleteResultResponse = test::read_body_json(resp).await;
        assert_eq!(body.deleted, 2);

        let uploads: Vec<UploadResponse> = admin_list(&app, "/admin/uploads").await;
        assert!(uploads.iter().any(|u| u.slug == other_slug));
    }

    #[derive(Deserialize)]
    struct HourlyCountResponse {
        count: i64,
    }

    #[derive(Deserialize)]
    struct MimeCountResponse {
        mime: String,
        count: i64,
    }

    #[derive(Deserialize)]
    struct IpStatsResponse {
        hourly: Vec<HourlyCountResponse>,
        top_mimes: Vec<MimeCountResponse>,
    }

    #[sqlx::test]
    async fn admin_ip_stats_returns_hourly_and_top_mimes(pool: MySqlPool) {
        let mut settings = admin_settings();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool).await;

        let ip = "9.9.9.9";
        let xff = &[("X-Forwarded-For", ip)];

        for (name, content_type, body) in [
            ("a.png", "image/png", "content a"),
            ("b.png", "image/png", "content b"),
            ("c.txt", "text/plain", "content c"),
        ] {
            let req = upload_req(&multipart_body_with_type(name, content_type, body), xff);
            assert!(test::call_service(&app, req).await.status().is_success());
        }

        let stats: IpStatsResponse =
            test::read_body_json(admin_get(&app, &format!("/admin/ip-stats/{ip}")).await).await;

        // Continuous 7-day-hourly timeline, all 3 uploads landing in the current hour.
        assert_eq!(stats.hourly.len(), 168);
        assert_eq!(stats.hourly.iter().map(|h| h.count).sum::<i64>(), 3);
        assert_eq!(stats.hourly.last().unwrap().count, 3);

        assert_eq!(stats.top_mimes.len(), 2);
        assert_eq!(stats.top_mimes[0].mime, "image/png");
        assert_eq!(stats.top_mimes[0].count, 2);
        assert_eq!(stats.top_mimes[1].mime, "text/plain");
        assert_eq!(stats.top_mimes[1].count, 1);
    }

    #[derive(Serialize)]
    struct IpRangeBody<'a> {
        start_ip: &'a str,
        end_ip: &'a str,
        reason: Option<&'a str>,
        expires_timestamp: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        type_: Option<u32>,
    }

    #[derive(Deserialize)]
    struct IdResponse {
        id: i64,
    }

    #[derive(Deserialize)]
    struct IpRangeResponse {
        id: i64,
        start_ip: String,
        end_ip: String,
        type_: u32,
    }

    #[sqlx::test]
    async fn admin_bans_ip_range_add_list_delete(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;

        let resp = admin_post(
            &app,
            "/admin/bans/ips",
            &IpRangeBody {
                start_ip: "1.2.3.0",
                end_ip: "1.2.3.255",
                reason: Some("spam"),
                expires_timestamp: None,
                type_: None,
            },
        )
        .await;
        assert_eq!(resp.status(), 201);
        let created: IdResponse = test::read_body_json(resp).await;

        let ranges: Vec<IpRangeResponse> = admin_list(&app, "/admin/bans/ips").await;
        let range = ranges
            .iter()
            .find(|r| r.id == created.id)
            .expect("banned range should be listed");
        assert_eq!(range.start_ip, "1.2.3.0");
        assert_eq!(range.end_ip, "1.2.3.255");
        assert_eq!(range.type_, 1);

        let resp = admin_delete(&app, &format!("/admin/bans/ips/{}", created.id)).await;
        assert_eq!(resp.status(), 204);

        let ranges: Vec<IpRangeResponse> = admin_list(&app, "/admin/bans/ips").await;
        assert!(!ranges.iter().any(|r| r.id == created.id));
    }

    #[derive(Serialize)]
    struct WhitelistBody<'a> {
        start_ip: &'a str,
        end_ip: &'a str,
        reason: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct WhitelistResponse {
        id: i64,
        start_ip: String,
        end_ip: String,
    }

    #[sqlx::test]
    async fn admin_whitelist_ip_add_list_delete_and_enforced(pool: MySqlPool) {
        let mut settings = admin_settings();
        settings.trusted_proxies = Some("127.0.0.1".to_string());
        let app = full_app(settings, pool.clone()).await;

        let resp = admin_post(
            &app,
            "/admin/whitelist/ips",
            &WhitelistBody {
                start_ip: "10.0.0.5",
                end_ip: "10.0.0.9",
                reason: Some("office"),
            },
        )
        .await;
        assert_eq!(resp.status(), 201);
        let created: IdResponse = test::read_body_json(resp).await;

        let entries: Vec<WhitelistResponse> = admin_list(&app, "/admin/whitelist/ips").await;
        let entry = entries
            .iter()
            .find(|e| e.id == created.id)
            .expect("whitelisted range should be listed");
        assert_eq!(entry.start_ip, "10.0.0.5");
        assert_eq!(entry.end_ip, "10.0.0.9");

        // Enforcement: a ReadOnly ban on the same range is overridden for whitelisted IPs.
        let banned_ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        ban_ip(&pool, banned_ip, 1).await;
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "10.0.0.7")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "whitelisted IP must upload despite the ban covering it, got: {}",
            resp.status()
        );

        let resp = admin_delete(&app, &format!("/admin/whitelist/ips/{}", created.id)).await;
        assert_eq!(resp.status(), 204);

        // Once the whitelist entry is gone the ban applies again.
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("X-Forwarded-For", "10.0.0.7")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[derive(Serialize)]
    struct FilenameBody<'a> {
        pattern: &'a str,
        reason: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct FilenameResponse {
        pattern: String,
    }

    #[sqlx::test]
    async fn admin_bans_filename_add_list_delete_and_enforced(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;

        let resp = admin_post(
            &app,
            "/admin/bans/filenames",
            &FilenameBody {
                pattern: r"\.exe$",
                reason: Some("executables"),
            },
        )
        .await;
        assert_eq!(resp.status(), 201);

        let patterns: Vec<FilenameResponse> = admin_list(&app, "/admin/bans/filenames").await;
        assert!(patterns.iter().any(|p| p.pattern == r"\.exe$"));

        // Banned filename pattern is rejected at upload time.
        let req = multipart_request(&multipart_body("test.exe", "MZ"));
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);

        let encoded_pattern =
            percent_encoding::utf8_percent_encode(r"\.exe$", percent_encoding::NON_ALPHANUMERIC);
        let resp = admin_delete(&app, &format!("/admin/bans/filenames/{encoded_pattern}")).await;
        assert_eq!(resp.status(), 204);

        // Upload succeeds again once the ban is lifted.
        let req = multipart_request(&multipart_body("test.exe", "MZ"));
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[derive(Serialize)]
    struct MimeBody<'a> {
        mime: &'a str,
    }

    #[sqlx::test]
    async fn admin_bans_mime_add_list_delete(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;

        let resp = admin_post(
            &app,
            "/admin/bans/mimes",
            &MimeBody {
                mime: "application/x-msdownload",
            },
        )
        .await;
        assert_eq!(resp.status(), 201);

        let mimes: Vec<String> = admin_list(&app, "/admin/bans/mimes").await;
        assert!(mimes.contains(&"application/x-msdownload".to_string()));

        // Mime types contain a slash, so the delete route uses a greedy path match.
        let resp = admin_delete(&app, "/admin/bans/mimes/application/x-msdownload").await;
        assert_eq!(resp.status(), 204);

        let mimes: Vec<String> = admin_list(&app, "/admin/bans/mimes").await;
        assert!(!mimes.contains(&"application/x-msdownload".to_string()));
    }

    #[derive(Serialize)]
    struct HashBody<'a> {
        hash: &'a str,
        reason: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct HashResponse {
        hash: String,
    }

    #[sqlx::test]
    async fn admin_bans_hash_add_list_delete(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;
        let hash = "a".repeat(64); // 32 bytes of 0xaa, hex-encoded

        let resp = admin_post(
            &app,
            "/admin/bans/hashes",
            &HashBody {
                hash: &hash,
                reason: Some("known malware"),
            },
        )
        .await;
        assert_eq!(resp.status(), 201);

        let hashes: Vec<HashResponse> = admin_list(&app, "/admin/bans/hashes").await;
        assert!(hashes.iter().any(|h| h.hash == hash));

        let resp = admin_delete(&app, &format!("/admin/bans/hashes/{hash}")).await;
        assert_eq!(resp.status(), 204);

        let hashes: Vec<HashResponse> = admin_list(&app, "/admin/bans/hashes").await;
        assert!(!hashes.iter().any(|h| h.hash == hash));
    }

    #[derive(Serialize)]
    struct UserAgentBody<'a> {
        pattern: &'a str,
        reason: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct UserAgentResponse {
        pattern: String,
    }

    #[sqlx::test]
    async fn admin_bans_user_agent_add_list_delete_and_enforced(pool: MySqlPool) {
        let app = full_app(admin_settings(), pool).await;

        let resp = admin_post(
            &app,
            "/admin/bans/user-agents",
            &UserAgentBody {
                pattern: "python-requests",
                reason: Some("scraper"),
            },
        )
        .await;
        assert_eq!(resp.status(), 201);

        let patterns: Vec<UserAgentResponse> = admin_list(&app, "/admin/bans/user-agents").await;
        assert!(patterns.iter().any(|p| p.pattern == "python-requests"));

        // Banned user agent is rejected at upload time.
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("User-Agent", "python-requests/2.31.0")],
        );
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);

        let resp = admin_delete(&app, "/admin/bans/user-agents/python-requests").await;
        assert_eq!(resp.status(), 204);

        // Upload succeeds again once the ban is lifted.
        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("User-Agent", "python-requests/2.31.0")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn upload_and_download_log_user_agent(pool: MySqlPool) {
        let app = full_app(Settings::test_defaults(), pool.clone()).await;

        let req = upload_req(
            &multipart_body("test.txt", "hello"),
            &[("User-Agent", "UploaderAgent/1.0")],
        );
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let slug = slug(&url).to_string();

        let uploaded_ua: Option<String> =
            sqlx::query_scalar("SELECT user_agent FROM uploads WHERE slug = ?")
                .bind(&slug)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(uploaded_ua.as_deref(), Some("UploaderAgent/1.0"));

        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .insert_header(("User-Agent", "DownloaderAgent/2.0"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        wait_for_accesses_count(&pool, 1).await;
        let accessed_ua: Option<String> =
            sqlx::query_scalar("SELECT user_agent FROM accesses LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(accessed_ua.as_deref(), Some("DownloaderAgent/2.0"));
    }

    #[sqlx::test]
    async fn dedup_reuses_existing_upload(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.dedup = true;
        let app = full_app(settings, pool.clone()).await;

        let slug1 = upload_and_get_slug(&app, "file.txt").await;

        // Upload the same content with a different filename.
        let slug2 = upload_and_get_slug(&app, "other.txt").await;

        assert_eq!(slug1, slug2, "dedup should return the same slug");

        // Only one DB row.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "should not create a duplicate row");
    }

    #[sqlx::test]
    async fn dedup_disabled_uploads_twice(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.dedup = false;
        let app = full_app(settings, pool.clone()).await;

        let slug1 = upload_and_get_slug(&app, "file.txt").await;
        let slug2 = upload_and_get_slug(&app, "file.txt").await;

        assert_ne!(slug1, slug2, "with dedup off, each upload gets a new slug");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "should create two rows when dedup is off");
    }

    #[sqlx::test]
    async fn dedup_ignores_deleted_upload(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.dedup = true;
        settings.admin_token = Some("secret".to_string());
        let app = full_app(settings, pool.clone()).await;

        let slug1 = upload_and_get_slug(&app, "file.txt").await;

        // Delete the upload via admin API.
        let _resp = admin_delete(&app, &format!("/admin/uploads/slug/{slug1}")).await;
        assert!(_resp.status().is_success());

        // Upload the same content again — should get a new slug, not reuse the deleted one.
        let slug2 = upload_and_get_slug(&app, "file.txt").await;

        assert_ne!(slug2, slug1, "dedup should not reuse a deleted upload");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "only the new row should exist in uploads");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "the deleted row should be archived");
    }

    #[sqlx::test]
    async fn deleting_upload_purges_its_accesses(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.admin_token = Some("secret".to_string());
        let app = full_app(settings, pool.clone()).await;

        let slug = upload_and_get_slug(&app, "test.txt").await;
        let resp = test::call_service(
            &app,
            peer(test::TestRequest::get())
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        wait_for_accesses_count(&pool, 1).await;

        let _resp = admin_delete(&app, &format!("/admin/uploads/slug/{slug}")).await;
        assert!(_resp.status().is_success());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "the download log should be cascade-deleted");
    }

    /// Like `upload_and_get_slug`, but with explicit content, so multiple
    /// uploads in one test stay distinct under dedup.
    async fn upload_content<S>(app: &S, filename: &str, content: &str) -> String
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error>,
    {
        let req = multipart_request(&multipart_body(filename, content));
        let resp = test::call_service(app, req).await;
        assert!(
            resp.status().is_success(),
            "upload failed: {}",
            resp.status()
        );
        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        slug(&url).to_string()
    }

    /// Backdates an upload's `upload_timestamp` by the given number of days.
    async fn backdate_upload(pool: &MySqlPool, slug: &str, days_ago: i64) {
        let ts = time::OffsetDateTime::now_utc() - time::Duration::days(days_ago);
        let ts = time::PrimitiveDateTime::new(ts.date(), ts.time());
        sqlx::query("UPDATE uploads SET upload_timestamp = ? WHERE slug = ?")
            .bind(ts)
            .bind(slug)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn upload_id_by_slug(pool: &MySqlPool, slug: &str) -> uuid::Uuid {
        sqlx::query_scalar("SELECT id FROM uploads WHERE slug = ?")
            .bind(slug)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn never_downloaded_uploads_are_deleted_after_n_days(pool: MySqlPool) {
        let mut settings = Settings::test_defaults();
        settings.never_downloaded_days = Some(30);
        let app = full_app(settings.clone(), pool.clone()).await;

        let stale = upload_content(&app, "stale.txt", "stale content").await;
        let fresh = upload_content(&app, "fresh.txt", "fresh content").await;

        backdate_upload(&pool, &stale, 40).await;
        let stale_id = upload_id_by_slug(&pool, &stale).await;

        let db = to_db_pool(&pool);
        let count = db::delete_never_downloaded(&db, &settings, 30)
            .await
            .unwrap();
        assert_eq!(count, 1, "only the old never-downloaded upload goes");

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "the fresh upload survives");
        let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(archived, 1, "the deleted row should be archived");

        // the stale file is unlinked, the fresh one stays on disk
        assert!(!uuid_to_path(std::path::Path::new(&settings.store_path), &stale_id).exists());
        let fresh_id = upload_id_by_slug(&pool, &fresh).await;
        assert!(
            uuid_to_path(std::path::Path::new(&settings.store_path), &fresh_id).exists(),
            "fresh file must stay on disk"
        );
    }

    #[sqlx::test]
    async fn downloaded_old_upload_is_kept(pool: MySqlPool) {
        let settings = Settings::test_defaults();
        let app = full_app(settings.clone(), pool.clone()).await;

        let slug = upload_content(&app, "popular.txt", "downloaded content").await;
        backdate_upload(&pool, &slug, 40).await;
        let id = upload_id_by_slug(&pool, &slug).await;

        db::log_access(
            &to_db_pool(&pool),
            id,
            Some("127.0.0.1".parse().unwrap()),
            None,
            Some(18),
            200,
        )
        .await
        .unwrap();

        let db = to_db_pool(&pool);
        let count = db::delete_never_downloaded(&db, &settings, 30)
            .await
            .unwrap();
        assert_eq!(count, 0, "a file with a downloads log entry must survive");

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[sqlx::test]
    async fn count_never_downloaded_reports_without_deleting(pool: MySqlPool) {
        let settings = Settings::test_defaults();
        let app = full_app(settings.clone(), pool.clone()).await;

        let stale = upload_content(&app, "stale.txt", "stale content").await;
        let _fresh = upload_content(&app, "fresh.txt", "fresh content").await;
        let downloaded = upload_content(&app, "popular.txt", "downloaded content").await;

        backdate_upload(&pool, &stale, 40).await;
        backdate_upload(&pool, &downloaded, 40).await;

        let downloaded_id = upload_id_by_slug(&pool, &downloaded).await;
        db::log_access(
            &to_db_pool(&pool),
            downloaded_id,
            Some("127.0.0.1".parse().unwrap()),
            None,
            Some(18),
            200,
        )
        .await
        .unwrap();

        let db = to_db_pool(&pool);
        let (count, bytes) = db::count_never_downloaded(&db, 30).await.unwrap();
        assert_eq!(
            count, 1,
            "only the stale never-downloaded upload is counted"
        );
        assert_eq!(bytes, 13, "reported bytes are the stale upload's size");

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 3, "a dry run deletes nothing");
        let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(archived, 0, "a dry run archives nothing");
    }
}

#[cfg(test)]
mod sync_tests {
    use sqlx::MySqlPool;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::asn;
    use crate::db_pool;
    use crate::model::BanType;
    use crate::sync;

    fn db(pool: &MySqlPool) -> db_pool::DbPool {
        db_pool::build_pool((*pool.connect_options()).clone(), 5).unwrap()
    }

    async fn insert_bl(pool: &MySqlPool, url: &str, t: BanType, interval: u64) -> i32 {
        let r = sqlx::query(
            "INSERT INTO blacklist (url, type, update_interval_seconds, last_update) VALUES (?, ?, ?, NULL)",
        )
        .bind(url)
        .bind(t as u32)
        .bind(interval)
        .execute(pool)
        .await
        .unwrap();
        r.last_insert_id() as i32
    }

    fn ip(s: &str) -> Vec<u8> {
        crate::ip::to_db_vec(s.parse().unwrap())
    }

    macro_rules! bl_mock {
        ($server:ident, $body:expr) => {
            Mock::given(method("GET"))
                .and(path("/blacklist"))
                .respond_with(ResponseTemplate::new(200).set_body_string($body))
                .mount(&$server)
                .await
        };
    }

    #[sqlx::test]
    async fn sync_single_ip(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "10.0.0.1\n192.168.1.100\n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let ranges: Vec<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT start_ip, end_ip FROM banned_ip_ranges ORDER BY start_ip")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            ranges,
            vec![
                (ip("10.0.0.1"), ip("10.0.0.1")),
                (ip("192.168.1.100"), ip("192.168.1.100"))
            ]
        );
    }

    #[sqlx::test]
    async fn sync_cidr(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "10.0.0.0/24\n172.16.0.0/16\n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let ranges: Vec<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT start_ip, end_ip FROM banned_ip_ranges ORDER BY start_ip")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            ranges,
            vec![
                (ip("10.0.0.0"), ip("10.0.0.255")),
                (ip("172.16.0.0"), ip("172.16.255.255"))
            ]
        );
    }

    #[sqlx::test]
    async fn sync_range(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "192.168.1.1\n10.0.0.5\n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM banned_ip_ranges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[sqlx::test]
    async fn sync_comments(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "# comment\n10.0.0.1\n\n# another\n192.168.1.1\n   \n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM banned_ip_ranges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[sqlx::test]
    async fn sync_replaces_old_entries(pool: MySqlPool) {
        let s = MockServer::start().await;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = counter.clone();
        let r = move |_req: &wiremock::Request| {
            let n = c2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let body = if n == 0 {
                "10.0.0.1\n10.0.0.2\n10.0.0.3\n"
            } else {
                "192.168.1.1\n192.168.1.2\n"
            };
            ResponseTemplate::new(200).set_body_string(body)
        };
        Mock::given(method("GET"))
            .and(path("/blacklist"))
            .respond_with(r)
            .mount(&s)
            .await;

        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM banned_ip_ranges")
                .fetch_one(&pool)
                .await
                .unwrap(),
            3
        );

        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let ranges: Vec<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT start_ip, end_ip FROM banned_ip_ranges ORDER BY start_ip")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM banned_ip_ranges")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            ranges,
            vec![
                (ip("192.168.1.1"), ip("192.168.1.1")),
                (ip("192.168.1.2"), ip("192.168.1.2"))
            ]
        );
    }

    #[sqlx::test]
    async fn sync_sets_last_update(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "10.0.0.1\n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let last: Option<time::PrimitiveDateTime> =
            sqlx::query_scalar("SELECT last_update FROM blacklist WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(last.is_some());
    }

    #[sqlx::test]
    async fn sync_sets_blacklist_id(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "10.0.0.1\n10.0.0.2\n");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let ids: Vec<i32> = sqlx::query_scalar(
            "SELECT DISTINCT blacklist_id FROM banned_ip_ranges ORDER BY blacklist_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(ids, vec![id]);
    }

    #[sqlx::test]
    async fn sync_empty_body(pool: MySqlPool) {
        let s = MockServer::start().await;
        bl_mock!(s, "");
        let id = insert_bl(&pool, &(s.uri() + "/blacklist"), BanType::ReadOnly, 3600).await;
        sync::sync_blacklist(db(&pool), id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM banned_ip_ranges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn sync_nonexistent_blacklist_fails(pool: MySqlPool) {
        let result = sync::sync_blacklist(db(&pool), 99999).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn asn_sync_replaces_table(pool: MySqlPool) {
        let db = db(&pool);
        let ranges = asn::parse_body(
            b"1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare\n\
              1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n",
        )
        .unwrap();
        assert_eq!(crate::db::replace_ip_asn(&db, &ranges).await.unwrap(), 2);

        // Point lookup: greatest start_ip <= target, then containment check.
        let row: (u32, String, String) = sqlx::query_as(
            "SELECT asn, country, org FROM ip_asn \
             WHERE start_ip <= ? AND end_ip >= ? ORDER BY start_ip DESC LIMIT 1",
        )
        .bind(crate::ip::to_db_vec("1.0.0.42".parse().unwrap()))
        .bind(crate::ip::to_db_vec("1.0.0.42".parse().unwrap()))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (13335, "US".to_string(), "Cloudflare".to_string()));

        // Re-running replaces, not appends.
        let ranges2 = asn::parse_body(
            b"1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare\n\
              1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
              1.0.4.0\t1.0.7.255\t38803\tAU\tGtelecom\n",
        )
        .unwrap();
        assert_eq!(crate::db::replace_ip_asn(&db, &ranges2).await.unwrap(), 3);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_asn")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 3);
    }

    #[sqlx::test]
    async fn asn_sync_via_cli_downloads_and_stores(pool: MySqlPool) {
        // Full path through sync_asn with a gzipped local file.
        let gz = asn::gz_compress(b"1.0.0.0\t1.0.0.255\t13335\tUS\tCloudflare\n");
        let path = std::env::temp_dir().join("filehost2-asn-test.tsv.gz");
        std::fs::write(&path, &gz).unwrap();
        let count = asn::sync_asn(&db(&pool), Some(path.to_str().unwrap()))
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(count, 1);
        let asn_col: u32 = sqlx::query_scalar("SELECT asn FROM ip_asn LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(asn_col, 13335);
    }
}

// these tests need a DB
// go steal one at the database store
#[cfg(test)]
mod tests {
    use actix_http::Request;
    use actix_multipart::form::MultipartFormConfig;
    use actix_web::{App, Error, dev::ServiceResponse, test, web};
    use sqlx::MySqlPool;

    use crate::handlers;
    use crate::settings::Settings;
    use crate::templates;

    fn test_settings() -> Settings {
        Settings {
            name: "some filehost name idc".to_string(),
            database_url: String::new(),
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
            store_path: format!("/tmp/filehost_test_{}/", uuid::Uuid::new_v4()),
            log_path: None,
            max_ext_len: 7,
            auto_file_ext: false,
            trust_xff: false,
            admin_email: "test@example.com".to_string(),
            clamd_addr: None,
            max_uploads_per_day: None,
            max_bytes_per_day: None,
            max_upload_bytes_per_sec: None,
        }
    }

    async fn index_app(
        settings: Settings,
    ) -> impl actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error> {
        let tmpl = templates::render(&settings);
        test::init_service(
            App::new()
                .service(handlers::index)
                .app_data(web::Data::new(tmpl))
                .app_data(web::Data::new(settings)),
        )
        .await
    }

    async fn full_app(
        settings: Settings,
        pool: MySqlPool,
    ) -> impl actix_web::dev::Service<Request, Response = ServiceResponse, Error = Error> {
        std::fs::create_dir_all(&settings.store_path).unwrap();
        let tmpl = templates::render(&settings);
        test::init_service(
            App::new()
                .service(handlers::index)
                .service(handlers::upload)
                .service(handlers::get_file)
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(settings.clone()))
                .app_data(web::Data::new(tmpl))
                .app_data(
                    MultipartFormConfig::default().total_limit(settings.max_filesize * 1024 * 1024),
                ),
        )
        .await
    }

    #[actix_web::test]
    async fn index_returns_200() {
        let app = index_app(test_settings()).await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn hupl_config_download() {
        let app = index_app(test_settings()).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/?config=hupl").to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("application/json"), "expected JSON, got: {ct}");
    }

    #[sqlx::test]
    async fn unknown_slug_returns_404(pool: MySqlPool) {
        let app = full_app(test_settings(), pool).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/doesntexist").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
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

    fn multipart_request(content: &str) -> actix_http::Request {
        test::TestRequest::post()
            .uri("/")
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            ))
            .set_payload(format!("{}--{BOUNDARY}--\r\n", content.to_string()))
            .to_request()
    }

    #[sqlx::test]
    async fn upload_and_retrieve(pool: MySqlPool) {
        let app = full_app(test_settings(), pool).await;

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
        let url = url.trim();
        assert!(url.starts_with("http://"), "expected URL, got: {url}");

        // Fetch the file back by slug.
        let slug = url.trim_start_matches("http://localhost:8080/");
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            format!("inline; filename=\"{file_name}\"")
        );
        assert_eq!(&test::read_body(resp).await[..], file_content.as_bytes());
    }

    #[sqlx::test]
    async fn html_served_as_plaintext_attachment(pool: MySqlPool) {
        let app = full_app(test_settings(), pool).await;

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
        let slug = url.trim().trim_start_matches("http://localhost:8080/");

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let cd = resp
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            cd.starts_with("attachment"),
            "expected attachment disposition, got: {cd}"
        );

        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            !ct.contains("text/html"),
            "expected non-HTML content type, got: {ct}"
        );
    }

    async fn ban_ip(pool: &MySqlPool, ip: std::net::Ipv4Addr) {
        let ip_int = u32::from(ip);
        sqlx::query(
            "INSERT INTO banned_ipv4_ranges (start_ip, end_ip, banned_timestamp) VALUES (?, ?, NOW())",
        )
        .bind(ip_int)
        .bind(ip_int)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn xff_used_when_trust_xff_enabled(pool: MySqlPool) {
        let banned_ip: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip).await;

        let mut settings = test_settings();
        settings.trust_xff = true;
        let app = full_app(settings, pool).await;

        let req = test::TestRequest::post()
            .uri("/")
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            ))
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .set_payload(format!(
                "{}--{BOUNDARY}--\r\n",
                multipart_body("test.txt", "hello")
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[sqlx::test]
    async fn xff_ignored_when_trust_xff_disabled(pool: MySqlPool) {
        let banned_ip: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
        ban_ip(&pool, banned_ip).await;

        let app = full_app(test_settings(), pool).await;

        let req = test::TestRequest::post()
            .uri("/")
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            ))
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .set_payload(format!(
                "{}--{BOUNDARY}--\r\n",
                multipart_body("test.txt", "hello")
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "XFF should be ignored when trust_xff=false, got: {}",
            resp.status()
        );
    }

    async fn upload_and_get_slug(
        app: &impl actix_web::dev::Service<
            Request,
            Response = ServiceResponse,
            Error = Error,
        >,
        filename: &str,
    ) -> String {
        let req = multipart_request(&multipart_body(filename, "content"));
        let resp = test::call_service(app, req).await;
        assert!(resp.status().is_success(), "upload failed: {}", resp.status());
        let url = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        url.trim()
            .trim_start_matches("http://localhost:8080/")
            .to_string()
    }

    #[sqlx::test]
    async fn download_is_logged(pool: MySqlPool) {
        let app = full_app(test_settings(), pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/{slug}"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test]
    async fn download_logs_xff_ip(pool: MySqlPool) {
        let mut settings = test_settings();
        settings.trust_xff = true;
        let app = full_app(settings, pool.clone()).await;
        let slug = upload_and_get_slug(&app, "test.txt").await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/{slug}"))
                .insert_header(("X-Forwarded-For", "10.0.0.1"))
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());

        let ipv4: Option<u32> = sqlx::query_scalar("SELECT ipv4 FROM accesses LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ipv4, Some(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1))));
    }

    fn php_source_dir() -> String {
        format!("/tmp/filehost_php_test_{}/", uuid::Uuid::new_v4())
    }

    #[sqlx::test]
    async fn import_php_imports_file(pool: MySqlPool) {
        let settings = test_settings();
        std::fs::create_dir_all(&settings.store_path).unwrap();

        let src = php_source_dir();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(format!("{src}abc123.txt"), b"hello").unwrap();

        crate::import::import_php(&pool, &settings, src.clone().into(), None)
            .await
            .unwrap();

        let row: (String, Option<u32>) = sqlx::query_as(
            "SELECT original_name, uploader_ip FROM uploads WHERE slug = 'abc123.txt'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "abc123.txt"); // falls back to slug
        assert_eq!(row.1, None);

        std::fs::remove_dir_all(&src).ok();
    }

    #[sqlx::test]
    async fn import_php_uses_log(pool: MySqlPool) {
        let settings = test_settings();
        std::fs::create_dir_all(&settings.store_path).unwrap();

        let src = php_source_dir();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(format!("{src}abc123.txt"), b"hello").unwrap();

        // Log file lives outside the files dir so it isn't imported as a file.
        let log_path = format!("{src}../uploads.log");
        std::fs::write(
            &log_path,
            "2026-06-06T14:30:45+00:00\t10.0.0.1\t5\t'original name.txt'\tabc123.txt\n",
        )
        .unwrap();

        crate::import::import_php(&pool, &settings, src.clone().into(), Some(log_path.into()))
            .await
            .unwrap();

        let row: (String, Option<u32>) = sqlx::query_as(
            "SELECT original_name, uploader_ip FROM uploads WHERE slug = 'abc123.txt'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "original name.txt");
        assert_eq!(row.1, Some(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1))));

        std::fs::remove_dir_all(&src).ok();
    }

    #[sqlx::test]
    async fn import_php_log_uses_last_occurrence(pool: MySqlPool) {
        let settings = test_settings();
        std::fs::create_dir_all(&settings.store_path).unwrap();

        let src = php_source_dir();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(format!("{src}abc123.txt"), b"hello").unwrap();

        let log_path = format!("{src}../uploads.log");
        std::fs::write(
            &log_path,
            "2026-01-01T00:00:00+00:00\t1.1.1.1\t5\t'old.txt'\tabc123.txt\n\
             2026-06-06T14:30:45+00:00\t10.0.0.1\t5\t'new.txt'\tabc123.txt\n",
        )
        .unwrap();

        crate::import::import_php(&pool, &settings, src.clone().into(), Some(log_path.into()))
            .await
            .unwrap();

        let original_name: String =
            sqlx::query_scalar("SELECT original_name FROM uploads WHERE slug = 'abc123.txt'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(original_name, "new.txt");

        std::fs::remove_dir_all(&src).ok();
    }

    #[sqlx::test]
    async fn import_php_is_idempotent(pool: MySqlPool) {
        let settings = test_settings();
        std::fs::create_dir_all(&settings.store_path).unwrap();

        let src = php_source_dir();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(format!("{src}abc123.txt"), b"hello").unwrap();

        crate::import::import_php(&pool, &settings, src.clone().into(), None)
            .await
            .unwrap();
        crate::import::import_php(&pool, &settings, src.clone().into(), None)
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM uploads WHERE slug = 'abc123.txt'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1, "second import should be skipped");

        std::fs::remove_dir_all(&src).ok();
    }

    #[sqlx::test]
    async fn upload_multiple(pool: MySqlPool) {
        let app = full_app(test_settings(), pool).await;

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
}

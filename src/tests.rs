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
            admin_email: "test@example.com".to_string(),
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
        format!(
            "--{BOUNDARY}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: text/plain\r\n\
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
            format!("attachment; filename=\"{file_name}\"")
        );
        assert_eq!(&test::read_body(resp).await[..], file_content.as_bytes());
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

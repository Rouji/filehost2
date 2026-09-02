use actix_web::web::Bytes;
use tinytemplate::TinyTemplate;

use crate::settings::Settings;

#[derive(Clone)]
pub(crate) struct RenderedTemplates {
    pub(crate) index: Bytes,
    pub(crate) hupl: Bytes,
    pub(crate) sharex: Bytes,
    pub(crate) captcha: Bytes,
    pub(crate) captcha_js: Bytes,
}

pub(crate) fn render(settings: &Settings) -> RenderedTemplates {
    let mut tt = TinyTemplate::new();
    tt.add_template("index", include_str!("../templates/index.html"))
        .expect("Failed to add template");
    tt.add_template("hupl", include_str!("../templates/hupl.json"))
        .expect("Failed to add template");
    tt.add_template("sharex", include_str!("../templates/sharex.sxcu"))
        .expect("Failed to add template");

    RenderedTemplates {
        index: Bytes::from(
            tt.render("index", &settings)
                .expect("Failed to render index template"),
        ),
        hupl: Bytes::from(
            tt.render("hupl", &settings)
                .expect("Failed to render hupl template"),
        ),
        sharex: Bytes::from(
            tt.render("sharex", &settings)
                .expect("Failed to render sharex template"),
        ),
        // no actual template vars in here, but lots of {} that would break templating
        captcha: Bytes::from_static(include_bytes!("../templates/captcha.html")),
        captcha_js: Bytes::from_static(include_bytes!("../templates/captcha.js")),
    }
}

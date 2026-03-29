use tinytemplate::TinyTemplate;

use crate::settings::Settings;

#[derive(Clone)]
pub(crate) struct RenderedTemplates {
    pub(crate) index: String,
    pub(crate) hupl: String,
    pub(crate) sharex: String,
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
        index: tt
            .render("index", &settings)
            .expect("Failed to render index template"),
        hupl: tt
            .render("hupl", &settings)
            .expect("Failed to render hupl template"),
        sharex: tt
            .render("sharex", &settings)
            .expect("Failed to render sharex template"),
    }
}

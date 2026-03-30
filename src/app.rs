use adw::prelude::*;
use gtk::gdk;

use crate::config::APP_ID;
use crate::window::MainWindow;

pub fn build_app() -> adw::Application {
    let app = adw::Application::builder().application_id(APP_ID).build();

    app.connect_startup(|_| {
        load_css();
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::PreferDark);
    });

    app.connect_activate(|app| {
        let window = MainWindow::new(app);
        window.present();
    });

    app
}

fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(include_str!("../data/style.css"));

    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

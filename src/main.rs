mod app;
mod checks;
mod config;
mod models;
mod remediation;
mod report;
mod scanner;
mod widgets;
mod window;

use adw::prelude::ApplicationExtManual;

fn main() -> gtk::glib::ExitCode {
    let app = app::build_app();
    app.run()
}

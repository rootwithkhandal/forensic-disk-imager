// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod acquisition;
mod hasher;
mod output;
mod report;
mod state;
mod error;
mod platform;

fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FORGELENS Disk Imager")
            .with_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Forgelens Disk Imager",
        options,
        Box::new(|cc| Ok(Box::new(app::ForgelensApp::new(cc)))),
    )
}

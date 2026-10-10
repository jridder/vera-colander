#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod model;
mod worker;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sieve Rules")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([820.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "sievectl",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

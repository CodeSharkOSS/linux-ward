use eframe::egui;

mod app;
mod dupes;
mod java;
mod perf;
mod pkg;
mod services;
mod targets;
mod util;

fn main() -> eframe::Result {
    if std::env::args().any(|a| a == "--scan") {
        scan_report();
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Disk Cleaner")
            .with_app_id("diskclean")
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Disk Cleaner",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

/// `diskclean --scan`: print what the GUI would show, without changing anything.
fn scan_report() {
    use util::human;
    for d in util::disks() {
        println!(
            "{:<20} {} free of {}",
            d.mount,
            human(d.avail),
            human(d.total)
        );
    }
    let pm = pkg::Pm::detect();
    println!(
        "\nPackage manager: {}",
        pm.map(|p| p.name()).unwrap_or("none")
    );
    let pkgs = pm
        .map(|p| p.list_installed())
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("package list failed: {e}");
            None
        });
    let sizes = pkgs
        .as_ref()
        .map(|v| v.iter().map(|p| (p.name.clone(), p.size)).collect())
        .unwrap_or_default();
    if let Some(mut v) = pkgs {
        v.sort_by_key(|p| std::cmp::Reverse(p.size));
        println!("{} packages installed; largest:", v.len());
        for p in v.iter().take(5) {
            println!("  {:<40} {:>10}  {:?}", p.name, human(p.size), p.manual);
        }
    }
    println!("\nReclaimable:");
    for t in targets::scan_all(pm, &sizes) {
        let size = t.size.map(human).unwrap_or_else(|| "?".into());
        println!(
            "  {:<28} {:>10} {}",
            t.name,
            size,
            if t.needs_root() { "(root)" } else { "" }
        );
        for d in t.details.iter().take(5) {
            println!("      {d}");
        }
    }
}

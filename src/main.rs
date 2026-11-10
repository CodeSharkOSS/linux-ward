use eframe::egui;

mod app;
mod devclean;
mod dupes;
mod java;
mod perf;
mod pkg;
mod ports;
mod procscan;
mod secscan;
mod services;
mod targets;
mod util;

fn main() -> eframe::Result {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!(
            "diskclean — free disk space and keep a Linux system tidy\n\n\
             USAGE:\n  diskclean            open the window\n  diskclean --scan     print what could be reclaimed, change nothing\n  \
             diskclean --clean [--dry-run]\n                       run the safe, pre-selected cleanups that need no password\n                       (Trash, crash-free caches...); --dry-run only lists them\n\n\
             Folders listed in ~/.config/diskclean/exclude (one per line) are skipped by every scan.\n\
             Actions are logged to ~/.local/state/diskclean/actions.log"
        );
        return Ok(());
    }
    // Internal: the suspect-process scan, run as root by the window via pkexec.
    if std::env::args().any(|a| a == "--proc-scan") {
        let args: Vec<String> = std::env::args().collect();
        if let Some(h) = args
            .iter()
            .position(|a| a == "--home")
            .and_then(|i| args.get(i + 1))
        {
            // SAFETY: nothing else is running yet, so no other thread can be reading the environment.
            unsafe { std::env::set_var("HOME", h) };
        }
        print!("{}", procscan::encode(&procscan::scan()));
        return Ok(());
    }
    if std::env::args().any(|a| a == "--clean") {
        clean_cli(std::env::args().any(|a| a == "--dry-run"));
        return Ok(());
    }
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

/// `diskclean --clean [--dry-run]`: run the targets that are pre-selected as safe and need no
/// administrator rights. Nothing is deleted with --dry-run.
fn clean_cli(dry_run: bool) {
    use util::human;
    let pm = pkg::Pm::detect();
    let targets: Vec<targets::Target> = targets::scan_all(pm, &Default::default())
        .into_iter()
        .filter(|t| t.selected && !t.needs_root())
        .collect();
    if targets.is_empty() {
        println!("Nothing to clean.");
        return;
    }
    for t in &targets {
        println!(
            "{} {:<24} {}",
            if dry_run { "would clean" } else { "cleaning" },
            t.name,
            t.size.map(human).unwrap_or_else(|| "?".into())
        );
    }
    if dry_run {
        return;
    }
    targets::execute(&targets, &mut |l| {
        util::log_action(&l);
        println!("{l}");
    });
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

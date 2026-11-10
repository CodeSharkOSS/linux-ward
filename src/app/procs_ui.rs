//! The Processes tab: running programs ranked by how unusual they look.

use super::*;
use crate::procscan::{self, Level, ScanResult, Suspect};
use crate::targets::Action;

impl App {
    fn start_proc_scan(&mut self) {
        self.procs_scanning = true;
        let n = self.notifier();
        std::thread::spawn(move || n.send(Msg::Procs(Box::new(procscan::scan()))));
    }

    pub(super) fn apply_procs(&mut self, r: ScanResult) {
        self.procs = r.suspects;
        self.procs_inspected = r.inspected;
        self.procs_opaque = r.opaque;
        self.procs_scanning = false;
        self.procs_scanned = true;
    }

    /// Check one executable with ClamAV, if it is installed.
    fn clam_scan(&mut self, path: String) {
        let (tool, args): (&str, Vec<String>) = if util::which("clamdscan") {
            (
                "clamdscan",
                vec!["--fdpass".into(), "--no-summary".into(), path.clone()],
            )
        } else if util::which("clamscan") {
            ("clamscan", vec!["--no-summary".into(), path.clone()])
        } else {
            self.log
                .push("✘ ClamAV isn't installed (clamscan / clamdscan not found)".into());
            return;
        };
        self.busy = Some("Scanning with ClamAV…".into());
        let n = self.notifier();
        std::thread::spawn(move || {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = util::run(tool, &a);
            let verdict = out.combined();
            n.send(Msg::Log(if out.ok {
                format!("✔ ClamAV: {}", verdict.lines().next().unwrap_or("OK"))
            } else {
                format!(
                    "✘ ClamAV: {}",
                    verdict
                        .lines()
                        .next()
                        .unwrap_or("scan failed or found something")
                )
            }));
            n.send(Msg::Done { refresh: false });
        });
    }

    pub(super) fn processes_tab(&mut self, ui: &mut egui::Ui) {
        if !self.procs_scanned && !self.procs_scanning {
            self.start_proc_scan();
        }
        let mut rescan = false;
        let mut stop: Option<Suspect> = None;
        let mut clam: Option<String> = None;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if self.procs_scanning {
                ui.spinner();
                ui.label(RichText::new("inspecting processes…").weak());
            } else if ui.button("⟳ Scan again").clicked() {
                rescan = true;
            }
            if self.procs_scanned {
                ui.label(
                    RichText::new(format!(
                        "{} processes inspected · {} to review",
                        self.procs_inspected,
                        self.procs.len()
                    ))
                    .weak(),
                );
            }
        });
        ui.label(
            RichText::new("Looks for signs often seen in malware: programs running from /tmp or a deleted file, names imitating system services, shells wired to the network, injected libraries, crypto-miners, hidden processes and suspicious startup entries. These are hints, not verdicts: many legitimate tools trip a check, so read the reasons before acting. Nothing is stopped automatically.")
                .weak()
                .size(12.0),
        );
        if self.procs_opaque > 0 {
            ui.label(RichText::new(format!("ℹ {} processes belong to other users and can't be fully inspected without administrator rights.", self.procs_opaque)).weak().size(12.0));
        }
        ui.separator();

        if self.procs_scanned && self.procs.is_empty() {
            ui.add_space(12.0);
            ui.label(
                RichText::new("✔ Nothing unusual found.")
                    .color(Color32::from_rgb(90, 190, 110))
                    .strong(),
            );
            ui.label(RichText::new("This doesn't prove the system is clean: rootkits and well-made malware can hide from these checks. Pair it with a scanner such as ClamAV.").weak());
        }

        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                for (i, s) in self.procs.iter().enumerate() {
                    let (label, color) = match s.level() {
                        Level::High => ("HIGH", Color32::from_rgb(230, 90, 80)),
                        Level::Medium => ("MEDIUM", Color32::from_rgb(230, 170, 60)),
                        Level::Low => ("LOW", Color32::GRAY),
                    };
                    let who = match s.pid {
                        Some(p) => format!("{}  [pid {p}]", s.name),
                        None => s.name.clone(),
                    };
                    let head = egui::RichText::new(format!("{label}  {who}"))
                        .color(color)
                        .strong();
                    egui::CollapsingHeader::new(head)
                        .id_salt(("proc", i))
                        .default_open(s.level() == Level::High)
                        .show(ui, |ui| {
                            for r in &s.reasons {
                                ui.label(format!("• {r}"));
                            }
                            ui.add_space(4.0);
                            if !s.exe.is_empty() {
                                ui.label(
                                    RichText::new(format!("Program: {}", s.exe))
                                        .monospace()
                                        .size(12.0),
                                );
                            }
                            if !s.user.is_empty() {
                                ui.label(
                                    RichText::new(format!("Run by: {}", s.user))
                                        .weak()
                                        .size(12.0),
                                );
                            }
                            if !s.cmdline.is_empty() {
                                ui.label(
                                    RichText::new(format!("Command: {}", s.cmdline))
                                        .monospace()
                                        .size(11.5)
                                        .weak(),
                                );
                            }
                            ui.horizontal(|ui| {
                                let file = s.exe.strip_suffix(" (deleted)").unwrap_or(&s.exe);
                                let real = std::path::Path::new(file).is_absolute()
                                    && std::path::Path::new(file).exists();
                                if real
                                    && ui.small_button("Open folder").clicked()
                                    && let Some(parent) = std::path::Path::new(file).parent()
                                {
                                    util::open(parent);
                                }
                                if real
                                    && ui
                                        .small_button("Scan file with ClamAV")
                                        .on_hover_text("Needs ClamAV (clamscan / clamdscan)")
                                        .clicked()
                                {
                                    clam = Some(file.to_string());
                                }
                                if ui.small_button("Copy details").clicked() {
                                    ui.ctx().copy_text(format!(
                                        "{who}\n{}\n{}\n{}",
                                        s.reasons.join("\n"),
                                        s.exe,
                                        s.cmdline
                                    ));
                                }
                                if s.mine
                                    && s.pid.is_some()
                                    && ui
                                        .add_enabled(
                                            self.busy.is_none(),
                                            egui::Button::new("Stop…").small(),
                                        )
                                        .on_hover_text("Ask the process to exit (SIGTERM)")
                                        .clicked()
                                {
                                    stop = Some(s.clone());
                                }
                            });
                        });
                }
            });

        if rescan {
            self.start_proc_scan();
        }
        if let Some(p) = clam {
            self.clam_scan(p);
        }
        if let Some(s) = stop
            && let Some(pid) = s.pid
        {
            self.confirm = Some(Confirm::Perf {
                title: format!("Stop {} (pid {pid})", s.name),
                note: Some("Sends SIGTERM so the program can shut down. If it is malware, stopping it is not enough: find and remove what starts it (see its reasons) and change any passwords it could have seen.".into()),
                actions: vec![Action::User(vec![vec!["kill".into(), pid.to_string()]])],
            });
        }
    }
}

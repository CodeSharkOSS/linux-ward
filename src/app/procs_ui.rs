//! The Processes tab: running programs ranked by how unusual they look.

use super::*;
use crate::procscan::{self, Level, ScanResult, Suspect};
use crate::targets::Action;

impl App {
    /// Scan as the current user, or (elevated) as root through pkexec so that processes of
    /// other users can be inspected too. The root run is this same program in `--proc-scan` mode.
    fn start_proc_scan(&mut self, elevated: bool) {
        self.procs_scanning = true;
        self.procs_elevated = elevated;
        let n = self.notifier();
        if !elevated {
            std::thread::spawn(move || n.send(Msg::Procs(Box::new(procscan::scan()))));
            return;
        }
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "diskclean".into());
        let home = util::home().display().to_string();
        std::thread::spawn(move || {
            let out =
                util::run_privileged(&[vec![exe, "--proc-scan".into(), "--home".into(), home]]);
            match procscan::decode(&out.stdout) {
                Some(r) => n.send(Msg::Procs(Box::new(r))),
                None => {
                    let why = if out.stderr.trim().is_empty() {
                        out.combined()
                    } else {
                        out.stderr.clone()
                    };
                    n.send(Msg::Log(format!(
                        "✘ Administrator scan failed: {}",
                        why.lines().next().unwrap_or("no result")
                    )));
                    // Fall back to what the current user can see.
                    n.send(Msg::Procs(Box::new(procscan::scan())));
                }
            }
        });
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
            self.start_proc_scan(false);
        }
        let mut rescan = false;
        let mut elevate = false;
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
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("ℹ {} processes belong to other users and can't be fully inspected without administrator rights.", self.procs_opaque)).weak().size(12.0));
                if !self.procs_scanning && ui.small_button("🔒 Scan all processes…").on_hover_text("Asks for your password once and runs this scan as administrator. Read-only: nothing is changed.").clicked() {
                    elevate = true;
                }
            });
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
                                if s.pid.is_some()
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

        if elevate {
            self.start_proc_scan(true);
        } else if rescan {
            // Scanning again keeps the access level of the last scan.
            self.start_proc_scan(self.procs_elevated);
        }
        if let Some(p) = clam {
            self.clam_scan(p);
        }
        if let Some(s) = stop
            && let Some(pid) = s.pid
        {
            let kill = vec!["kill".to_string(), pid.to_string()];
            // SAFETY: geteuid has no preconditions.
            let own_uid = unsafe { libc::geteuid() };
            self.confirm = Some(Confirm::Perf {
                title: format!("Stop {} (pid {pid})", s.name),
                note: Some("Sends SIGTERM so the program can shut down. If it is malware, stopping it is not enough: find and remove what starts it (see its reasons) and change any passwords it could have seen.".into()),
                actions: vec![if s.uid == own_uid {
                    Action::User(vec![kill])
                } else {
                    // Another user's process (or an unknown owner): needs administrator rights.
                    Action::Root(vec![kill])
                }],
            });
        }
    }
}

//! The Processes tab: running programs ranked by how unusual they look.

use super::*;
use crate::clam;
use crate::procscan::{self, Level, ScanResult, Suspect};

enum ClamJob {
    Folder(String),
    Files(Vec<String>, String),
}
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
        self.procs_exes = r.exes;
        self.procs_scanning = false;
        self.procs_scanned = true;
    }

    /// Run a ClamAV scan in the background; the result lands in the panel on this tab.
    fn start_clam(&mut self, job: ClamJob) {
        self.clam_scanning = true;
        self.clam_result = None;
        let n = self.notifier();
        std::thread::spawn(move || {
            let out = match job {
                ClamJob::Folder(dir) => clam::scan_folder(&dir),
                ClamJob::Files(paths, label) => clam::scan_files(&paths, &label),
            };
            n.send(Msg::Log(match (&out.error, out.infected.len()) {
                (Some(e), _) => format!("✘ ClamAV: {e}"),
                (None, 0) => format!("✔ ClamAV found no threats in {}", out.target),
                (None, k) => format!("!! ClamAV found {k} infected file(s) in {}", out.target),
            }));
            n.send(Msg::Clam(Box::new(out)));
        });
    }

    /// The always-visible malware scanner panel: scan what is running, or any folder.
    fn clam_panel(&mut self, ui: &mut egui::Ui) {
        let mut job: Option<ClamJob> = None;
        let mut trash: Option<Vec<PathBuf>> = None;
        egui::CollapsingHeader::new(RichText::new("🛡 Malware scan (ClamAV)").strong()).default_open(true).show(ui, |ui| {
            let installed = util::which("clamscan") || util::which("clamdscan");
            if !installed {
                ui.colored_label(Color32::from_rgb(230, 170, 60), "ClamAV isn't installed, so files can't be scanned for known malware yet.");
                ui.label(RichText::new(format!("Install it with: {}", clam::install_hint(self.pm))).monospace().size(12.0));
                return;
            }
            ui.label(RichText::new("ClamAV recognises known viruses and malware by signature. This complements the behaviour checks below: it can't spot brand-new threats, but it will catch common ones.").weak().size(12.0));
            ui.horizontal_wrapped(|ui| {
                let idle = !self.clam_scanning && self.busy.is_none();
                if ui.add_enabled(idle, egui::Button::new("Scan running programs")).on_hover_text("Scans the program file behind every process that is running now").clicked() {
                    // From the last process scan: it covers every user's programs after an administrator scan.
                    let exes = if self.procs_exes.is_empty() {
                        procscan::running_executables()
                    } else {
                        self.procs_exes.clone()
                    };
                    let label = format!("{} running programs", exes.len());
                    job = Some(ClamJob::Files(exes, label));
                }
                ui.separator();
                ui.label("Folder");
                ui.add(egui::TextEdit::singleline(&mut self.clam_dir).desired_width(260.0));
                if ui.add_enabled(idle && !self.clam_dir.trim().is_empty(), egui::Button::new("Scan folder")).clicked() {
                    job = Some(ClamJob::Folder(self.clam_dir.trim().to_string()));
                }
                if self.procs_opaque > 0 && !self.clam_scanning {
                    ui.label(RichText::new(format!("covers your own programs only: use \"Scan all processes…\" below first to include {} other processes", self.procs_opaque)).weak().size(12.0));
                }
                if self.clam_scanning {
                    ui.spinner();
                    ui.label(RichText::new("scanning… ClamAV loads its signatures first (~15 s), and a large folder can take several minutes").weak());
                }
            });
            if let Some(r) = &self.clam_result {
                ui.add_space(4.0);
                if let Some(e) = &r.error {
                    ui.colored_label(Color32::from_rgb(220, 90, 80), format!("✘ Scan of {} failed: {e}", r.target));
                } else if r.infected.is_empty() {
                    ui.label(RichText::new(format!("✔ No threats found in {}", r.target)).color(Color32::from_rgb(90, 190, 110)).strong());
                } else {
                    ui.colored_label(Color32::from_rgb(230, 90, 80), format!("⚠ {} threat(s) found in {}", r.infected.len(), r.target));
                    for (path, sig) in &r.infected {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(sig).color(Color32::from_rgb(230, 90, 80)).strong());
                            ui.label(RichText::new(path).monospace().size(12.0));
                            if ui.small_button("Open").clicked()
                                && let Some(parent) = std::path::Path::new(path).parent()
                            {
                                util::open(parent);
                            }
                            if ui.small_button("Move to Trash…").clicked() {
                                trash = Some(vec![PathBuf::from(path)]);
                            }
                        });
                    }
                }
                let how = match r.tool {
                    Some(clam::Tool::Daemon) => "via clamd",
                    Some(clam::Tool::Standalone) => "via clamscan",
                    None => "",
                };
                let line = r.summary.join(" · ");
                if !line.is_empty() || !how.is_empty() {
                    ui.label(RichText::new(format!("{line}  {how}")).weak().size(12.0));
                }
            }
        });
        if let Some(j) = job {
            self.start_clam(j);
        }
        if let Some(paths) = trash {
            self.confirm = Some(Confirm::Files {
                size: 0,
                paths,
                permanent: false,
            });
        }
        ui.separator();
    }

    pub(super) fn processes_tab(&mut self, ui: &mut egui::Ui) {
        if !self.procs_scanned && !self.procs_scanning {
            self.start_proc_scan(false);
        }
        let mut rescan = false;
        let mut elevate = false;
        let mut stop: Option<Suspect> = None;
        let mut clam_one: Option<String> = None;

        ui.add_space(6.0);
        self.clam_panel(ui);
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
            ui.horizontal_wrapped(|ui| {
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
            ui.label(RichText::new("This doesn't prove the system is clean: rootkits and well-made malware can hide from these checks. Use the malware scan above as a second opinion.").weak());
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
                                    clam_one = Some(file.to_string());
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
        if let Some(p) = clam_one {
            let label = format!("file {p}");
            self.start_clam(ClamJob::Files(vec![p], label));
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

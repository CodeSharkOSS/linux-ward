//! The Projects tab (build artifacts, stale toolchains, git housekeeping) and the Ports tab.

use super::*;
use crate::devclean::{self, Artifact, Repo, Toolchain};
use crate::ports::{self, Listener};
use crate::targets::Action;

pub(super) struct ArtEntry {
    pub a: Artifact,
    pub sel: bool,
}

pub(super) struct TcEntry {
    pub t: Toolchain,
    pub sel: bool,
}

pub(super) struct RepoEntry {
    pub r: Repo,
    pub gc: bool,
    pub branches: Vec<(String, bool)>,
}

impl RepoEntry {
    pub(super) fn new(r: Repo) -> Self {
        let branches = r.merged.iter().map(|b| (b.clone(), false)).collect();
        RepoEntry {
            r,
            gc: false,
            branches,
        }
    }
}

fn toolchain_present(t: &Toolchain) -> bool {
    if t.removal.dirs.is_empty() {
        // rustup toolchains are removed by command: check the folder it manages.
        t.removal
            .cmds
            .first()
            .and_then(|c| c.last())
            .is_some_and(|n| util::home().join(".rustup/toolchains").join(n).exists())
    } else {
        t.removal.dirs.iter().any(|p| p.exists())
    }
}

impl App {
    /// Called after any deletion so removed things drop out of the lists.
    pub(super) fn dev_prune(&mut self) {
        self.dev_art.retain(|e| e.a.path.exists());
        self.dev_tc.retain(|e| toolchain_present(&e.t));
    }

    fn start_dev_scan(&mut self) {
        self.dev_scanning = true;
        let root = PathBuf::from(self.dev_root.trim());
        let n = self.notifier();
        std::thread::spawn(move || {
            n.send(Msg::DevArtifacts(devclean::scan_artifacts(&root)));
            n.send(Msg::DevToolchains(devclean::toolchains()));
            let repos: Vec<Repo> = devclean::repos_under(&root)
                .iter()
                .map(|p| devclean::inspect_repo(p))
                .collect();
            n.send(Msg::DevRepos(repos));
        });
    }

    pub(super) fn projects_tab(&mut self, ui: &mut egui::Ui) {
        let mut scan = false;
        let mut delete = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Code folder");
            ui.add(egui::TextEdit::singleline(&mut self.dev_root).desired_width(260.0));
            if self.dev_scanning {
                ui.spinner();
                ui.label(RichText::new("scanning…").weak());
            } else if ui.button("Scan").clicked() {
                scan = true;
            }
            ui.label(RichText::new("Finds build output, old toolchains and git housekeeping. Folders listed in ~/.config/diskclean/exclude are skipped.").weak().size(12.0));
        });

        let art_sel: u64 = self
            .dev_art
            .iter()
            .filter(|e| e.sel)
            .map(|e| e.a.size)
            .sum();
        let n_sel = self.dev_art.iter().filter(|e| e.sel).count()
            + self.dev_tc.iter().filter(|e| e.sel).count()
            + self
                .dev_repos
                .iter()
                .map(|r| usize::from(r.gc) + r.branches.iter().filter(|b| b.1).count())
                .sum::<usize>();
        let tc_sel: u64 = self.dev_tc.iter().filter(|e| e.sel).map(|e| e.t.size).sum();
        ui.horizontal(|ui| {
            ui.label(format!(
                "{n_sel} selected · {} to free",
                human(art_sel + tc_sel)
            ));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        n_sel > 0 && self.busy.is_none(),
                        egui::Button::new("Delete / run selected…"),
                    )
                    .clicked()
                {
                    delete = true;
                }
            });
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let total: u64 = self.dev_art.iter().map(|e| e.a.size).sum();
            egui::CollapsingHeader::new(RichText::new(format!("🏗 Build artifacts ({} · {})", self.dev_art.len(), human(total))).strong())
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(RichText::new("Generated output that your tools rebuild (target/, node_modules/, build/, .venv/…). Deleted folders are not recoverable, but nothing in them is source code.").weak().size(12.0));
                    ui.horizontal(|ui| {
                        ui.label("Select untouched for over");
                        ui.add(egui::DragValue::new(&mut self.dev_idle_days).range(0..=3650).suffix(" days"));
                        if ui.small_button("Select").clicked() {
                            for e in &mut self.dev_art {
                                e.sel = e.a.idle_days >= self.dev_idle_days;
                            }
                        }
                        if ui.small_button("Clear").clicked() {
                            for e in &mut self.dev_art {
                                e.sel = false;
                            }
                        }
                    });
                    for e in &mut self.dev_art {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut e.sel, "");
                            ui.label(RichText::new(human(e.a.size)).strong());
                            ui.label(RichText::new(e.a.kind).color(Color32::from_rgb(110, 170, 230)).small());
                            ui.label(RichText::new(e.a.path.display().to_string()).monospace().size(12.0)).on_hover_text(e.a.path.display().to_string());
                            ui.label(RichText::new(format!("{} days idle", e.a.idle_days)).weak().small());
                        });
                    }
                });

            let tc_total: u64 = self.dev_tc.iter().map(|e| e.t.size).sum();
            egui::CollapsingHeader::new(RichText::new(format!("🧰 Language toolchains ({} · {})", self.dev_tc.len(), human(tc_total))).strong())
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(RichText::new("Old versions of rustup, nvm, SDKMAN and pyenv toolchains; IDE settings, plugins and caches left behind by earlier JetBrains / Android Studio versions; and Android SDK platforms, build-tools, NDKs, system images and emulator devices. The newest version, or one in use, is protected. Old IDE folders hold that version's own settings: the newest version imported them when it first ran.").weak().size(12.0));
                    for e in &mut self.dev_tc {
                        ui.horizontal(|ui| {
                            ui.add_enabled(!e.t.current, egui::Checkbox::without_text(&mut e.sel)).on_disabled_hover_text("In use / default");
                            ui.label(RichText::new(human(e.t.size)).strong());
                            ui.label(RichText::new(e.t.kind).color(Color32::from_rgb(110, 170, 230)).small());
                            ui.label(&e.t.name);
                            if e.t.current {
                                ui.label(RichText::new("in use").color(Color32::from_rgb(90, 190, 110)).small());
                            }
                        });
                    }
                });

            egui::CollapsingHeader::new(RichText::new(format!("🌿 Git repositories ({})", self.dev_repos.len())).strong())
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(RichText::new("`git gc` compacts a repository. Merged branches are removed with `git branch -d`, which refuses anything not fully merged.").weak().size(12.0));
                    for r in &mut self.dev_repos {
                        egui::CollapsingHeader::new(format!("{}  ({} .git · {} merged branches)", r.r.path.display(), human(r.r.git_size), r.branches.len()))
                            .id_salt(&r.r.path)
                            .show(ui, |ui| {
                                ui.checkbox(&mut r.gc, "Compact (git gc --prune=now)");
                                for (b, sel) in &mut r.branches {
                                    ui.checkbox(sel, format!("Delete merged branch {b}"));
                                }
                                if r.branches.is_empty() {
                                    ui.label(RichText::new(format!("No branches merged into {}.", r.r.default_branch)).weak());
                                }
                            });
                    }
                });
        });

        if scan {
            self.start_dev_scan();
        }
        if delete {
            let mut dirs: Vec<PathBuf> = self
                .dev_art
                .iter()
                .filter(|e| e.sel)
                .map(|e| e.a.path.clone())
                .collect();
            let mut cmds: Vec<Vec<String>> = Vec::new();
            for e in self.dev_tc.iter().filter(|e| e.sel && !e.t.current) {
                dirs.extend(e.t.removal.dirs.iter().cloned());
                cmds.extend(e.t.removal.cmds.iter().cloned());
            }
            for r in &self.dev_repos {
                if r.gc {
                    cmds.push(devclean::gc_cmd(&r.r.path));
                }
                for (b, _) in r.branches.iter().filter(|b| b.1) {
                    cmds.push(devclean::delete_branch_cmd(&r.r.path, b));
                }
            }
            let mut actions = Vec::new();
            if !dirs.is_empty() {
                actions.push(Action::RemoveDirs(dirs));
            }
            if !cmds.is_empty() {
                actions.push(Action::User(cmds));
            }
            self.confirm = Some(Confirm::Perf {
                title: "Delete developer files".into(),
                note: Some("Folders are deleted permanently (they are regenerable build output or old toolchains). Check the list below.".into()),
                actions,
            });
        }
    }

    // ----- Ports ------------------------------------------------------------------------------

    fn start_ports_scan(&mut self) {
        self.ports_loading = true;
        let n = self.notifier();
        std::thread::spawn(move || n.send(Msg::Ports(ports::listeners())));
    }

    pub(super) fn ports_tab(&mut self, ui: &mut egui::Ui) {
        if !self.ports_loaded && !self.ports_loading {
            self.start_ports_scan();
        }
        let mut reload = false;
        let mut stop: Option<Listener> = None;
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if self.ports_loading {
                ui.spinner();
            } else if ui.button("⟳ Refresh").clicked() {
                reload = true;
            }
            let exposed = self.ports.iter().filter(|l| l.exposed).count();
            ui.label(
                RichText::new(format!(
                    "{} listening · {} reachable from the network",
                    self.ports.len(),
                    exposed
                ))
                .weak(),
            );
        });
        ui.label(RichText::new("TCP ports something is listening on. Leftover dev servers and databases show up here; \"network\" means it accepts connections from other machines, not just this one.").weak().size(12.0));
        if let Some(e) = &self.ports_error {
            ui.colored_label(Color32::from_rgb(220, 90, 80), e);
        }
        ui.separator();
        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(80.0))
            .column(Column::exact(70.0))
            .column(Column::initial(170.0).at_least(80.0))
            .column(Column::remainder().clip(true))
            .column(Column::exact(80.0))
            .header(24.0, |mut h| {
                for t in ["Reach", "Port", "Address", "Process", ""] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(24.0, self.ports.len(), |mut row| {
                    let l = &self.ports[row.index()];
                    row.col(|ui| {
                        let (t, c) = if l.exposed {
                            ("network", Color32::from_rgb(230, 170, 60))
                        } else {
                            ("local", Color32::from_rgb(90, 190, 110))
                        };
                        ui.label(RichText::new(t).color(c));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(l.port.to_string()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&l.addr).monospace().size(12.0));
                    });
                    row.col(|ui| {
                        let name = if l.process.is_empty() {
                            "(another user or system)".to_string()
                        } else {
                            l.process.clone()
                        };
                        ui.label(match l.pid {
                            Some(p) => format!("{name}  [pid {p}]"),
                            None => name,
                        });
                    });
                    row.col(|ui| {
                        if l.mine
                            && l.pid.is_some()
                            && ui
                                .small_button("Stop…")
                                .on_hover_text("Ask the process to exit (SIGTERM)")
                                .clicked()
                        {
                            stop = Some(l.clone());
                        }
                    });
                });
            });
        if reload {
            self.start_ports_scan();
        }
        if let Some(l) = stop
            && let Some(pid) = l.pid
        {
            self.confirm = Some(Confirm::Perf {
                title: format!("Stop {} (port {})", l.process, l.port),
                note: Some("Sends SIGTERM so the program can shut down cleanly. Unsaved work in it may be lost.".into()),
                actions: vec![Action::User(vec![vec!["kill".into(), pid.to_string()]])],
            });
        }
    }
}

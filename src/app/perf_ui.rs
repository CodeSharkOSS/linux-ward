//! The Performance tab: live load, boot analysis, startup items, kernels,
//! config leftovers, package health and tuning checks.

use std::time::Duration;

use super::*;
use crate::perf::{self, LeftKind, Level, Pressure, Proc};
use crate::targets::Action;

pub(super) const GREEN: Color32 = Color32::from_rgb(90, 190, 110);
pub(super) const AMBER: Color32 = Color32::from_rgb(230, 170, 60);
pub(super) const BLUE: Color32 = Color32::from_rgb(90, 160, 230);
pub(super) const RED: Color32 = Color32::from_rgb(220, 90, 80);

impl App {
    pub(super) fn load_perf(&mut self) {
        if self.perf_loading {
            self.perf_reload_pending = true;
            return;
        }
        self.perf_loading = true;
        let (n, pm) = (self.notifier(), self.pm);
        std::thread::spawn(move || n.send(Msg::Perf(Box::new(perf::load_snapshot(pm)))));
    }

    fn poll_live(&mut self) {
        let due = self
            .live_at
            .is_none_or(|t| t.elapsed() > Duration::from_secs(3));
        if due && !self.live_pending {
            self.live_pending = true;
            let n = self.notifier();
            std::thread::spawn(move || n.send(Msg::Live(Box::new(perf::live_snapshot()))));
        }
        // Keep the tab ticking while it is visible.
        self.ctx.request_repaint_after(Duration::from_secs(1));
    }

    pub(super) fn start_perf_action(&mut self, title: String, actions: Vec<Action>) {
        self.busy = Some(format!("{title}…"));
        // The reboot reminder only makes sense for system tuning, not for deleting build folders.
        let reboot_hint = self.tab == Tab::Performance;
        let n = self.notifier();
        std::thread::spawn(move || {
            let targets: Vec<Target> = actions
                .into_iter()
                .map(|action| Target {
                    name: title.clone(),
                    description: String::new(),
                    size: None,
                    details: vec![],
                    action,
                    selected: true,
                    group: Group::System,
                })
                .collect();
            // Root commands from all actions are batched into a single password prompt.
            targets::execute(&targets, &mut |l| n.send(Msg::Log(l)));
            n.send(Msg::Log(if reboot_hint {
                "Done. Some changes (kernel, tuned, fstab, guest tools) take full effect after a reboot.".into()
            } else {
                "Done.".into()
            }));
            n.send(Msg::Done { refresh: true });
            n.send(Msg::ReloadPerf);
        });
    }

    fn start_health(&mut self) {
        let Some(pm) = self.pm else { return };
        self.health.clear();
        self.health_running = true;
        let n = self.notifier();
        std::thread::spawn(move || {
            for c in perf::health_checks(pm) {
                n.send(Msg::Health(Box::new(perf::run_check(&c))));
            }
            n.send(Msg::HealthDone);
        });
    }

    fn start_diff(&mut self, l: perf::Leftover) {
        let n = self.notifier();
        std::thread::spawn(move || {
            let text = perf::leftover_diff(&l);
            n.send(Msg::Diff(l.path, text));
        });
    }

    pub(super) fn performance_tab(&mut self, ui: &mut egui::Ui) {
        if self.perf.is_none() && !self.perf_loading {
            self.load_perf();
        }
        self.poll_live();

        let mut confirm: Option<Confirm> = None;
        let mut run_health = false;
        let mut reload = false;
        let mut diff_req: Option<perf::Leftover> = None;
        let mut autostart_toggle: Option<(perf::Autostart, bool)> = None;
        let idle = self.busy.is_none();
        // Take the snapshot out so the closures below can freely mutate other fields of `self`.
        let snap = self.perf.take();

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Find out what is slowing this system down, and fix it. Nothing changes until you confirm.").weak());
            if self.perf_loading {
                ui.spinner();
            } else if ui.small_button("⟳ Re-check").clicked() {
                reload = true;
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            // ---- recommended fixes (the main event) ---------------------------------
            if let Some(s) = &snap {
                let mut recs: Vec<perf::Rec> = s.recs.clone();
                for h in self.health.iter().filter(|h| !h.ok) {
                    if let Some(f) = &h.fix {
                        recs.push(perf::Rec { tag: "Health", title: f.label.clone(), detail: format!("{}: {}", h.title, h.desc), safe: false, actions: vec![f.action.clone()] });
                    }
                }
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.heading("✅ Recommended fixes");
                        if let Some(vm) = &s.vm {
                            ui.label(RichText::new(format!("· VM guest detected ({vm}) – VM-specific fixes included")).weak());
                        }
                    });
                    if recs.is_empty() {
                        ui.label("Nothing found that needs fixing. 🎉");
                    }
                    for r in &recs {
                        let mut on = self.rec_sel.get(&r.title).copied().unwrap_or(r.safe);
                        ui.horizontal_wrapped(|ui| {
                            if ui.checkbox(&mut on, "").changed() {
                                self.rec_sel.insert(r.title.clone(), on);
                            }
                            ui.label(RichText::new(r.tag).small().color(if r.tag == "VM" { BLUE } else { Color32::GRAY }));
                            ui.label(RichText::new(&r.title).strong());
                            if !r.safe {
                                ui.label(RichText::new("review").small().color(AMBER));
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.add_space(26.0);
                            ui.add(egui::Label::new(RichText::new(&r.detail).weak().size(12.0)).wrap());
                        });
                    }
                    let chosen: Vec<&perf::Rec> =
                        recs.iter().filter(|r| self.rec_sel.get(&r.title).copied().unwrap_or(r.safe)).collect();
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let label = format!("⚡ Apply {} selected fix(es)…", chosen.len());
                        if ui.add_enabled(idle && !chosen.is_empty(), egui::Button::new(RichText::new(label).strong())).clicked() {
                            let review: Vec<&str> = chosen.iter().filter(|r| !r.safe).map(|r| r.title.as_str()).collect();
                            confirm = Some(Confirm::Perf {
                                title: format!("Apply {} fix(es)", chosen.len()),
                                note: Some(format!(
                                    "{}{}",
                                    chosen.iter().map(|r| format!("• {}", r.title)).collect::<Vec<_>>().join("\n"),
                                    if review.is_empty() { String::new() } else { format!("\n\nThese change things you may use: {}", review.join("; ")) }
                                )),
                                actions: chosen.iter().flat_map(|r| r.actions.clone()).collect(),
                            });
                        }
                        if ui.small_button("Recommended only").clicked() {
                            self.rec_sel = recs.iter().map(|r| (r.title.clone(), r.safe)).collect();
                        }
                        if ui.small_button("Select all").clicked() {
                            self.rec_sel = recs.iter().map(|r| (r.title.clone(), true)).collect();
                        }
                        if ui.small_button("None").clicked() {
                            self.rec_sel = recs.iter().map(|r| (r.title.clone(), false)).collect();
                        }
                    });
                });
                for f in &s.findings {
                    egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.0, AMBER)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(format!("⚠ {} – can't be fixed from inside this machine", f.title)).strong().color(AMBER));
                        ui.label(RichText::new(&f.detail).size(12.0));
                    });
                }
                ui.add_space(6.0);
                if !s.undos.is_empty() {
                    egui::CollapsingHeader::new(RichText::new(format!("↩ Changes made by linuxward ({}) – undo", s.undos.len())).strong()).id_salt("perf-undo")
                        .default_open(false)
                        .show(ui, |ui| {
                            for u in &s.undos {
                                ui.horizontal(|ui| {
                                    if ui.add_enabled(idle, egui::Button::new("Undo…").small()).clicked() {
                                        confirm = Some(Confirm::Perf {
                                            title: format!("Undo: {}", u.title),
                                            note: Some(u.detail.clone()),
                                            actions: u.actions.clone(),
                                        });
                                    }
                                    ui.label(RichText::new(&u.title).strong());
                                });
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    ui.add(egui::Label::new(RichText::new(&u.detail).weak().size(12.0)).wrap());
                                });
                            }
                        });
                    ui.add_space(6.0);
                }
            }

            // ---- live load ---------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new("📊 Live load – what is slow right now").strong())
                .default_open(true)
                .show(ui, |ui| match &self.live {
                    None => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Measuring…");
                        });
                    }
                    Some(l) => {
                        for line in &l.verdict {
                            ui.label(RichText::new(format!("➤ {line}")).strong());
                        }
                        ui.add_space(4.0);
                        egui::Grid::new("pressure").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                            for (label, p) in [("CPU", &l.cpu), ("Disk I/O", &l.io), ("Memory", &l.mem)] {
                                ui.label(label);
                                pressure_bar(ui, p);
                                ui.end_row();
                            }
                        });
                        ui.label(
                            RichText::new(format!(
                                "Load average {:.2} / {:.2} / {:.2} · RAM {} free of {} · swap {} used of {}",
                                l.load[0],
                                l.load[1],
                                l.load[2],
                                human(l.mem_avail),
                                human(l.mem_total),
                                human(l.swap_used),
                                human(l.swap_total)
                            ))
                            .weak(),
                        );
                        ui.add_space(4.0);
                        ui.columns(3, |cols| {
                            proc_list(&mut cols[0], "Top CPU", &l.top_cpu, |p| format!("{:.0}%", p.cpu));
                            proc_list(&mut cols[1], "Top memory", &l.top_mem, |p| human(p.mem));
                            proc_list(&mut cols[2], "Top disk I/O (your processes)", &l.top_io, |p| format!("{}/s", human(p.io)));
                        });
                    }
                });

            let Some(s) = &snap else {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Analysing the system…");
                });
                return;
            };

            // ---- tuning / quick wins -----------------------------------------------
            let warns = s.tuning.iter().filter(|t| t.level == Level::Warn).count();
            egui::CollapsingHeader::new(RichText::new(format!("🔧 Quick checks & tuning ({warns} to look at)")).strong()).id_salt("perf-checks")
                .default_open(true)
                .show(ui, |ui| {
                    for t in &s.tuning {
                        ui.horizontal_wrapped(|ui| {
                            let (icon, color) = match t.level {
                                Level::Ok => ("✔", GREEN),
                                Level::Warn => ("⚠", AMBER),
                                Level::Info => ("ℹ", BLUE),
                            };
                            ui.label(RichText::new(icon).color(color));
                            ui.label(RichText::new(&t.title).strong());
                            ui.label(RichText::new(&t.detail).weak());
                            if let Some(f) = &t.fix
                                && ui.add_enabled(idle, egui::Button::new(&f.label).small()).clicked()
                            {
                                confirm = Some(Confirm::Perf { title: f.label.clone(), note: Some(t.detail.clone()), actions: vec![f.action.clone()] });
                            }
                        });
                    }
                });

            // ---- boot ---------------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new("⏱ Boot time").strong()).default_open(true).show(ui, |ui| {
                let b = &s.boot;
                if b.summary.is_empty() {
                    ui.label("systemd-analyze is not available on this system.");
                    return;
                }
                ui.label(RichText::new(&b.summary).monospace().size(12.0));
                if let Some(h) = &b.hint {
                    ui.colored_label(AMBER, format!("⚠ {h}"));
                }
                egui::Grid::new("blame").striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
                    for (secs, unit) in b.blame.iter().take(12) {
                        let t = RichText::new(format!("{secs:.1}s")).monospace();
                        ui.label(if *secs >= 10.0 { t.color(AMBER) } else { t });
                        ui.label(RichText::new(unit).monospace().size(12.0));
                        ui.end_row();
                    }
                });
                if !b.chain.is_empty() {
                    egui::CollapsingHeader::new("Critical chain").show(ui, |ui| {
                        ui.label(RichText::new(&b.chain).monospace().size(11.5));
                    });
                }
            });

            // ---- startup items --------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new(format!(
                "🚀 Startup items ({} services, {} autostart apps)",
                s.services.len(),
                s.autostart.len()
            )).strong()).id_salt("perf-startup")
            .show(ui, |ui| {
                ui.label(RichText::new("Services enabled at boot, slowest first. Essential system services are locked.").weak());
                egui::Grid::new("services").striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
                    for sv in s.services.iter().take(30) {
                        ui.label(RichText::new(sv.secs.map_or("–".to_string(), |t| format!("{t:.1}s"))).monospace());
                        ui.label(RichText::new(&sv.unit).monospace().size(12.0));
                        if ui
                            .add_enabled(idle && !sv.protected, egui::Button::new("Disable…").small())
                            .on_disabled_hover_text("Essential service – protected")
                            .clicked()
                        {
                            confirm = Some(Confirm::Perf {
                                title: format!("Disable {}", sv.unit),
                                note: Some("It will no longer start at boot. You can re-enable it later with `systemctl enable`.".into()),
                                actions: vec![Action::Root(vec![vec!["systemctl".into(), "disable".into(), sv.unit.clone()]])],
                            });
                        }
                        ui.end_row();
                    }
                });
                if s.services.len() > 30 {
                    ui.label(RichText::new(format!("…and {} more", s.services.len() - 30)).weak());
                }
                ui.add_space(6.0);
                ui.strong("Apps that start when you log in");
                if s.autostart.is_empty() {
                    ui.label(RichText::new("None.").weak());
                }
                for a in &s.autostart {
                    let mut on = a.enabled;
                    if ui
                        .add_enabled(idle, egui::Checkbox::new(&mut on, &a.name))
                        .on_hover_text(format!("{}{}", a.path.display(), if a.system { " (system-wide entry)" } else { "" }))
                        .changed()
                    {
                        autostart_toggle = Some((a.clone(), on));
                    }
                }
            });

            // ---- kernels ----------------------------------------------------------------
            let removable: u64 = s.kernels.iter().filter(|k| k.removable()).map(|k| k.size).sum();
            egui::CollapsingHeader::new(RichText::new(format!(
                "🐧 Kernels ({} installed, {} removable)",
                s.kernels.len(),
                s.kernels.iter().filter(|k| k.removable()).count()
            )).strong()).id_salt("perf-kernels")
            .default_open(s.kernels.iter().any(|k| k.removable()))
            .show(ui, |ui| {
                if s.kernels.is_empty() {
                    ui.label(RichText::new("Kernel management is supported on Fedora/RHEL (dnf) and Debian/Ubuntu (apt).").weak());
                    return;
                }
                ui.label(RichText::new("Old kernels pile up in /boot and the boot menu. The running and newest kernels are always kept.").weak());
                for k in &s.kernels {
                    ui.horizontal(|ui| {
                        let mut sel = self.sel_kernels.contains(&k.version);
                        if ui.add_enabled(k.removable(), egui::Checkbox::without_text(&mut sel)).changed() {
                            if sel {
                                self.sel_kernels.insert(k.version.clone());
                            } else {
                                self.sel_kernels.remove(&k.version);
                            }
                        }
                        ui.label(RichText::new(&k.version).monospace());
                        if k.running {
                            ui.colored_label(GREEN, "running");
                        }
                        if k.newest {
                            ui.colored_label(BLUE, "newest");
                        }
                        ui.label(RichText::new(format!("{} · {} package(s)", human(k.size), k.packages.len())).weak());
                    });
                }
                let chosen: Vec<&perf::Kernel> = s.kernels.iter().filter(|k| self.sel_kernels.contains(&k.version)).collect();
                ui.horizontal(|ui| {
                    if ui.add_enabled(idle && !chosen.is_empty(), egui::Button::new("🗑 Remove selected kernels…")).clicked()
                        && let Some(pm) = self.pm
                    {
                        let size: u64 = chosen.iter().map(|k| k.size).sum();
                        confirm = Some(Confirm::Perf {
                            title: format!("Remove {} kernel(s)", chosen.len()),
                            note: Some(format!("Frees about {} (plus their initramfs in /boot).", human(size))),
                            actions: vec![Action::Root(perf::kernel_remove_cmds(pm, &chosen))],
                        });
                    }
                    if ui.add_enabled(removable > 0, egui::Button::new("Select all old")).clicked() {
                        self.sel_kernels = s.kernels.iter().filter(|k| k.removable()).map(|k| k.version.clone()).collect();
                    }
                });
            });

            // ---- config leftovers -----------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new(format!("📄 Config leftovers from upgrades ({})", s.leftovers.len())).strong()).id_salt("perf-leftovers")
                .show(ui, |ui| {
                    if s.leftovers.is_empty() {
                        ui.label("No leftover .rpmnew/.rpmsave style files in /etc. 🎉");
                        return;
                    }
                    ui.label(
                        RichText::new(
                            "Upgrades leave these beside your config files. They are not read by the system, so they are clutter rather than a slowdown, \
                             but an old .new file can hide a setting you should merge. Use Diff to compare before deleting.",
                        )
                        .weak(),
                    );
                    for l in &s.leftovers {
                        ui.horizontal(|ui| {
                            let mut sel = self.sel_left.contains(&l.path);
                            if ui.checkbox(&mut sel, "").changed() {
                                if sel {
                                    self.sel_left.insert(l.path.clone());
                                } else {
                                    self.sel_left.remove(&l.path);
                                }
                            }
                            let (tag, color) = match l.kind {
                                LeftKind::NewDefault => ("new default", BLUE),
                                LeftKind::OldCopy => ("your old copy", AMBER),
                            };
                            ui.label(RichText::new(tag).color(color).small());
                            ui.label(RichText::new(l.path.display().to_string()).monospace().size(12.0));
                            if ui.small_button(if self.diffs.contains_key(&l.path) { "Hide diff" } else { "Diff" }).clicked()
                                && self.diffs.remove(&l.path).is_none()
                            {
                                diff_req = Some(l.clone());
                            }
                        });
                        if let Some(d) = self.diffs.get(&l.path) {
                            egui::ScrollArea::vertical().id_salt(("diff", &l.path)).max_height((ui.ctx().content_rect().height() * 0.3).max(160.0)).show(ui, |ui| {
                                ui.label(RichText::new(d).monospace().size(11.0));
                            });
                        }
                    }
                    let chosen: Vec<&perf::Leftover> = s.leftovers.iter().filter(|l| self.sel_left.contains(&l.path)).collect();
                    ui.horizontal(|ui| {
                        if ui.add_enabled(idle && !chosen.is_empty(), egui::Button::new("🗑 Delete selected…")).clicked()
                            && let Some(pm) = self.pm
                        {
                            let old = chosen.iter().filter(|l| l.kind == LeftKind::OldCopy).count();
                            confirm = Some(Confirm::Perf {
                                title: format!("Delete {} leftover file(s)", chosen.len()),
                                note: (old > 0).then(|| {
                                    format!("{old} of these are your OLD customised copies; the package default is live now. Check the diff first if you changed anything.")
                                }),
                                actions: vec![Action::Root(perf::leftover_delete_cmds(pm, &chosen))],
                            });
                        }
                        if ui.small_button("Select all").clicked() {
                            self.sel_left = s.leftovers.iter().map(|l| l.path.clone()).collect();
                        }
                    });
                });

            // ---- package health ------------------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new("🩺 Package health after upgrades").strong()).default_open(true).show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.health_running {
                        ui.spinner();
                        ui.label("Running checks (rpm -Va can take a minute)…");
                    } else if ui.add_enabled(self.pm.is_some(), egui::Button::new("Run health checks")).clicked() {
                        run_health = true;
                    }
                });
                for h in &self.health {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(if h.ok { RichText::new("✔").color(GREEN) } else { RichText::new("⚠").color(AMBER) });
                        ui.label(RichText::new(h.title).strong());
                        if let Some(f) = &h.fix
                            && ui.add_enabled(idle, egui::Button::new(&f.label).small()).clicked()
                        {
                            confirm = Some(Confirm::Perf { title: f.label.clone(), note: Some(h.desc.into()), actions: vec![f.action.clone()] });
                        }
                    });
                    ui.label(RichText::new(h.desc).weak().size(12.0));
                    if !h.output.trim().is_empty() {
                        egui::CollapsingHeader::new(if h.ok { "Output" } else { "Details" }).id_salt(h.title).default_open(!h.ok).show(ui, |ui| {
                            egui::ScrollArea::vertical().id_salt(("health", h.title)).max_height((ui.ctx().content_rect().height() * 0.3).max(180.0)).show(ui, |ui| {
                                ui.label(RichText::new(&h.output).monospace().size(11.0));
                            });
                        });
                    }
                    ui.add_space(4.0);
                }
                ui.label(RichText::new("Tip: Packages → Obsolete lists installed packages that no repository provides any more.").weak().size(12.0));
            });
            ui.add_space(10.0);
        });

        self.perf = snap;
        if reload {
            self.load_perf();
        }
        if run_health {
            self.start_health();
        }
        if let Some(l) = diff_req {
            self.start_diff(l);
        }
        if let Some((a, on)) = autostart_toggle {
            match perf::set_autostart(&a, on) {
                Ok(()) => {
                    self.log.push(format!(
                        "✔ {} {} at login",
                        if on { "Enabled" } else { "Disabled" },
                        a.name
                    ));
                    self.load_perf();
                }
                Err(e) => self.log.push(format!("✘ Could not change {}: {e}", a.name)),
            }
        }
        if confirm.is_some() {
            self.confirm = confirm;
        }
    }
}

fn pressure_bar(ui: &mut egui::Ui, p: &Pressure) {
    let now = p.some[0];
    let mut bar = egui::ProgressBar::new((now / 100.0).clamp(0.0, 1.0))
        .desired_width(ui.available_width().min(1000.0))
        .text(format!(
            "{:.1}% now · {:.1}% 1 min · {:.1}% 5 min stalled",
            p.some[0], p.some[1], p.some[2]
        ));
    if now > 25.0 {
        bar = bar.fill(RED);
    } else if now > 10.0 {
        bar = bar.fill(AMBER);
    }
    ui.add(bar);
}

fn proc_list(ui: &mut egui::Ui, title: &str, procs: &[Proc], value: impl Fn(&Proc) -> String) {
    ui.strong(title);
    if procs.is_empty() {
        ui.label(RichText::new("idle").weak());
    }
    for p in procs {
        ui.horizontal(|ui| {
            ui.label(RichText::new(value(p)).monospace().size(12.0));
            ui.add(egui::Label::new(RichText::new(&p.name).size(12.0)).truncate())
                .on_hover_text(format!("{} (pid {})", p.name, p.pid));
        });
    }
}

/// Used by the confirmation dialog: the commands an action will run.
pub(super) fn action_lines(a: &Action) -> (Vec<String>, bool) {
    match a {
        Action::Root(c) => (c.iter().map(|c| c.join(" ")).collect(), true),
        Action::User(c) => (c.iter().map(|c| c.join(" ")).collect(), false),
        Action::RemoveDirs(d) => (
            d.iter()
                .map(|p| format!("delete {}", p.display()))
                .collect(),
            false,
        ),
        Action::ClearDirs(d) => (
            d.iter().map(|p| format!("clear {}", p.display())).collect(),
            false,
        ),
    }
}

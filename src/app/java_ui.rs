//! The Java tab: installed runtimes, running JVMs, and fixes that make Java faster and lighter.

use super::perf_ui::{AMBER, BLUE, GREEN};
use super::*;
use crate::java::{self, JProc, JavaReport};
use crate::perf::Rec;

impl App {
    pub(super) fn load_java(&mut self) {
        if self.java_loading {
            return;
        }
        self.java_loading = true;
        let (n, pm) = (self.notifier(), self.pm);
        std::thread::spawn(move || n.send(Msg::Java(Box::new(java::scan(pm)))));
    }

    /// The shared "recommended fixes" box: tick what you want, apply it in one step.
    fn rec_panel(
        &mut self,
        ui: &mut egui::Ui,
        heading: &str,
        recs: &[Rec],
        confirm: &mut Option<Confirm>,
    ) {
        let idle = self.busy.is_none();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading(heading);
            if recs.is_empty() {
                ui.label("Nothing found that needs fixing. 🎉");
            }
            for r in recs {
                let mut on = self.rec_sel.get(&r.title).copied().unwrap_or(r.safe);
                ui.horizontal_wrapped(|ui| {
                    if ui.checkbox(&mut on, "").changed() {
                        self.rec_sel.insert(r.title.clone(), on);
                    }
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
            let chosen: Vec<&Rec> = recs
                .iter()
                .filter(|r| self.rec_sel.get(&r.title).copied().unwrap_or(r.safe))
                .collect();
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let label = format!("⚡ Apply {} selected fix(es)…", chosen.len());
                if ui
                    .add_enabled(
                        idle && !chosen.is_empty(),
                        egui::Button::new(RichText::new(label).strong()),
                    )
                    .clicked()
                {
                    let review: Vec<&str> = chosen
                        .iter()
                        .filter(|r| !r.safe)
                        .map(|r| r.title.as_str())
                        .collect();
                    *confirm = Some(Confirm::Perf {
                        title: format!("Apply {} fix(es)", chosen.len()),
                        note: Some(format!(
                            "{}{}",
                            chosen
                                .iter()
                                .map(|r| format!("• {}", r.title))
                                .collect::<Vec<_>>()
                                .join("\n"),
                            if review.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    "\n\nThese change things you may rely on: {}",
                                    review.join("; ")
                                )
                            }
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
    }

    pub(super) fn java_tab(&mut self, ui: &mut egui::Ui) {
        if self.java.is_none() && !self.java_loading {
            self.load_java();
        }
        let mut reload = false;
        let mut confirm: Option<Confirm> = None;
        let report: Option<JavaReport> = self.java.take();

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Make Java programs start faster and use less memory. Nothing changes until you confirm.").weak());
            if self.java_loading {
                ui.spinner();
            } else if ui.small_button("⟳ Re-scan").clicked() {
                reload = true;
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let Some(r) = &report else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Scanning Java runtimes and running JVMs…");
                });
                return;
            };
            let default = r.jvms.iter().find(|j| j.is_default);
            ui.label(
                RichText::new(format!(
                    "This machine: {} RAM, {} CPU core(s) · default `java`: {}",
                    human(r.ram),
                    r.cpus,
                    default.map_or("none".to_string(), |j| format!("Java {} ({})", j.version, j.vendor))
                ))
                .weak(),
            );
            ui.add_space(4.0);

            self.rec_panel(ui, "✅ Recommended Java fixes", &r.recs, &mut confirm);
            for f in &r.findings {
                egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.0, AMBER)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("⚠ {f}")).size(12.5));
                });
            }
            ui.add_space(6.0);

            // ---- running JVMs ---------------------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new(format!("▶ Running JVMs ({})", r.procs.len())).strong()).id_salt("java-running").default_open(true).show(ui, |ui| {
                if r.procs.is_empty() {
                    ui.label(RichText::new("No Java programs are running.").weak());
                }
                for p in &r.procs {
                    jproc_row(ui, p);
                }
            });

            // ---- installed runtimes ---------------------------------------------------------------
            let (system, bundled): (Vec<_>, Vec<_>) = r.jvms.iter().partition(|j| !j.bundled);
            egui::CollapsingHeader::new(RichText::new(format!("☕ Installed runtimes ({})", system.len())).strong()).id_salt("java-installed").default_open(true).show(ui, |ui| {
                egui::Grid::new("jvms").striped(true).spacing([14.0, 4.0]).show(ui, |ui| {
                    for h in ["Version", "Vendor", "Type", "Support", "Size", "Start-up cache", "Location"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for j in &system {
                        let ver = RichText::new(format!("{}{}", j.version, if j.is_default { "  ★ default" } else { "" })).strong();
                        ui.label(if j.is_default { ver.color(GREEN) } else { ver });
                        ui.label(&j.vendor);
                        ui.label(if j.is_jdk { "JDK" } else { "JRE" });
                        let (label, warn) = java::support(j.major);
                        ui.label(if warn { RichText::new(label).color(AMBER) } else { RichText::new(label) });
                        ui.label(human(j.size));
                        ui.label(if j.major < 12 {
                            RichText::new("n/a").weak()
                        } else if j.cds_missing {
                            RichText::new("missing").color(AMBER)
                        } else {
                            RichText::new("ok").color(GREEN)
                        });
                        if ui.link(RichText::new(j.home.display().to_string()).monospace().size(11.5)).on_hover_text("Open folder").clicked() {
                            util::open(&j.home);
                        }
                        ui.end_row();
                    }
                });
                if !bundled.is_empty() {
                    ui.label(
                        RichText::new(format!(
                            "{} more runtime(s) are bundled inside other apps (IDEs and similar). They are managed by those apps and left alone.",
                            bundled.len()
                        ))
                        .weak()
                        .size(12.0),
                    );
                }
            });

            // ---- flags tuned to this machine --------------------------------------------------------
            egui::CollapsingHeader::new(RichText::new("🧰 JVM flags tuned to this machine").strong()).show(ui, |ui| {
                ui.label(RichText::new("Starting points based on your RAM and CPU count. Paste them into a launcher script, `JAVA_TOOL_OPTIONS`, or an IDE's .vmoptions.").weak().size(12.0));
                for (name, flags) in &r.flag_sets {
                    ui.horizontal(|ui| {
                        ui.strong(name);
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(flags.clone());
                        }
                    });
                    ui.label(RichText::new(flags).monospace().size(12.0).color(BLUE));
                    ui.add_space(2.0);
                }
            });
            ui.add_space(10.0);
        });

        self.java = report;
        if reload {
            self.load_java();
        }
        if confirm.is_some() {
            self.confirm = confirm;
        }
    }
}

fn jproc_row(ui: &mut egui::Ui, p: &JProc) {
    let heap = match (p.heap_used, p.max_heap) {
        (Some(u), Some(m)) => format!("heap {} / {}", human(u), human(m)),
        (None, Some(m)) => format!("max heap {}", human(m)),
        _ => "heap unknown".into(),
    };
    let title = format!(
        "{} · pid {} · {} RAM · {} · {} · {:.0}% CPU",
        p.label,
        p.pid,
        human(p.rss),
        heap,
        p.gc.as_deref().unwrap_or("GC ?"),
        p.cpu
    );
    let text = RichText::new(title);
    egui::CollapsingHeader::new(if p.advice.is_empty() {
        text
    } else {
        text.color(AMBER)
    })
    .id_salt(("jproc", p.pid))
    .default_open(false)
    .show(ui, |ui| {
        for a in &p.advice {
            ui.label(RichText::new(format!("➤ {a}")).size(12.5));
        }
        if p.advice.is_empty() {
            ui.label(
                RichText::new("Nothing to improve: heap, GC and memory look healthy.")
                    .color(GREEN)
                    .size(12.5),
            );
        }
        if let Some(h) = &p.jvm_home {
            ui.label(
                RichText::new(format!(
                    "Runtime: {}{}",
                    h.display(),
                    p.major.map_or(String::new(), |m| format!(" (Java {m})"))
                ))
                .weak()
                .size(12.0),
            );
        }
        ui.label(
            RichText::new(format!("{} threads", p.threads))
                .weak()
                .size(12.0),
        );
        if let Some(ide) = &p.ide {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Heap cap {} set in: {}",
                        ide.xmx.map_or("(default)".to_string(), human),
                        ide.vmoptions.display()
                    ))
                    .weak()
                    .size(12.0),
                );
                if ui.link("open").clicked() {
                    util::open(&ide.vmoptions);
                }
            });
        }
        if !p.flags.is_empty() {
            egui::CollapsingHeader::new("Live JVM flags")
                .id_salt(("jflags", p.pid))
                .show(ui, |ui| {
                    ui.label(RichText::new(&p.flags).monospace().size(11.0));
                });
        }
    });
}

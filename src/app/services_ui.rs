//! The Services tab: every running service, what it does, and a link to its configuration.

use super::perf_ui::{AMBER, BLUE, GREEN};
use super::*;
use crate::services::{self, Detail, Scope, Svc};
use crate::targets::Action;

impl App {
    pub(super) fn load_services(&mut self) {
        if self.svc_loading {
            return;
        }
        self.svc_loading = true;
        let (n, scope) = (self.notifier(), self.svc_scope);
        std::thread::spawn(move || n.send(Msg::Services(scope, services::list_running(scope))));
    }

    fn load_svc_detail(&mut self, svc: Svc) {
        if !self.svc_pending.insert(svc.unit.clone()) {
            return;
        }
        let (n, scope, pm) = (self.notifier(), self.svc_scope, self.pm);
        std::thread::spawn(move || {
            let d = services::load_detail(scope, &svc, pm);
            n.send(Msg::SvcDetail(scope, svc.unit, Box::new(d)));
        });
    }

    fn svc_action(&self, verb: &str, unit: &str) -> Confirm {
        let (scope, mut cmd) = (self.svc_scope, vec!["systemctl".to_string()]);
        if scope == Scope::User {
            cmd.push("--user".into());
        }
        cmd.extend([verb.to_string(), unit.to_string()]);
        let note = match verb {
            "restart" => {
                "The service stops and starts again. Anything using it is briefly interrupted."
            }
            "stop" => {
                "The service stops now. It will start again at next boot (or when something asks for it) unless you also disable it."
            }
            _ => {
                "It will no longer start automatically. It keeps running until you stop it or reboot."
            }
        };
        let action = if scope == Scope::System {
            Action::Root(vec![cmd])
        } else {
            Action::User(vec![cmd])
        };
        Confirm::Perf {
            title: format!("{} {unit}", verb[..1].to_uppercase() + &verb[1..]),
            note: Some(note.into()),
            actions: vec![action],
        }
    }

    /// Right-hand detail panel for the selected service. Shown at window level (before the
    /// central panel) so the table gets only the space that is left over.
    pub(super) fn svc_detail_panel(&mut self, ui: &mut egui::Ui) {
        let mut new_sel: Option<String> = None;
        let mut confirm: Option<Confirm> = None;
        let selected: Option<Svc> = self
            .svc_sel
            .as_ref()
            .and_then(|u| self.svcs.iter().find(|s| &s.unit == u))
            .cloned();
        if let Some(svc) = &selected {
            if !self.svc_detail.contains_key(&svc.unit) {
                self.load_svc_detail(svc.clone());
            }
            let detail: Option<std::sync::Arc<Detail>> = self.svc_detail.get(&svc.unit).cloned();
            let idle = self.busy.is_none();
            let protected = if self.svc_scope == Scope::System {
                crate::perf::service_protected(&svc.unit)
            } else {
                crate::perf::user_service_protected(&svc.unit)
            };
            egui::Panel::right("svc_detail").frame(egui::Frame::side_top_panel(ui.style()).fill(ui.visuals().extreme_bg_color).inner_margin(10.0)).resizable(true).default_size(440.0).min_size(300.0).show(ui, |ui| {
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(&svc.unit);
                        if ui.small_button("✕").on_hover_text("Close").clicked() {
                            new_sel = Some(String::new());
                        }
                    });
                    ui.label(RichText::new(svc.category).color(BLUE).small());
                    ui.add_space(4.0);
                    ui.strong("What it does");
                    ui.label(svc.blurb.unwrap_or(&svc.description));
                    if svc.blurb.is_some() && !svc.description.is_empty() {
                        ui.label(RichText::new(format!("Unit description: {}", svc.description)).weak().size(12.0));
                    }
                    ui.add_space(4.0);
                    egui::Grid::new("svc_facts").num_columns(2).spacing([12.0, 3.0]).show(ui, |ui| {
                        let mut row = |k: &str, v: String| {
                            ui.label(RichText::new(k).weak());
                            ui.label(v);
                            ui.end_row();
                        };
                        row("Process ID", svc.pid.to_string());
                        row("Memory", svc.mem.map_or("not tracked".into(), human));
                        row("Running since", if svc.since.is_empty() { "–".into() } else { svc.since.clone() });
                        row("At boot", if svc.enabled.is_empty() { "–".into() } else { svc.enabled.clone() });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let hover = if protected { "Essential service – protected" } else { "" };
                        for (label, verb) in [("Restart…", "restart"), ("Stop…", "stop"), ("Disable…", "disable")] {
                            if ui.add_enabled(idle && !protected, egui::Button::new(label).small()).on_disabled_hover_text(hover).clicked() {
                                confirm = Some(self.svc_action(verb, &svc.unit));
                            }
                        }
                    });
                    ui.separator();

                    let Some(d) = &detail else {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Loading configuration…");
                        });
                        return;
                    };
                    if let Some((pkg, summary)) = &d.package {
                        ui.strong("Package");
                        ui.label(format!("{pkg} – {summary}"));
                        ui.add_space(4.0);
                    }
                    ui.strong("Configuration");
                    ui.label(RichText::new("Click a path to open it in your default editor. Files under /usr are the vendor defaults; change behaviour with an override in /etc.").weak().size(12.0));
                    if d.config_files.is_empty() {
                        ui.label(RichText::new("No configuration files found for this service.").weak());
                    }
                    for p in &d.config_files {
                        ui.horizontal(|ui| {
                            let kind = if p.is_dir() { "📁" } else { "📄" };
                            if ui.link(RichText::new(format!("{kind} {}", p.display())).monospace().size(12.0)).on_hover_text("Open").clicked() {
                                util::open(p);
                            }
                            if !p.is_dir() && ui.small_button("folder").on_hover_text("Open the containing folder").clicked()
                                && let Some(parent) = p.parent()
                            {
                                util::open(parent);
                            }
                            let tag = if p.starts_with("/etc") { ("custom", GREEN) } else { ("vendor", AMBER) };
                            ui.label(RichText::new(tag.0).color(tag.1).small());
                        });
                    }
                    ui.add_space(6.0);
                    egui::CollapsingHeader::new(RichText::new("Effective unit file (systemctl cat)").strong()).show(ui, |ui| {
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(d.unit_text.clone());
                        }
                        ui.label(RichText::new(&d.unit_text).monospace().size(11.5));
                    });
                });
            });
        }
        if let Some(u) = new_sel {
            self.svc_sel = (!u.is_empty()).then_some(u);
        }
        if confirm.is_some() {
            self.confirm = confirm;
        }
    }

    pub(super) fn services_tab(&mut self, ui: &mut egui::Ui) {
        if !self.svc_loaded && !self.svc_loading {
            self.load_services();
        }
        let mut reload = false;
        let mut new_sel: Option<String> = None;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let before = self.svc_scope;
            ui.selectable_value(&mut self.svc_scope, Scope::System, "System services");
            ui.selectable_value(&mut self.svc_scope, Scope::User, "Your session");
            if self.svc_scope != before {
                reload = true;
                self.svc_sel = None;
                self.svc_detail.clear();
                self.svc_pending.clear();
                // The old list belongs to the other scope: acting on it would run commands in the wrong one.
                self.svcs.clear();
                self.svc_loaded = false;
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.svc_filter)
                    .hint_text("🔍 Filter services")
                    .desired_width(field_width(ui, 0.2, 180.0, 400.0)),
            );
            let mut cats: Vec<&str> = self.svcs.iter().map(|s| s.category).collect();
            cats.sort_unstable();
            cats.dedup();
            egui::ComboBox::from_id_salt("svc_cat")
                .selected_text(if self.svc_cat.is_empty() {
                    "All categories".to_string()
                } else {
                    self.svc_cat.clone()
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.svc_cat, String::new(), "All categories");
                    for c in cats {
                        ui.selectable_value(&mut self.svc_cat, c.to_string(), c);
                    }
                });
            if self.svc_loading {
                ui.spinner();
            } else if ui.small_button("⟳ Reload").clicked() {
                reload = true;
            }
        });

        let f = self.svc_filter.trim().to_lowercase();
        let idx: Vec<usize> = (0..self.svcs.len())
            .filter(|&i| {
                let s = &self.svcs[i];
                (self.svc_cat.is_empty() || s.category == self.svc_cat)
                    && (f.is_empty()
                        || s.unit.to_lowercase().contains(&f)
                        || s.description.to_lowercase().contains(&f))
            })
            .collect();
        let total: u64 = idx.iter().filter_map(|&i| self.svcs[i].mem).sum();
        ui.label(
            RichText::new(format!(
                "{} running · {} shown · {} of memory (user@ includes all your apps)",
                self.svcs.len(),
                idx.len(),
                human(total)
            ))
            .weak(),
        );
        ui.separator();

        // ---- detail panel -------------------------------------------------------------------

        // ---- table ----------------------------------------------------------------------------
        let rows = &self.svcs;
        let sel = &self.svc_sel;
        ui.scope(|ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(220.0).at_least(120.0).clip(true))
                .column(Column::initial(100.0).at_least(60.0).clip(true))
                .column(
                    Column::remainder()
                        .at_least(140.0)
                        .clip(true)
                        .resizable(false),
                )
                .column(Column::initial(80.0).at_least(60.0))
                .column(Column::initial(70.0).at_least(50.0))
                .header(24.0, |mut h| {
                    for t in ["Service", "Category", "What it is", "Memory", "At boot"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|body| {
                    body.rows(22.0, idx.len(), |mut row| {
                        let s = &rows[idx[row.index()]];
                        row.set_selected(sel.as_deref() == Some(s.unit.as_str()));
                        row.col(|ui| {
                            ui.label(
                                RichText::new(s.unit.strip_suffix(".service").unwrap_or(&s.unit))
                                    .strong(),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(s.category).weak());
                        });
                        row.col(|ui| {
                            let text = if s.description.is_empty() {
                                s.blurb.unwrap_or("")
                            } else {
                                &s.description
                            };
                            let r = ui.label(text);
                            if let Some(b) = s.blurb {
                                r.on_hover_text(b);
                            }
                        });
                        row.col(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(s.mem.map_or("–".to_string(), human));
                            });
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&s.enabled).weak());
                        });
                        if row.response().clicked() {
                            new_sel = Some(s.unit.clone());
                        }
                    });
                });
        });

        if let Some(u) = new_sel {
            self.svc_sel = (!u.is_empty()).then_some(u);
        }
        if reload {
            self.svc_loaded = false;
            self.load_services();
        }
    }
}

//! The confirmation dialog shown before anything is deleted or changed.

use super::*;

impl App {
    pub(super) fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(c) = self.confirm.take() else { return };
        let mut decision: Option<bool> = None;
        let resp = egui::Modal::new(egui::Id::unique("confirm")).backdrop_color(Color32::from_black_alpha(190)).show(ctx, |ui| {
            ui.set_max_width(560.0);
            match &c {
                Confirm::Clean(idx) => {
                    ui.heading("Clean up?");
                    ui.add_space(6.0);
                    let mut total = 0;
                    let mut root = false;
                    for t in idx.iter().filter_map(|&i| self.targets.get(i)) {
                        total += t.size.unwrap_or(0);
                        root |= t.needs_root();
                        ui.label(format!(
                            "• {}  {}",
                            t.name,
                            t.size.map(|s| format!("({})", human(s))).unwrap_or_default()
                        ));
                    }
                    ui.add_space(6.0);
                    ui.label(format!("Up to {} will be freed. This can't be undone.", human(total)));
                    if root {
                        ui.label(RichText::new("🔒 You'll be asked for your password once.").weak());
                    }
                    buttons(ui, "Clean", true, &mut decision);
                }
                Confirm::Remove { names, preview } => {
                    ui.heading(format!("Remove {} package(s)?", names.len()));
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical().id_salt("names").max_height(90.0).show(ui, |ui| {
                        ui.label(RichText::new(names.join("  ")).monospace());
                    });
                    ui.separator();
                    let mut ok = false;
                    match preview {
                        None => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Checking what else would be removed…");
                            });
                        }
                        Some((text, affected)) => {
                            let mut blocked: Vec<&String> = names.iter().filter(|n| pkg::is_protected(n)).collect();
                            if let Some(a) = affected {
                                blocked.extend(a.iter().filter(|n| pkg::is_protected(n)));
                                let extra: Vec<&String> = a.iter().filter(|n| !names.contains(n)).collect();
                                if extra.is_empty() {
                                    ui.label("No other packages will be removed.");
                                } else {
                                    ui.colored_label(
                                        Color32::from_rgb(230, 160, 60),
                                        format!("⚠ {} additional package(s) depend on these and will also be removed:", extra.len()),
                                    );
                                    egui::ScrollArea::vertical().id_salt("extra").max_height(90.0).show(ui, |ui| {
                                        ui.label(RichText::new(extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("  ")).monospace());
                                    });
                                }
                            }
                            egui::CollapsingHeader::new("Package manager output").show(ui, |ui| {
                                egui::ScrollArea::vertical().id_salt("out").max_height(200.0).show(ui, |ui| {
                                    ui.label(RichText::new(text).monospace().size(11.5));
                                });
                            });
                            if blocked.is_empty() {
                                ok = true;
                            } else {
                                blocked.dedup();
                                ui.colored_label(
                                    Color32::from_rgb(220, 90, 80),
                                    format!(
                                        "✘ Blocked: this would remove essential packages ({}).",
                                        blocked.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                                    ),
                                );
                            }
                        }
                    }
                    buttons(ui, "Remove", ok, &mut decision);
                }
                Confirm::Upgrade { names } => {
                    let full = self.pm.is_some_and(Pm::upgrade_is_full);
                    ui.heading(if full { "Upgrade the whole system?".to_string() } else { format!("Upgrade {} package(s)?", names.len()) });
                    ui.add_space(6.0);
                    if full {
                        ui.label("pacman does not support partial upgrades: every package with an update will be upgraded.");
                    }
                    egui::ScrollArea::vertical().id_salt("upg").max_height(200.0).show(ui, |ui| {
                        for n in names {
                            let new = self.upgradable.get(n).map(String::as_str).unwrap_or("?");
                            ui.label(RichText::new(format!("{n}  →  {new}")).monospace().size(12.0));
                        }
                    });
                    ui.label(RichText::new("🔒 You'll be asked for your password once.").weak());
                    buttons(ui, "Upgrade", !names.is_empty(), &mut decision);
                }
                Confirm::Perf { title, note, actions } => {
                    ui.heading(title.as_str());
                    ui.add_space(6.0);
                    if let Some(n) = note {
                        ui.label(n.as_str());
                        ui.add_space(4.0);
                    }
                    let (mut lines, mut root) = (Vec::new(), false);
                    for a in actions {
                        let (l, r) = perf_ui::action_lines(a);
                        lines.extend(l);
                        root |= r;
                    }
                    egui::ScrollArea::vertical().id_salt("perf_cmds").max_height(160.0).show(ui, |ui| {
                        for l in &lines {
                            ui.label(RichText::new(format!("$ {l}")).monospace().size(11.5));
                        }
                    });
                    if root {
                        ui.label(RichText::new("🔒 You'll be asked for your password once.").weak());
                    }
                    buttons(ui, "Run", !lines.is_empty(), &mut decision);
                }
                Confirm::Files { paths, size, permanent } => {
                    ui.heading(if *permanent { "Delete permanently?" } else { "Move to Trash?" });
                    ui.add_space(6.0);
                    ui.label(format!("{} file(s), {}", paths.len(), human(*size)));
                    egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                        for p in paths {
                            ui.label(RichText::new(p.display().to_string()).monospace().size(11.5));
                        }
                    });
                    if *permanent {
                        ui.colored_label(Color32::from_rgb(220, 90, 80), "These files can't be recovered.");
                    }
                    buttons(ui, if *permanent { "Delete" } else { "Move to Trash" }, true, &mut decision);
                }
            }
        });

        match decision {
            Some(true) => match c {
                Confirm::Clean(idx) => self.start_clean(idx),
                Confirm::Remove { names, .. } => self.start_remove(names),
                Confirm::Upgrade { names } => self.start_upgrade(names),
                Confirm::Perf { title, actions, .. } => self.start_perf_action(title, actions),
                Confirm::Files {
                    paths, permanent, ..
                } => self.start_delete_files(paths, permanent),
            },
            Some(false) => {}
            None if resp.should_close() => {}
            None => self.confirm = Some(c),
        }
    }
}

pub(super) fn buttons(ui: &mut egui::Ui, label: &str, enabled: bool, decision: &mut Option<bool>) {
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(enabled, egui::Button::new(RichText::new(label).strong()))
            .clicked()
        {
            *decision = Some(true);
        }
        if ui.button("Cancel").clicked() {
            *decision = Some(false);
        }
    });
}

//! The Cleanup tab: reclaimable space found by the scan, cleaned in one go.

use super::{
    Align, App, Color32, Confirm, Group, Layout, Msg, RichText, Target, egui, human, targets,
};

impl App {
    pub(super) fn start_clean(&mut self, idx: &[usize]) {
        let chosen: Vec<Target> = idx
            .iter()
            .filter_map(|&i| self.targets.get(i).cloned())
            .collect();
        self.busy = Some("Cleaning…".into());
        let n = self.notifier();
        std::thread::spawn(move || {
            targets::execute(&chosen, &mut |l| n.send(Msg::Log(l)));
            n.send(Msg::Done { refresh: true });
        });
    }

    pub(super) fn cleanup_tab(&mut self, ui: &mut egui::Ui) {
        let mut clean = false;
        let mut rescan = false;

        // Footer first so it stays pinned at the bottom.
        egui::Panel::bottom("cleanup_footer").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let sel: Vec<&Target> = self.targets.iter().filter(|t| t.selected).collect();
                let total: u64 = sel.iter().filter_map(|t| t.size).sum();
                let root = sel.iter().any(|t| t.needs_root());
                ui.label(format!("{} selected · about {}", sel.len(), human(total)));
                if root {
                    ui.label(RichText::new("🔒 needs your password").weak());
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let enabled = !sel.is_empty() && self.busy.is_none() && !self.scanning;
                    if ui
                        .add_enabled(
                            enabled,
                            egui::Button::new(RichText::new("Clean selected").strong()),
                        )
                        .clicked()
                    {
                        clean = true;
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.strong("Disks");
                for d in &self.disks {
                    let used = d.total.saturating_sub(d.avail);
                    let frac = used as f32 / d.total as f32;
                    ui.horizontal(|ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(150.0, 18.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_min_width(150.0);
                                ui.add(
                                    egui::Label::new(RichText::new(&d.mount).monospace())
                                        .truncate(),
                                )
                                .on_hover_text(&d.device);
                            },
                        );
                        let mut bar = egui::ProgressBar::new(frac)
                            .desired_width(ui.available_width().min(1000.0))
                            .text(format!(
                                "{} used of {} · {} free",
                                human(used),
                                human(d.total),
                                human(d.avail)
                            ));
                        if frac > 0.9 {
                            bar = bar.fill(Color32::from_rgb(200, 70, 60));
                        }
                        ui.add(bar);
                    });
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.strong("Reclaimable space");
                    if self.scanning {
                        ui.spinner();
                        ui.label(RichText::new("scanning…").weak());
                    } else if ui.small_button("⟳ Rescan").clicked() {
                        rescan = true;
                    }
                });
                ui.add_space(4.0);

                let mut last_group: Option<Group> = None;
                for t in &mut self.targets {
                    if last_group != Some(t.group) {
                        last_group = Some(t.group);
                        ui.add_space(6.0);
                        ui.label(RichText::new(t.group.label()).small().strong());
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut t.selected, "");
                            ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
                                let size = match t.size {
                                    Some(s) => RichText::new(human(s)).strong(),
                                    None => RichText::new("size unknown").weak(),
                                };
                                ui.label(size);
                                ui.with_layout(Layout::top_down(Align::LEFT), |ui| {
                                    let mut name = t.name.clone();
                                    if t.needs_root() {
                                        name.push_str("  🔒");
                                    }
                                    ui.label(RichText::new(name).strong());
                                    ui.label(RichText::new(&t.description).size(12.5).weak());
                                    if !t.details.is_empty() {
                                        egui::CollapsingHeader::new(
                                            RichText::new(format!("{} item(s)", t.details.len()))
                                                .small(),
                                        )
                                        .id_salt(("details", &t.name))
                                        .show(ui, |ui| {
                                            for d in t.details.iter().take(300) {
                                                ui.label(RichText::new(d).monospace().size(11.5));
                                            }
                                            if t.details.len() > 300 {
                                                ui.label(format!(
                                                    "…and {} more",
                                                    t.details.len() - 300
                                                ));
                                            }
                                        });
                                    }
                                });
                            });
                        });
                    });
                }
                if self.targets.is_empty() && !self.scanning {
                    ui.label("Nothing to clean. 🎉");
                }
            });

        if rescan {
            self.refresh();
        }
        if clean {
            let idx = self
                .targets
                .iter()
                .enumerate()
                .filter(|(_, t)| t.selected)
                .map(|(i, _)| i)
                .collect();
            self.confirm = Some(Confirm::Clean(idx));
        }
    }
}

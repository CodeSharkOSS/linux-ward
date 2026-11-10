//! The Packages tab: browse, upgrade and remove installed packages.

use super::*;

impl App {
    pub(super) fn start_preview(&mut self, names: Vec<String>) {
        let Some(pm) = self.pm else { return };
        self.confirm = Some(Confirm::Remove {
            names: names.clone(),
            preview: None,
        });
        let n = self.notifier();
        std::thread::spawn(move || {
            let (out, affected) = pm.preview_remove(&names);
            n.send(Msg::Preview {
                names,
                text: out.combined(),
                affected,
            });
        });
    }

    pub(super) fn start_remove(&mut self, names: Vec<String>) {
        let Some(pm) = self.pm else { return };
        self.busy = Some(format!("Removing {} package(s)…", names.len()));
        let n = self.notifier();
        std::thread::spawn(move || {
            n.send(Msg::Log(format!("Removing: {}", names.join(" "))));
            let out = util::run_privileged(&pm.remove_cmds(&names));
            for l in out.combined().lines().filter(|l| !l.trim().is_empty()) {
                n.send(Msg::Log(format!("  {l}")));
            }
            n.send(Msg::Log(if out.ok {
                "✔ Packages removed".into()
            } else {
                "✘ Removal failed (see above)".into()
            }));
            n.send(Msg::Done { refresh: true });
        });
    }

    pub(super) fn start_upgrade(&mut self, names: Vec<String>) {
        let Some(pm) = self.pm else { return };
        self.busy = Some("Upgrading…".into());
        let n = self.notifier();
        std::thread::spawn(move || {
            n.send(Msg::Log(if pm.upgrade_is_full() {
                "Upgrading the whole system".into()
            } else {
                format!("Upgrading: {}", names.join(" "))
            }));
            let out = util::run_privileged(&pm.upgrade_cmds(&names));
            for l in out.combined().lines().filter(|l| !l.trim().is_empty()) {
                n.send(Msg::Log(format!("  {l}")));
            }
            n.send(Msg::Log(if out.ok {
                "✔ Upgrade finished".into()
            } else {
                "✘ Upgrade failed (see above)".into()
            }));
            n.send(Msg::Done { refresh: true });
        });
    }

    pub(super) fn packages_tab(&mut self, ui: &mut egui::Ui) {
        let mut remove = false;
        let mut upgrade = false;
        let mut reload = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("🔍 Filter packages").desired_width(field_width(ui, 0.25, 200.0, 420.0)));
            let has_manual = self.rows.iter().any(|r| r.pkg.manual.is_some());
            ui.add_enabled(has_manual, egui::Checkbox::new(&mut self.manual_only, "Installed by me only"))
                .on_hover_text("Hide packages that were pulled in automatically as dependencies");
            ui.checkbox(&mut self.group, "Group by type")
                .on_hover_text("Group packages into libraries, development, fonts, applications… (guessed from package names)");
            if self.pkg_loading {
                ui.spinner();
            } else if ui.small_button("⟳ Reload").clicked() {
                reload = true;
            }
        });
        let is_unused = |unused: &HashSet<String>, name: &str| {
            unused.contains(name) || unused.contains(name.split(':').next().unwrap_or(name))
        };
        let n_obsolete = self
            .rows
            .iter()
            .filter(|r| is_unused(&self.obsolete, &r.pkg.name))
            .count();
        let lookup = |name: &str| {
            self.upgradable
                .get(name)
                .or_else(|| self.upgradable.get(name.split(':').next().unwrap_or(name)))
        };
        let n_upgradable = self
            .rows
            .iter()
            .filter(|r| lookup(&r.pkg.name).is_some())
            .count();
        let n_unused = self
            .rows
            .iter()
            .filter(|r| is_unused(&self.unused, &r.pkg.name))
            .count();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, PkgView::All, format!("All ({})", self.rows.len()));
            ui.selectable_value(&mut self.view, PkgView::Unused, format!("Unused – safe to remove ({n_unused})"))
                .on_hover_text("Automatically installed packages that nothing needs any more (what autoremove would delete)");
            ui.selectable_value(&mut self.view, PkgView::InUse, format!("In use ({})", self.rows.len() - n_unused))
                .on_hover_text("Installed by you, or required by another installed package");
            ui.selectable_value(&mut self.view, PkgView::Obsolete, format!("Obsolete ({n_obsolete})"))
                .on_hover_text("Installed, but no enabled repository provides them any more (dropped, renamed, or installed by hand). Check before removing.");
            ui.selectable_value(&mut self.view, PkgView::Conflicts, format!("Conflicts ({})", self.conflicts.len()))
                .on_hover_text("Installed packages that declare a conflict with another installed package. The package manager normally prevents this, so it usually means a forced install or a repository change. Version-limited conflicts are not checked.");
            ui.selectable_value(&mut self.view, PkgView::Upgradable, format!("Upgradable ({n_upgradable})"))
                .on_hover_text("A newer version is available from an enabled repository");
            if self.view == PkgView::Unused
                && ui.add_enabled(n_unused > 0, egui::Button::new("Select all unused").small()).clicked()
            {
                for r in self.rows.iter_mut() {
                    if is_unused(&self.unused, &r.pkg.name) && !pkg::is_protected(&r.pkg.name) {
                        r.selected = true;
                    }
                }
            }
        });

        let f = self.filter.trim().to_lowercase();
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let p = &self.rows[i].pkg;
                let u = is_unused(&self.unused, &p.name);
                let view_ok = match self.view {
                    PkgView::All => true,
                    PkgView::Unused => u,
                    PkgView::InUse => !u,
                    PkgView::Obsolete => is_unused(&self.obsolete, &p.name),
                    PkgView::Upgradable => lookup(&p.name).is_some(),
                    PkgView::Conflicts => self.conflicts.contains_key(&p.name),
                };
                view_ok
                    && (!self.manual_only || p.manual == Some(true))
                    && (f.is_empty() || p.name.to_lowercase().contains(&f))
            })
            .collect();
        match self.sort {
            SortBy::Name => idx.sort_by(|&a, &b| self.rows[a].pkg.name.cmp(&self.rows[b].pkg.name)),
            SortBy::Size => idx.sort_by_key(|&i| self.rows[i].pkg.size),
        }
        if self.sort_desc {
            idx.reverse();
        }
        enum Item {
            Head(Category, usize, u64),
            Pkg(usize),
        }
        let mut items: Vec<Item> = Vec::with_capacity(idx.len() + 8);
        if self.group {
            idx.sort_by_key(|&i| pkg::category(&self.rows[i].pkg.name)); // stable: keeps the chosen order inside a group
            let mut totals: HashMap<Category, (usize, u64)> = HashMap::new();
            for &i in &idx {
                let t = totals
                    .entry(pkg::category(&self.rows[i].pkg.name))
                    .or_default();
                t.0 += 1;
                t.1 += self.rows[i].pkg.size;
            }
            let mut last = None;
            for &i in &idx {
                let c = pkg::category(&self.rows[i].pkg.name);
                if last != Some(c) {
                    last = Some(c);
                    let (n, size) = totals[&c];
                    items.push(Item::Head(c, n, size));
                }
                if !self.collapsed.contains(&c) {
                    items.push(Item::Pkg(i));
                }
            }
        } else {
            items.extend(idx.iter().map(|&i| Item::Pkg(i)));
        }
        let mut toggle: Option<Category> = None;
        let upgrades_known = self.upgradable_known;

        ui.horizontal(|ui| {
            let sel: Vec<&Row> = self.rows.iter().filter(|r| r.selected).collect();
            let size: u64 = sel.iter().map(|r| r.pkg.size).sum();
            let shown_size: u64 = idx.iter().map(|&i| self.rows[i].pkg.size).sum();
            ui.label(RichText::new(format!("{} shown ({})", idx.len(), human(shown_size))).weak());
            ui.separator();
            ui.label(format!("{} selected · {}", sel.len(), human(size)));
            let any = !sel.is_empty();
            let sel_upgradable = sel.iter().any(|r| lookup(&r.pkg.name).is_some());
            if ui
                .add_enabled(any, egui::Button::new("Clear selection").small())
                .clicked()
            {
                self.rows.iter_mut().for_each(|r| r.selected = false);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        any && self.busy.is_none(),
                        egui::Button::new("🗑 Remove selected…"),
                    )
                    .clicked()
                {
                    remove = true;
                }
                let full = self.pm.is_some_and(Pm::upgrade_is_full);
                let can_upgrade = self.busy.is_none()
                    && if full {
                        n_upgradable > 0
                    } else {
                        sel_upgradable
                    };
                let label = if full {
                    "⬆ Upgrade system…"
                } else {
                    "⬆ Upgrade selected…"
                };
                let hover = if full {
                    "pacman does not support partial upgrades, so this upgrades every package"
                } else {
                    "Upgrade the selected packages that have a newer version"
                };
                if ui
                    .add_enabled(can_upgrade, egui::Button::new(label))
                    .on_hover_text(hover)
                    .clicked()
                {
                    upgrade = true;
                }
            });
        });
        if let Some(e) = &self.pkg_error {
            ui.colored_label(Color32::from_rgb(220, 90, 80), e);
        }
        ui.separator();

        let arrow = |active: bool, desc: bool| {
            if !active {
                ""
            } else if desc {
                " ⏷"
            } else {
                " ⏶"
            }
        };
        let (sort, desc) = (self.sort, self.sort_desc);
        let mut new_sort = None;
        let rows = &mut self.rows;
        let (unused, obsolete, upgradable, collapsed) = (
            &self.unused,
            &self.obsolete,
            &self.upgradable,
            &self.collapsed,
        );
        let conflicts = &self.conflicts;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            // Not resizable, or the table would keep this column's old width instead of growing it.
            .column(Column::remainder().at_least(140.0).clip(true).resizable(false))
            .column(Column::initial(130.0).at_least(60.0).clip(true))
            .column(Column::initial(130.0).at_least(60.0).clip(true))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(90.0).at_least(60.0))
            .header(24.0, |mut h| {
                h.col(|_| {});
                h.col(|ui| {
                    if ui.button(RichText::new(format!("Name{}", arrow(sort == SortBy::Name, desc))).strong()).clicked() {
                        new_sort = Some(SortBy::Name);
                    }
                });
                h.col(|ui| {
                    ui.strong("Installed");
                });
                h.col(|ui| {
                    ui.strong("Available");
                });
                h.col(|ui| {
                    if ui.button(RichText::new(format!("Size{}", arrow(sort == SortBy::Size, desc))).strong()).clicked() {
                        new_sort = Some(SortBy::Size);
                    }
                });
                h.col(|ui| {
                    ui.strong("Origin");
                });
                h.col(|ui| {
                    ui.strong("Status");
                });
            })
            .body(|body| {
                body.rows(22.0, items.len(), |mut row| {
                    let i = match &items[row.index()] {
                        Item::Pkg(i) => *i,
                        Item::Head(c, n, size) => {
                            let open = !collapsed.contains(c);
                            row.col(|_| {});
                            row.col(|ui| {
                                let text = format!("{} {}  ({n} · {})", if open { "▾" } else { "▸" }, c.label(), human(*size));
                                if ui.add(egui::Button::new(RichText::new(text).strong()).frame(false)).clicked() {
                                    toggle = Some(*c);
                                }
                            });
                            for _ in 0..5 {
                                row.col(|_| {});
                            }
                            return;
                        }
                    };
                    let r = &mut rows[i];
                    let protected = pkg::is_protected(&r.pkg.name);
                    let base = r.pkg.name.split(':').next().unwrap_or(&r.pkg.name);
                    let newer = upgradable.get(&r.pkg.name).or_else(|| upgradable.get(base));
                    row.col(|ui| {
                        ui.add_enabled(!protected, egui::Checkbox::without_text(&mut r.selected))
                            .on_disabled_hover_text("Essential system package – protected");
                    });
                    row.col(|ui| {
                        let mut t = RichText::new(&r.pkg.name);
                        if protected {
                            t = t.weak();
                        }
                        match conflicts.get(&r.pkg.name) {
                            Some(c) => {
                                let list = c.join(", ");
                                ui.horizontal(|ui| {
                                    ui.label(t);
                                    ui.label(RichText::new(format!("⚔ conflicts with {list}")).color(Color32::from_rgb(230, 110, 80)).small());
                                })
                                .response
                                .on_hover_text(format!("Declared to conflict with: {list}"));
                            }
                            None => {
                                ui.label(t);
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&r.pkg.version).monospace().size(11.5));
                    });
                    row.col(|ui| {
                        let mono = |t: &str| RichText::new(t.to_string()).monospace().size(11.5);
                        match newer {
                            Some(new) => {
                                ui.label(mono(new).color(Color32::from_rgb(90, 160, 230)))
                                    .on_hover_text(format!("Installed {}, newer {new} is available", r.pkg.version));
                            }
                            None if is_unused(obsolete, &r.pkg.name) => {
                                ui.label(RichText::new("not in repo").weak().size(11.5))
                                    .on_hover_text("No enabled repository provides this package");
                            }
                            None if upgrades_known => {
                                ui.label(RichText::new("up to date").weak().size(11.5))
                                    .on_hover_text("The repository has no newer version than the one installed");
                            }
                            None => {
                                ui.label(RichText::new("–").weak());
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(human(r.pkg.size));
                        });
                    });
                    row.col(|ui| {
                        ui.label(match r.pkg.manual {
                            Some(true) => RichText::new("you"),
                            Some(false) => RichText::new("dependency").weak(),
                            None => RichText::new("–").weak(),
                        });
                    });
                    row.col(|ui| {
                        if is_unused(unused, &r.pkg.name) {
                            ui.label(RichText::new("unused").color(Color32::from_rgb(90, 190, 110)));
                        } else if is_unused(obsolete, &r.pkg.name) {
                            ui.label(RichText::new("obsolete").color(Color32::from_rgb(230, 170, 60)))
                                .on_hover_text("Not provided by any enabled repository – review before removing");
                        } else {
                            ui.label(RichText::new("in use").weak());
                        }
                    });
                });
            });

        if let Some(c) = toggle
            && !self.collapsed.remove(&c)
        {
            self.collapsed.insert(c);
        }
        if let Some(s) = new_sort {
            if self.sort == s {
                self.sort_desc = !self.sort_desc;
            } else {
                self.sort = s;
                self.sort_desc = s == SortBy::Size;
            }
        }
        if reload {
            self.refresh();
        }
        if upgrade {
            let names: Vec<String> = if self.pm.is_some_and(Pm::upgrade_is_full) {
                let mut v: Vec<String> = self.upgradable.keys().cloned().collect();
                v.sort();
                v
            } else {
                self.rows
                    .iter()
                    .filter(|r| r.selected)
                    .filter(|r| {
                        let base = r.pkg.name.split(':').next().unwrap_or(&r.pkg.name);
                        self.upgradable.contains_key(&r.pkg.name)
                            || self.upgradable.contains_key(base)
                    })
                    .map(|r| {
                        r.pkg
                            .name
                            .split(':')
                            .next()
                            .unwrap_or(&r.pkg.name)
                            .to_string()
                    })
                    .collect()
            };
            self.confirm = Some(Confirm::Upgrade { names });
        }
        if remove {
            let names: Vec<String> = self
                .rows
                .iter()
                .filter(|r| r.selected)
                .map(|r| r.pkg.name.clone())
                .collect();
            self.start_preview(names);
        }
    }
}

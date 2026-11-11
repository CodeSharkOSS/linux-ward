//! Navigation: tabs are grouped into four sections so the top bar stays readable.

use super::*;

#[derive(PartialEq, Clone, Copy)]
pub(super) enum Section {
    FreeSpace,
    Software,
    Developer,
    Health,
}

#[derive(PartialEq, Clone, Copy)]
pub(super) enum Tab {
    Cleanup,
    LargeFiles,
    Duplicates,
    Packages,
    Services,
    Projects,
    Ports,
    Java,
    Performance,
    Security,
    Processes,
}

impl Section {
    const ALL: [Section; 4] = [
        Section::FreeSpace,
        Section::Software,
        Section::Developer,
        Section::Health,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::FreeSpace => "💾 Free space",
            Section::Software => "📦 Software",
            Section::Developer => "🛠 Developer",
            Section::Health => "🩺 Health & security",
        }
    }

    fn tabs(self) -> &'static [Tab] {
        match self {
            Section::FreeSpace => &[Tab::Cleanup, Tab::LargeFiles, Tab::Duplicates],
            Section::Software => &[Tab::Packages, Tab::Services],
            Section::Developer => &[Tab::Projects, Tab::Ports, Tab::Java],
            Section::Health => &[Tab::Performance, Tab::Security, Tab::Processes],
        }
    }
}

impl Tab {
    pub(super) fn section(self) -> Section {
        Section::ALL
            .into_iter()
            .find(|s| s.tabs().contains(&self))
            .unwrap_or(Section::FreeSpace)
    }

    fn icon(self) -> &'static str {
        match self {
            Tab::Cleanup => "🗑",
            Tab::LargeFiles => "📁",
            Tab::Duplicates => "📋",
            Tab::Packages => "📦",
            Tab::Services => "⚙",
            Tab::Projects => "🏗",
            Tab::Ports => "🔌",
            Tab::Java => "☕",
            Tab::Performance => "🚀",
            Tab::Security => "🔑",
            Tab::Processes => "🔍",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Tab::Cleanup => "Quick clean",
            Tab::LargeFiles => "Large files",
            Tab::Duplicates => "Duplicates",
            Tab::Packages => "Packages",
            Tab::Services => "Services",
            Tab::Projects => "Dev cleanup",
            Tab::Ports => "Open ports",
            Tab::Java => "Java",
            Tab::Performance => "Health & speed",
            Tab::Security => "Security",
            Tab::Processes => "Suspect processes",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Tab::Cleanup => "Caches, logs, Trash, unused packages and other safe-to-remove items",
            Tab::LargeFiles => "Find the biggest files in a folder",
            Tab::Duplicates => "Find identical files and keep one copy",
            Tab::Packages => "Browse, upgrade and remove installed packages; see conflicts",
            Tab::Services => "What is running in the background, and what each service does",
            Tab::Projects => {
                "Build output, old toolchains, old IDE versions, Android SDK and git housekeeping"
            }
            Tab::Ports => "Programs listening for network connections",
            Tab::Java => "Installed JVMs, running Java processes and memory tuning",
            Tab::Performance => {
                "Boot time, startup items, kernels, tuning and system health checks"
            }
            Tab::Security => "Find files that may hold secrets, and permission mistakes",
            Tab::Processes => {
                "Running programs that look unusual: deleted or /tmp executables, imitated names, hidden processes"
            }
        }
    }
}

impl App {
    /// Two clearly different levels: sections are large filled pills; the tabs inside the current
    /// section sit on a tinted strip below, in smaller text, with an underline marking the active one.
    pub(super) fn top_bar(&mut self, ui: &mut egui::Ui) {
        let accent = ui.visuals().selection.bg_fill;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("🧹 LinuxWard");
            ui.add_space(14.0);
            let current = self.tab.section();
            for s in Section::ALL {
                let active = current == s;
                let text = RichText::new(s.label()).size(15.0).strong();
                let text = if active {
                    text.color(ui.visuals().selection.stroke.color)
                } else {
                    text
                };
                let button = egui::Button::new(text)
                    .fill(if active { accent } else { Color32::TRANSPARENT })
                    .min_size(egui::vec2(0.0, 30.0))
                    .corner_radius(15.0);
                if ui.add(button).clicked() && !active {
                    // Go to the tab last used in that section, or its first.
                    self.tab = self
                        .last_tab
                        .get(&s.label())
                        .copied()
                        .unwrap_or(s.tabs()[0]);
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(b) = &self.busy {
                    ui.label(b);
                    ui.spinner();
                } else if let Some(pm) = self.pm {
                    ui.label(RichText::new(pm.name()).weak());
                }
            });
        });
        ui.add_space(4.0);

        // Sub-tabs: a full-width tinted strip so it reads as belonging to the section above.
        let strip = ui.visuals().faint_bg_color.gamma_multiply(1.6);
        egui::Frame::new()
            .fill(strip)
            .inner_margin(egui::Margin::symmetric(14, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    // Give each tab room: roomier buttons and more space between them.
                    ui.spacing_mut().button_padding = egui::vec2(12.0, 6.0);
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let section = self.tab.section();
                    ui.label(
                        RichText::new(format!(
                            "{} ›",
                            section.label().split_once(' ').map_or("", |p| p.1)
                        ))
                        .weak()
                        .small(),
                    );
                    ui.add_space(4.0);
                    for &t in section.tabs() {
                        let enabled = t != Tab::Packages || self.pm.is_some();
                        let hint = if enabled {
                            t.hint()
                        } else {
                            "No supported package manager was found"
                        };
                        let active = self.tab == t;
                        let text = RichText::new(format!("{}  {}", t.icon(), t.label())).size(14.0);
                        let text = if active {
                            text.strong().color(ui.visuals().hyperlink_color)
                        } else {
                            text
                        };
                        let resp = ui
                            .add_enabled(enabled, egui::Button::new(text).frame(false))
                            .on_hover_text(hint);
                        if active {
                            let r = resp.rect;
                            ui.painter().hline(
                                r.x_range(),
                                r.bottom() + 1.0,
                                egui::Stroke::new(2.0, ui.visuals().hyperlink_color),
                            );
                        }
                        if resp.clicked() {
                            self.tab = t;
                        }
                    }
                    self.last_tab.insert(section.label(), self.tab);
                });
            });
    }
}

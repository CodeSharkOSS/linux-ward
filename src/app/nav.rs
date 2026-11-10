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
            Section::Health => &[Tab::Performance, Tab::Security],
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
        }
    }
}

impl App {
    pub(super) fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("🧹 Disk Cleaner");
            ui.separator();
            let current = self.tab.section();
            for s in Section::ALL {
                if ui
                    .selectable_label(current == s, RichText::new(s.label()).strong())
                    .clicked()
                    && current != s
                {
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
        ui.horizontal(|ui| {
            let section = self.tab.section();
            for &t in section.tabs() {
                let enabled = t != Tab::Packages || self.pm.is_some();
                let hint = if enabled {
                    t.hint()
                } else {
                    "No supported package manager was found"
                };
                ui.add_enabled_ui(enabled, |ui| {
                    ui.selectable_value(&mut self.tab, t, t.label())
                        .on_hover_text(hint);
                });
            }
            self.last_tab.insert(section.label(), self.tab);
        });
        ui.add_space(2.0);
    }
}

//! The Disks & filesystems tab: SMART health, filesystem checks, fstab and kernel-log errors,
//! each finding with the repairs that exist for it.

use super::perf_ui::{AMBER, BLUE, GREEN, RED};
use super::{App, Color32, Confirm, Msg, RichText, egui};
use crate::fshealth::{self, Finding, Item, Repair, Sev};

fn sev_style(s: Sev) -> (&'static str, Color32) {
    match s {
        Sev::Ok => ("✔", GREEN),
        Sev::Info => ("ℹ", BLUE),
        Sev::Warn => ("⚠", AMBER),
        Sev::Bad => ("✘", RED),
    }
}

fn show_finding(ui: &mut egui::Ui, f: &Finding, chosen: &mut Option<Repair>) {
    let (icon, color) = sev_style(f.sev);
    ui.horizontal_top(|ui| {
        ui.label(RichText::new(icon).color(color).strong());
        ui.vertical(|ui| {
            ui.label(&f.text);
            if let Some(a) = &f.advice {
                ui.label(RichText::new(a).weak().small());
            }
            if !f.repairs.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for r in &f.repairs {
                        let label = if r.risky {
                            format!("🔧 {}…", r.label)
                        } else {
                            format!("{}…", r.label)
                        };
                        if ui.button(label).on_hover_text(&r.note).clicked() {
                            *chosen = Some(r.clone());
                        }
                    }
                });
            }
        });
    });
    ui.add_space(3.0);
}

fn show_item(ui: &mut egui::Ui, item: &Item, chosen: &mut Option<Repair>) {
    let (icon, color) = sev_style(item.worst());
    let head = RichText::new(format!("{icon}  {}", item.title))
        .color(color)
        .strong();
    egui::CollapsingHeader::new(head)
        .id_salt(&item.title)
        .default_open(item.worst() >= Sev::Warn)
        .show(ui, |ui| {
            if !item.subtitle.is_empty() {
                ui.label(RichText::new(&item.subtitle).weak());
            }
            for f in &item.findings {
                show_finding(ui, f, chosen);
            }
            if !item.raw.trim().is_empty() {
                egui::CollapsingHeader::new("Tool output")
                    .id_salt(("raw", &item.title))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt(("rawscroll", &item.title))
                            .max_height(240.0)
                            .show(ui, |ui| {
                                ui.label(RichText::new(item.raw.trim_end()).monospace().size(11.5));
                            });
                    });
            }
        });
}

impl App {
    fn start_fs_scan(&mut self) {
        self.fs_scanning = true;
        self.fs_stale = false;
        let n = self.notifier();
        std::thread::spawn(move || n.send(Msg::FsReport(Box::new(fshealth::scan()))));
    }

    pub(super) fn disks_tab(&mut self, ui: &mut egui::Ui) {
        let mut scan = false;
        let mut chosen: Option<Repair> = None;
        ui.horizontal(|ui| {
            ui.heading("💽 Disks & filesystems");
            if self.fs_scanning {
                ui.spinner();
                ui.label("Scanning…");
            } else if ui
                .button(if self.fs_report.is_some() {
                    "Scan again"
                } else {
                    "Scan"
                })
                .clicked()
            {
                scan = true;
            }
        });
        ui.label(
            RichText::new("Reads each drive's SMART health and checks every ext2/3/4, XFS, Btrfs and FAT filesystem, /etc/fstab and the kernel log. Scanning changes nothing and asks for your password once. Repairs are offered next to each problem and always ask first.")
                .weak(),
        );
        if self.fs_stale {
            ui.colored_label(
                AMBER,
                "A repair just ran: scan again to confirm the result.",
            );
        }
        ui.separator();

        let busy = self.busy.is_some();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                let Some(r) = &self.fs_report else {
                    if !self.fs_scanning {
                        ui.add_space(20.0);
                        ui.label("Press Scan to check your drives and filesystems.");
                    }
                    return;
                };
                for n in &r.notes {
                    ui.colored_label(AMBER, format!("⚠ {n}"));
                }
                let problems = r
                    .drives
                    .iter()
                    .chain(&r.filesystems)
                    .chain([&r.mounts, &r.kernel])
                    .filter(|i| i.worst() >= Sev::Warn)
                    .count();
                if problems == 0 {
                    ui.colored_label(GREEN, "✔ Nothing needs attention.");
                } else {
                    ui.colored_label(
                        RED,
                        format!("{problems} item(s) need attention (expanded below)."),
                    );
                }
                ui.add_space(6.0);

                ui.add_enabled_ui(!busy, |ui| {
                    ui.strong("Drives (SMART)");
                    if r.drives.is_empty() {
                        ui.label(RichText::new("No physical drives found.").weak());
                    }
                    for i in &r.drives {
                        show_item(ui, i, &mut chosen);
                    }
                    ui.add_space(8.0);
                    ui.strong("Filesystems");
                    if r.filesystems.is_empty() {
                        ui.label(
                            RichText::new("No ext2/3/4, XFS, Btrfs or FAT filesystems found.")
                                .weak(),
                        );
                    }
                    for i in &r.filesystems {
                        show_item(ui, i, &mut chosen);
                    }
                    ui.add_space(8.0);
                    ui.strong("System");
                    show_item(ui, &r.mounts, &mut chosen);
                    show_item(ui, &r.kernel, &mut chosen);
                });
            });

        if scan {
            self.start_fs_scan();
        }
        if let Some(r) = chosen {
            let mut note = r.note;
            if r.risky {
                note.push_str("\n\nThis can change or remove data on the disk. Make sure you have a backup of anything important.");
            }
            self.confirm = Some(Confirm::Perf {
                title: r.label,
                note: Some(note),
                actions: r.actions,
            });
        }
    }
}

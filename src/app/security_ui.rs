//! The Security tab: lists files that commonly hold secrets, and permission mistakes.

use super::*;
use crate::secscan::{self, Finding, Severity};

pub(super) struct SecEntry {
    pub f: Finding,
    pub selected: bool,
}

impl App {
    fn start_security_scan(&mut self) {
        self.sec_scanning = true;
        let root = PathBuf::from(self.sec_root.trim());
        let opts = secscan::Options {
            scan_contents: self.sec_contents,
        };
        let n = self.notifier();
        std::thread::spawn(move || {
            let (found, scanned) = secscan::scan(&root, opts);
            n.send(Msg::Security(found, scanned));
        });
    }

    pub(super) fn security_tab(&mut self, ui: &mut egui::Ui) {
        let mut scan = false;
        let mut trash_now = false;
        let mut restrict: Option<PathBuf> = None;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Folder");
            ui.add(egui::TextEdit::singleline(&mut self.sec_root).desired_width(260.0));
            ui.checkbox(&mut self.sec_contents, "Look inside text files for keys and tokens")
                .on_hover_text("Reads small config/text files and looks for private keys, cloud and API tokens, and passwords in URLs. Secret values are never shown or stored.");
            if self.sec_scanning {
                ui.spinner();
                ui.label(RichText::new("scanning…").weak());
            } else if ui.button("Scan").clicked() {
                scan = true;
            }
        });
        ui.label(
            RichText::new("Finds files that commonly hold secrets so you can check they're protected or shouldn't be there. Findings are leads, not proof: review each before acting. Nothing is changed unless you click.")
                .weak()
                .size(12.0),
        );

        let count = |s: Severity| self.sec.iter().filter(|e| e.f.severity == s).count();
        let selected: Vec<PathBuf> = self
            .sec
            .iter()
            .filter(|e| e.selected)
            .map(|e| e.f.path.clone())
            .collect();
        ui.horizontal(|ui| {
            if self.sec_scanned > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} findings ({} high · {} medium · {} info) in {} files",
                        self.sec.len(),
                        count(Severity::High),
                        count(Severity::Medium),
                        count(Severity::Low),
                        self.sec_scanned
                    ))
                    .weak(),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !selected.is_empty() && self.busy.is_none(),
                        egui::Button::new("Move selected to Trash"),
                    )
                    .clicked()
                {
                    trash_now = true;
                }
            });
        });
        ui.separator();

        let sec = &mut self.sec;
        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            .column(Column::exact(60.0))
            .column(Column::initial(190.0).at_least(100.0).clip(true))
            .column(Column::remainder().at_least(150.0).clip(true))
            .column(Column::exact(150.0))
            .header(24.0, |mut h| {
                h.col(|_| {});
                for t in ["Risk", "What", "Where / details", ""] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(40.0, sec.len(), |mut row| {
                    let e = &mut sec[row.index()];
                    row.col(|ui| {
                        ui.add(egui::Checkbox::without_text(&mut e.selected));
                    });
                    row.col(|ui| {
                        let color = match e.f.severity {
                            Severity::High => Color32::from_rgb(230, 90, 80),
                            Severity::Medium => Color32::from_rgb(230, 170, 60),
                            Severity::Low => Color32::GRAY,
                        };
                        ui.label(RichText::new(e.f.severity.label()).color(color).strong());
                    });
                    row.col(|ui| {
                        ui.label(&e.f.kind);
                    });
                    row.col(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(e.f.path.display().to_string()).monospace().size(12.0))
                                .on_hover_text(e.f.path.display().to_string());
                            ui.label(RichText::new(format!("{} · mode {:o}", e.f.detail, e.f.mode)).weak().small());
                        });
                    });
                    row.col(|ui| {
                        if e.f.fixable
                            && ui.small_button("Restrict").on_hover_text("chmod: remove access for everyone but you (600 for files, 700 for folders)").clicked()
                        {
                            restrict = Some(e.f.path.clone());
                        }
                        if ui.small_button("Open").on_hover_text("Open containing folder").clicked()
                            && let Some(parent) = e.f.path.parent()
                        {
                            util::open(parent);
                        }
                    });
                });
            });

        if scan {
            self.start_security_scan();
        }
        if let Some(p) = restrict {
            match secscan::restrict(&p) {
                Ok(()) => {
                    self.log
                        .push(format!("✔ Restricted permissions on {}", p.display()));
                    // Re-evaluate: drop the entry if it was only a permission problem.
                    if let Some(i) = self.sec.iter().position(|e| e.f.path == p) {
                        let e = &mut self.sec[i];
                        let by_perm = e.f.kind.contains("not private")
                            || e.f.kind.starts_with("World-writable");
                        if by_perm {
                            self.sec.remove(i);
                        } else {
                            e.f.fixable = false;
                            e.f.mode = if p.is_dir() { 0o700 } else { 0o600 };
                            if e.f.severity == Severity::High {
                                e.f.severity = Severity::Medium;
                            }
                        }
                    }
                }
                Err(err) => self
                    .log
                    .push(format!("✘ Could not restrict {}: {err}", p.display())),
            }
        }
        if trash_now {
            self.confirm = Some(Confirm::Files {
                size: 0,
                paths: selected,
                permanent: false,
            });
        }
    }
}

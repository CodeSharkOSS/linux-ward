//! The Duplicates tab: find identical files, keep one copy, move the rest to Trash.

use super::*;
use crate::dupes::{self, DupGroup};

pub(super) struct DupEntry {
    pub path: PathBuf,
    pub age: String,
    pub selected: bool,
}

pub(super) struct DupView {
    pub size: u64,
    pub files: Vec<DupEntry>,
}

impl DupView {
    pub(super) fn from(g: DupGroup) -> Self {
        DupView {
            size: g.size,
            files: g
                .files
                .into_iter()
                .map(|f| DupEntry {
                    path: f.path,
                    age: f
                        .modified
                        .and_then(|t| t.elapsed().ok())
                        .map(|d| format!("{} days ago", d.as_secs() / 86_400))
                        .unwrap_or_default(),
                    selected: false,
                })
                .collect(),
        }
    }
}

impl App {
    fn start_dupes_scan(&mut self) {
        self.dupes_scanning = true;
        let root = PathBuf::from(self.dupes_root.trim());
        let min = self.dupes_min_mb * 1024 * 1024;
        let hidden = self.dupes_hidden;
        let n = self.notifier();
        std::thread::spawn(move || {
            let (groups, scanned) = dupes::scan(&root, min, hidden);
            n.send(Msg::Dupes(groups, scanned));
        });
    }

    pub(super) fn dupes_tab(&mut self, ui: &mut egui::Ui) {
        let mut scan = false;
        let mut auto = false;
        let mut trash_now = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Folder");
            ui.add(egui::TextEdit::singleline(&mut self.dupes_root).desired_width(260.0));
            ui.label("Larger than");
            ui.add(
                egui::DragValue::new(&mut self.dupes_min_mb)
                    .range(0..=1_000_000)
                    .suffix(" MB"),
            );
            ui.checkbox(&mut self.dupes_hidden, "Include hidden folders");
            if self.dupes_scanning {
                ui.spinner();
                ui.label(RichText::new("scanning and comparing…").weak());
            } else if ui.button("Scan").clicked() {
                scan = true;
            }
        });

        let wasted: u64 = self
            .dupes
            .iter()
            .map(|g| g.size * (g.files.len() as u64 - 1))
            .sum();
        let sel: Vec<&DupEntry> = self
            .dupes
            .iter()
            .flat_map(|g| &g.files)
            .filter(|f| f.selected)
            .collect();
        let sel_size: u64 = self
            .dupes
            .iter()
            .map(|g| g.size * g.files.iter().filter(|f| f.selected).count() as u64)
            .sum();
        // Never allow deleting every copy of a file.
        let wiped = self
            .dupes
            .iter()
            .filter(|g| g.files.iter().all(|f| f.selected))
            .count();
        ui.horizontal(|ui| {
            if self.dupes_scanned > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} sets of duplicates · {} wasted · {} files checked",
                        self.dupes.len(),
                        human(wasted),
                        self.dupes_scanned
                    ))
                    .weak(),
                );
                ui.separator();
            }
            ui.label(format!("{} selected · {}", sel.len(), human(sel_size)));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let can = !sel.is_empty() && wiped == 0 && self.busy.is_none();
                let btn = ui.add_enabled(can, egui::Button::new("Move selected to Trash"));
                if wiped > 0 {
                    btn.on_disabled_hover_text(
                        "Every copy in at least one set is selected. Keep one.",
                    );
                } else if btn.clicked() {
                    trash_now = true;
                }
                if ui
                    .add_enabled(
                        !self.dupes.is_empty(),
                        egui::Button::new("Select all but the oldest"),
                    )
                    .on_hover_text("In each set, keep the oldest copy and select the rest")
                    .clicked()
                {
                    auto = true;
                }
            });
        });
        if wiped > 0 {
            ui.colored_label(
                Color32::from_rgb(230, 160, 60),
                format!(
                    "⚠ {wiped} set(s) have every copy selected – deselect one in each to continue."
                ),
            );
        }
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                for (gi, g) in self.dupes.iter_mut().enumerate() {
                    let head = format!(
                        "{} × {}  ·  {} wasted",
                        g.files.len(),
                        human(g.size),
                        human(g.size * (g.files.len() as u64 - 1))
                    );
                    egui::CollapsingHeader::new(RichText::new(head).strong())
                        .id_salt(("dupe", gi))
                        .show(ui, |ui| {
                            for f in &mut g.files {
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut f.selected, "");
                                    ui.label(
                                        RichText::new(f.path.display().to_string())
                                            .monospace()
                                            .size(12.0),
                                    )
                                    .on_hover_text(f.path.display().to_string());
                                    ui.label(RichText::new(&f.age).weak().small());
                                    if ui
                                        .small_button("Open")
                                        .on_hover_text("Open containing folder")
                                        .clicked()
                                        && let Some(parent) = f.path.parent()
                                    {
                                        util::open(parent);
                                    }
                                });
                            }
                        });
                }
            });

        if scan {
            self.start_dupes_scan();
        }
        if auto {
            for g in &mut self.dupes {
                for (i, f) in g.files.iter_mut().enumerate() {
                    f.selected = i > 0; // files are sorted oldest first
                }
            }
        }
        if trash_now {
            let paths: Vec<PathBuf> = self
                .dupes
                .iter()
                .flat_map(|g| &g.files)
                .filter(|f| f.selected)
                .map(|f| f.path.clone())
                .collect();
            self.confirm = Some(Confirm::Files {
                size: sel_size,
                paths,
                permanent: false,
            });
        }
    }
}

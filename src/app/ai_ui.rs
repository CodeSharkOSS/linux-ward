//! The AI configs tab: find Claude, Codex, Gemini, Cursor, Copilot and other AI assistant
//! config/instruction files, and edit them in place (with a backup made on every save).

use std::path::PathBuf;

use super::{
    Align, App, Color32, Column, Layout, Msg, RichText, TableBuilder, egui, field_width, human,
    util,
};
use crate::aiconf::{self, AiFile};

pub(super) struct AiState {
    pub files: Vec<AiFile>,
    pub scanning: bool,
    pub scanned_once: bool,
    pub root: String,
    pub visited: usize,
    pub filter: String,
    /// The file open in the editor.
    pub open: Option<AiFile>,
    pub text: String,
    /// Text as last read from or written to disk, to tell whether there are unsaved edits.
    pub saved: String,
    pub load_error: Option<String>,
    pub json_error: Option<String>,
    /// Sensitive files stay hidden until the user asks to see them.
    pub reveal: bool,
}

impl AiState {
    pub fn new() -> Self {
        Self {
            files: vec![],
            scanning: false,
            scanned_once: false,
            root: util::home().display().to_string(),
            visited: 0,
            filter: String::new(),
            open: None,
            text: String::new(),
            saved: String::new(),
            load_error: None,
            json_error: None,
            reveal: false,
        }
    }

    pub fn dirty(&self) -> bool {
        self.open.is_some() && self.text != self.saved
    }
}

impl App {
    fn start_ai_scan(&mut self) {
        self.ai.scanning = true;
        let root = PathBuf::from(self.ai.root.trim());
        let n = self.notifier();
        std::thread::spawn(move || {
            let (files, visited) = aiconf::scan(&root);
            n.send(Msg::AiConfigs(files, visited));
        });
    }

    fn open_ai_file(&mut self, f: &AiFile) {
        let ai = &mut self.ai;
        ai.open = Some(f.clone());
        ai.reveal = false;
        match aiconf::load(&f.path) {
            Ok(t) => {
                ai.json_error = aiconf::json_error(&f.path, &t);
                ai.saved.clone_from(&t);
                ai.text = t;
                ai.load_error = None;
            }
            Err(e) => {
                ai.text.clear();
                ai.saved.clear();
                ai.json_error = None;
                ai.load_error = Some(e);
            }
        }
    }

    fn save_ai_file(&mut self) {
        let Some(f) = self.ai.open.clone() else {
            return;
        };
        let line = match aiconf::save(&f.path, &self.ai.text) {
            Ok(backup) => {
                self.ai.saved.clone_from(&self.ai.text);
                format!(
                    "✔ Saved {} (previous version kept at {})",
                    f.path.display(),
                    backup.display()
                )
            }
            Err(e) => format!("✘ Could not save {}: {e}", f.path.display()),
        };
        util::log_action(&line);
        self.log.push(line);
    }

    pub(super) fn ai_editor_panel(&mut self, ui: &mut egui::Ui) {
        let Some(file) = self.ai.open.clone() else {
            return;
        };
        let mut close = false;
        let mut save = false;
        let mut revert = false;
        let frame = egui::Frame::side_top_panel(ui.style())
            .fill(ui.visuals().extreme_bg_color)
            .inner_margin(10.0);
        egui::Panel::right("ai_editor")
            .frame(frame)
            .resizable(true)
            .default_size(560.0)
            .min_size(320.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        file.path.file_name().map_or_else(
                            || "File".to_string(),
                            |n| n.to_string_lossy().into_owned(),
                        ),
                    );
                    if ui.small_button("✕").on_hover_text("Close").clicked() {
                        close = true;
                    }
                });
                ui.label(
                    RichText::new(file.path.display().to_string())
                        .monospace()
                        .size(12.0),
                );
                ui.label(
                    RichText::new(format!("{} · {}", file.tool, file.kind))
                        .weak()
                        .small(),
                );
                ui.add_space(4.0);
                if let Some(e) = &self.ai.load_error {
                    ui.colored_label(Color32::from_rgb(220, 90, 80), e);
                    return;
                }
                if file.sensitive && !self.ai.reveal {
                    ui.colored_label(
                        Color32::from_rgb(230, 160, 60),
                        "This file may contain API keys or login tokens, so it is hidden.",
                    );
                    if ui.button("Show and edit anyway").clicked() {
                        self.ai.reveal = true;
                    }
                    return;
                }
                let dirty = self.ai.dirty();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(dirty, egui::Button::new("💾 Save"))
                        .clicked()
                    {
                        save = true;
                    }
                    if ui.add_enabled(dirty, egui::Button::new("Revert")).clicked() {
                        revert = true;
                    }
                    if ui.button("Open folder").clicked()
                        && let Some(p) = file.path.parent()
                    {
                        util::open(p);
                    }
                    if dirty {
                        ui.label(
                            RichText::new("unsaved changes").color(Color32::from_rgb(230, 160, 60)),
                        );
                    }
                });
                if let Some(e) = &self.ai.json_error {
                    ui.colored_label(
                        Color32::from_rgb(220, 90, 80),
                        format!("Not valid JSON: {e}. The tool may ignore or reject this file."),
                    );
                }
                ui.add_space(4.0);
                egui::ScrollArea::both().auto_shrink(false).show(ui, |ui| {
                    let changed = ui
                        .add(
                            egui::TextEdit::multiline(&mut self.ai.text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(30),
                        )
                        .changed();
                    if changed {
                        self.ai.json_error = aiconf::json_error(&file.path, &self.ai.text);
                    }
                });
            });
        if save {
            self.save_ai_file();
        }
        if revert {
            self.ai.text.clone_from(&self.ai.saved);
            self.ai.json_error = aiconf::json_error(&file.path, &self.ai.text);
        }
        if close && !self.ai.dirty() {
            self.ai.open = None;
        } else if close {
            self.log
                .push("Save or revert your changes before closing the editor.".into());
        }
    }

    pub(super) fn ai_tab(&mut self, ui: &mut egui::Ui) {
        if !self.ai.scanned_once && !self.ai.scanning {
            self.ai.scanned_once = true;
            self.start_ai_scan();
        }
        let mut scan = false;
        let mut to_open: Option<AiFile> = None;
        let dirty = self.ai.dirty();

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Folder");
            ui.add(
                egui::TextEdit::singleline(&mut self.ai.root)
                    .desired_width(field_width(ui, 0.3, 220.0, 700.0)),
            );
            ui.label("Filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.ai.filter)
                    .desired_width(160.0)
                    .hint_text("tool, kind or path"),
            );
            if self.ai.scanning {
                ui.spinner();
                ui.label(RichText::new("scanning…").weak());
            } else if ui.button("Scan").clicked() {
                scan = true;
            }
        });
        ui.label(
            RichText::new(
                "Finds config, instruction and memory files for Claude Code, Codex, Gemini, Cursor, Copilot, Aider and similar tools, in your home folder and inside projects under the folder above. Click a file to edit it; a copy of the old version is kept on every save.",
            )
            .weak()
            .small(),
        );
        if self.ai.visited > 0 {
            ui.label(
                RichText::new(format!(
                    "{} found in {} files",
                    self.ai.files.len(),
                    self.ai.visited
                ))
                .weak(),
            );
        }
        if dirty {
            ui.colored_label(
                Color32::from_rgb(230, 160, 60),
                "Save or revert the open file before opening another.",
            );
        }
        ui.separator();

        let needle = self.ai.filter.trim().to_lowercase();
        let rows: Vec<&AiFile> = self
            .ai
            .files
            .iter()
            .filter(|f| {
                needle.is_empty()
                    || f.tool.to_lowercase().contains(&needle)
                    || f.kind.to_lowercase().contains(&needle)
                    || f.path.to_string_lossy().to_lowercase().contains(&needle)
            })
            .collect();
        let open_path = self.ai.open.as_ref().map(|f| f.path.clone());
        ui.add_enabled_ui(!dirty, |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::exact(170.0))
                .column(Column::exact(110.0))
                .column(Column::remainder().clip(true))
                .column(Column::exact(70.0))
                .header(24.0, |mut h| {
                    for t in ["Tool", "Kind", "Path", "Size"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|body| {
                    body.rows(22.0, rows.len(), |mut row| {
                        let f = rows[row.index()];
                        let is_open = open_path.as_ref() == Some(&f.path);
                        row.col(|ui| {
                            ui.label(f.tool);
                        });
                        row.col(|ui| {
                            let k = if f.sensitive {
                                format!("🔒 {}", f.kind)
                            } else {
                                f.kind.to_string()
                            };
                            ui.label(k);
                        });
                        row.col(|ui| {
                            let text = RichText::new(f.path.display().to_string())
                                .monospace()
                                .size(12.0);
                            if ui
                                .selectable_label(is_open, text)
                                .on_hover_text(f.path.display().to_string())
                                .clicked()
                            {
                                to_open = Some(f.clone());
                            }
                        });
                        row.col(|ui| {
                            ui.label(human(f.size));
                        });
                    });
                });
        });
        if self.ai.scanned_once && !self.ai.scanning && self.ai.files.is_empty() {
            ui.label("No AI config files found under this folder.");
        }

        if scan {
            self.start_ai_scan();
        }
        if let Some(f) = to_open {
            self.open_ai_file(&f);
        }
    }
}

//! The Large files tab: find big files and move them to Trash.

use super::*;

impl App {
    pub(super) fn start_large_scan(&mut self) {
        self.large_scanning = true;
        let root = PathBuf::from(self.large_root.trim());
        let min = self.large_min_mb * 1024 * 1024;
        let include_hidden = self.large_hidden;
        let n = self.notifier();
        std::thread::spawn(move || {
            let mut scanned = 0;
            let mut found: Vec<(PathBuf, u64)> = walkdir::WalkDir::new(&root)
                .follow_links(false)
                .same_file_system(true)
                .into_iter()
                // Hidden folders hold toolchains, caches and app data that are rarely safe to delete by hand.
                .filter_entry(|e| {
                    e.depth() == 0
                        || (!util::excluded(e.path())
                            && (include_hidden
                                || !e.file_name().to_string_lossy().starts_with('.')))
                })
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
                .inspect(|_| scanned += 1)
                .filter_map(|e| e.metadata().ok().map(|m| (e.into_path(), m.len())))
                .filter(|(_, len)| *len >= min)
                .collect();
            found.sort_by_key(|f| std::cmp::Reverse(f.1));
            found.truncate(1000);
            n.send(Msg::Large(found, scanned));
        });
    }

    pub(super) fn start_delete_files(&mut self, paths: Vec<PathBuf>, permanent: bool) {
        self.busy = Some("Deleting files…".into());
        let n = self.notifier();
        std::thread::spawn(move || {
            if permanent {
                let mut ok = 0;
                for p in &paths {
                    match std::fs::remove_file(p) {
                        Ok(()) => ok += 1,
                        Err(e) => n.send(Msg::Log(format!("✘ {}: {e}", p.display()))),
                    }
                }
                n.send(Msg::Log(format!("✔ Permanently deleted {ok} file(s)")));
            } else {
                match trash::delete_all(&paths) {
                    Ok(()) => n.send(Msg::Log(format!(
                        "✔ Moved {} file(s) to Trash. Empty the Trash on the Cleanup tab to free the space.",
                        paths.len()
                    ))),
                    Err(e) => n.send(Msg::Log(format!("✘ Could not move to Trash: {e}"))),
                }
            }
            n.send(Msg::Done { refresh: true });
        });
    }

    // ----- UI -------------------------------------------------------------

    pub(super) fn large_tab(&mut self, ui: &mut egui::Ui) {
        let mut scan = false;
        let mut action: Option<bool> = None; // Some(permanent)

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Folder");
            ui.add(egui::TextEdit::singleline(&mut self.large_root).desired_width(260.0));
            ui.label("Larger than");
            ui.add(egui::DragValue::new(&mut self.large_min_mb).range(1..=1_000_000).suffix(" MB"));
            ui.checkbox(&mut self.large_hidden, "Include hidden folders")
                .on_hover_text("Dot-folders like ~/.cargo or ~/.local hold toolchains and app data; caches are better cleaned from the Cleanup tab");
            if self.large_scanning {
                ui.spinner();
                ui.label(RichText::new("scanning…").weak());
            } else if ui.button("Scan").clicked() {
                scan = true;
            }
        });
        ui.horizontal(|ui| {
            let sel: Vec<&LargeFile> = self.large.iter().filter(|f| f.selected).collect();
            let size: u64 = sel.iter().map(|f| f.size).sum();
            if self.large_scanned > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} found in {} files",
                        self.large.len(),
                        self.large_scanned
                    ))
                    .weak(),
                );
                ui.separator();
            }
            ui.label(format!("{} selected · {}", sel.len(), human(size)));
            let any = !sel.is_empty() && self.busy.is_none();
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(any, egui::Button::new("Delete permanently…"))
                    .clicked()
                {
                    action = Some(true);
                }
                if ui
                    .add_enabled(any, egui::Button::new("Move to Trash"))
                    .clicked()
                {
                    action = Some(false);
                }
            });
        });
        ui.separator();

        let large = &mut self.large;
        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            .column(Column::exact(90.0))
            .column(Column::remainder().clip(true))
            .column(Column::exact(48.0))
            .header(24.0, |mut h| {
                h.col(|_| {});
                h.col(|ui| {
                    ui.strong("Size");
                });
                h.col(|ui| {
                    ui.strong("Path");
                });
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(22.0, large.len(), |mut row| {
                    let f = &mut large[row.index()];
                    row.col(|ui| {
                        ui.add(egui::Checkbox::without_text(&mut f.selected));
                    });
                    row.col(|ui| {
                        ui.label(human(f.size));
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(f.path.display().to_string())
                                .monospace()
                                .size(12.0),
                        )
                        .on_hover_text(f.path.display().to_string());
                    });
                    row.col(|ui| {
                        if ui
                            .small_button("Open")
                            .on_hover_text("Open containing folder")
                            .clicked()
                            && let Some(parent) = f.path.parent()
                        {
                            let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
                        }
                    });
                });
            });

        if scan {
            self.start_large_scan();
        }
        if let Some(permanent) = action {
            let sel: Vec<&LargeFile> = self.large.iter().filter(|f| f.selected).collect();
            self.confirm = Some(Confirm::Files {
                size: sel.iter().map(|f| f.size).sum(),
                paths: sel.into_iter().map(|f| f.path.clone()).collect(),
                permanent,
            });
        }
    }
}

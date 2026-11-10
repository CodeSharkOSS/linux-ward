//! The egui user interface. All slow work runs on background threads and
//! reports back through a channel, so the window never freezes.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};

mod dupes_ui;
mod java_ui;
mod perf_ui;
mod security_ui;
mod services_ui;

use crate::java;
use crate::perf;
use crate::pkg::{self, Category, Package, Pm};
use crate::services::{self, Scope};
use crate::targets::{self, Group, Target};
use crate::util::{self, DiskInfo, human};

enum Msg {
    Disks(Vec<DiskInfo>),
    Targets(Vec<Target>),
    Packages(Result<Vec<Package>, String>),
    Unused(HashSet<String>),
    Obsolete(HashSet<String>),
    Conflicts(std::collections::BTreeMap<String, Vec<String>>),
    Upgradable(Option<HashMap<String, String>>),
    Large(Vec<(PathBuf, u64)>, usize),
    Dupes(Vec<crate::dupes::DupGroup>, usize),
    Security(Vec<crate::secscan::Finding>, usize),
    Perf(Box<perf::Snapshot>),
    Java(Box<java::JavaReport>),
    Services(Scope, Vec<services::Svc>),
    SvcDetail(String, Box<services::Detail>),
    ReloadPerf,
    Live(Box<perf::Live>),
    Health(Box<perf::HealthResult>),
    HealthDone,
    Diff(PathBuf, String),
    Preview {
        names: Vec<String>,
        text: String,
        affected: Option<Vec<String>>,
    },
    Log(String),
    Done {
        refresh: bool,
    },
}

#[derive(Clone)]
struct Notifier {
    tx: Sender<Msg>,
    ctx: egui::Context,
}

impl Notifier {
    fn send(&self, m: Msg) {
        let _ = self.tx.send(m);
        self.ctx.request_repaint();
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Cleanup,
    Packages,
    LargeFiles,
    Duplicates,
    Security,
    Performance,
    Services,
    Java,
}

/// Which packages the Packages tab lists.
#[derive(PartialEq, Clone, Copy)]
enum PkgView {
    All,
    /// Nothing depends on these any more: safe to remove.
    Unused,
    /// Installed by the user, or still required by something else.
    InUse,
    /// No enabled repository provides these any more.
    Obsolete,
    /// A newer version is available in a repository.
    Upgradable,
    /// Declared to conflict with another installed package.
    Conflicts,
}

#[derive(PartialEq, Clone, Copy)]
enum SortBy {
    Name,
    Size,
}

enum Confirm {
    Clean(Vec<usize>),
    Remove {
        names: Vec<String>,
        preview: Option<(String, Option<Vec<String>>)>,
    },
    Upgrade {
        names: Vec<String>,
    },
    Perf {
        title: String,
        note: Option<String>,
        actions: Vec<crate::targets::Action>,
    },
    Files {
        paths: Vec<PathBuf>,
        size: u64,
        permanent: bool,
    },
}

struct Row {
    pkg: Package,
    selected: bool,
}

struct LargeFile {
    path: PathBuf,
    size: u64,
    selected: bool,
}

pub struct App {
    pm: Option<Pm>,
    tab: Tab,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    ctx: egui::Context,

    disks: Vec<DiskInfo>,
    targets: Vec<Target>,
    scanning: bool,

    rows: Vec<Row>,
    pkg_loading: bool,
    pkg_error: Option<String>,
    filter: String,
    manual_only: bool,
    view: PkgView,
    unused: HashSet<String>,
    obsolete: HashSet<String>,
    conflicts: std::collections::BTreeMap<String, Vec<String>>,
    /// Package name -> newer available version.
    upgradable: HashMap<String, String>,
    /// False until the upgrade check succeeded (so "up to date" is never shown on a failed check).
    upgradable_known: bool,
    group: bool,
    collapsed: HashSet<Category>,
    sort: SortBy,
    sort_desc: bool,

    large: Vec<LargeFile>,
    large_scanning: bool,
    large_root: String,
    large_min_mb: u64,
    large_scanned: usize,
    large_hidden: bool,

    dupes: Vec<dupes_ui::DupView>,
    dupes_scanning: bool,
    dupes_root: String,
    dupes_min_mb: u64,
    dupes_scanned: usize,
    dupes_hidden: bool,

    sec: Vec<security_ui::SecEntry>,
    sec_scanning: bool,
    sec_root: String,
    sec_contents: bool,
    sec_scanned: usize,

    perf: Option<perf::Snapshot>,
    perf_loading: bool,
    live: Option<perf::Live>,
    live_at: Option<std::time::Instant>,
    live_pending: bool,
    health: Vec<perf::HealthResult>,
    health_running: bool,
    diffs: HashMap<PathBuf, String>,
    sel_kernels: HashSet<String>,
    sel_left: HashSet<PathBuf>,
    /// Recommended-fix checkboxes the user has changed from their default.
    rec_sel: HashMap<String, bool>,

    java: Option<java::JavaReport>,
    java_loading: bool,

    svc_scope: Scope,
    svcs: Vec<services::Svc>,
    svc_loaded: bool,
    svc_loading: bool,
    svc_filter: String,
    svc_cat: String,
    svc_sel: Option<String>,
    svc_detail: HashMap<String, services::Detail>,
    svc_pending: HashSet<String>,

    busy: Option<String>,
    log: Vec<String>,
    confirm: Option<Confirm>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        let pm = Pm::detect();
        let mut app = Self {
            pm,
            tab: Tab::Cleanup,
            tx,
            rx,
            ctx: cc.egui_ctx.clone(),
            disks: vec![],
            targets: vec![],
            scanning: false,
            rows: vec![],
            pkg_loading: false,
            pkg_error: None,
            filter: String::new(),
            manual_only: false,
            view: PkgView::All,
            unused: HashSet::new(),
            obsolete: HashSet::new(),
            conflicts: Default::default(),
            upgradable: HashMap::new(),
            upgradable_known: false,
            group: false,
            collapsed: HashSet::new(),
            sort: SortBy::Size,
            sort_desc: true,
            large: vec![],
            large_scanning: false,
            large_root: util::home().display().to_string(),
            large_min_mb: 100,
            large_scanned: 0,
            large_hidden: false,
            dupes: vec![],
            dupes_scanning: false,
            dupes_root: util::home().display().to_string(),
            dupes_min_mb: 1,
            dupes_scanned: 0,
            dupes_hidden: false,
            sec: vec![],
            sec_scanning: false,
            sec_root: util::home().display().to_string(),
            sec_contents: true,
            sec_scanned: 0,
            perf: None,
            perf_loading: false,
            live: None,
            live_at: None,
            live_pending: false,
            health: vec![],
            health_running: false,
            diffs: HashMap::new(),
            sel_kernels: HashSet::new(),
            sel_left: HashSet::new(),
            rec_sel: HashMap::new(),
            java: None,
            java_loading: false,
            svc_scope: Scope::System,
            svcs: vec![],
            svc_loaded: false,
            svc_loading: false,
            svc_filter: String::new(),
            svc_cat: String::new(),
            svc_sel: None,
            svc_detail: HashMap::new(),
            svc_pending: HashSet::new(),
            busy: None,
            log: vec![match pm {
                Some(p) => format!("Detected package manager: {}", p.name()),
                None => "No supported package manager found (apt, dnf, pacman, zypper); package features disabled.".into(),
            }],
            confirm: None,
        };
        app.refresh();
        app
    }

    fn notifier(&self) -> Notifier {
        Notifier {
            tx: self.tx.clone(),
            ctx: self.ctx.clone(),
        }
    }

    /// Rescan disks, packages and cleanup targets.
    fn refresh(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.pkg_loading = true;
        let n = self.notifier();
        let pm = self.pm;
        std::thread::spawn(move || {
            n.send(Msg::Disks(util::disks()));
            let pkgs = pm
                .map(|p| p.list_installed())
                .unwrap_or_else(|| Err("No supported package manager".into()));
            let sizes: HashMap<String, u64> = pkgs
                .as_ref()
                .map(|v| v.iter().map(|p| (p.name.clone(), p.size)).collect())
                .unwrap_or_default();
            n.send(Msg::Packages(pkgs));
            // Orphaned dependencies; failure just means nothing is marked unused.
            let unused = pm.and_then(|p| p.list_orphans().ok()).unwrap_or_default();
            n.send(Msg::Unused(unused.into_iter().collect()));
            let obsolete = pm.and_then(|p| p.list_obsolete().ok()).unwrap_or_default();
            n.send(Msg::Obsolete(obsolete.into_iter().collect()));
            n.send(Msg::Conflicts(
                pm.and_then(|p| p.list_conflicts().ok()).unwrap_or_default(),
            ));
            let upg = pm.and_then(|p| p.list_upgradable().ok());
            n.send(Msg::Upgradable(upg.map(|v| v.into_iter().collect())));
            n.send(Msg::Targets(targets::scan_all(pm, &sizes)));
        });
    }

    fn drain(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Disks(d) => self.disks = d,
                Msg::Targets(mut t) => {
                    // Keep the user's checkbox choices across rescans.
                    let prev: HashMap<String, bool> = self
                        .targets
                        .iter()
                        .map(|t| (t.name.clone(), t.selected))
                        .collect();
                    for t in &mut t {
                        if let Some(&s) = prev.get(&t.name) {
                            t.selected = s;
                        }
                    }
                    self.targets = t;
                    self.scanning = false;
                }
                Msg::Packages(res) => {
                    self.pkg_loading = false;
                    match res {
                        Ok(pkgs) => {
                            let sel: HashSet<String> = self
                                .rows
                                .iter()
                                .filter(|r| r.selected)
                                .map(|r| r.pkg.name.clone())
                                .collect();
                            self.rows = pkgs
                                .into_iter()
                                .map(|p| Row {
                                    selected: sel.contains(&p.name),
                                    pkg: p,
                                })
                                .collect();
                            self.pkg_error = None;
                        }
                        Err(e) => self.pkg_error = Some(e),
                    }
                }
                Msg::Unused(u) => self.unused = u,
                Msg::Obsolete(o) => self.obsolete = o,
                Msg::Conflicts(c) => self.conflicts = c,
                Msg::Upgradable(u) => {
                    self.upgradable_known = u.is_some();
                    self.upgradable = u.unwrap_or_default();
                }
                Msg::Large(files, scanned) => {
                    self.large = files
                        .into_iter()
                        .map(|(path, size)| LargeFile {
                            path,
                            size,
                            selected: false,
                        })
                        .collect();
                    self.large_scanned = scanned;
                    self.large_scanning = false;
                }
                Msg::Dupes(groups, scanned) => {
                    self.dupes = groups.into_iter().map(dupes_ui::DupView::from).collect();
                    self.dupes_scanned = scanned;
                    self.dupes_scanning = false;
                }
                Msg::Security(found, scanned) => {
                    self.sec = found
                        .into_iter()
                        .map(|f| security_ui::SecEntry { f, selected: false })
                        .collect();
                    self.sec_scanned = scanned;
                    self.sec_scanning = false;
                }
                Msg::Perf(p) => {
                    self.perf_loading = false;
                    let alive: HashSet<&String> = p.kernels.iter().map(|k| &k.version).collect();
                    self.sel_kernels.retain(|v| alive.contains(v));
                    let files: HashSet<&PathBuf> = p.leftovers.iter().map(|l| &l.path).collect();
                    self.sel_left.retain(|f| files.contains(f));
                    self.diffs.retain(|f, _| files.contains(f));
                    self.perf = Some(*p);
                }
                Msg::ReloadPerf => {
                    self.load_perf();
                    self.load_java();
                    self.svc_loaded = false;
                }
                Msg::Java(r) => {
                    self.java_loading = false;
                    self.java = Some(*r);
                }
                Msg::Services(scope, v) => {
                    self.svc_loading = false;
                    // Ignore a stale answer if the user switched scope meanwhile.
                    if scope == self.svc_scope {
                        self.svcs = v;
                        self.svc_loaded = true;
                    }
                }
                Msg::SvcDetail(unit, d) => {
                    self.svc_pending.remove(&unit);
                    self.svc_detail.insert(unit, *d);
                }
                Msg::Live(l) => {
                    self.live = Some(*l);
                    self.live_pending = false;
                    self.live_at = Some(std::time::Instant::now());
                }
                Msg::Health(h) => self.health.push(*h),
                Msg::HealthDone => self.health_running = false,
                Msg::Diff(path, text) => {
                    self.diffs.insert(path, text);
                }
                Msg::Preview {
                    names,
                    text,
                    affected,
                } => {
                    if let Some(Confirm::Remove { names: n, preview }) = &mut self.confirm
                        && *n == names
                    {
                        *preview = Some((text, affected));
                    }
                }
                Msg::Log(l) => {
                    self.log.push(l);
                    if self.log.len() > 5000 {
                        self.log.drain(..1000);
                    }
                }
                Msg::Done { refresh } => {
                    self.busy = None;
                    self.large
                        .retain(|f| std::fs::symlink_metadata(&f.path).is_ok());
                    for g in &mut self.dupes {
                        g.files
                            .retain(|f| std::fs::symlink_metadata(&f.path).is_ok());
                    }
                    self.dupes.retain(|g| g.files.len() > 1);
                    self.sec
                        .retain(|e| std::fs::symlink_metadata(&e.f.path).is_ok());
                    if refresh {
                        self.refresh();
                    }
                }
            }
        }
    }

    // ----- actions --------------------------------------------------------

    fn start_clean(&mut self, idx: Vec<usize>) {
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

    fn start_preview(&mut self, names: Vec<String>) {
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

    fn start_remove(&mut self, names: Vec<String>) {
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

    fn start_upgrade(&mut self, names: Vec<String>) {
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

    fn start_large_scan(&mut self) {
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
                    include_hidden
                        || e.depth() == 0
                        || !e.file_name().to_string_lossy().starts_with('.')
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

    fn start_delete_files(&mut self, paths: Vec<PathBuf>, permanent: bool) {
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

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("🧹 Disk Cleaner");
            ui.separator();
            ui.selectable_value(&mut self.tab, Tab::Cleanup, "Cleanup");
            ui.add_enabled_ui(self.pm.is_some(), |ui| {
                ui.selectable_value(&mut self.tab, Tab::Packages, "Packages");
            });
            ui.selectable_value(&mut self.tab, Tab::LargeFiles, "Large files");
            ui.selectable_value(&mut self.tab, Tab::Duplicates, "Duplicates");
            ui.selectable_value(&mut self.tab, Tab::Security, "Security");
            ui.selectable_value(&mut self.tab, Tab::Performance, "Performance");
            ui.selectable_value(&mut self.tab, Tab::Services, "Services");
            ui.selectable_value(&mut self.tab, Tab::Java, "Java");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(b) = &self.busy {
                    ui.label(b);
                    ui.spinner();
                } else if let Some(pm) = self.pm {
                    ui.label(RichText::new(pm.name()).weak());
                }
            });
        });
        ui.add_space(2.0);
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Activity");
            if ui.small_button("Clear").clicked() {
                self.log.clear();
            }
        });
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for l in &self.log {
                    let color = if l.starts_with('✘') || l.contains("!! ") {
                        Some(Color32::from_rgb(220, 90, 80))
                    } else if l.starts_with('✔') {
                        Some(Color32::from_rgb(90, 180, 100))
                    } else {
                        None
                    };
                    let mut t = RichText::new(l).monospace().size(12.0);
                    if let Some(c) = color {
                        t = t.color(c);
                    }
                    ui.label(t);
                }
            });
    }

    fn cleanup_tab(&mut self, ui: &mut egui::Ui) {
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
                            .desired_width(ui.available_width().min(520.0))
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
                for (i, t) in self.targets.iter_mut().enumerate() {
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
                                        .id_salt(("details", i))
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

    fn packages_tab(&mut self, ui: &mut egui::Ui) {
        let mut remove = false;
        let mut upgrade = false;
        let mut reload = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("🔍 Filter packages").desired_width(220.0));
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
            .column(Column::remainder().at_least(140.0).clip(true))
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

    fn large_tab(&mut self, ui: &mut egui::Ui) {
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

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
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

fn buttons(ui: &mut egui::Ui, label: &str, enabled: bool, decision: &mut Option<bool>) {
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

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(140.0)
            .min_size(60.0)
            .show(ui, |ui| self.log_panel(ui));
        if self.tab == Tab::Services && self.svc_sel.is_some() {
            self.svc_detail_panel(ui);
        }
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Cleanup => self.cleanup_tab(ui),
            Tab::Packages => self.packages_tab(ui),
            Tab::LargeFiles => self.large_tab(ui),
            Tab::Duplicates => self.dupes_tab(ui),
            Tab::Security => self.security_tab(ui),
            Tab::Performance => self.performance_tab(ui),
            Tab::Services => self.services_tab(ui),
            Tab::Java => self.java_tab(ui),
        });
        let ctx = ui.ctx().clone();
        self.confirm_dialog(&ctx);
    }
}

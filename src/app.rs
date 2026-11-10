//! The egui user interface. All slow work runs on background threads and
//! reports back through a channel, so the window never freezes.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};

mod cleanup_ui;
mod confirm_ui;
mod dev_ui;
mod dupes_ui;
mod java_ui;
mod large_ui;
mod nav;
mod procs_ui;
use nav::Tab;
mod packages_ui;
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
    DevArtifacts(Vec<crate::devclean::Artifact>),
    DevToolchains(Vec<crate::devclean::Toolchain>),
    DevRepos(Vec<crate::devclean::Repo>),
    DevDone,
    Ports(Result<Vec<crate::ports::Listener>, String>),
    Procs(Box<crate::procscan::ScanResult>),
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

/// Run independent jobs side by side (or one after another when `parallel` is false).
fn run_jobs<'a>(parallel: bool, jobs: Vec<Box<dyn FnOnce() + Send + 'a>>) {
    if parallel {
        std::thread::scope(|sc| {
            for j in jobs {
                sc.spawn(j);
            }
        });
    } else {
        for j in jobs {
            j();
        }
    }
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
    last_tab: HashMap<&'static str, Tab>,
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
    sec_git: bool,

    dev_root: String,
    dev_scanning: bool,
    dev_idle_days: u64,
    dev_art: Vec<dev_ui::ArtEntry>,
    dev_tc: Vec<dev_ui::TcEntry>,
    dev_repos: Vec<dev_ui::RepoEntry>,
    ports: Vec<crate::ports::Listener>,
    ports_loaded: bool,
    ports_loading: bool,
    ports_error: Option<String>,
    procs: Vec<crate::procscan::Suspect>,
    procs_scanning: bool,
    procs_scanned: bool,
    procs_elevated: bool,
    procs_inspected: usize,
    procs_opaque: usize,
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
    svc_detail: HashMap<String, std::sync::Arc<services::Detail>>,
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
            last_tab: HashMap::new(),
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
            sec_git: true,
            dev_root: util::home().display().to_string(),
            dev_scanning: false,
            dev_idle_days: 90,
            dev_art: vec![],
            dev_tc: vec![],
            dev_repos: vec![],
            ports: vec![],
            ports_loaded: false,
            ports_loading: false,
            ports_error: None,
            procs: vec![],
            procs_scanning: false,
            procs_scanned: false,
            procs_elevated: false,
            procs_inspected: 0,
            procs_opaque: 0,
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
            // The queries are independent and each mostly waits on a subprocess, so run them
            // side by side. zypper locks its database, so it stays sequential.
            let parallel = pm != Some(Pm::Zypper);
            let n = &n;
            run_jobs(
                parallel,
                vec![
                    Box::new(move || n.send(Msg::Disks(util::disks()))),
                    Box::new(move || {
                        let pkgs = pm
                            .map(|p| p.list_installed())
                            .unwrap_or_else(|| Err("No supported package manager".into()));
                        let sizes: HashMap<String, u64> = pkgs
                            .as_ref()
                            .map(|v| v.iter().map(|p| (p.name.clone(), p.size)).collect())
                            .unwrap_or_default();
                        n.send(Msg::Packages(pkgs));
                        // Orphan sizes come from the package list, so the cleanup scan follows it.
                        n.send(Msg::Targets(targets::scan_all(pm, &sizes)));
                    }),
                    // Orphaned dependencies; failure just means nothing is marked unused.
                    Box::new(move || {
                        let v = pm.and_then(|p| p.list_orphans().ok()).unwrap_or_default();
                        n.send(Msg::Unused(v.into_iter().collect()));
                    }),
                    Box::new(move || {
                        let v = pm.and_then(|p| p.list_obsolete().ok()).unwrap_or_default();
                        n.send(Msg::Obsolete(v.into_iter().collect()));
                    }),
                    Box::new(move || {
                        let v = pm.and_then(|p| p.list_conflicts().ok()).unwrap_or_default();
                        n.send(Msg::Conflicts(v));
                    }),
                    Box::new(move || {
                        let v = pm.and_then(|p| p.list_upgradable().ok());
                        n.send(Msg::Upgradable(v.map(|v| v.into_iter().collect())));
                    }),
                ],
            );
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
                Msg::DevArtifacts(a) => {
                    self.dev_art = a
                        .into_iter()
                        .map(|a| dev_ui::ArtEntry { a, sel: false })
                        .collect();
                }
                Msg::DevToolchains(t) => {
                    self.dev_tc = t
                        .into_iter()
                        .map(|t| dev_ui::TcEntry { t, sel: false })
                        .collect();
                }
                Msg::DevRepos(r) => {
                    self.dev_repos = r.into_iter().map(dev_ui::RepoEntry::new).collect();
                }
                Msg::DevDone => {
                    self.dev_scanning = false;
                }
                Msg::Ports(r) => {
                    self.ports_loading = false;
                    self.ports_loaded = true;
                    match r {
                        Ok(v) => {
                            self.ports = v;
                            self.ports_error = None;
                        }
                        Err(e) => self.ports_error = Some(e),
                    }
                }
                Msg::Procs(r) => self.apply_procs(*r),
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
                    self.svc_detail.insert(unit, std::sync::Arc::from(d));
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
                    util::log_action(&l);
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
                    self.dev_prune();
                    self.ports_loaded = false;
                    // A scan that needed a password is not repeated behind the user's back.
                    self.procs_scanned = self.procs_elevated;
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
            Tab::Projects => self.projects_tab(ui),
            Tab::Ports => self.ports_tab(ui),
            Tab::Processes => self.processes_tab(ui),
            Tab::Performance => self.performance_tab(ui),
            Tab::Services => self.services_tab(ui),
            Tab::Java => self.java_tab(ui),
        });
        let ctx = ui.ctx().clone();
        self.confirm_dialog(&ctx);
    }
}

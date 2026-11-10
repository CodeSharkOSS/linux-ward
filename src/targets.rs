//! Cleanup targets: things that take space and can be safely reclaimed.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::pkg::Pm;
use crate::util::{
    self, clear_dir_contents, dir_usage, home, human, run, run_privileged, run_with_stdin, which,
};

#[derive(Clone, Debug)]
pub enum Action {
    /// Delete the contents of these directories as the current user.
    ClearDirs(Vec<PathBuf>),
    /// Delete these directories themselves (project build folders, old toolchains).
    RemoveDirs(Vec<PathBuf>),
    /// Run these commands as the current user.
    User(Vec<Vec<String>>),
    /// Run these commands as root (batched into one pkexec prompt).
    Root(Vec<Vec<String>>),
}

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub description: String,
    /// Reclaimable size, if known.
    pub size: Option<u64>,
    /// Individual items (packages, revisions...) shown in an expandable list.
    pub details: Vec<String>,
    pub action: Action,
    pub selected: bool,
    pub group: Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    User,
    System,
    Packages,
    Developer,
}

impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Group::User => "Your files",
            Group::System => "System",
            Group::Packages => "Packages",
            Group::Developer => "Developer caches",
        }
    }
}

impl Target {
    pub fn needs_root(&self) -> bool {
        matches!(self.action, Action::Root(_))
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// Scan everything in parallel. Targets with nothing to reclaim are dropped.
pub fn scan_all(pm: Option<Pm>, pkg_sizes: &HashMap<String, u64>) -> Vec<Target> {
    let jobs: Vec<Box<dyn FnOnce() -> Option<Target> + Send + '_>> = vec![
        Box::new(user_cache),
        Box::new(trash),
        Box::new(journal),
        Box::new(rotated_logs),
        Box::new(coredumps),
        Box::new(move || pm.and_then(pkg_cache)),
        Box::new(move || pm.and_then(|pm| orphans(pm, pkg_sizes))),
        Box::new(flatpak_unused),
        Box::new(snap_old),
        Box::new(cargo_cache),
        Box::new(npm_cache),
        Box::new(go_cache),
        Box::new(gradle_cache),
        Box::new(maven_cache),
        Box::new(pnpm_store),
        Box::new(conda_pkgs),
        Box::new(nuget_cache),
        Box::new(bundler_cache),
        Box::new(|| container_cache("docker")),
        Box::new(|| container_cache("podman")),
    ];
    let mut targets: Vec<Target> = std::thread::scope(|sc| {
        let handles: Vec<_> = jobs.into_iter().map(|j| sc.spawn(j)).collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .collect()
    });
    targets.retain(|t| t.size != Some(0) || !t.details.is_empty());
    targets.sort_by_key(|t| t.group);
    targets
}

fn user_cache() -> Option<Target> {
    let dir = util::xdg_cache();
    Some(Target {
        name: "Application cache".into(),
        description: format!(
            "Everything in {}. Apps rebuild it as needed; close browsers and other apps first.",
            dir.display()
        ),
        size: Some(dir_usage(&dir)),
        details: top_children(&dir, 12),
        action: Action::ClearDirs(vec![dir]),
        selected: false,
        group: Group::User,
    })
}

fn trash() -> Option<Target> {
    let base = util::xdg_data().join("Trash");
    let dirs: Vec<PathBuf> = ["files", "info", "expunged"]
        .iter()
        .map(|d| base.join(d))
        .filter(|d| d.is_dir())
        .collect();
    let size = dirs.iter().map(|d| dir_usage(d)).sum();
    Some(Target {
        name: "Trash".into(),
        description: format!(
            "Files you deleted in your file manager ({}).",
            base.display()
        ),
        size: Some(size),
        details: vec![],
        action: Action::ClearDirs(dirs),
        selected: true,
        group: Group::User,
    })
}

fn journal() -> Option<Target> {
    if !which("journalctl") {
        return None;
    }
    let size = dir_usage("/var/log/journal".as_ref()) + dir_usage("/run/log/journal".as_ref());
    Some(Target {
        name: "System journal".into(),
        description: "systemd logs. Keeps the last 7 days and caps the journal at 200 MiB (size shown is the current total).".into(),
        size: Some(size),
        details: vec![],
        action: Action::Root(vec![s(&["journalctl", "--vacuum-time=7d", "--vacuum-size=200M"])]),
        selected: false,
        group: Group::System,
    })
}

fn is_rotated_log(name: &str) -> bool {
    name.ends_with(".gz")
        || name.ends_with(".xz")
        || name.ends_with(".zst")
        || name.ends_with(".old")
        || name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit()))
}

fn rotated_logs() -> Option<Target> {
    use std::os::unix::fs::MetadataExt;
    let mut size = 0;
    let mut count = 0;
    for e in walkdir::WalkDir::new("/var/log")
        .same_file_system(true)
        .into_iter()
        .filter_map(Result::ok)
    {
        if e.path().starts_with("/var/log/journal") || !e.file_type().is_file() {
            continue;
        }
        if is_rotated_log(&e.file_name().to_string_lossy())
            && let Ok(m) = e.metadata()
        {
            size += m.blocks() * 512;
            count += 1;
        }
    }
    Some(Target {
        name: "Old rotated logs".into(),
        description: format!(
            "{count} archived log files in /var/log (*.gz, *.1, *.old…). Current logs are kept."
        ),
        size: Some(size),
        details: vec![],
        action: Action::Root(vec![s(&[
            "find",
            "/var/log",
            "-xdev",
            "-type",
            "f",
            "-not",
            "-path",
            "/var/log/journal/*",
            "(",
            "-name",
            "*.gz",
            "-o",
            "-name",
            "*.xz",
            "-o",
            "-name",
            "*.zst",
            "-o",
            "-name",
            "*.old",
            "-o",
            "-regex",
            ".*\\.[0-9]+",
            ")",
            "-delete",
        ])]),
        selected: false,
        group: Group::System,
    })
}

fn coredumps() -> Option<Target> {
    let dir = "/var/lib/systemd/coredump";
    if !std::path::Path::new(dir).is_dir() {
        return None;
    }
    Some(Target {
        name: "Crash dumps".into(),
        description: "Core dumps saved by systemd-coredump when programs crash.".into(),
        size: Some(dir_usage(dir.as_ref())),
        details: vec![],
        action: Action::Root(vec![s(&["find", dir, "-type", "f", "-delete"])]),
        selected: true,
        group: Group::System,
    })
}

fn pkg_cache(pm: Pm) -> Option<Target> {
    let size = pm.cache_dirs().iter().map(|d| dir_usage(d.as_ref())).sum();
    Some(Target {
        name: "Package cache".into(),
        description: pm.cache_description().into(),
        size: Some(size),
        details: vec![],
        action: Action::Root(pm.cache_clean_cmds()),
        selected: true,
        group: Group::Packages,
    })
}

fn orphans(pm: Pm, pkg_sizes: &HashMap<String, u64>) -> Option<Target> {
    let names = match pm.list_orphans() {
        Ok(n) => n,
        Err(e) => {
            return Some(Target {
                name: "Unused dependencies".into(),
                description: format!(
                    "Could not list orphaned packages: {}",
                    e.lines().next().unwrap_or("")
                ),
                size: Some(0),
                details: vec![e],
                action: Action::Root(vec![]),
                selected: false,
                group: Group::Packages,
            });
        }
    };
    let lookup = |n: &String| {
        pkg_sizes
            .get(n)
            .or_else(|| pkg_sizes.get(n.split(':').next().unwrap_or(n)))
            .copied()
    };
    let size = names.iter().filter_map(lookup).sum();
    let details = names.iter().map(|n| match lookup(n) {
        Some(sz) => format!("{n}  ({})", human(sz)),
        None => n.clone(),
    });
    Some(Target {
        name: "Unused dependencies".into(),
        description: "Packages installed only as dependencies of software that's since been removed (incl. old kernels on Debian/Ubuntu).".into(),
        size: Some(size),
        details: details.collect(),
        action: Action::Root(pm.orphan_remove_cmds(&names)),
        selected: false,
        group: Group::Packages,
    })
}

fn flatpak_unused() -> Option<Target> {
    if !which("flatpak") {
        return None;
    }
    // There's no dry-run flag, so answer "n" to the confirmation and read the list it printed.
    let out = run_with_stdin("flatpak", &["uninstall", "--unused"], Some("n\n"));
    let details: Vec<String> = out
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.split_once('.')
                .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        })
        .map(|l| {
            l.split_once('.')
                .map(|(_, r)| r.trim().to_string())
                .unwrap_or_default()
        })
        .filter(|l| !l.is_empty())
        .collect();
    if details.is_empty() {
        return None;
    }
    Some(Target {
        name: "Unused Flatpak runtimes".into(),
        description: "Runtimes and extensions no installed Flatpak app uses any more.".into(),
        size: None,
        details,
        action: Action::User(vec![s(&[
            "flatpak",
            "uninstall",
            "--unused",
            "--noninteractive",
            "-y",
        ])]),
        selected: true,
        group: Group::Packages,
    })
}

fn snap_old() -> Option<Target> {
    if !which("snap") {
        return None;
    }
    let out = run("snap", &["list", "--all"]);
    let mut cmds = Vec::new();
    let mut details = Vec::new();
    let mut size = 0;
    for line in out.stdout.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || !f.last().is_some_and(|n| n.contains("disabled")) {
            continue;
        }
        let (name, rev) = (f[0], f[2]);
        if !crate::pkg::valid_name(name) || !rev.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let sz = std::fs::metadata(format!("/var/lib/snapd/snaps/{name}_{rev}.snap"))
            .map(|m| m.len())
            .unwrap_or(0);
        size += sz;
        details.push(format!("{name} revision {rev}  ({})", human(sz)));
        cmds.push(vec![
            "snap".into(),
            "remove".into(),
            name.into(),
            format!("--revision={rev}"),
        ]);
    }
    Some(Target {
        name: "Old Snap revisions".into(),
        description: "Disabled older revisions snapd keeps around for rollback.".into(),
        size: Some(size),
        details,
        action: Action::Root(cmds),
        selected: true,
        group: Group::Packages,
    })
}

fn cargo_cache() -> Option<Target> {
    let base = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".cargo"));
    let dirs: Vec<PathBuf> = ["registry/cache", "registry/src", "git/checkouts"]
        .iter()
        .map(|d| base.join(d))
        .filter(|d| d.is_dir())
        .collect();
    if dirs.is_empty() {
        return None;
    }
    Some(Target {
        name: "Cargo download cache".into(),
        description: "Downloaded crate archives and extracted sources in ~/.cargo. Re-downloaded on the next build.".into(),
        size: Some(dirs.iter().map(|d| dir_usage(d)).sum()),
        details: vec![],
        action: Action::ClearDirs(dirs),
        selected: false,
        group: Group::Developer,
    })
}

fn npm_cache() -> Option<Target> {
    let dir = home().join(".npm/_cacache");
    dir.is_dir().then(|| Target {
        name: "npm cache".into(),
        description: "npm's package download cache (~/.npm/_cacache).".into(),
        size: Some(dir_usage(&dir)),
        details: vec![],
        action: Action::ClearDirs(vec![dir]),
        selected: false,
        group: Group::Developer,
    })
}

/// A developer cache that is just a directory which tools re-fill on demand.
fn simple_dev_cache(name: &str, description: &str, dirs: Vec<PathBuf>) -> Option<Target> {
    let dirs: Vec<PathBuf> = dirs.into_iter().filter(|d| d.is_dir()).collect();
    if dirs.is_empty() {
        return None;
    }
    Some(Target {
        name: name.into(),
        description: description.into(),
        size: Some(dirs.iter().map(|d| dir_usage(d)).sum()),
        details: vec![],
        action: Action::ClearDirs(dirs),
        selected: false,
        group: Group::Developer,
    })
}

fn pnpm_store() -> Option<Target> {
    simple_dev_cache(
        "pnpm store",
        "pnpm's shared package store. Projects re-link from the network the next time they install.",
        vec![
            util::xdg_data().join("pnpm/store"),
            home().join(".pnpm-store"),
        ],
    )
}

fn conda_pkgs() -> Option<Target> {
    simple_dev_cache(
        "Conda package cache",
        "Downloaded conda/mamba packages and tarballs (pkgs). Existing environments keep working only if their files are copies, not hard links; clean with `conda clean` if unsure.",
        vec![
            home().join(".conda/pkgs"),
            home().join("miniconda3/pkgs"),
            home().join("anaconda3/pkgs"),
            home().join("miniforge3/pkgs"),
            home().join("mambaforge/pkgs"),
        ],
    )
}

fn nuget_cache() -> Option<Target> {
    simple_dev_cache(
        "NuGet packages",
        "Downloaded .NET packages in ~/.nuget/packages. Restored on the next build.",
        vec![home().join(".nuget/packages")],
    )
}

fn bundler_cache() -> Option<Target> {
    simple_dev_cache(
        "Bundler cache",
        "Cached .gem files in ~/.bundle/cache. Re-downloaded on the next `bundle install`.",
        vec![home().join(".bundle/cache")],
    )
}

fn gradle_cache() -> Option<Target> {
    let base = std::env::var_os("GRADLE_USER_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".gradle"));
    let dirs: Vec<PathBuf> = ["caches", "wrapper/dists", "daemon"]
        .iter()
        .map(|d| base.join(d))
        .filter(|d| d.is_dir())
        .collect();
    if dirs.is_empty() {
        return None;
    }
    Some(Target {
        name: "Gradle caches".into(),
        description: "Downloaded dependencies, wrapper distributions and daemon logs in ~/.gradle. Re-downloaded on the next build (needs network).".into(),
        size: Some(dirs.iter().map(|d| dir_usage(d)).sum()),
        details: vec![],
        action: Action::ClearDirs(dirs),
        selected: false,
        group: Group::Developer,
    })
}

fn maven_cache() -> Option<Target> {
    let dir = home().join(".m2/repository");
    dir.is_dir().then(|| Target {
        name: "Maven repository".into(),
        description: "Downloaded artifacts in ~/.m2/repository. Re-downloaded on the next build; locally installed (mvn install) artifacts are lost too.".into(),
        size: Some(dir_usage(&dir)),
        details: top_children(&dir, 12),
        action: Action::ClearDirs(vec![dir]),
        selected: false,
        group: Group::Developer,
    })
}

fn go_cache() -> Option<Target> {
    if !which("go") {
        return None;
    }
    let modcache = run("go", &["env", "GOMODCACHE"]).stdout.trim().to_string();
    let gocache = run("go", &["env", "GOCACHE"]).stdout.trim().to_string();
    let size = [&modcache, &gocache]
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| dir_usage(p.as_ref()))
        .sum();
    Some(Target {
        name: "Go module & build cache".into(),
        description: "go clean -modcache -cache".into(),
        size: Some(size),
        details: vec![],
        action: Action::User(vec![s(&["go", "clean", "-modcache", "-cache"])]),
        selected: false,
        group: Group::Developer,
    })
}

/// "1.2GB (50%)" / "512MB" / "0B" → bytes (docker and podman use decimal units).
fn parse_reclaimable(s: &str) -> u64 {
    let tok = s.split_whitespace().next().unwrap_or("");
    let split = tok
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(tok.len());
    let (num, unit) = tok.split_at(split);
    let mult = match unit.to_ascii_lowercase().as_str() {
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => 1.0,
    };
    (num.parse::<f64>().unwrap_or(0.0) * mult) as u64
}

/// Unused Docker / Podman images, stopped containers and build cache. Volumes are never touched.
fn container_cache(tool: &str) -> Option<Target> {
    if !which(tool) {
        return None;
    }
    let df = run(
        tool,
        &["system", "df", "--format", "{{.Type}}\t{{.Reclaimable}}"],
    );
    // Docker needs the daemon socket; if the user can't reach it, fall back to running as root.
    let has_access = df.ok;
    if !has_access && tool == "podman" {
        return None;
    }
    let mut size = 0;
    let mut details = Vec::new();
    if has_access {
        for line in df.stdout.lines() {
            if let Some((kind, rec)) = line.split_once('\t') {
                size += parse_reclaimable(rec);
                details.push(format!("{kind}: {} reclaimable", rec.trim()));
            }
        }
    } else if !std::path::Path::new("/var/run/docker.sock").exists() {
        return None; // daemon not installed/running
    }
    let cmd = vec![s(&[tool, "system", "prune", "-af"])];
    let title = if tool == "docker" { "Docker" } else { "Podman" };
    Some(Target {
        name: format!("{title} unused data"),
        description: format!(
            "Stopped containers, unused images, networks and build cache ({tool} system prune -a). Volumes are NOT removed.{}",
            if has_access {
                ""
            } else {
                " Needs administrator access (you're not in the docker group); size unknown."
            }
        ),
        size: has_access.then_some(size),
        details,
        action: if has_access {
            Action::User(cmd)
        } else {
            Action::Root(cmd)
        },
        selected: false,
        group: Group::Developer,
    })
}

/// Largest immediate children of a directory, for the details list.
fn top_children(dir: &std::path::Path, n: usize) -> Vec<String> {
    let mut v: Vec<(u64, String)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            (
                dir_usage(&e.path()),
                e.file_name().to_string_lossy().into_owned(),
            )
        })
        .filter(|(sz, _)| *sz > 0)
        .collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.0));
    v.into_iter()
        .take(n)
        .map(|(sz, name)| format!("{name}  ({})", human(sz)))
        .collect()
}

/// Execute the given targets. User-level work runs first, then all root
/// commands are batched into a single authentication prompt.
pub fn execute(targets: &[Target], log: &mut dyn FnMut(String)) {
    let mut root_cmds = Vec::new();
    for t in targets {
        match &t.action {
            Action::ClearDirs(dirs) => {
                let mut freed = 0;
                let mut errors = Vec::new();
                for d in dirs {
                    let (f, e) = clear_dir_contents(d);
                    freed += f;
                    errors.extend(e);
                }
                log(format!("✔ {}: freed {}", t.name, human(freed)));
                if !errors.is_empty() {
                    log(format!(
                        "  {} item(s) could not be removed (in use or no permission), e.g. {}",
                        errors.len(),
                        errors[0]
                    ));
                }
            }
            Action::RemoveDirs(dirs) => {
                let mut freed = 0;
                for d in dirs {
                    match util::remove_dir_checked(d) {
                        Ok(n) => freed += n,
                        Err(e) => log(format!("✘ {}: {e}", d.display())),
                    }
                }
                log(format!(
                    "✔ {}: removed {} folder(s), freed {}",
                    t.name,
                    dirs.len(),
                    human(freed)
                ));
            }
            Action::User(cmds) => {
                for c in cmds {
                    log(format!("$ {}", c.join(" ")));
                    let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
                    let out = run(&c[0], &args);
                    for l in out.combined().lines().filter(|l| !l.trim().is_empty()) {
                        log(format!("  {l}"));
                    }
                    log(if out.ok {
                        format!("✔ {} done", t.name)
                    } else {
                        format!("✘ {} failed", t.name)
                    });
                }
            }
            Action::Root(cmds) => root_cmds.extend(cmds.iter().cloned()),
        }
    }
    if !root_cmds.is_empty() {
        log("Requesting administrator privileges…".into());
        let out = run_privileged(&root_cmds);
        for l in out.combined().lines().filter(|l| !l.trim().is_empty()) {
            log(format!("  {l}"));
        }
        log(if out.ok {
            "✔ System cleanup finished".into()
        } else {
            "✘ System cleanup reported errors (see above)".into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reclaimable() {
        assert_eq!(parse_reclaimable("1.5GB (50%)"), 1_500_000_000);
        assert_eq!(parse_reclaimable("0B"), 0);
        assert_eq!(parse_reclaimable("512MB"), 512_000_000);
    }

    #[test]
    fn rotated() {
        assert!(is_rotated_log("syslog.1"));
        assert!(is_rotated_log("syslog.2.gz"));
        assert!(is_rotated_log("dpkg.log.old"));
        assert!(!is_rotated_log("syslog"));
        assert!(!is_rotated_log("auth.log"));
    }
}

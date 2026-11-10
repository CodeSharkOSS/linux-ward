//! Package manager abstraction for apt, dnf, pacman and zypper.

use std::collections::HashSet;

use crate::util::{CmdOut, run, which};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pm {
    Apt,
    Dnf,
    Pacman,
    Zypper,
}

#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// Installed size in bytes.
    pub size: u64,
    /// `Some(true)` if explicitly installed by the user, `Some(false)` if pulled in as a dependency.
    pub manual: Option<bool>,
}

/// Packages that the app refuses to remove, whatever the user selects.
const PROTECTED: &[&str] = &[
    "base",
    "filesystem",
    "glibc",
    "libc6",
    "libc-bin",
    "bash",
    "dash",
    "coreutils",
    "util-linux",
    "systemd",
    "systemd-sysv",
    "udev",
    "sudo",
    "polkit",
    "pkexec",
    "policykit-1",
    "apt",
    "dpkg",
    "dnf",
    "dnf5",
    "rpm",
    "pacman",
    "zypper",
    "libzypp",
    "grub",
    "grub2",
    "grub-common",
    "grub-pc",
    "grub-efi-amd64",
    "grub-efi-amd64-signed",
    "grub2-common",
    "shim",
    "shim-signed",
    "linux",
    "kernel",
    "kernel-core",
    "kernel-default",
    "linux-lts",
    "linux-zen",
    "linux-hardened",
    "openssl",
    "login",
    "passwd",
    "shadow",
    "init",
    "mount",
    "e2fsprogs",
];

/// Names passed to the package manager must look like real package names
/// (defence in depth: they are also shell-quoted).
pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('-')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+._:@-~".contains(c))
}

/// Rough kind of package, guessed from its name. Declaration order is display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Applications,
    Libraries,
    Development,
    LanguageModules,
    Fonts,
    KernelFirmware,
    DocsLocales,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Applications => "Applications & tools",
            Category::Libraries => "Libraries",
            Category::Development => "Development (headers, compilers, debug)",
            Category::LanguageModules => "Language modules (Python, Perl, Ruby…)",
            Category::Fonts => "Fonts",
            Category::KernelFirmware => "Kernel & firmware",
            Category::DocsLocales => "Documentation & language packs",
        }
    }
}

/// Classify a package by naming conventions (apt, rpm and Arch names). A heuristic:
/// anything unrecognised is an application.
pub fn category(name: &str) -> Category {
    let n = name.split(':').next().unwrap_or(name).to_lowercase();
    let starts = |ps: &[&str]| ps.iter().any(|p| n.starts_with(p));
    let ends = |ss: &[&str]| ss.iter().any(|s| n.ends_with(s));
    if starts(&[
        "kernel",
        "linux-image",
        "linux-modules",
        "linux-firmware",
        "linux-headers",
        "firmware-",
    ]) || ends(&["-firmware", "-ucode"])
    {
        Category::KernelFirmware
    } else if starts(&[
        "fonts-",
        "font-",
        "ttf-",
        "otf-",
        "xorg-fonts",
        "texlive-fonts",
    ]) || ends(&["-fonts", "-font"])
    {
        Category::Fonts
    } else if ends(&[
        "-doc",
        "-docs",
        "-langpack",
        "-l10n",
        "-i18n",
        "-locale",
        "-help",
        "-manpages",
    ]) || starts(&[
        "man-pages",
        "hunspell-",
        "aspell-",
        "myspell-",
        "langpacks-",
        "glibc-langpack",
        "glibc-all-langpacks",
        "mythes-",
        "libreoffice-help",
        "libreoffice-langpack",
    ]) {
        Category::DocsLocales
    } else if ends(&[
        "-dev",
        "-devel",
        "-headers",
        "-static",
        "-dbg",
        "-dbgsym",
        "-debuginfo",
        "-debugsource",
    ]) || starts(&[
        "gcc",
        "g++",
        "clang",
        "llvm",
        "cmake",
        "build-essential",
        "autoconf",
        "automake",
        "gdb",
    ]) {
        Category::Development
    } else if starts(&[
        "python3-", "python2-", "python-", "perl-", "ruby-", "rubygem-", "golang-", "nodejs-",
        "node-", "php-", "lua-", "r-cran-",
    ]) || (n.starts_with("lib")
        && (n.ends_with("-perl") || n.ends_with("-ruby") || n.ends_with("-python")))
    {
        Category::LanguageModules
    } else if (n.starts_with("lib")
        && !starts(&["libreoffice", "libvirt", "libinput-tools", "libva-utils"]))
        || ends(&["-libs", "-lib"])
    {
        Category::Libraries
    } else {
        Category::Applications
    }
}

/// Packages that own the running kernel's image or modules, by asking the package manager.
/// Names alone are not enough: rpm calls it `kernel-core`, openSUSE `kernel-default`, Arch
/// `linux-zen`, and only dpkg-style names happen to contain the release string.
fn running_kernel_packages() -> &'static HashSet<String> {
    static OWNERS: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
    OWNERS.get_or_init(|| {
        let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let rel = rel.trim();
        let mut owners = HashSet::new();
        if rel.is_empty() {
            return owners;
        }
        let files = [
            format!("/boot/vmlinuz-{rel}"),
            format!("/usr/lib/modules/{rel}/vmlinuz"),
            format!("/lib/modules/{rel}/vmlinuz"),
            format!("/lib/modules/{rel}/modules.dep"),
        ];
        for f in files
            .iter()
            .filter(|f| std::path::Path::new(f.as_str()).exists())
        {
            let names: Vec<String> = if which("rpm") {
                run("rpm", &["-qf", "--qf", "%{NAME}\n", f])
                    .stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .collect()
            } else if which("dpkg") {
                run("dpkg", &["-S", f])
                    .stdout
                    .lines()
                    .filter_map(|l| l.split_once(": "))
                    .flat_map(|(p, _)| p.split(", ").map(str::to_string).collect::<Vec<_>>())
                    .collect()
            } else if which("pacman") {
                run("pacman", &["-Qoq", f])
                    .stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            owners.extend(
                names
                    .into_iter()
                    .filter(|n| !n.is_empty() && !n.contains(' ')),
            );
        }
        owners
    })
}

pub fn is_protected(name: &str) -> bool {
    let base = name.split(':').next().unwrap_or(name);
    if PROTECTED.contains(&base) || running_kernel_packages().contains(base) {
        return true;
    }
    // Name-based fallback for the running kernel when the owner lookup found nothing.
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let rel = rel.trim();
    !rel.is_empty()
        && base.contains(rel)
        && (base.starts_with("linux-") || base.starts_with("kernel"))
}

impl Pm {
    pub fn detect() -> Option<Pm> {
        if which("apt-get") && which("dpkg-query") {
            Some(Pm::Apt)
        } else if which("pacman") {
            Some(Pm::Pacman)
        } else if which("dnf") || which("dnf5") {
            Some(Pm::Dnf)
        } else if which("zypper") {
            Some(Pm::Zypper)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Pm::Apt => "APT (dpkg)",
            Pm::Dnf => "DNF",
            Pm::Pacman => "pacman",
            Pm::Zypper => "zypper",
        }
    }

    fn dnf() -> &'static str {
        if which("dnf") { "dnf" } else { "dnf5" }
    }

    pub fn cache_dirs(self) -> Vec<&'static str> {
        match self {
            Pm::Apt => vec!["/var/cache/apt/archives"],
            Pm::Dnf => vec!["/var/cache/dnf", "/var/cache/libdnf5"],
            Pm::Pacman => vec!["/var/cache/pacman/pkg"],
            Pm::Zypper => vec!["/var/cache/zypp/packages"],
        }
    }

    pub fn cache_clean_cmds(self) -> Vec<Vec<String>> {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match self {
            Pm::Apt => vec![v(&["apt-get", "clean"])],
            Pm::Dnf => vec![v(&[Self::dnf(), "clean", "all"])],
            // paccache keeps the latest version so downgrades remain possible.
            Pm::Pacman if which("paccache") => {
                vec![v(&["paccache", "-rk1"]), v(&["paccache", "-ruk0"])]
            }
            Pm::Pacman => vec![v(&["pacman", "-Sc", "--noconfirm"])],
            Pm::Zypper => vec![v(&["zypper", "--non-interactive", "clean", "--all"])],
        }
    }

    pub fn cache_description(self) -> &'static str {
        match self {
            Pm::Apt => "Downloaded .deb files kept in /var/cache/apt/archives (apt-get clean).",
            Pm::Dnf => "Cached repository metadata and packages (dnf clean all).",
            Pm::Pacman if which("paccache") => {
                "Old package versions in /var/cache/pacman/pkg; the newest copy of installed packages is kept (paccache)."
            }
            Pm::Pacman => "Cached packages that are no longer installed (pacman -Sc).",
            Pm::Zypper => "Cached packages and metadata (zypper clean --all).",
        }
    }

    pub fn list_installed(self) -> Result<Vec<Package>, String> {
        match self {
            Pm::Apt => list_apt(),
            Pm::Dnf | Pm::Zypper => list_rpm(self),
            Pm::Pacman => list_pacman(),
        }
    }

    /// Packages installed as dependencies that nothing needs any more.
    pub fn list_orphans(self) -> Result<Vec<String>, String> {
        let out = match self {
            Pm::Apt => run("apt-get", &["-s", "autoremove"]),
            Pm::Dnf => run(
                Self::dnf(),
                &["-q", "repoquery", "--unneeded", "--qf", "%{name}\n"],
            ),
            Pm::Pacman => run("pacman", &["-Qdtq"]),
            Pm::Zypper => run("zypper", &["--non-interactive", "packages", "--unneeded"]),
        };
        // `pacman -Qdtq` exits 1 when there are no orphans.
        if !out.ok
            && !(self == Pm::Pacman && out.stdout.trim().is_empty() && out.stderr.trim().is_empty())
        {
            return Err(out.combined());
        }
        let mut names: Vec<String> = match self {
            Pm::Apt => out
                .stdout
                .lines()
                .filter_map(|l| l.strip_prefix("Remv "))
                .filter_map(|l| l.split_whitespace().next())
                .map(str::to_string)
                .collect(),
            Pm::Dnf | Pm::Pacman => out
                .stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Pm::Zypper => out
                .stdout
                .lines()
                .filter(|l| l.starts_with('i'))
                .filter_map(|l| l.split('|').nth(2))
                .map(|n| n.trim().to_string())
                .collect(),
        };
        names.retain(|n| valid_name(n));
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Installed packages that no enabled repository provides any more
    /// (obsolete, dropped by the distro, or installed by hand). Not necessarily
    /// safe to remove, so these are only flagged, never auto-selected.
    pub fn list_obsolete(self) -> Result<Vec<String>, String> {
        let out = match self {
            Pm::Apt => run("apt", &["list", "--installed"]),
            Pm::Dnf => run(
                Self::dnf(),
                &["-q", "repoquery", "--extras", "--qf", "%{name}\n"],
            ),
            Pm::Pacman => run("pacman", &["-Qmq"]),
            Pm::Zypper => run("zypper", &["--non-interactive", "packages", "--orphaned"]),
        };
        // `pacman -Qmq` exits 1 when there are none.
        if !out.ok
            && !(self == Pm::Pacman && out.stdout.trim().is_empty() && out.stderr.trim().is_empty())
        {
            return Err(out.combined());
        }
        let mut names: Vec<String> = match self {
            // "name/now 1.0 amd64 [installed,local]" – "local" means no repo has it.
            Pm::Apt => out
                .stdout
                .lines()
                .filter(|l| l.contains(",local]"))
                .filter_map(|l| l.split('/').next())
                .map(str::to_string)
                .collect(),
            Pm::Dnf | Pm::Pacman => out
                .stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Pm::Zypper => out
                .stdout
                .lines()
                .filter(|l| l.starts_with('i'))
                .filter_map(|l| l.split('|').nth(2))
                .map(|n| n.trim().to_string())
                .collect(),
        };
        names.retain(|n| valid_name(n));
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Installed packages that have a newer version in an enabled repository,
    /// as `(name, new version)`. Uses already-downloaded metadata (no root).
    pub fn list_upgradable(self) -> Result<Vec<(String, String)>, String> {
        let out = match self {
            Pm::Apt => run("apt", &["list", "--upgradable"]),
            Pm::Dnf => run(
                Self::dnf(),
                &[
                    "-q",
                    "repoquery",
                    "--upgrades",
                    "--latest-limit",
                    "1",
                    "--qf",
                    "%{name}\t%{version}-%{release}\n",
                ],
            ),
            Pm::Pacman => run("pacman", &["-Qu"]),
            Pm::Zypper => run("zypper", &["--non-interactive", "--quiet", "list-updates"]),
        };
        // `pacman -Qu` exits 1 when there is nothing to upgrade.
        if !out.ok
            && !(self == Pm::Pacman && out.stdout.trim().is_empty() && out.stderr.trim().is_empty())
        {
            return Err(out.combined());
        }
        let mut v = parse_upgradable(self, &out.stdout);
        v.retain(|(n, _)| valid_name(n));
        v.sort();
        v.dedup_by(|a, b| a.0 == b.0);
        Ok(v)
    }

    /// Pacman does not support partial upgrades, so "upgrade" means a full `-Syu`.
    pub fn upgrade_is_full(self) -> bool {
        self == Pm::Pacman
    }

    pub fn upgrade_cmds(self, names: &[String]) -> Vec<Vec<String>> {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let names: Vec<String> = names.iter().filter(|n| valid_name(n)).cloned().collect();
        // pacman can only upgrade everything; for the others an empty list would mean "all packages".
        if names.is_empty() && self != Pm::Pacman {
            return Vec::new();
        }
        let with = |mut base: Vec<String>| {
            base.extend(names.iter().cloned());
            base
        };
        match self {
            Pm::Apt => vec![
                v(&["apt-get", "update"]),
                with(v(&[
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "--only-upgrade",
                    "-y",
                ])),
            ],
            Pm::Dnf => vec![with(vec![
                Self::dnf().into(),
                "upgrade".into(),
                "-y".into(),
            ])],
            Pm::Pacman => vec![v(&["pacman", "-Syu", "--noconfirm"])],
            Pm::Zypper => vec![with(v(&["zypper", "--non-interactive", "update"]))],
        }
    }

    /// Remove exactly the orphans that were scanned and shown to the user, minus protected ones.
    /// (A blanket `autoremove` would remove whatever is autoremovable *at run time*, which can be
    /// more than was listed and, on apt, also purges configuration files.)
    pub fn orphan_remove_cmds(self, names: &[String]) -> Vec<Vec<String>> {
        let chosen: Vec<String> = names
            .iter()
            .filter(|n| valid_name(n) && !is_protected(n))
            .cloned()
            .collect();
        if chosen.is_empty() {
            return Vec::new();
        }
        let mut cmd: Vec<String> = match self {
            Pm::Apt => vec![
                "env".into(),
                "DEBIAN_FRONTEND=noninteractive".into(),
                "apt-get".into(),
                "remove".into(),
                "-y".into(),
            ],
            Pm::Dnf => vec![Self::dnf().into(), "remove".into(), "-y".into()],
            Pm::Pacman => vec!["pacman".into(), "-Rns".into(), "--noconfirm".into()],
            Pm::Zypper => vec![
                "zypper".into(),
                "--non-interactive".into(),
                "rm".into(),
                "--clean-deps".into(),
            ],
        };
        cmd.extend(chosen);
        vec![cmd]
    }

    pub fn install_cmds(self, names: &[String]) -> Vec<Vec<String>> {
        let mut cmd: Vec<String> = match self {
            Pm::Apt => vec![
                "env".into(),
                "DEBIAN_FRONTEND=noninteractive".into(),
                "apt-get".into(),
                "install".into(),
                "-y".into(),
            ],
            Pm::Dnf => vec![Self::dnf().into(), "install".into(), "-y".into()],
            Pm::Pacman => vec![
                "pacman".into(),
                "-S".into(),
                "--noconfirm".into(),
                "--needed".into(),
            ],
            Pm::Zypper => vec![
                "zypper".into(),
                "--non-interactive".into(),
                "install".into(),
            ],
        };
        let before = cmd.len();
        cmd.extend(names.iter().filter(|n| valid_name(n)).cloned());
        if cmd.len() == before {
            vec![]
        } else {
            vec![cmd]
        }
    }

    pub fn remove_cmds(self, names: &[String]) -> Vec<Vec<String>> {
        let mut cmd: Vec<String> = match self {
            Pm::Apt => vec![
                "env".into(),
                "DEBIAN_FRONTEND=noninteractive".into(),
                "apt-get".into(),
                "remove".into(),
                "-y".into(),
            ],
            Pm::Dnf => vec![Self::dnf().into(), "remove".into(), "-y".into()],
            // Without -c pacman refuses to remove packages others depend on, which is what we want.
            Pm::Pacman => vec!["pacman".into(), "-Rns".into(), "--noconfirm".into()],
            Pm::Zypper => vec!["zypper".into(), "--non-interactive".into(), "rm".into()],
        };
        cmd.extend(
            names
                .iter()
                .filter(|n| valid_name(n) && !is_protected(n))
                .cloned(),
        );
        vec![cmd]
    }

    /// Dry-run a removal without root. Returns the tool output and the full list
    /// of packages that would be removed (when the tool reports it).
    pub fn preview_remove(self, names: &[String]) -> (CmdOut, Option<Vec<String>>) {
        let names: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|n| valid_name(n))
            .collect();
        let with = |base: &[&str]| -> Vec<String> {
            base.iter()
                .chain(names.iter())
                .map(|s| s.to_string())
                .collect()
        };
        match self {
            Pm::Apt => {
                let args = with(&["-s", "remove"]);
                let out = run(
                    "apt-get",
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                );
                let list = out
                    .stdout
                    .lines()
                    .filter_map(|l| l.strip_prefix("Remv "))
                    .filter_map(|l| l.split_whitespace().next())
                    .map(str::to_string)
                    .collect();
                // A failed simulation (lock, unmet dependency) says nothing about what would go.
                let list = out.ok.then_some(list);
                (out, list)
            }
            Pm::Pacman => {
                let args = with(&["-Rns", "--print", "--print-format", "%n"]);
                let out = run(
                    "pacman",
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                );
                let list = out.ok.then(|| {
                    out.stdout
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .collect()
                });
                (out, list)
            }
            Pm::Dnf => {
                let args = with(&["remove", "--assumeno"]);
                let out = run(
                    Self::dnf(),
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                );
                // dnf exits non-zero for --assumeno, so judge by whether it printed a plan.
                let list = parse_dnf_removals(&out.stdout);
                (out, (!list.is_empty()).then_some(list))
            }
            Pm::Zypper => {
                let args = with(&["--non-interactive", "rm", "--dry-run"]);
                let out = run(
                    "zypper",
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                );
                let list = parse_zypper_removals(&out.stdout);
                let known = out.ok && !list.is_empty();
                (out, known.then_some(list))
            }
        }
    }
}

/// Package names from `dnf remove --assumeno`: the indented rows under the "Removing…" headings.
fn parse_dnf_removals(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_plan = false;
    for l in text.lines() {
        if l.starts_with("Removing") && l.trim_end().ends_with(':') {
            in_plan = true;
        } else if l.starts_with("Transaction Summary") {
            break;
        } else if in_plan && l.starts_with(' ') {
            if let Some(n) = l.split_whitespace().next() {
                names.push(n.to_string());
            }
        } else if !l.trim().is_empty() && !l.starts_with(' ') {
            in_plan = false;
        }
    }
    names
}

/// Package names from `zypper rm --dry-run`: the block after "…going to be REMOVED:".
fn parse_zypper_removals(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_block = false;
    for l in text.lines() {
        if l.contains("going to be REMOVED") {
            in_block = true;
        } else if in_block {
            if l.trim().is_empty() {
                in_block = false;
            } else {
                names.extend(
                    l.split_whitespace()
                        .filter(|t| !t.starts_with('('))
                        .map(str::to_string),
                );
            }
        }
    }
    names
}

fn parse_upgradable(pm: Pm, text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| match pm {
            // "name/suite 2.0 amd64 [upgradable from: 1.0]"
            Pm::Apt => {
                if !l.contains("[upgradable from") {
                    return None;
                }
                let name = l.split('/').next()?;
                let ver = l.split_whitespace().nth(1)?;
                Some((name.to_string(), ver.to_string()))
            }
            // "name\tversion"
            Pm::Dnf => {
                let (n, v) = l.split_once('\t')?;
                Some((n.trim().to_string(), v.trim().to_string()))
            }
            // "name 1.0-1 -> 2.0-1"
            Pm::Pacman => {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() >= 4 && f[2] == "->").then(|| (f[0].to_string(), f[3].to_string()))
            }
            // "v | repo | name | current | available | arch"
            Pm::Zypper => {
                let f: Vec<&str> = l.split('|').map(str::trim).collect();
                (f.len() >= 5 && f[0] == "v").then(|| (f[2].to_string(), f[4].to_string()))
            }
        })
        .filter(|(n, v)| !n.is_empty() && !v.is_empty())
        .collect()
}

fn list_apt() -> Result<Vec<Package>, String> {
    let out = run(
        "dpkg-query",
        &[
            "-W",
            "-f",
            "${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Installed-Size}\n",
        ],
    );
    if !out.ok {
        return Err(out.combined());
    }
    let manual: HashSet<String> = run("apt-mark", &["showmanual"])
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .collect();
    let have_manual = !manual.is_empty();
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 4 || !f[0].starts_with("ii") {
                return None;
            }
            let name = f[1].to_string();
            let base = name.split(':').next().unwrap_or(&name);
            Some(Package {
                manual: have_manual.then(|| manual.contains(&name) || manual.contains(base)),
                version: f[2].to_string(),
                size: f[3].trim().parse::<u64>().unwrap_or(0) * 1024,
                name,
            })
        })
        .collect())
}

fn list_rpm(pm: Pm) -> Result<Vec<Package>, String> {
    let out = run(
        "rpm",
        &[
            "-qa",
            "--qf",
            "%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n",
        ],
    );
    if !out.ok {
        return Err(out.combined());
    }
    let manual: Option<HashSet<String>> = match pm {
        Pm::Dnf => {
            let o = run(
                Pm::dnf(),
                &["-q", "repoquery", "--userinstalled", "--qf", "%{name}\n"],
            );
            o.ok.then(|| {
                o.stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
        }
        _ => None,
    };
    // zypper records automatically installed packages in this file.
    let auto: Option<HashSet<String>> = (pm == Pm::Zypper)
        .then(|| std::fs::read_to_string("/var/lib/zypp/AutoInstalled").ok())
        .flatten()
        .map(|s| {
            s.lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect()
        });
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 3 || f[0] == "gpg-pubkey" {
                return None;
            }
            let name = f[0].to_string();
            let is_manual = match (&manual, &auto) {
                (Some(m), _) => Some(m.contains(&name)),
                (_, Some(a)) => Some(!a.contains(&name)),
                _ => None,
            };
            Some(Package {
                version: f[1].to_string(),
                size: f[2].trim().parse().unwrap_or(0),
                manual: is_manual,
                name,
            })
        })
        .collect())
}

fn list_pacman() -> Result<Vec<Package>, String> {
    let out = run("pacman", &["-Qi"]);
    if !out.ok {
        return Err(out.combined());
    }
    let explicit_out = run("pacman", &["-Qeq"]);
    // Without the explicit list every package would look like an automatic dependency.
    if !explicit_out.ok && !explicit_out.stderr.trim().is_empty() {
        return Err(explicit_out.combined());
    }
    let explicit: HashSet<String> = explicit_out
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .collect();
    Ok(parse_pacman_qi(&out.stdout, &explicit))
}

fn parse_pacman_qi(text: &str, explicit: &HashSet<String>) -> Vec<Package> {
    let mut pkgs = Vec::new();
    for block in text.split("\n\n") {
        let (mut name, mut version, mut size) = (None, String::new(), 0u64);
        for line in block.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k.trim() {
                "Name" => name = Some(v.trim().to_string()),
                "Version" => version = v.trim().to_string(),
                "Installed Size" => size = crate::util::parse_size(v).unwrap_or(0),
                _ => {}
            }
        }
        if let Some(name) = name {
            pkgs.push(Package {
                manual: Some(explicit.contains(&name)),
                name,
                version,
                size,
            });
        }
    }
    pkgs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("libstdc++6:amd64"));
        assert!(valid_name("python3.12"));
        assert!(!valid_name("-rf"));
        assert!(!valid_name("foo bar"));
        assert!(!valid_name("a;b"));
        assert!(is_protected("libc6:amd64"));
        assert!(is_protected("sudo"));
        assert!(!is_protected("gimp"));
    }

    #[test]
    fn categories() {
        assert_eq!(category("libc6:amd64"), Category::Libraries);
        assert_eq!(category("libreoffice-core"), Category::Applications);
        assert_eq!(category("libreoffice-help-en"), Category::DocsLocales);
        assert_eq!(category("libssl-dev"), Category::Development);
        assert_eq!(category("openssl-devel"), Category::Development);
        assert_eq!(category("python3-requests"), Category::LanguageModules);
        assert_eq!(category("fonts-dejavu-core"), Category::Fonts);
        assert_eq!(category("kernel-core"), Category::KernelFirmware);
        assert_eq!(category("firefox"), Category::Applications);
    }

    #[test]
    fn upgradable_parse() {
        let apt = "Listing...\nfoo/stable 2.0 amd64 [upgradable from: 1.0]\nbar/stable,now 3 all [upgradable from: 2]\n";
        assert_eq!(
            parse_upgradable(Pm::Apt, apt),
            vec![("foo".into(), "2.0".into()), ("bar".into(), "3".into())]
        );
        assert_eq!(
            parse_upgradable(Pm::Pacman, "zlib 1.3-1 -> 1.3.1-2\n"),
            vec![("zlib".into(), "1.3.1-2".into())]
        );
        assert_eq!(
            parse_upgradable(Pm::Dnf, "vim\t9.1-2\n"),
            vec![("vim".into(), "9.1-2".into())]
        );
        let z = "S | Repository | Name | Current Version | Available Version | Arch\n--+------+-----+---+---+---\nv | Main | vim | 1 | 2 | x86_64\n";
        assert_eq!(
            parse_upgradable(Pm::Zypper, z),
            vec![("vim".into(), "2".into())]
        );
    }

    #[test]
    fn pacman_parse() {
        let txt = "Name            : firefox\nVersion         : 130.0-1\nInstalled Size  : 240.50 MiB\n\nName            : zlib\nVersion         : 1:1.3.1-2\nInstalled Size  : 389.00 KiB\n";
        let ex: HashSet<String> = ["firefox".to_string()].into();
        let p = parse_pacman_qi(txt, &ex);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "firefox");
        assert_eq!(p[0].manual, Some(true));
        assert_eq!(p[1].version, "1:1.3.1-2");
        assert_eq!(p[1].size, 389 * 1024);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Runs against the real system package manager (skipped when none is found).
    #[test]
    #[ignore]
    fn live_preview() {
        let Some(pm) = Pm::detect() else { return };
        let pkgs = pm.list_installed().unwrap();
        assert!(!pkgs.is_empty());
        let target = pkgs
            .iter()
            .find(|p| p.name.starts_with("libreoffice-core"))
            .or(pkgs.first())
            .unwrap();
        let (out, affected) = pm.preview_remove(std::slice::from_ref(&target.name));
        println!(
            "{}\naffected: {:?}",
            out.combined()
                .lines()
                .take(5)
                .collect::<Vec<_>>()
                .join("\n"),
            affected.as_ref().map(|a| a.len())
        );
        println!("orphans: {:?}", pm.list_orphans());
        println!(
            "remove cmd: {:?}",
            pm.remove_cmds(&[target.name.clone(), "sudo".into(), "bad;name".into()])
        );
    }
}

#[cfg(test)]
mod live_upgrade_tests {
    use super::*;

    #[test]
    #[ignore]
    fn live_upgradable() {
        let Some(pm) = Pm::detect() else { return };
        let r = pm.list_upgradable();
        println!(
            "{:?}",
            r.as_ref()
                .map(|v| (v.len(), v.iter().take(5).collect::<Vec<_>>()))
        );
        println!("{:?}", pm.upgrade_cmds(&["foo".into(), "bad;x".into()]));
        assert!(r.is_ok());
    }
}

/// One installed package's identity for conflict detection.
struct ConflictRec {
    name: String,
    provides: Vec<String>,
    /// Only unconditional conflicts ("foo"); version-ranged ones ("foo < 2") are skipped
    /// because they can't be judged without comparing versions, and a false alarm is worse than none.
    conflicts: Vec<String>,
}

/// Map each package to the other installed packages it is declared to conflict with (both directions).
fn match_conflicts(recs: &[ConflictRec]) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_cap: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for r in recs {
        by_cap
            .entry(r.name.as_str())
            .or_default()
            .push(r.name.as_str());
        for p in &r.provides {
            by_cap.entry(p.as_str()).or_default().push(r.name.as_str());
        }
    }
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in recs {
        for c in &r.conflicts {
            for other in by_cap.get(c.as_str()).into_iter().flatten() {
                if *other != r.name {
                    out.entry(r.name.clone())
                        .or_default()
                        .insert(other.to_string());
                    out.entry(other.to_string())
                        .or_default()
                        .insert(r.name.clone());
                }
            }
        }
    }
    out.into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn split_caps(s: &str, sep: char) -> Vec<String> {
    s.split(sep)
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("none"))
        .map(str::to_string)
        .collect()
}

impl Pm {
    /// Installed packages that are declared to conflict with another installed package.
    /// The package manager normally prevents this, so hits usually mean a forced install
    /// or a repository change.
    pub fn list_conflicts(self) -> Result<std::collections::BTreeMap<String, Vec<String>>, String> {
        let mut recs = Vec::new();
        match self {
            Pm::Dnf | Pm::Zypper => {
                let out = run(
                    "rpm",
                    &[
                        "-qa",
                        "--qf",
                        "%{NAME}\t[%{PROVIDENAME} ]\t[%{CONFLICTNEVRS}|]\n",
                    ],
                );
                if !out.ok {
                    return Err(out.combined());
                }
                for l in out.stdout.lines() {
                    let mut f = l.split('\t');
                    let (Some(name), Some(prov), Some(conf)) = (f.next(), f.next(), f.next())
                    else {
                        continue;
                    };
                    recs.push(ConflictRec {
                        name: name.into(),
                        provides: split_caps(prov, ' '),
                        conflicts: split_caps(conf, '|')
                            .into_iter()
                            .filter(|c| !c.contains(' '))
                            .collect(),
                    });
                }
            }
            Pm::Apt => {
                let out = run(
                    "dpkg-query",
                    &[
                        "-W",
                        "-f",
                        "${db:Status-Abbrev}\t${Package}\t${Provides}\t${Conflicts}\n",
                    ],
                );
                if !out.ok {
                    return Err(out.combined());
                }
                let clean = |v: Vec<String>| -> Vec<String> {
                    v.into_iter()
                        .filter(|c| !c.contains('(') && !c.contains('|'))
                        .map(|c| c.split(':').next().unwrap_or(&c).to_string())
                        .collect()
                };
                for l in out.stdout.lines() {
                    let mut f = l.split('\t');
                    let (Some(state), Some(name), Some(prov), Some(conf)) =
                        (f.next(), f.next(), f.next(), f.next())
                    else {
                        continue;
                    };
                    if !state.starts_with('i') {
                        continue; // removed (rc) or never installed (un)
                    }
                    recs.push(ConflictRec {
                        name: name.into(),
                        provides: split_caps(prov, ',')
                            .into_iter()
                            .map(|p| p.split_whitespace().next().unwrap_or("").to_string())
                            .collect(),
                        conflicts: clean(split_caps(conf, ',')),
                    });
                }
            }
            Pm::Pacman => {
                let out = run("pacman", &["-Qi"]);
                if !out.ok {
                    return Err(out.combined());
                }
                let strip = |v: Vec<String>| -> Vec<String> {
                    v.into_iter()
                        .filter(|c| !c.contains(['<', '>']))
                        .map(|c| c.split('=').next().unwrap_or(&c).to_string())
                        .collect()
                };
                for block in out.stdout.split("\n\n") {
                    let field = |key: &str| {
                        block
                            .lines()
                            .find(|l| l.starts_with(key))
                            .and_then(|l| l.split_once(':'))
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default()
                    };
                    let name = field("Name");
                    if name.is_empty() {
                        continue;
                    }
                    recs.push(ConflictRec {
                        name,
                        provides: strip(split_caps(&field("Provides"), ' ')),
                        // "foo>=1  bar": two spaces between entries, a constraint stays inside its entry.
                        conflicts: split_caps(&field("Conflicts With"), ' ')
                            .into_iter()
                            .filter(|c| !c.contains(['<', '>', '=']))
                            .collect(),
                    });
                }
            }
        }
        Ok(match_conflicts(&recs))
    }
}

#[cfg(test)]
mod removal_preview_tests {
    use super::*;

    #[test]
    fn dnf_plan_lists_dependents_too() {
        let t = "Package Arch Version Repository Size\nRemoving:\n zip x86_64 0:3.0 fedora 694 KiB\nRemoving dependent packages:\n systemtap x86_64 0:5.6 fedora 0.0 B\nRemoving unused dependencies:\n tbb x86_64 0:1 fedora 4 KiB\n\nTransaction Summary:\n Removing: 3 packages\n";
        assert_eq!(parse_dnf_removals(t), vec!["zip", "systemtap", "tbb"]);
        assert!(parse_dnf_removals("Nothing to do.").is_empty());
    }

    #[test]
    fn zypper_plan_lists_removed_block() {
        let t = "Resolving...\nThe following 3 packages are going to be REMOVED:\n  a b\n  c\n\n3 packages to remove.\n";
        assert_eq!(parse_zypper_removals(t), vec!["a", "b", "c"]);
    }

    #[test]
    fn orphan_removal_uses_the_listed_names_and_skips_protected() {
        assert!(Pm::Apt.orphan_remove_cmds(&[]).is_empty());
        let cmds = Pm::Apt.orphan_remove_cmds(&["libfoo1".into(), "bash".into()]);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains(&"libfoo1".to_string()) && !cmds[0].contains(&"bash".to_string()));
        assert!(!cmds[0].contains(&"autoremove".to_string()));
        assert!(
            Pm::Dnf.upgrade_cmds(&[]).is_empty(),
            "an empty list must not mean 'upgrade everything'"
        );
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::*;

    fn rec(name: &str, prov: &[&str], conf: &[&str]) -> ConflictRec {
        ConflictRec {
            name: name.into(),
            provides: prov.iter().map(|s| s.to_string()).collect(),
            conflicts: conf.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn conflicts_match_names_and_provides_both_ways_and_ignore_self() {
        let r = [
            rec("a", &["a", "mta"], &["mta"]), // conflicts with its own provide: ignore
            rec("b", &["mta"], &["a-old", "mta"]),
            rec("c", &[], &["a"]),
            rec("d", &[], &["missing"]),
        ];
        let m = match_conflicts(&r);
        assert_eq!(m["a"], vec!["b", "c"]);
        assert_eq!(m["b"], vec!["a"]);
        assert_eq!(m["c"], vec!["a"]);
        assert!(!m.contains_key("d"));
    }
}

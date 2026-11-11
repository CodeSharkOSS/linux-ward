//! System performance diagnostics: boot time, startup items, old kernels,
//! config leftovers, package health, live load and tuning checks.
//! Everything here only *reads* the system; fixes are returned as `Action`s
//! that the UI runs after confirmation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pkg::Pm;
use crate::targets::Action;
use crate::util::{self, human, run, which};

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// ----- boot ------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Boot {
    pub summary: String,
    /// (seconds, unit) – slowest first.
    pub blame: Vec<(f64, String)>,
    pub chain: String,
    pub hint: Option<String>,
}

/// "1min 3.198s" style durations from systemd-analyze.
fn parse_dur(tok: &str) -> Option<f64> {
    for (suf, mul) in [
        ("min", 60.0),
        ("ms", 0.001),
        ("us", 1e-6),
        ("μs", 1e-6),
        ("h", 3600.0),
        ("d", 86400.0),
        ("s", 1.0),
    ] {
        if let Some(n) = tok.strip_suffix(suf) {
            return n.parse::<f64>().ok().map(|v| v * mul);
        }
    }
    None
}

fn parse_blame(text: &str) -> Vec<(f64, String)> {
    text.lines()
        .filter_map(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            let n = toks.iter().take_while(|t| parse_dur(t).is_some()).count();
            if n == 0 || n >= toks.len() {
                return None;
            }
            let secs = toks[..n].iter().filter_map(|t| parse_dur(t)).sum();
            Some((secs, toks[n..].join(" ")))
        })
        .collect()
}

fn load_boot() -> Boot {
    if !which("systemd-analyze") {
        return Boot::default();
    }
    let summary = run("systemd-analyze", &["--no-pager"])
        .stdout
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let mut blame = parse_blame(&run("systemd-analyze", &["blame", "--no-pager"]).stdout);
    blame.sort_by(|a, b| b.0.total_cmp(&a.0));
    let chain = run("systemd-analyze", &["critical-chain", "--no-pager"])
        .stdout
        .lines()
        .take(30)
        .collect::<Vec<_>>()
        .join("\n");
    let hint = blame.first().and_then(|(secs, unit)| {
        (*secs >= 10.0 && unit.ends_with(".device")).then(|| {
            format!(
                "Boot is waiting {secs:.0}s for a hardware device ({unit}). That usually means a disk in /etc/fstab that is missing, \
                 a device a virtual machine presents but never answers (e.g. a CD-ROM), or a driver timing out. Check /etc/fstab \
                 and remove unused devices; add `nofail,x-systemd.device-timeout=5s` to optional mounts."
            )
        })
    });
    Boot {
        summary,
        blame,
        chain,
        hint,
    }
}

// ----- startup items -----------------------------------------------------------

#[derive(Clone)]
pub struct Service {
    pub unit: String,
    pub secs: Option<f64>,
    pub protected: bool,
}

const PROTECTED_SERVICES: &[&str] = &[
    "systemd-",
    "dbus",
    "gdm",
    "sddm",
    "lightdm",
    "NetworkManager",
    "polkit",
    "udev",
    "auditd",
    "plymouth",
    "lvm2",
    "dm-event",
    "getty",
    "user@",
    "accounts-daemon",
    "selinux",
    "firewalld",
    "sshd",
    "chronyd",
    "mdmonitor",
    "rtkit",
    // Remote access, network and firewall units whose names differ between distros.
    "ssh",
    "user-runtime-dir@",
    "wpa_supplicant",
    "iwd",
    "apparmor",
    "ufw",
    "nftables",
    "iptables",
    "ip6tables",
    "networking",
    "rsyslog",
    "cron",
    "crond",
    "zfs",
    "multipathd",
];

/// Units of the desktop session that must keep running in "Your session" scope.
const PROTECTED_USER_SERVICES: &[&str] = &[
    "org.gnome.Shell",
    "org.gnome.SettingsDaemon",
    "gnome-session",
    "gnome-shell",
    "dbus",
    "pipewire",
    "wireplumber",
    "at-spi",
    "xdg-desktop-portal",
    "xdg-document-portal",
    "xdg-permission-store",
    "dconf",
    "gvfs",
    "plasma-",
    "kwin",
    "ssh-agent",
    "gpg-agent",
    "gcr-ssh-agent",
];

/// Essential services that the app will not stop or disable.
pub fn service_protected(unit: &str) -> bool {
    PROTECTED_SERVICES.iter().any(|p| unit.starts_with(p))
}

/// Same for the user manager: stopping the shell, dbus or the sound server ends the session.
pub fn user_service_protected(unit: &str) -> bool {
    PROTECTED_USER_SERVICES.iter().any(|p| unit.starts_with(p))
}

fn load_services(blame: &[(f64, String)]) -> Vec<Service> {
    let out = run(
        "systemctl",
        &[
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
    );
    let cost: HashMap<&str, f64> = blame.iter().map(|(s, u)| (u.as_str(), *s)).collect();
    let mut v: Vec<Service> = out
        .stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| crate::pkg::valid_name(u))
        .map(|u| Service {
            unit: u.to_string(),
            secs: cost.get(u).copied(),
            protected: PROTECTED_SERVICES.iter().any(|p| u.starts_with(p)),
        })
        .collect();
    v.sort_by(|a, b| {
        b.secs
            .unwrap_or(-1.0)
            .total_cmp(&a.secs.unwrap_or(-1.0))
            .then_with(|| a.unit.cmp(&b.unit))
    });
    v
}

#[derive(Clone)]
pub struct Autostart {
    pub file: String,
    pub name: String,
    pub path: PathBuf,
    pub enabled: bool,
    /// Provided by the system (/etc/xdg/autostart) rather than the user.
    pub system: bool,
}

fn user_autostart_dir() -> PathBuf {
    util::home().join(".config/autostart")
}

fn desktop_key(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .map(|v| v.trim().to_string())
    })
}

fn load_autostart() -> Vec<Autostart> {
    let mut map: BTreeMap<String, Autostart> = BTreeMap::new();
    for (dir, system) in [
        (PathBuf::from("/etc/xdg/autostart"), true),
        (user_autostart_dir(), false),
    ] {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let file = e.file_name().to_string_lossy().into_owned();
            if !file.ends_with(".desktop") {
                continue;
            }
            let text = std::fs::read_to_string(e.path()).unwrap_or_default();
            let hidden = desktop_key(&text, "Hidden").is_some_and(|v| v == "true")
                || desktop_key(&text, "X-GNOME-Autostart-enabled").is_some_and(|v| v == "false");
            // A user file overrides the system one of the same name; keep the system name if the override has none.
            let prev_name = map.get(&file).map(|a| a.name.clone());
            let name = desktop_key(&text, "Name")
                .or(prev_name)
                .unwrap_or_else(|| file.clone());
            map.insert(
                file.clone(),
                Autostart {
                    file,
                    name,
                    path: e.path(),
                    enabled: !hidden,
                    system,
                },
            );
        }
    }
    map.into_values().collect()
}

/// Enable or disable an autostart entry by editing/creating a file in the user's autostart folder.
pub fn set_autostart(a: &Autostart, enable: bool) -> Result<(), String> {
    let dir = user_autostart_dir();
    let user_path = dir.join(&a.file);
    let has_system_copy = Path::new("/etc/xdg/autostart").join(&a.file).exists();
    let err = |e: std::io::Error| format!("{}: {e}", user_path.display());
    if enable && has_system_copy && user_path.exists() {
        let text = std::fs::read_to_string(&user_path).map_err(err)?;
        // Only a file that does nothing but hide the system entry may be removed; one the user
        // customised (its own Exec= or flags) keeps its contents and just stops being hidden.
        let pure_override = text.lines().map(str::trim).all(|l| {
            l.is_empty()
                || l.starts_with('#')
                || l == "[Desktop Entry]"
                || ["Hidden=", "X-GNOME-Autostart-enabled=", "Type=", "Name="]
                    .iter()
                    .any(|k| l.starts_with(k))
        });
        if pure_override {
            return std::fs::remove_file(&user_path).map_err(err);
        }
    }
    let base = if user_path.exists() {
        std::fs::read_to_string(&user_path).map_err(err)?
    } else if has_system_copy {
        // Start from the real system entry so the copy keeps its Exec= line.
        std::fs::read_to_string(Path::new("/etc/xdg/autostart").join(&a.file)).map_err(err)?
    } else {
        return Err("autostart file not found".into());
    };
    let mut lines: Vec<String> = base
        .lines()
        .filter(|l| !l.starts_with("Hidden=") && !l.starts_with("X-GNOME-Autostart-enabled="))
        .map(str::to_string)
        .collect();
    if !enable {
        let at = lines
            .iter()
            .position(|l| l.trim() == "[Desktop Entry]")
            .map_or(0, |i| i + 1);
        lines.insert(at, "Hidden=true".into());
    }
    std::fs::create_dir_all(&dir).map_err(err)?;
    std::fs::write(&user_path, lines.join("\n") + "\n").map_err(err)
}

// ----- kernels -----------------------------------------------------------------

#[derive(Clone)]
pub struct Kernel {
    /// Version key, e.g. `7.3.3-300.fc45.x86_64` (rpm) or `6.8.0-45` (apt).
    pub version: String,
    pub packages: Vec<String>,
    pub size: u64,
    pub running: bool,
    pub newest: bool,
}

impl Kernel {
    /// The running kernel and the newest one are never offered for removal.
    pub fn removable(&self) -> bool {
        !self.running && !self.newest
    }
}

fn chunks(s: &str) -> Vec<(bool, String)> {
    let mut v: Vec<(bool, String)> = Vec::new();
    for c in s.chars() {
        let d = c.is_ascii_digit();
        match v.last_mut() {
            Some((kind, text)) if *kind == d => text.push(c),
            _ => v.push((d, c.to_string())),
        }
    }
    v
}

/// Version-aware comparison ("7.10" > "7.9").
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (ca, cb) = (chunks(a), chunks(b));
    for (x, y) in ca.iter().zip(cb.iter()) {
        let o = if x.0 && y.0 {
            x.1.parse::<u64>()
                .unwrap_or(0)
                .cmp(&y.1.parse::<u64>().unwrap_or(0))
        } else {
            x.1.cmp(&y.1)
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    ca.len().cmp(&cb.len())
}

fn finish_kernels(
    map: BTreeMap<String, Kernel>,
    running: &str,
    is_running: impl Fn(&str, &str) -> bool,
) -> Vec<Kernel> {
    let mut v: Vec<Kernel> = map.into_values().collect();
    v.sort_by(|a, b| natural_cmp(&b.version, &a.version));
    for (i, k) in v.iter_mut().enumerate() {
        k.newest = i == 0;
        k.running = is_running(&k.version, running);
    }
    v
}

pub fn kernels(pm: Pm) -> Vec<Kernel> {
    let running = run("uname", &["-r"]).stdout.trim().to_string();
    let mut map: BTreeMap<String, Kernel> = BTreeMap::new();
    let mut add = |ver: String, pkg: String, size: u64| {
        let k = map.entry(ver.clone()).or_insert_with(|| Kernel {
            version: ver,
            packages: vec![],
            size: 0,
            running: false,
            newest: false,
        });
        k.packages.push(pkg);
        k.size += size;
    };
    match pm {
        Pm::Dnf => {
            const NAMES: &[&str] = &[
                "kernel",
                "kernel-core",
                "kernel-modules",
                "kernel-modules-core",
                "kernel-modules-extra",
                "kernel-devel",
            ];
            let out = run(
                "rpm",
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n",
                ],
            );
            for l in out.stdout.lines() {
                let f: Vec<&str> = l.split('\t').collect();
                if f.len() == 3 && NAMES.contains(&f[0]) {
                    add(
                        f[1].to_string(),
                        format!("{}-{}", f[0], f[1]),
                        f[2].parse().unwrap_or(0),
                    );
                }
            }
            finish_kernels(map, &running, |v, r| v == r)
        }
        Pm::Apt => {
            const PREFIXES: &[&str] = &[
                "linux-image-unsigned-",
                "linux-image-",
                "linux-headers-",
                "linux-modules-extra-",
                "linux-modules-",
            ];
            let out = run(
                "dpkg-query",
                &[
                    "-W",
                    "-f",
                    "${db:Status-Abbrev}\t${Package}\t${Installed-Size}\n",
                ],
            );
            for l in out.stdout.lines() {
                let f: Vec<&str> = l.split('\t').collect();
                if f.len() < 3 || !f[0].starts_with("ii") {
                    continue;
                }
                let Some(rest) = PREFIXES.iter().find_map(|p| f[1].strip_prefix(p)) else {
                    continue;
                };
                if !rest.starts_with(|c: char| c.is_ascii_digit()) {
                    continue; // meta packages such as linux-image-generic
                }
                let key = rest.splitn(3, '-').take(2).collect::<Vec<_>>().join("-");
                add(
                    key,
                    f[1].to_string(),
                    f[2].trim().parse::<u64>().unwrap_or(0) * 1024,
                );
            }
            finish_kernels(map, &running, |v, r| {
                r == v || r.starts_with(&format!("{v}-"))
            })
        }
        _ => vec![],
    }
}

pub fn kernel_remove_cmds(pm: Pm, ks: &[&Kernel]) -> Vec<Vec<String>> {
    let pkgs: Vec<String> = ks
        .iter()
        .filter(|k| k.removable())
        .flat_map(|k| k.packages.iter().cloned())
        .filter(|p| crate::pkg::valid_name(p))
        .collect();
    if pkgs.is_empty() {
        return vec![];
    }
    let mut cmd = match pm {
        Pm::Dnf => strs(&["dnf", "remove", "-y"]),
        Pm::Apt => strs(&[
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "purge",
            "-y",
        ]),
        _ => return vec![],
    };
    cmd.extend(pkgs);
    vec![cmd]
}

// ----- config leftovers --------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LeftKind {
    /// The package shipped a new default; your edited file is still in use.
    NewDefault,
    /// Your edited file was replaced by the package default; this is your old copy.
    OldCopy,
}

#[derive(Clone)]
pub struct Leftover {
    pub path: PathBuf,
    pub live: PathBuf,
    pub kind: LeftKind,
    /// Byte-for-byte the same as the live file, so deleting it loses nothing.
    pub identical: bool,
}

fn leftover_suffixes(pm: Pm) -> &'static [(&'static str, LeftKind)] {
    match pm {
        Pm::Dnf | Pm::Zypper => &[
            (".rpmnew", LeftKind::NewDefault),
            (".rpmsave", LeftKind::OldCopy),
            (".rpmorig", LeftKind::OldCopy),
        ],
        Pm::Apt => &[
            (".dpkg-new", LeftKind::NewDefault),
            (".dpkg-dist", LeftKind::NewDefault),
            (".dpkg-old", LeftKind::OldCopy),
        ],
        Pm::Pacman => &[
            (".pacnew", LeftKind::NewDefault),
            (".pacsave", LeftKind::OldCopy),
        ],
    }
}

pub fn leftovers(pm: Pm) -> Vec<Leftover> {
    let sfx = leftover_suffixes(pm);
    let mut v: Vec<Leftover> = walkdir::WalkDir::new("/etc")
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let (s, kind) = sfx.iter().find(|(s, _)| name.ends_with(s))?;
            let live = e.path().with_file_name(name.strip_suffix(s)?);
            let identical = match (std::fs::read(e.path()), std::fs::read(&live)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
            Some(Leftover {
                path: e.into_path(),
                live,
                kind: *kind,
                identical,
            })
        })
        .collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v
}

pub fn leftover_delete_cmds(pm: Pm, files: &[&Leftover]) -> Vec<Vec<String>> {
    let sfx = leftover_suffixes(pm);
    let mut cmd = strs(&["rm", "-f", "--"]);
    for f in files {
        let p = f.path.to_string_lossy();
        // Only ever delete recognised leftovers inside /etc.
        if f.path.starts_with("/etc/")
            && !p.contains("..")
            && sfx.iter().any(|(s, _)| p.ends_with(s))
        {
            cmd.push(p.into_owned());
        }
    }
    if cmd.len() > 3 { vec![cmd] } else { vec![] }
}

/// Unified diff between the live config file and a leftover (truncated).
pub fn leftover_diff(l: &Leftover) -> String {
    if !l.live.exists() {
        return "(the live file no longer exists)".into();
    }
    let (live, other) = (l.live.to_string_lossy(), l.path.to_string_lossy());
    let out = run("diff", &["-u", "--", &live, &other]);
    let text = out.combined();
    if text.trim().is_empty() {
        return "(identical to the live file – safe to delete)".into();
    }
    let mut lines: Vec<&str> = text.lines().take(300).collect();
    if text.lines().count() > 300 {
        lines.push("… (truncated)");
    }
    lines.join("\n")
}

// ----- health checks -----------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Judge {
    /// Healthy when the command exits 0.
    ExitOk,
    /// `rpm -Va`: healthy when no non-config file differs.
    RpmVerify,
    /// Healthy when the command prints nothing.
    EmptyOutput,
}

#[derive(Clone)]
pub struct Check {
    pub title: &'static str,
    pub desc: &'static str,
    pub cmd: Vec<String>,
    pub judge: Judge,
    pub fix: Option<Fix>,
}

#[derive(Clone)]
pub struct Fix {
    pub label: String,
    pub action: Action,
}

#[derive(Clone)]
pub struct HealthResult {
    pub title: &'static str,
    pub desc: &'static str,
    pub ok: bool,
    pub output: String,
    pub fix: Option<Fix>,
}

/// Package-manager checks plus general system hygiene checks (failed services, firewall, security updates).
pub fn health_checks(pm: Pm) -> Vec<Check> {
    let root = |cmds: &[&[&str]]| Action::Root(cmds.iter().map(|c| strs(c)).collect());
    let mut v = pm_checks(pm);
    v.push(Check {
        title: "Failed services",
        desc: "`systemctl --failed` lists system services that crashed or failed to start.",
        cmd: strs(&["systemctl", "--failed", "--no-legend", "--plain"]),
        judge: Judge::EmptyOutput,
        fix: Some(Fix {
            label: "Clear the failed state (does not fix the cause)".into(),
            action: root(&[&["systemctl", "reset-failed"]]),
        }),
    });
    v.push(Check {
        title: "Firewall not running",
        desc: "Checks that firewalld, ufw or nftables is active. Skip this if you rely on a router or another firewall.",
        cmd: strs(&[
            "sh",
            "-c",
            "systemctl is-active --quiet firewalld || systemctl is-active --quiet ufw || systemctl is-active --quiet nftables",
        ]),
        judge: Judge::ExitOk,
        fix: None,
    });
    match pm {
        Pm::Dnf => v.push(Check {
            title: "Pending security updates",
            desc: "`dnf updateinfo list --security` from already-downloaded metadata. Refresh your package index to see the latest.",
            cmd: strs(&["sh", "-c", "dnf updateinfo list --security 2>/dev/null"]),
            judge: Judge::EmptyOutput,
            fix: Some(Fix {
                label: "Install security updates".into(),
                action: root(&[&["dnf", "upgrade", "--security", "-y"]]),
            }),
        }),
        Pm::Apt => v.push(Check {
            title: "Pending security updates",
            desc: "Simulated `apt-get upgrade`, showing packages from a security repository. Refresh your package index to see the latest.",
            cmd: strs(&["sh", "-c", "apt-get -s upgrade 2>/dev/null | grep -i '^Inst.*security' || true"]),
            judge: Judge::EmptyOutput,
            fix: None,
        }),
        _ => {}
    }
    v
}

fn pm_checks(pm: Pm) -> Vec<Check> {
    let root = |cmds: &[&[&str]]| Action::Root(cmds.iter().map(|c| strs(c)).collect());
    match pm {
        Pm::Dnf => {
            let dnf = if which("dnf") { "dnf" } else { "dnf5" };
            vec![
                Check {
                    title: "Packages out of sync with the release",
                    desc: "Dry run of `dnf distro-sync`: lists packages that differ from what your repositories ship. After a version upgrade this is the main way to clean up mixed or leftover packages.",
                    cmd: strs(&[dnf, "distro-sync", "--assumeno"]),
                    judge: Judge::ExitOk,
                    fix: Some(Fix {
                        label: "Sync packages to the release".into(),
                        action: root(&[&[dnf, "distro-sync", "-y"]]),
                    }),
                },
                Check {
                    title: "Broken dependencies",
                    desc: "`dnf check` looks for missing or conflicting dependencies and duplicate packages.",
                    cmd: strs(&[dnf, "check"]),
                    judge: Judge::ExitOk,
                    fix: None,
                },
                Check {
                    title: "Modified or damaged system files",
                    desc: "`rpm -Va` compares installed files with the package database (config files ignored). Can take a minute.",
                    cmd: strs(&["rpm", "-Va"]),
                    judge: Judge::RpmVerify,
                    fix: None,
                },
            ]
        }
        Pm::Apt => vec![
            Check {
                title: "Broken dependencies",
                desc: "`apt-get check` looks for broken dependencies.",
                cmd: strs(&["apt-get", "check"]),
                judge: Judge::ExitOk,
                fix: Some(Fix {
                    label: "Repair (apt-get -f install, dpkg --configure -a)".into(),
                    action: root(&[
                        &["dpkg", "--configure", "-a"],
                        &["apt-get", "-f", "install", "-y"],
                    ]),
                }),
            },
            Check {
                title: "Half-installed packages",
                desc: "`dpkg --audit` lists packages left half-configured by an interrupted upgrade.",
                cmd: strs(&["dpkg", "--audit"]),
                judge: Judge::EmptyOutput,
                fix: Some(Fix {
                    label: "Finish configuring".into(),
                    action: root(&[&["dpkg", "--configure", "-a"]]),
                }),
            },
        ],
        Pm::Pacman => vec![
            Check {
                title: "Package database consistency",
                desc: "`pacman -Dk` checks dependencies and the sync database.",
                cmd: strs(&["pacman", "-Dk"]),
                judge: Judge::ExitOk,
                fix: None,
            },
            Check {
                title: "Missing package files",
                desc: "`pacman -Qkq` lists packages with missing files.",
                cmd: strs(&["pacman", "-Qkq"]),
                judge: Judge::EmptyOutput,
                fix: None,
            },
        ],
        Pm::Zypper => vec![Check {
            title: "Broken dependencies",
            desc: "`zypper verify` checks that dependencies of installed packages are satisfied.",
            cmd: strs(&["zypper", "--non-interactive", "verify", "--dry-run"]),
            judge: Judge::ExitOk,
            fix: Some(Fix {
                label: "Repair dependencies".into(),
                action: root(&[&["zypper", "--non-interactive", "verify"]]),
            }),
        }],
    }
}

/// `rpm -Va` lines look like `S.5....T.  c /etc/foo`; ignore config files ('c') and ghost files ('g').
fn rpm_va_problems(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| {
            let mut it = l.split_whitespace();
            let (Some(flags), Some(second)) = (it.next(), it.next()) else {
                return !l.trim().is_empty();
            };
            let is_attr = second.len() == 1 && "cdglr".contains(second);
            // c/d/g/l/r mark config, doc, ghost, licence and readme files: edits there aren't damage.
            !is_attr && flags.len() >= 2
        })
        .collect()
}

pub fn run_check(c: &Check) -> HealthResult {
    let args: Vec<&str> = c.cmd[1..].iter().map(String::as_str).collect();
    let out = run(&c.cmd[0], &args);
    let (ok, output) = match c.judge {
        Judge::ExitOk => (out.ok, out.combined()),
        Judge::EmptyOutput => (out.stdout.trim().is_empty() && out.ok, out.combined()),
        Judge::RpmVerify => {
            let bad = rpm_va_problems(&out.stdout);
            (bad.is_empty(), bad.join("\n"))
        }
    };
    let output = output.lines().take(200).collect::<Vec<_>>().join("\n");
    HealthResult {
        title: c.title,
        desc: c.desc,
        ok,
        output,
        fix: if ok { None } else { c.fix.clone() },
    }
}

// ----- live load -----------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Pressure {
    pub some: [f32; 3],
    pub full: [f32; 3],
}

#[derive(Clone)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub mem: u64,
    /// Bytes read+written per second (only for processes we may inspect).
    pub io: u64,
}

#[derive(Clone, Default)]
pub struct Live {
    pub cpu: Pressure,
    pub io: Pressure,
    pub mem: Pressure,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_avail: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub top_cpu: Vec<Proc>,
    pub top_mem: Vec<Proc>,
    pub top_io: Vec<Proc>,
    pub verdict: Vec<String>,
}

fn parse_pressure(text: &str) -> Pressure {
    let mut p = Pressure::default();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        let target = match it.next() {
            Some("some") => &mut p.some,
            Some("full") => &mut p.full,
            _ => continue,
        };
        for kv in it {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            let i = match k {
                "avg10" => 0,
                "avg60" => 1,
                "avg300" => 2,
                _ => continue,
            };
            target[i] = v.parse().unwrap_or(0.0);
        }
    }
    p
}

fn meminfo_kb(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

struct Sample {
    pid: u32,
    name: String,
    ticks: u64,
    rss_pages: u64,
    io: Option<u64>,
}

/// Parse `/proc/<pid>/stat`: returns (name, utime+stime ticks, rss pages).
pub fn parse_stat(s: &str) -> Option<(String, u64, u64)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let name = s[open + 1..close].to_string();
    let f: Vec<&str> = s[close + 1..].split_whitespace().collect();
    // After the ')' field 3 (state) is index 0, so utime(14) is 11, stime(15) is 12, rss(24) is 21.
    let g = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
    Some((name, g(11)? + g(12)?, g(21)?))
}

fn sample_procs() -> Vec<Sample> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let (name, ticks, rss_pages) =
                parse_stat(&std::fs::read_to_string(e.path().join("stat")).ok()?)?;
            let io = std::fs::read_to_string(e.path().join("io")).ok().map(|t| {
                t.lines()
                    .filter(|l| l.starts_with("read_bytes:") || l.starts_with("write_bytes:"))
                    .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                    .sum()
            });
            Some(Sample {
                pid,
                name,
                ticks,
                rss_pages,
                io,
            })
        })
        .collect()
}

/// Measure load for ~0.5 s and work out what is hogging the machine.
pub fn live_snapshot() -> Live {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let a = sample_procs();
    let t0 = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    let b = sample_procs();
    let dt = t0.elapsed().as_secs_f32().max(0.05);
    // SAFETY: sysconf has no preconditions.
    let (tck, page) = unsafe {
        (
            libc::sysconf(libc::_SC_CLK_TCK).max(1) as f32,
            libc::sysconf(libc::_SC_PAGESIZE).max(1) as u64,
        )
    };
    let before: HashMap<u32, &Sample> = a.iter().map(|s| (s.pid, s)).collect();
    let procs: Vec<Proc> = b
        .iter()
        .map(|s| {
            let prev = before.get(&s.pid);
            let cpu = prev.map_or(0.0, |p| {
                s.ticks.saturating_sub(p.ticks) as f32 / tck / dt * 100.0
            });
            let io = match (s.io, prev.and_then(|p| p.io)) {
                (Some(n), Some(o)) => (n.saturating_sub(o) as f32 / dt) as u64,
                _ => 0,
            };
            Proc {
                pid: s.pid,
                name: s.name.clone(),
                cpu,
                mem: s.rss_pages * page,
                io,
            }
        })
        .collect();
    let top = |key: fn(&Proc) -> f64, min: f64| {
        let mut v: Vec<Proc> = procs.iter().filter(|p| key(p) > min).cloned().collect();
        v.sort_by(|x, y| key(y).total_cmp(&key(x)));
        v.truncate(6);
        v
    };
    let mi = read("/proc/meminfo");
    let load: Vec<f32> = read("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect();
    let mut live = Live {
        cpu: parse_pressure(&read("/proc/pressure/cpu")),
        io: parse_pressure(&read("/proc/pressure/io")),
        mem: parse_pressure(&read("/proc/pressure/memory")),
        load: [
            *load.first().unwrap_or(&0.0),
            *load.get(1).unwrap_or(&0.0),
            *load.get(2).unwrap_or(&0.0),
        ],
        mem_total: meminfo_kb(&mi, "MemTotal"),
        mem_avail: meminfo_kb(&mi, "MemAvailable"),
        swap_total: meminfo_kb(&mi, "SwapTotal"),
        swap_used: meminfo_kb(&mi, "SwapTotal").saturating_sub(meminfo_kb(&mi, "SwapFree")),
        top_cpu: top(|p| p.cpu as f64, 0.5),
        top_mem: top(|p| p.mem as f64, 0.0),
        top_io: top(|p| p.io as f64, 1024.0),
        verdict: vec![],
    };
    live.verdict = verdict(&live);
    live
}

fn verdict(l: &Live) -> Vec<String> {
    let mut v = Vec::new();
    let name = |list: &[Proc]| {
        list.first()
            .map(|p| format!(" Biggest: {} ({:.0}%).", p.name, p.cpu))
            .unwrap_or_default()
    };
    if l.cpu.some[0] > 25.0 {
        v.push(format!(
            "CPU is contended ({:.0}% of the time something waited for a core).{}",
            l.cpu.some[0],
            name(&l.top_cpu)
        ));
    }
    if l.io.some[0] > 10.0 || l.io.full[0] > 5.0 {
        v.push(format!(
            "Disk I/O is a bottleneck ({:.0}% of the time tasks stalled on the disk). Look at the I/O list, a running indexer or backup, or a failing/slow disk.",
            l.io.some[0]
        ));
    }
    if l.mem.some[0] > 5.0 {
        v.push(format!(
            "Memory pressure ({:.0}% stalled). Close heavy apps or add swap/zram.",
            l.mem.some[0]
        ));
    }
    // Idle pages parked in swap are normal; it only matters when RAM is also nearly gone.
    if l.swap_total > 0
        && l.swap_used * 2 > l.swap_total
        && l.mem_total > 0
        && l.mem_avail * 5 < l.mem_total
    {
        v.push("More than half of swap is in use and little RAM is free – the machine is short of RAM.".into());
    }
    if v.is_empty() {
        v.push("No bottleneck right now: CPU, disk and memory are all keeping up.".into());
    }
    v
}

// ----- tuning ----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Info,
}

#[derive(Clone)]
pub struct Tuning {
    pub title: String,
    pub detail: String,
    pub level: Level,
    pub fix: Option<Fix>,
}

fn has_ssd() -> bool {
    std::fs::read_dir("/sys/block").is_ok_and(|rd| {
        rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            !["loop", "ram", "zram", "sr", "dm-"]
                .iter()
                .any(|p| n.starts_with(p))
                && std::fs::read_to_string(e.path().join("queue/rotational"))
                    .is_ok_and(|r| r.trim() == "0")
        })
    })
}

pub fn tuning(pm: Option<Pm>, kernels: &[Kernel]) -> Vec<Tuning> {
    let mut v = Vec::new();
    let t = |title: &str, detail: String, level: Level, fix: Option<Fix>| Tuning {
        title: title.into(),
        detail,
        level,
        fix,
    };
    let root_fix = |label: &str, cmds: &[&[&str]]| {
        Some(Fix {
            label: label.into(),
            action: Action::Root(cmds.iter().map(|c| strs(c)).collect()),
        })
    };

    // Reboot pending: a newer kernel is installed than the one running.
    if let Some(newest) = kernels.first()
        && !newest.running
        && kernels.iter().any(|k| k.running)
    {
        v.push(t("Reboot pending", format!("A newer kernel ({}) is installed but you are still running an older one. Reboot to use it.", newest.version), Level::Warn, None));
    }

    if std::path::Path::new("/.autorelabel").exists() {
        v.push(t("SELinux relabel scheduled", "A full filesystem relabel runs on the next boot, which makes that boot slow. This is expected after some upgrades.".into(), Level::Info, None));
    }

    let failed = run(
        "systemctl",
        &["--failed", "--no-legend", "--plain", "--no-pager"],
    )
    .stdout;
    let failed: Vec<&str> = failed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if failed.is_empty() {
        v.push(t(
            "Failed services",
            "No failed system services.".into(),
            Level::Ok,
            None,
        ));
    } else {
        v.push(t(
            "Failed services",
            format!(
                "{} service(s) failed and may be retrying or wasting time: {}",
                failed.len(),
                failed.join(", ")
            ),
            Level::Warn,
            root_fix("Clear failed state", &[&["systemctl", "reset-failed"]]),
        ));
    }

    if has_ssd() {
        let enabled = run("systemctl", &["is-enabled", "fstrim.timer"])
            .stdout
            .trim()
            == "enabled";
        if enabled {
            v.push(t(
                "SSD trim",
                "Weekly TRIM (fstrim.timer) is enabled.".into(),
                Level::Ok,
                None,
            ));
        } else {
            v.push(t(
                "SSD trim",
                "An SSD was found but periodic TRIM is not enabled; writes slow down over time."
                    .into(),
                Level::Warn,
                root_fix(
                    "Enable fstrim.timer",
                    &[&["systemctl", "enable", "--now", "fstrim.timer"]],
                ),
            ));
        }
    }

    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    let has_swap = swaps.lines().skip(1).any(|l| !l.trim().is_empty());
    let zram = swaps.contains("zram");
    let swappiness = std::fs::read_to_string("/proc/sys/vm/swappiness")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !has_swap {
        let fix = (pm == Some(Pm::Dnf)).then(|| Fix {
            label: "Install zram swap (takes effect after reboot)".into(),
            action: Action::Root(vec![strs(&[
                "dnf",
                "install",
                "-y",
                "zram-generator-defaults",
            ])]),
        });
        v.push(t(
            "Swap",
            "No swap or zram is active. Without it memory spikes can freeze the desktop.".into(),
            Level::Warn,
            fix,
        ));
    } else {
        v.push(t(
            "Swap",
            format!(
                "{} active, swappiness {swappiness}.",
                if zram {
                    "Compressed zram swap is"
                } else {
                    "Swap is"
                }
            ),
            Level::Ok,
            None,
        ));
    }

    for (_, pct) in util::disks()
        .iter()
        .filter(|d| d.mount == "/")
        .map(|d| (d, (d.total.saturating_sub(d.avail)) * 100 / d.total.max(1)))
    {
        if pct >= 90 {
            v.push(t("Root filesystem almost full", format!("/ is {pct}% full; filesystems slow down and updates can fail near 100%. Use the Cleanup and Large files tabs."), Level::Warn, None));
        }
    }

    // Indexers hammer the disk after an upgrade while they rebuild their database.
    let indexers = [
        "localsearch",
        "tracker-miner",
        "baloo_file",
        "tracker-extract",
    ];
    let running: Vec<String> = sample_procs()
        .into_iter()
        .filter(|s| indexers.iter().any(|i| s.name.starts_with(i)))
        .map(|s| s.name)
        .collect();
    if !running.is_empty() {
        v.push(t("File indexer running", format!("{} is running. Indexers re-scan everything after upgrades and can keep the disk busy for a while; they settle on their own. Disable file search in your desktop Settings if it never does.", running.join(", ")), Level::Info, None));
    }

    if let Some(pm) = pm {
        let (label, cmds): (&str, Vec<Vec<String>>) = match pm {
            Pm::Dnf => (
                "Refresh package metadata",
                vec![strs(&["dnf", "makecache", "--refresh"])],
            ),
            Pm::Apt => ("Refresh package index", vec![strs(&["apt-get", "update"])]),
            Pm::Zypper => (
                "Refresh package metadata",
                vec![strs(&["zypper", "--non-interactive", "refresh"])],
            ),
            Pm::Pacman => ("", vec![]),
        };
        if !cmds.is_empty() {
            v.push(t("Package metadata", "Rebuild the package manager's cache; fixes slow or erroring updates after an upgrade.".into(), Level::Info, Some(Fix { label: label.into(), action: Action::Root(cmds) })));
        }
    }
    v.push(t("Shared-library cache", "Rebuild the linker cache (ldconfig); fixes programs failing to find or slowly loading libraries after upgrades.".into(), Level::Info, root_fix("Run ldconfig", &[&["ldconfig"]])));
    if which("fc-cache") {
        v.push(t(
            "Font cache",
            "Rebuild the font cache; fixes slow app start-up and missing glyphs after upgrades."
                .into(),
            Level::Info,
            Some(Fix {
                label: "Rebuild font cache".into(),
                action: Action::User(vec![strs(&["fc-cache", "-r"])]),
            }),
        ));
    }
    // /system-update is the trigger for a download that is still waiting for its reboot.
    let upgrade_staged = std::fs::symlink_metadata("/system-update").is_ok();
    if Path::new("/var/lib/system-upgrade").exists() && !upgrade_staged {
        let size = util::dir_usage(Path::new("/var/lib/system-upgrade"));
        if size > 50 << 20 {
            v.push(t(
                "Leftover upgrade download",
                format!(
                    "/var/lib/system-upgrade holds {} from a past release upgrade.",
                    human(size)
                ),
                Level::Info,
                root_fix("Delete it", &[&["rm", "-rf", "/var/lib/system-upgrade"]]),
            ));
        }
    }
    v
}

// ----- virtual machines, fstab and recommended fixes ---------------------------------

/// One thing the user can fix with a click. Several are applied together with a single password prompt.
#[derive(Clone)]
pub struct Rec {
    pub tag: &'static str,
    pub title: String,
    pub detail: String,
    /// Safe fixes are pre-selected; the rest need a conscious opt-in.
    pub safe: bool,
    pub actions: Vec<Action>,
}

/// A diagnosis with no fix available inside the guest.
#[derive(Clone)]
pub struct Finding {
    pub title: String,
    pub detail: String,
}

pub fn vm_kind() -> Option<String> {
    if !which("systemd-detect-virt") {
        return None;
    }
    let out = run("systemd-detect-virt", &["--vm"]);
    let k = out.stdout.trim();
    (!k.is_empty() && k != "none").then(|| k.to_string())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Vmware,
    Qemu,
    Vbox,
    HyperV,
}

const FAMILIES: [Family; 4] = [Family::Vmware, Family::Qemu, Family::Vbox, Family::HyperV];

fn family(kind: &str) -> Option<Family> {
    match kind {
        "vmware" => Some(Family::Vmware),
        "kvm" | "qemu" | "bochs" => Some(Family::Qemu),
        "oracle" => Some(Family::Vbox),
        "microsoft" => Some(Family::HyperV),
        _ => None,
    }
}

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Vmware => "VMware",
        Family::Qemu => "QEMU/KVM",
        Family::Vbox => "VirtualBox",
        Family::HyperV => "Hyper-V",
    }
}

/// Guest-integration packages (clipboard, resize, time sync, graceful shutdown) for a hypervisor.
fn guest_packages(pm: Pm, f: Family, desktop: bool) -> Vec<&'static str> {
    match (f, pm) {
        (Family::Vmware, Pm::Pacman) => vec!["open-vm-tools"],
        (Family::Vmware, _) if desktop => vec!["open-vm-tools", "open-vm-tools-desktop"],
        (Family::Vmware, _) => vec!["open-vm-tools"],
        (Family::Qemu, _) if desktop => vec!["qemu-guest-agent", "spice-vdagent"],
        (Family::Qemu, _) => vec!["qemu-guest-agent"],
        (Family::Vbox, Pm::Dnf) => vec!["virtualbox-guest-additions"],
        (Family::Vbox, Pm::Apt) => vec!["virtualbox-guest-utils", "virtualbox-guest-x11"],
        (Family::Vbox, Pm::Pacman) => vec!["virtualbox-guest-utils"],
        (Family::Vbox, Pm::Zypper) => vec!["virtualbox-guest-tools", "virtualbox-guest-x11"],
        (Family::HyperV, Pm::Dnf) => vec!["hyperv-daemons"],
        (Family::HyperV, Pm::Pacman) => vec!["hyperv"],
        (Family::HyperV, Pm::Zypper) => vec!["hyper-v"],
        (Family::HyperV, Pm::Apt) => vec![],
    }
}

fn guest_service(f: Family) -> Option<&'static str> {
    match f {
        Family::Vmware => Some("vmtoolsd"),
        Family::Qemu => Some("qemu-guest-agent"),
        _ => None,
    }
}

fn pkg_installed(pm: Pm, name: &str) -> bool {
    match pm {
        Pm::Dnf | Pm::Zypper => run("rpm", &["-q", name]).ok,
        Pm::Apt => run("dpkg-query", &["-W", "-f", "${db:Status-Abbrev}", name])
            .stdout
            .starts_with("ii"),
        Pm::Pacman => run("pacman", &["-Q", name]).ok,
    }
}

// --- /etc/fstab ---

#[derive(Clone, Debug, PartialEq)]
pub struct FstabIssue {
    pub device: String,
    pub mount: String,
    pub reason: &'static str,
}

const FSTAB_BAK: &str = "/etc/fstab.linuxward.bak";
const PPD_CONF: &str = "/etc/tuned/ppd.conf";
const PPD_BAK: &str = "/etc/tuned/ppd.conf.linuxward.bak";

/// Copy `src` to `dst` unless a backup already exists, so applying a fix twice never overwrites the original with an edited copy.
fn backup_cmd(src: &str, dst: &str) -> Vec<String> {
    strs(&[
        "sh",
        "-c",
        "[ -e \"$2\" ] || cp -a \"$1\" \"$2\"",
        "sh",
        src,
        dst,
    ])
}

const NOFAIL_OPTS: &str = "nofail,x-systemd.device-timeout=5s";

fn device_present(dev: &str) -> bool {
    let by = |dir: &str, id: &str| Path::new("/dev/disk").join(dir).join(id).exists();
    if let Some(id) = dev.strip_prefix("UUID=") {
        by("by-uuid", id)
    } else if let Some(id) = dev.strip_prefix("PARTUUID=") {
        by("by-partuuid", id)
    } else if let Some(id) = dev.strip_prefix("LABEL=") {
        by("by-label", &id.replace(' ', "\\x20"))
    } else if let Some(id) = dev.strip_prefix("PARTLABEL=") {
        by("by-partlabel", id)
    } else if dev.starts_with("/dev/") {
        Path::new(dev).exists()
    } else {
        true
    }
}

/// Entries that can stall boot: a block device that is not there, or a shared-folder/network mount that is not marked optional.
pub fn parse_fstab(text: &str, present: impl Fn(&str) -> bool) -> Vec<FstabIssue> {
    const SKIP_FS: &[&str] = &[
        "tmpfs", "proc", "sysfs", "devpts", "overlay", "efivarfs", "devtmpfs", "none",
    ];
    const OPTIONAL_FS: &[&str] = &[
        "fuse", "cifs", "nfs", "nfs4", "9p", "virtiofs", "vboxsf", "vmhgfs", "davfs",
    ];
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || SKIP_FS.contains(&f[2]) {
                return None;
            }
            let (dev, mount, fs, opts) = (f[0], f[1], f[2], f[3]);
            let has = |o: &str| opts.split(',').any(|x| x == o);
            if has("nofail") || has("noauto") || mount == "/" {
                return None;
            }
            let reason = if !present(dev) {
                "device is missing – boot waits for it"
            } else if OPTIONAL_FS.contains(&fs)
                || dev.starts_with("vmhgfs-fuse")
                || dev.starts_with("//")
                || dev.contains(":/")
            {
                "shared/network mount not marked optional – can block or delay boot"
            } else {
                return None;
            };
            Some(FstabIssue {
                device: dev.to_string(),
                mount: mount.to_string(),
                reason,
            })
        })
        .collect()
}

/// `sed` expression that appends the nofail options to the entry for `device`.
pub fn fstab_sed(device: &str) -> Option<String> {
    if device.is_empty()
        || !device
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "=_./-:".contains(c))
    {
        return None;
    }
    let dev = device.replace('.', "\\.");
    // Only lines that don't already say nofail/noauto, so running this twice changes nothing.
    Some(format!(
        "/^{dev}[[:space:]]/{{/nofail|noauto/!s|^({dev}[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+)([^[:space:]]+)|\\1\\2,{NOFAIL_OPTS}|}}"
    ))
}

pub fn fstab_fix_cmds(issues: &[FstabIssue]) -> Vec<Vec<String>> {
    // One edit per device: two issues on the same device would otherwise each add the options.
    let mut devices: Vec<&str> = issues.iter().map(|i| i.device.as_str()).collect();
    devices.sort_unstable();
    devices.dedup();
    let seds: Vec<String> = devices.into_iter().filter_map(fstab_sed).collect();
    if seds.is_empty() {
        return vec![];
    }
    let mut v = vec![backup_cmd("/etc/fstab", FSTAB_BAK)];
    v.extend(seds.into_iter().map(|e| {
        vec![
            "sed".into(),
            "-i".into(),
            "-E".into(),
            e,
            "/etc/fstab".into(),
        ]
    }));
    v.push(strs(&["systemctl", "daemon-reload"]));
    v
}

// --- boot diagnosis from the kernel log ---

/// Look for hardware timeouts during boot (virtual NVMe/SCSI controllers that stop answering, devices that never appear).
fn boot_findings(vm: Option<&str>) -> Vec<Finding> {
    let mut v = Vec::new();
    let out = run("journalctl", &["-b", "-k", "--no-pager", "-q", "-o", "cat"]);
    let nvme = out
        .stdout
        .lines()
        .filter(|l| l.contains("nvme") && l.contains("timeout"))
        .count();
    if nvme > 0 {
        let fix = match vm {
            Some("vmware") => {
                "In VMware: shut the VM down, then in its settings replace the NVMe disk controller with SCSI (PVSCSI/LSI) or SATA, or use a newer virtual hardware version. This must be changed on the host; it cannot be fixed inside the guest."
            }
            Some(_) => {
                "In the hypervisor settings, attach the disk through a virtio/SCSI/SATA controller instead of NVMe, and update the hypervisor."
            }
            None => "Check the drive's health (smartctl) and firmware; update the kernel.",
        };
        v.push(Finding {
            title: format!("Disk controller timed out {nvme} time(s) during boot"),
            detail: format!("Each NVMe timeout stalls boot for about 30 seconds, which matches a long initrd phase. {fix}"),
        });
    }
    let waited: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| l.contains("Timed out waiting for device"))
        .take(3)
        .collect();
    if !waited.is_empty() {
        v.push(Finding {
            title: "Boot waited for a device that never appeared".into(),
            detail: waited.join("\n"),
        });
    }
    v
}

// --- recommended fixes ---

fn desktop_session() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|d| !d.is_empty())
}

fn software_renderer() -> bool {
    which("glxinfo")
        && run("glxinfo", &["-B"]).stdout.lines().any(|l| {
            let l = l.to_lowercase();
            l.contains("renderer")
                && (l.contains("llvmpipe") || l.contains("softpipe") || l.contains("swrast"))
        })
}

// --- VM latency tuning ---

const VM_IO_RULE: &str = "/etc/udev/rules.d/60-linuxward-vm-io.rules";
const VM_SYSCTL: &str = "/etc/sysctl.d/99-linuxward-vm.conf";

/// Shell-free "write this text to this file" command (content and path are passed as arguments, never interpolated).
fn write_file_cmd(path: &str, content: &str) -> Vec<String> {
    strs(&[
        "sh",
        "-c",
        "printf '%s' \"$1\" > \"$2\"",
        "sh",
        content,
        path,
    ])
}

/// Parse a block queue scheduler line such as `mq-deadline kyber [bfq] none`: (active, `none` is available).
pub fn parse_scheduler(s: &str) -> Option<(String, bool)> {
    let cur = s
        .split_whitespace()
        .find(|w| w.starts_with('[') && w.ends_with(']'))?;
    Some((
        cur.trim_matches(|c| c == '[' || c == ']').to_string(),
        s.split_whitespace()
            .any(|w| w.trim_matches(|c| c == '[' || c == ']') == "none"),
    ))
}

/// Virtual disks whose guest-side I/O scheduler just adds latency on top of the hypervisor's own queueing.
fn disks_needing_none() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/block")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| ["vd", "sd", "xvd", "nvme"].iter().any(|p| n.starts_with(p)))
        .filter(|n| {
            std::fs::read_to_string(format!("/sys/block/{n}/queue/scheduler"))
                .ok()
                .and_then(|s| parse_scheduler(&s))
                .is_some_and(|(cur, none)| none && cur != "none")
        })
        .collect();
    v.sort();
    v
}

/// sysctl values that smooth out stalls in a guest: smaller write-back bursts and less eager swapping to a real disk.
pub fn vm_sysctls(
    dirty: Option<u32>,
    dirty_bg: Option<u32>,
    swappiness: Option<u32>,
    disk_swap: bool,
) -> Vec<(&'static str, u32)> {
    let mut v = Vec::new();
    if dirty.is_some_and(|d| d > 10) {
        v.push(("vm.dirty_ratio", 10));
    }
    if dirty_bg.is_some_and(|d| d > 5) {
        v.push(("vm.dirty_background_ratio", 5));
    }
    if disk_swap && swappiness.is_some_and(|s| s > 10) {
        v.push(("vm.swappiness", 10));
    }
    v
}

fn read_u32(path: &str) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// `tuned` means a tuned daemon is running: it rewrites sysctls at boot, so the values go into a tuned profile instead of sysctl.d.
/// Returns the sysctl values that should be set.
fn vm_latency_recs(
    recs: &mut Vec<Rec>,
    findings: &mut Vec<Finding>,
    soft_render: bool,
    tuned: bool,
) -> Vec<(&'static str, u32)> {
    // I/O scheduler.
    let disks = disks_needing_none();
    if !disks.is_empty() {
        let rule = "# Written by linuxward: the hypervisor already schedules I/O, so skip the guest scheduler.\nACTION==\"add|change\", SUBSYSTEM==\"block\", ENV{DEVTYPE}==\"disk\", KERNEL==\"vd*|sd*|xvd*|nvme*n*\", ATTR{queue/scheduler}=\"none\"\n";
        let mut cmds = vec![write_file_cmd(VM_IO_RULE, rule)];
        cmds.extend(disks.iter().map(|d| {
            vec![
                "sh".into(),
                "-c".into(),
                "echo none > \"/sys/block/$1/queue/scheduler\"".into(),
                "sh".into(),
                d.clone(),
            ]
        }));
        recs.push(Rec {
            tag: "VM",
            title: format!("Use the `none` I/O scheduler on {} virtual disk(s)", disks.len()),
            detail: format!("{} – the host already queues and reorders I/O, so a second scheduler in the guest only adds latency. Applied now and persisted with {VM_IO_RULE}.", disks.join(", ")),
            safe: true,
            actions: vec![Action::Root(cmds)],
        });
    }

    // Write-back and swap behaviour.
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    let disk_swap = swaps
        .lines()
        .skip(1)
        .any(|l| !l.trim().is_empty() && !l.contains("zram"));
    let want = vm_sysctls(
        read_u32("/proc/sys/vm/dirty_ratio"),
        read_u32("/proc/sys/vm/dirty_background_ratio"),
        read_u32("/proc/sys/vm/swappiness"),
        disk_swap,
    );
    if !tuned && !want.is_empty() && !Path::new(VM_SYSCTL).exists() {
        let conf: String = std::iter::once(
            "# Written by linuxward: smoother disk write-back in a VM.\n".to_string(),
        )
        .chain(want.iter().map(|(k, v)| format!("{k} = {v}\n")))
        .collect();
        recs.push(Rec {
            tag: "VM",
            title: "Smooth out disk write-back and swapping".into(),
            detail: format!("Sets {}. Large dirty-page buffers flush in big bursts that freeze a VM; smaller ones keep it responsive. Saved in {VM_SYSCTL}.", want.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")),
            safe: true,
            actions: vec![Action::Root(vec![write_file_cmd(VM_SYSCTL, &conf), strs(&["sysctl", "-p", VM_SYSCTL])])],
        });
    }

    // Things that can only be changed on the host.
    if soft_render {
        findings.push(Finding {
            title: "No 3D acceleration".into(),
            detail: "The desktop is drawn by the CPU (llvmpipe). In the hypervisor's display settings enable 3D acceleration and give the VM at least 128 MB of video memory; this is the biggest single cause of UI lag.".into(),
        });
    }
    let mem_gib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .map(|kb| kb as f64 / 1048576.0);
    if let Some(g) = mem_gib.filter(|g| *g < 2.0) {
        findings.push(Finding { title: format!("Only {g:.1} GiB of RAM"), detail: "A modern desktop needs about 4 GiB. Shut the VM down and raise its memory in the hypervisor settings.".into() });
    }
    if std::thread::available_parallelism().is_ok_and(|n| n.get() < 2) {
        findings.push(Finding { title: "Only 1 virtual CPU".into(), detail: "Give the VM at least 2 vCPUs in the hypervisor settings so the desktop and background work don't compete for one core.".into() });
    }
    want
}

/// Disable services for good: also their enabled `.socket` units (socket activation would start them again on demand),
/// then check that nothing is still enabled so a failure shows up in the log instead of surfacing after a reboot.
pub fn disable_cmds(units: &[&str], enabled: impl Fn(&str) -> bool) -> Vec<Vec<String>> {
    let mut all: Vec<String> = units.iter().map(|u| u.to_string()).collect();
    for u in units {
        let sock = format!("{}.socket", u.trim_end_matches(".service"));
        if enabled(&sock) {
            all.push(sock);
        }
    }
    let mut disable = strs(&["systemctl", "disable", "--now"]);
    disable.extend(all.iter().cloned());
    let mut verify = strs(&[
        "sh",
        "-c",
        "for u in \"$@\"; do case \"$(systemctl is-enabled \"$u\" 2>/dev/null)\" in enabled*) echo \"!! $u is still enabled\"; exit 1;; esac; done; echo \"verified: disabled and will stay off after reboot\"",
        "sh",
    ]);
    verify.extend(all.iter().cloned());
    // Remember what we turned off so it can be turned back on.
    let mut record = strs(&[
        "sh",
        "-c",
        "mkdir -p /etc/linuxward && printf '%s\\n' \"$@\" >> /etc/linuxward/disabled-services",
        "sh",
    ]);
    record.extend(all);
    vec![disable, verify, record]
}

const PREV_MARK: &str = "# linuxward-previous-profile=";

fn profile_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// The tuned profile that was active before we switched, as recorded in our profile.
pub fn previous_profile(conf: &str) -> Option<String> {
    conf.lines()
        .find_map(|l| l.strip_prefix(PREV_MARK))
        .map(str::trim)
        .filter(|n| profile_name_ok(n))
        .map(str::to_string)
}

const TUNED_DIR: &str = "/etc/tuned/profiles/linuxward-vm";
const TUNED_PROFILE: &str = "linuxward-vm";

/// A tuned profile that is `virtual-guest` plus our sysctl overrides (tuned re-applies its own sysctls at boot, so sysctl.d alone loses).
pub fn tuned_profile_conf(sysctls: &[(&str, u32)], previous: &str) -> String {
    let mut s = String::from(
        "[main]\nsummary=virtual-guest plus smoother write-back (written by linuxward)\ninclude=virtual-guest\n",
    );
    if profile_name_ok(previous) {
        s.push_str(&format!("{PREV_MARK}{previous}\n"));
    }
    if !sysctls.is_empty() {
        s.push_str("\n[sysctl]\n");
        for (k, v) in sysctls {
            s.push_str(&format!("{k}={v}\n"));
        }
    }
    s
}

/// tuned-ppd re-applies the profile mapped to the desktop's power mode on every boot, silently undoing `tuned-adm profile`.
/// Re-map the active power mode to our profile. tuned-ppd refuses a config where two modes map to the same profile
/// ("Duplicate profile mapping") and then fails to start, so exactly one mode is changed, and a failed restart rolls the file back.
pub fn ppd_remap_cmds(power_mode: &str) -> Vec<Vec<String>> {
    let key = if !power_mode.is_empty()
        && power_mode
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-')
    {
        power_mode
    } else {
        "balanced"
    };
    vec![
        backup_cmd(PPD_CONF, PPD_BAK),
        // Start from the original so a mapping written by an earlier run can't produce a duplicate.
        strs(&[
            "sh",
            "-c",
            "if grep -q \"$3\" \"$2\" && [ -e \"$1\" ]; then cp -a \"$1\" \"$2\"; fi",
            "sh",
            PPD_BAK,
            PPD_CONF,
            TUNED_PROFILE,
        ]),
        vec![
            "sed".into(),
            "-E".into(),
            "-i".into(),
            format!("/^\\[profiles\\]/,/^\\[battery\\]/ s/^({key})=.*/\\1={TUNED_PROFILE}/"),
            PPD_CONF.into(),
        ],
        strs(&[
            "sh",
            "-c",
            "systemctl restart tuned-ppd || { cp -a \"$1\" \"$2\"; systemctl restart tuned-ppd; echo \"!! tuned-ppd rejected the new mapping; original restored\"; exit 1; }",
            "sh",
            PPD_BAK,
            PPD_CONF,
        ]),
    ]
}

fn build_recs(
    pm: Option<Pm>,
    vm: Option<&str>,
    kernels: &[Kernel],
    leftovers: &[Leftover],
    tuning: &[Tuning],
    services: &[Service],
) -> (Vec<Rec>, Vec<Finding>) {
    let mut recs: Vec<Rec> = Vec::new();
    let mut findings = boot_findings(vm);

    // Old kernels.
    if let Some(pm) = pm {
        let old: Vec<&Kernel> = kernels.iter().filter(|k| k.removable()).collect();
        let cmds = kernel_remove_cmds(pm, &old);
        if !cmds.is_empty() {
            let size: u64 = old.iter().map(|k| k.size).sum();
            recs.push(Rec {
                tag: "Cleanup",
                title: format!("Remove {} old kernel(s)", old.len()),
                detail: format!("{} · frees about {} and shortens the boot menu. The running and newest kernels stay.", old.iter().map(|k| k.version.as_str()).collect::<Vec<_>>().join(", "), human(size)),
                safe: true,
                actions: vec![Action::Root(cmds)],
            });
        }
        // Leftover config files that are identical to the live file lose nothing when deleted.
        let same: Vec<&Leftover> = leftovers.iter().filter(|l| l.identical).collect();
        let cmds = leftover_delete_cmds(pm, &same);
        if !cmds.is_empty() {
            recs.push(Rec {
                tag: "Cleanup",
                title: format!("Delete {} config leftover(s) identical to the live file", same.len()),
                detail: "These copies from upgrades are exactly the same as the file in use, so nothing is lost.".into(),
                safe: true,
                actions: vec![Action::Root(cmds)],
            });
        }
    }

    // Warnings from the quick checks that have a fix (failed services, TRIM, swap…).
    for t in tuning.iter().filter(|t| t.level == Level::Warn) {
        if let Some(f) = &t.fix {
            recs.push(Rec {
                tag: "Tuning",
                title: f.label.clone(),
                detail: format!("{}: {}", t.title, t.detail),
                // Clearing "failed" marks hides the evidence without fixing the cause.
                safe: t.title != "Failed services",
                actions: vec![f.action.clone()],
            });
        }
    }
    // Cache rebuilds, merged into one entry.
    let caches: Vec<&Fix> = tuning
        .iter()
        .filter(|t| {
            t.level == Level::Info
                && matches!(
                    t.title.as_str(),
                    "Package metadata" | "Shared-library cache" | "Font cache"
                )
        })
        .filter_map(|t| t.fix.as_ref())
        .collect();
    if !caches.is_empty() {
        recs.push(Rec {
            tag: "Tuning",
            title: "Refresh system caches".into(),
            detail: "Package metadata, the shared-library cache (ldconfig) and the font cache – stale caches are a common leftover of upgrades.".into(),
            safe: true,
            actions: caches.iter().map(|f| f.action.clone()).collect(),
        });
    }
    if let Some(f) = tuning
        .iter()
        .find(|t| t.title == "Leftover upgrade download")
        .and_then(|t| t.fix.as_ref())
    {
        recs.push(Rec {
            tag: "Cleanup",
            title: f.label.clone(),
            detail: "Delete the downloaded packages from a past release upgrade.".into(),
            safe: true,
            actions: vec![f.action.clone()],
        });
    }

    // fstab entries that can stall boot.
    if let Ok(text) = std::fs::read_to_string("/etc/fstab") {
        let issues = parse_fstab(&text, device_present);
        let cmds = fstab_fix_cmds(&issues);
        if !cmds.is_empty() {
            recs.push(Rec {
                tag: "Boot",
                title: format!("Make {} mount(s) in /etc/fstab non-blocking", issues.len()),
                detail: format!(
                    "{}. Adds `{NOFAIL_OPTS}` so boot continues if they are unavailable. A backup is saved as /etc/fstab.linuxward.bak.",
                    issues.iter().map(|i| format!("{} ({})", i.mount, i.reason)).collect::<Vec<_>>().join("; ")
                ),
                safe: true,
                actions: vec![Action::Root(cmds)],
            });
        }
    }

    // Guest-specific fixes.
    if let Some(kind) = vm {
        let fam = family(kind);
        if let (Some(pm), Some(fam)) = (pm, fam) {
            let desktop = desktop_session();
            let want = guest_packages(pm, fam, desktop);
            let missing: Vec<String> = want
                .iter()
                .filter(|p| !pkg_installed(pm, p))
                .map(|p| p.to_string())
                .collect();
            if !missing.is_empty() {
                recs.push(Rec {
                    tag: "VM",
                    title: format!("Install {} guest tools", family_name(fam)),
                    detail: format!("{} – smooth mouse and clipboard, auto-resize, time sync and clean shutdown. Missing: {}.", family_name(fam), missing.join(", ")),
                    safe: true,
                    actions: vec![Action::Root(pm.install_cmds(&missing))],
                });
            } else if let Some(svc) = guest_service(fam)
                && !run("systemctl", &["is-active", svc])
                    .stdout
                    .trim()
                    .starts_with("active")
            {
                recs.push(Rec {
                    tag: "VM",
                    title: format!("Start the {svc} service"),
                    detail: "The guest tools are installed but not running.".into(),
                    safe: true,
                    actions: vec![Action::Root(vec![strs(&[
                        "systemctl",
                        "enable",
                        "--now",
                        svc,
                    ])])],
                });
            }
            // Guest tools for other hypervisors only waste memory and start-up time.
            let mut foreign: Vec<String> = FAMILIES
                .iter()
                .filter(|f| **f != fam)
                .flat_map(|f| guest_packages(pm, *f, true))
                .filter(|p| !want.contains(p) && pkg_installed(pm, p))
                .map(str::to_string)
                .collect();
            foreign.sort();
            foreign.dedup();
            if !foreign.is_empty() {
                recs.push(Rec {
                    tag: "VM",
                    title: format!("Remove guest tools for other hypervisors ({})", foreign.len()),
                    detail: format!("This is a {} guest, but {} are installed. They do nothing here and add services and login autostarts.", family_name(fam), foreign.join(", ")),
                    safe: false,
                    actions: vec![Action::Root(pm.remove_cmds(&foreign))],
                });
            }
        }
        // Without GPU acceleration the desktop animations are drawn by the CPU.
        let soft = software_renderer();
        let tuned_on = which("tuned-adm")
            && run("systemctl", &["is-active", "tuned"]).stdout.trim() == "active";
        let want = vm_latency_recs(&mut recs, &mut findings, soft, tuned_on);
        // tuned has a profile made for guests.
        if tuned_on {
            let active = run("tuned-adm", &["active"]).stdout;
            let profile = active.split(':').nth(1).map(str::trim).unwrap_or("");
            if !profile.is_empty() && profile != TUNED_PROFILE {
                let mut cmds = vec![
                    strs(&["mkdir", "-p", TUNED_DIR]),
                    write_file_cmd(
                        &format!("{TUNED_DIR}/tuned.conf"),
                        &tuned_profile_conf(&want, profile),
                    ),
                ];
                let ppd = run("systemctl", &["is-active", "tuned-ppd"]).stdout.trim() == "active";
                if ppd {
                    let mode =
                        std::fs::read_to_string("/etc/tuned/ppd_base_profile").unwrap_or_default();
                    cmds.extend(ppd_remap_cmds(mode.trim()));
                }
                cmds.push(strs(&["tuned-adm", "profile", TUNED_PROFILE]));
                recs.push(Rec {
                    tag: "VM",
                    title: "Switch the tuned profile to a VM-tuned one".into(),
                    detail: format!(
                        "Current profile is `{profile}`, which is meant for physical servers. `{TUNED_PROFILE}` is `virtual-guest` (less swapping, disk readahead tuned for VMs){}.{}",
                        if want.is_empty() { String::new() } else { format!(" plus {}", want.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")) },
                        if ppd { " The desktop power mode is re-mapped to it too, otherwise tuned-ppd puts the old profile back at every boot." } else { "" }
                    ),
                    safe: true,
                    actions: vec![Action::Root(cmds)],
                });
            }
        }
        if soft
            && which("gsettings")
            && run(
                "gsettings",
                &["get", "org.gnome.desktop.interface", "enable-animations"],
            )
            .stdout
            .trim()
                == "true"
        {
            recs.push(Rec {
                tag: "VM",
                title: "Turn off desktop animations".into(),
                detail: "This VM has no 3D acceleration, so animations are rendered on the CPU. Turning them off makes the desktop feel much faster. (Or enable 3D acceleration in the VM's display settings.)".into(),
                safe: true,
                actions: vec![Action::User(vec![
                    strs(&["gsettings", "set", "org.gnome.desktop.interface", "enable-animations", "false"]),
                    vec!["sh".into(), "-c".into(), "mkdir -p \"$1\" && : > \"$1/animations-disabled\"".into(), "sh".into(), animations_marker_dir().display().to_string()],
                ])],
            });
        }
        // Hardware services that a VM does not have.
        const VM_USELESS: &[&str] = &[
            "bluetooth.service",
            "ModemManager.service",
            "switcheroo-control.service",
            "iio-sensor-proxy.service",
        ];
        let on: Vec<&str> = VM_USELESS
            .iter()
            .copied()
            .filter(|u| services.iter().any(|s| s.unit == *u))
            .collect();
        if !on.is_empty() {
            let cmds = disable_cmds(&on, |u| {
                run("systemctl", &["is-enabled", u]).stdout.trim() == "enabled"
            });
            recs.push(Rec {
                tag: "VM",
                title: format!("Disable {} service(s) for hardware a VM doesn't have", on.len()),
                detail: format!("{} – safe to disable unless you pass Bluetooth/modem hardware through to this VM.", on.join(", ")),
                safe: false,
                actions: vec![Action::Root(cmds)],
            });
        }
        const VM_OPTIONAL: &[&str] = &[
            "kdump.service",
            "abrtd.service",
            "cups-browsed.service",
            "avahi-daemon.service",
        ];
        let opt: Vec<&str> = VM_OPTIONAL
            .iter()
            .copied()
            .filter(|u| services.iter().any(|s| s.unit == *u))
            .collect();
        if !opt.is_empty() {
            let cmds = disable_cmds(&opt, |u| {
                run("systemctl", &["is-enabled", u]).stdout.trim() == "enabled"
            });
            recs.push(Rec {
                tag: "VM",
                title: format!("Disable {} background service(s) a VM rarely needs", opt.len()),
                detail: format!("{} – crash-dump reservation, crash reporting and printer/network discovery use RAM and CPU. Skip if you print or browse network devices from this VM.", opt.join(", ")),
                safe: false,
                actions: vec![Action::Root(cmds)],
            });
        }
        if family(kind).is_none() {
            findings.push(Finding {
                title: format!("Unrecognised hypervisor: {kind}"),
                detail:
                    "Generic checks still apply, but guest-tool recommendations are not available."
                        .into(),
            });
        }
    }
    (recs, findings)
}

// ----- undoing what linuxward changed -------------------------------------------------

/// A change linuxward made earlier, found from the files it left behind, with the commands that reverse it.
#[derive(Clone)]
pub struct Undo {
    pub title: String,
    pub detail: String,
    pub actions: Vec<Action>,
}

const DISABLED_LIST: &str = "/etc/linuxward/disabled-services";

fn animations_marker_dir() -> PathBuf {
    util::home().join(".config/linuxward")
}

fn unit_name_ok(u: &str) -> bool {
    [".service", ".socket", ".timer"]
        .iter()
        .any(|e| u.ends_with(e))
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-:\\".contains(c))
}

pub fn undo_items() -> Vec<Undo> {
    let mut v = Vec::new();
    let root = |cmds: Vec<Vec<String>>| vec![Action::Root(cmds)];
    let rm = |path: &str| strs(&["rm", "-f", "--", path]);

    if Path::new(VM_IO_RULE).exists() {
        v.push(Undo {
            title: "I/O scheduler rule".into(),
            detail: format!("Removes {VM_IO_RULE}. Disks go back to the kernel's default scheduler after the next reboot."),
            actions: root(vec![rm(VM_IO_RULE), strs(&["udevadm", "control", "--reload"])]),
        });
    }
    if Path::new(VM_SYSCTL).exists() {
        v.push(Undo {
            title: "Write-back / swappiness settings".into(),
            detail: format!("Removes {VM_SYSCTL}. The previous kernel defaults apply again after the next reboot."),
            actions: root(vec![rm(VM_SYSCTL)]),
        });
    }
    let tuned_conf = format!("{TUNED_DIR}/tuned.conf");
    if Path::new(&tuned_conf).exists() {
        let prev = std::fs::read_to_string(&tuned_conf)
            .ok()
            .and_then(|c| previous_profile(&c));
        let mut cmds = Vec::new();
        let mut what = format!("Deletes the `{TUNED_PROFILE}` profile");
        if Path::new(PPD_BAK).exists() {
            cmds.push(strs(&["mv", "-f", "--", PPD_BAK, PPD_CONF]));
            cmds.push(strs(&["systemctl", "restart", "tuned-ppd"]));
            what.push_str(" and restores the original power-mode mapping in /etc/tuned/ppd.conf");
        }
        // Deleting the profile while tuned still points at it would break tuned at the next start,
        // so the delete runs only if switching away succeeded.
        let switch = match &prev {
            Some(p) => {
                what.push_str(&format!(", then switches back to `{p}`"));
                p.clone()
            }
            None => {
                what.push_str(", then switches to the profile tuned recommends for this machine (the previous one wasn't recorded)");
                String::new()
            }
        };
        cmds.push(vec![
            "sh".into(),
            "-c".into(),
            "p=\"$1\"; [ -n \"$p\" ] || p=$(tuned-adm recommend) || exit 1; tuned-adm profile \"$p\" && rm -rf -- \"$2\"".into(),
            "sh".into(),
            switch,
            TUNED_DIR.into(),
        ]);
        v.push(Undo {
            title: "VM tuned profile".into(),
            detail: format!("{what}."),
            actions: root(cmds),
        });
    }
    if Path::new(FSTAB_BAK).exists() {
        v.push(Undo {
            title: "/etc/fstab changes".into(),
            detail: format!(
                "Restores /etc/fstab from {FSTAB_BAK}, the copy taken {} before linuxward added `nofail`. Edits made to fstab since then (new disks, changed UUIDs) are lost, which can stop the machine booting. The file being replaced is kept as /etc/fstab.linuxward.before-undo.",
                std::fs::metadata(FSTAB_BAK)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| format!("{} day(s) ago", d.as_secs() / 86_400))
                    .unwrap_or_else(|| "earlier".into())
            ),
            actions: root(vec![
                strs(&["sh", "-c", "cp -a -- /etc/fstab /etc/fstab.linuxward.before-undo && cp -a -- \"$1\" /etc/fstab.new && mv -f -- /etc/fstab.new /etc/fstab", "sh", FSTAB_BAK]),
                strs(&["systemctl", "daemon-reload"]),
            ]),
        });
    }
    if let Ok(text) = std::fs::read_to_string(DISABLED_LIST) {
        let mut units: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|u| unit_name_ok(u))
            .map(str::to_string)
            .collect();
        units.sort();
        units.dedup();
        if !units.is_empty() {
            // The record is deleted only if every service came back, so a failure can be retried.
            let mut enable = strs(&[
                "sh",
                "-c",
                "bad=0; for u in \"$@\"; do systemctl enable --now \"$u\" || bad=1; done; [ \"$bad\" = 0 ] && rm -f -- \"$0\"",
                DISABLED_LIST,
            ]);
            enable.extend(units.iter().cloned());
            v.push(Undo {
                title: format!("{} disabled service(s)", units.len()),
                detail: format!("Re-enables and starts: {}.", units.join(", ")),
                actions: root(vec![enable]),
            });
        }
    }
    let marker = animations_marker_dir().join("animations-disabled");
    if marker.exists() {
        v.push(Undo {
            title: "Desktop animations turned off".into(),
            detail: "Turns GNOME animations back on.".into(),
            actions: vec![Action::User(vec![
                strs(&[
                    "gsettings",
                    "set",
                    "org.gnome.desktop.interface",
                    "enable-animations",
                    "true",
                ]),
                strs(&["rm", "-f", "--", &marker.display().to_string()]),
            ])],
        });
    }
    v
}

// ----- snapshot ----------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Snapshot {
    pub boot: Boot,
    pub services: Vec<Service>,
    pub autostart: Vec<Autostart>,
    pub kernels: Vec<Kernel>,
    pub leftovers: Vec<Leftover>,
    pub tuning: Vec<Tuning>,
    /// Hypervisor name from `systemd-detect-virt` (vmware, kvm, oracle, microsoft…), if this is a VM guest.
    pub vm: Option<String>,
    /// One-click fixes, safest first.
    pub recs: Vec<Rec>,
    /// Problems found that can't be fixed from inside this machine.
    pub findings: Vec<Finding>,
    /// Earlier linuxward changes that can be reverted.
    pub undos: Vec<Undo>,
}

pub fn load_snapshot(pm: Option<Pm>) -> Snapshot {
    let (boot, autostart, kernels, leftovers) = std::thread::scope(|s| {
        let b = s.spawn(load_boot);
        let a = s.spawn(load_autostart);
        let k = s.spawn(move || pm.map(kernels).unwrap_or_default());
        let l = s.spawn(move || pm.map(leftovers).unwrap_or_default());
        (
            b.join().unwrap_or_default(),
            a.join().unwrap_or_default(),
            k.join().unwrap_or_default(),
            l.join().unwrap_or_default(),
        )
    });
    let services = load_services(&boot.blame);
    let tuning = tuning(pm, &kernels);
    let vm = vm_kind();
    let (recs, findings) = build_recs(pm, vm.as_deref(), &kernels, &leftovers, &tuning, &services);
    Snapshot {
        boot,
        services,
        autostart,
        kernels,
        leftovers,
        tuning,
        vm,
        recs,
        findings,
        undos: undo_items(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_blame() {
        assert!((parse_dur("829ms").unwrap() - 0.829).abs() < 1e-9);
        assert_eq!(parse_dur("1min"), Some(60.0));
        assert_eq!(parse_dur("3.5s"), Some(3.5));
        assert_eq!(parse_dur("foo.service"), None);
        let b = parse_blame(
            "1min 3.198s sys-module-fuse.device\n28.573s NetworkManager-wait-online.service\n829ms x.service\n",
        );
        assert_eq!(b.len(), 3);
        assert!((b[0].0 - 63.198).abs() < 1e-6);
        assert_eq!(b[0].1, "sys-module-fuse.device");
    }

    #[test]
    fn versions() {
        assert_eq!(
            natural_cmp("7.10.1-1.fc45", "7.9.9-9.fc45"),
            Ordering::Greater
        );
        assert_eq!(
            natural_cmp("7.3.3-300.fc45.x86_64", "7.3.3-200.fc44.x86_64"),
            Ordering::Greater
        );
        assert_eq!(natural_cmp("6.8.0-45", "6.8.0-45"), Ordering::Equal);
    }

    #[test]
    fn stat_parse() {
        let s = "1234 (Web Content) S 1 1234 1234 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 5 0 100 1000000 4321 18446744073709551615";
        let (name, ticks, rss) = parse_stat(s).unwrap();
        assert_eq!(name, "Web Content");
        assert_eq!(ticks, 200);
        assert_eq!(rss, 4321);
    }

    #[test]
    fn pressure() {
        let p = parse_pressure(
            "some avg10=9.68 avg60=5.47 avg300=6.39 total=1\nfull avg10=0.50 avg60=0.00 avg300=0.00 total=0\n",
        );
        assert_eq!(p.some, [9.68, 5.47, 6.39]);
        assert_eq!(p.full[0], 0.5);
    }

    #[test]
    fn rpm_va() {
        let t = "S.5....T.  c /etc/foo.conf\n.M.......    /usr/bin/bar\nmissing     /usr/lib/baz\n";
        let bad = rpm_va_problems(t);
        assert_eq!(bad.len(), 2);
        assert!(bad.iter().all(|l| !l.contains("foo.conf")));
    }

    #[test]
    fn fstab_detection_and_fix() {
        let tab = "UUID=aaaa / ext4 defaults 1 1\nUUID=bbbb /data ext4 defaults 0 2\nUUID=cccc /gone ext4 defaults 0 2\nvmhgfs-fuse /mnt/hgfs fuse defaults,allow_other 0 0\nUUID=dddd /ok ext4 defaults,nofail 0 2\n# comment\ntmpfs /tmp tmpfs defaults 0 0\n";
        let issues = parse_fstab(tab, |d| d != "UUID=cccc");
        assert_eq!(
            issues.iter().map(|i| i.device.as_str()).collect::<Vec<_>>(),
            vec!["UUID=cccc", "vmhgfs-fuse"]
        );
        // Apply the generated sed expression for real.
        let dir = std::env::temp_dir().join(format!("linuxward-fstab-{}", std::process::id()));
        std::fs::write(&dir, tab).unwrap();
        let expr = fstab_sed("vmhgfs-fuse").unwrap();
        let out = run("sed", &["-E", &expr, dir.to_str().unwrap()]);
        let _ = std::fs::remove_file(&dir);
        assert!(
            out.stdout
                .contains("defaults,allow_other,nofail,x-systemd.device-timeout=5s 0 0"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("UUID=bbbb /data ext4 defaults 0 2"));
        assert!(fstab_sed("a b;rm").is_none());
    }

    #[test]
    fn vm_tuning_helpers() {
        assert_eq!(
            parse_scheduler("mq-deadline kyber [bfq] none"),
            Some(("bfq".into(), true))
        );
        assert_eq!(
            parse_scheduler("[none] mq-deadline"),
            Some(("none".into(), true))
        );
        assert_eq!(
            parse_scheduler("[mq-deadline] kyber"),
            Some(("mq-deadline".into(), false))
        );
        assert_eq!(parse_scheduler("garbage"), None);
        assert_eq!(
            vm_sysctls(Some(20), Some(10), Some(60), true),
            vec![
                ("vm.dirty_ratio", 10),
                ("vm.dirty_background_ratio", 5),
                ("vm.swappiness", 10)
            ]
        );
        assert_eq!(
            vm_sysctls(Some(20), Some(5), Some(60), false),
            vec![("vm.dirty_ratio", 10)]
        );
        assert!(vm_sysctls(Some(10), Some(5), Some(10), true).is_empty());
        let c = write_file_cmd("/tmp/x", "a'b\"c");
        assert_eq!(&c[3..], ["sh", "a'b\"c", "/tmp/x"]);
    }

    #[test]
    fn tuned_profile_and_ppd() {
        let c = tuned_profile_conf(&[("vm.dirty_ratio", 10)], "throughput-performance");
        assert!(c.contains("include=virtual-guest") && c.contains("[sysctl]\nvm.dirty_ratio=10"));
        assert!(!tuned_profile_conf(&[], "").contains("[sysctl]"));
        assert_eq!(
            previous_profile(&c).as_deref(),
            Some("throughput-performance")
        );
        assert_eq!(previous_profile(&tuned_profile_conf(&[], "x;rm")), None);
        assert_eq!(ppd_remap_cmds("performance").len(), 4);
        assert!(ppd_remap_cmds("a/b;x")[2][3].contains("(balanced)="));
        // Run the generated sed for real: only the [profiles] section may change.
        let conf = "[profiles]\npower-saver=powersave\nbalanced=balanced\nperformance=throughput-performance\n\n[battery]\nbalanced=balanced-battery\n";
        let f = std::env::temp_dir().join(format!("linuxward-ppd-{}", std::process::id()));
        std::fs::write(&f, conf).unwrap();
        for c in ppd_remap_cmds("performance")
            .iter()
            .filter(|c| c[0] == "sed")
        {
            run(
                "sed",
                &[
                    c[1].as_str(),
                    c[2].as_str(),
                    c[3].as_str(),
                    f.to_str().unwrap(),
                ],
            );
        }
        let out = std::fs::read_to_string(&f).unwrap();
        let _ = std::fs::remove_file(&f);
        assert!(
            out.contains("balanced=balanced\nperformance=linuxward-vm\n"),
            "{out}"
        );
        assert!(
            out.contains("power-saver=powersave")
                && out.contains("[battery]\nbalanced=balanced-battery"),
            "{out}"
        );
    }

    #[test]
    fn disable_includes_sockets_and_verifies() {
        let cmds = disable_cmds(&["avahi-daemon.service", "abrtd.service"], |u| {
            u == "avahi-daemon.socket"
        });
        assert_eq!(
            cmds[0],
            strs(&[
                "systemctl",
                "disable",
                "--now",
                "avahi-daemon.service",
                "abrtd.service",
                "avahi-daemon.socket"
            ])
        );
        assert_eq!(
            cmds[1][4..],
            strs(&[
                "avahi-daemon.service",
                "abrtd.service",
                "avahi-daemon.socket"
            ])[..]
        );
        let ok = run(
            "sh",
            &[
                "-c",
                cmds[1][2].as_str(),
                "sh",
                "definitely-not-a-unit.service",
            ],
        );
        assert!(ok.ok && ok.stdout.contains("verified"), "{}", ok.stdout);
        let bad = run("sh", &["-c", cmds[1][2].as_str(), "sh", "sshd.service"]);
        let en = run("systemctl", &["is-enabled", "sshd.service"])
            .stdout
            .trim()
            == "enabled";
        assert_eq!(!bad.ok, en);
    }

    #[test]
    fn kernel_removal_never_touches_running_or_newest() {
        let k = |v: &str, running, newest| Kernel {
            version: v.into(),
            packages: vec![format!("kernel-core-{v}")],
            size: 0,
            running,
            newest,
        };
        let (a, b, c) = (
            k("3", false, true),
            k("2", true, false),
            k("1", false, false),
        );
        let cmds = kernel_remove_cmds(Pm::Dnf, &[&a, &b, &c]);
        assert_eq!(cmds, vec![strs(&["dnf", "remove", "-y", "kernel-core-1"])]);
        assert!(kernel_remove_cmds(Pm::Dnf, &[&a, &b]).is_empty());
    }

    #[test]
    fn leftover_delete_is_restricted() {
        let l = |p: &str| Leftover {
            path: p.into(),
            live: p.into(),
            kind: LeftKind::OldCopy,
            identical: false,
        };
        let (a, b, c) = (
            l("/etc/foo.conf.rpmsave"),
            l("/etc/passwd"),
            l("/home/x.rpmsave"),
        );
        let cmds = leftover_delete_cmds(Pm::Dnf, &[&a, &b, &c]);
        assert_eq!(
            cmds,
            vec![strs(&["rm", "-f", "--", "/etc/foo.conf.rpmsave"])]
        );
    }
}

#[cfg(test)]
mod live_perf_tests {
    use super::*;

    #[test]
    #[ignore]
    fn live_snapshot_print() {
        let pm = Pm::detect();
        let s = load_snapshot(pm);
        println!("BOOT {} | hint={:?}", s.boot.summary, s.boot.hint.is_some());
        println!(
            "blame top: {:?}",
            s.boot.blame.iter().take(3).collect::<Vec<_>>()
        );
        println!(
            "services {} (first {:?}) autostart {:?}",
            s.services.len(),
            s.services.first().map(|x| (&x.unit, x.secs)),
            s.autostart
                .iter()
                .map(|a| (&a.name, a.enabled))
                .collect::<Vec<_>>()
        );
        for k in &s.kernels {
            println!(
                "kernel {} running={} newest={} size={} pk={}",
                k.version,
                k.running,
                k.newest,
                human(k.size),
                k.packages.len()
            );
        }
        println!("leftovers {}", s.leftovers.len());
        for t in &s.tuning {
            println!(
                "tuning [{}] {} - {}",
                match t.level {
                    Level::Ok => "ok",
                    Level::Warn => "WARN",
                    Level::Info => "info",
                },
                t.title,
                t.detail.chars().take(80).collect::<String>()
            );
        }
        println!("VM: {:?}", s.vm);
        for r in &s.recs {
            println!(
                "REC [{}] safe={} {}\n     {}\n     {:?}",
                r.tag, r.safe, r.title, r.detail, r.actions
            );
        }
        for f in &s.findings {
            println!("FINDING {} :: {}", f.title, f.detail);
        }
        let l = live_snapshot();
        println!(
            "live cpu={:?} io={:?} verdict={:?}",
            l.cpu.some, l.io.some, l.verdict
        );
        println!(
            "top cpu {:?}",
            l.top_cpu
                .iter()
                .map(|p| (&p.name, p.cpu as u32))
                .collect::<Vec<_>>()
        );
        println!(
            "top io {:?}",
            l.top_io.iter().map(|p| (&p.name, p.io)).collect::<Vec<_>>()
        );
        if let Some(pm) = pm {
            for c in health_checks(pm).into_iter().take(2) {
                let r = run_check(&c);
                println!(
                    "health {} ok={} out={:?}",
                    r.title,
                    r.ok,
                    r.output.lines().take(3).collect::<Vec<_>>()
                );
            }
        }
    }
}

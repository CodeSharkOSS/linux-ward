//! Small helpers: size formatting, disk usage, running commands, privilege escalation.

use std::ffi::CString;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Human readable size using binary units.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Space actually allocated on disk under `path` (allocated blocks, like `du`).
/// Does not follow symlinks and stays on one filesystem. Unreadable entries are skipped.
pub fn dir_usage(path: &Path) -> u64 {
    if std::fs::symlink_metadata(path).is_err() {
        return 0;
    }
    walkdir::WalkDir::new(path)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_map(Result::ok)
        // Count files only, so an empty directory tree reports 0.
        .filter(|e| !e.file_type().is_dir())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.blocks() * 512)
        .sum()
}

/// Delete everything *inside* `dir`, keeping `dir` itself.
/// Returns (bytes freed, error messages).
pub fn clear_dir_contents(dir: &Path) -> (u64, Vec<String>) {
    let before = dir_usage(dir);
    let mut errors = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return (0, vec![format!("{}: {e}", dir.display())]),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // Honour the user's exclude list: never delete a listed folder, or one that contains one.
        if excluded(&p) || contains_excluded(&p) {
            errors.push(format!("{}: kept (in your exclude list)", p.display()));
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let res = if is_dir {
            // `dir_usage` stays on one filesystem; deleting must too, or a bind/FUSE mount
            // inside the folder would lose the files on the mounted volume.
            if has_other_filesystem(&p) {
                errors.push(format!(
                    "{}: skipped (another disk is mounted inside)",
                    p.display()
                ));
                continue;
            }
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        if let Err(e) = res {
            errors.push(format!("{}: {e}", p.display()));
        }
    }
    let after = dir_usage(dir);
    (before.saturating_sub(after), errors)
}

/// True if anything below `dir` lives on a different filesystem (a mount point).
pub fn has_other_filesystem(dir: &Path) -> bool {
    let Ok(root) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    let dev = root.dev();
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_dir())
        .any(|e| e.metadata().is_ok_and(|m| m.dev() != dev))
}

/// argv that sends SIGTERM to `pid` only if it is still running a program called `name`.
/// The pid comes from a list that may be minutes old; a recycled pid must not be signalled.
pub fn kill_checked_cmd(pid: u32, name: &str) -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        "[ \"$(cat /proc/$1/comm 2>/dev/null)\" = \"$2\" ] && kill \"$1\" || { echo \"process $1 is no longer $2; nothing was stopped\" >&2; exit 1; }".into(),
        "sh".into(),
        pid.to_string(),
        name.to_string(),
    ]
}

/// Delete a directory tree after sanity checks: it must be a real directory (not a symlink),
/// deep enough that it can't be `/`, a home directory or a top-level system folder.
pub fn remove_dir_checked(dir: &Path) -> Result<u64, String> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("not a plain directory".into());
    }
    if !dir.is_absolute() || dir.components().count() < 4 || dir == home() {
        return Err("refusing to delete a top-level folder".into());
    }
    if excluded(dir) || contains_excluded(dir) {
        return Err("it is, or contains, a folder in your exclude list".into());
    }
    if has_other_filesystem(dir) {
        return Err("another disk is mounted inside it".into());
    }
    let size = dir_usage(dir);
    std::fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
    Ok(size)
}

fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("linuxward")
}

fn exclude_list() -> &'static [PathBuf] {
    static LIST: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        std::fs::read_to_string(config_dir().join("exclude"))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| match l.strip_prefix("~/") {
                Some(rest) => home().join(rest),
                None => PathBuf::from(l),
            })
            .collect()
    })
}

/// Paths listed (one per line, `#` comments) in `~/.config/linuxward/exclude`. Every scan skips
/// them and nothing inside them is deleted.
pub fn excluded(path: &Path) -> bool {
    exclude_list().iter().any(|p| path.starts_with(p))
}

/// True if a listed folder lives *inside* `path`, so deleting `path` would delete it.
pub fn contains_excluded(path: &Path) -> bool {
    exclude_list().iter().any(|p| p.starts_with(path))
}

/// Append a line to `~/.local/state/linuxward/actions.log` (best effort). The file is opened once.
pub fn log_action(line: &str) {
    use std::sync::{Mutex, OnceLock};
    static FILE: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();
    let file = FILE.get_or_init(|| {
        let dir = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/state"))
            .join("linuxward");
        let _ = std::fs::create_dir_all(&dir);
        Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("actions.log"))
                .ok(),
        )
    });
    if let Ok(mut guard) = file.lock()
        && let Some(f) = guard.as_mut()
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{} {line}", utc_stamp(secs));
    }
}

/// Unix seconds → "YYYY-MM-DD HH:MM:SS" (UTC).
fn utc_stamp(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[derive(Clone, Debug)]
pub struct DiskInfo {
    pub mount: String,
    pub device: String,
    pub total: u64,
    pub avail: u64,
}

pub fn statvfs(path: &Path) -> Option<(u64, u64)> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills the zeroed struct; we check the return code.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `s` is a valid, writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let frsize = s.f_frsize as u64;
    Some((s.f_blocks as u64 * frsize, s.f_bavail as u64 * frsize))
}

/// Real, block-device backed mounts (one entry per device).
pub fn disks() -> Vec<DiskInfo> {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let (dev, mnt, fstype) = (f[0], unescape_mount(f[1]), f[2]);
        if !dev.starts_with("/dev/")
            || matches!(fstype, "squashfs" | "iso9660" | "udf")
            || dev.starts_with("/dev/loop")
            || mnt.starts_with("/snap/")
            || mnt.starts_with("/boot/efi")
            || !seen.insert(dev.to_string())
        {
            continue;
        }
        if let Some((total, avail)) = statvfs(Path::new(&mnt))
            && total > 0
        {
            out.push(DiskInfo {
                mount: mnt,
                device: dev.to_string(),
                total,
                avail,
            });
        }
    }
    out
}

fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

pub fn xdg_cache() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".cache"))
}

pub fn xdg_data() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".local/share"))
}

pub fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

#[derive(Clone, Debug, Default)]
pub struct CmdOut {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOut {
    pub fn combined(&self) -> String {
        let mut s = self.stdout.trim_end().to_string();
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(self.stderr.trim_end());
        }
        s
    }
}

/// Run a command with a C locale (so output is parseable) and capture output.
pub fn run(cmd: &str, args: &[&str]) -> CmdOut {
    run_with_stdin(cmd, args, None)
}

/// Like `run`, but gives up (and kills the child) after `secs` seconds. For tools that can hang, such as `jcmd`.
pub fn run_timeout(cmd: &str, args: &[&str], secs: u64) -> CmdOut {
    let spawned = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            return CmdOut {
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: format!("{cmd}: {e}"),
            };
        }
    };
    // Drain both pipes while waiting: a child that writes more than a pipe buffer (~64 KiB)
    // would otherwise block forever and be reported as a timeout.
    fn drain<R: std::io::Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
    }
    let out_reader = drain(child.stdout.take());
    let err_reader = drain(child.stderr.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(40))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return CmdOut {
                    ok: false,
                    code: None,
                    stdout: String::new(),
                    stderr: format!("{cmd}: timed out after {secs}s"),
                };
            }
        }
    };
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    CmdOut {
        ok: status.success(),
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// Open a file or folder with the desktop's default application.
pub fn open(path: &Path) {
    let _ = Command::new("xdg-open")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

pub fn run_with_stdin(cmd: &str, args: &[&str], stdin: Option<&str>) -> CmdOut {
    let mut c = Command::new(cmd);
    c.args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            return CmdOut {
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: format!("{cmd}: {e}"),
            };
        }
    };
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(input.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) => CmdOut {
            ok: o.status.success(),
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => CmdOut {
            ok: false,
            code: None,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

/// Quote one argument for POSIX sh.
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:=+@%,-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Run several commands as root behind a single authentication prompt (pkexec).
/// Each command keeps running even if an earlier one fails.
pub fn run_privileged(commands: &[Vec<String>]) -> CmdOut {
    let mut script = String::from("export LC_ALL=C\nrc=0\n");
    for cmd in commands {
        let line = cmd
            .iter()
            .map(|a| sh_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        script.push_str(&format!(
            "printf '%s\\n' {}\n{line} 2>&1 || {{ echo \"!! command failed with exit code $?\"; rc=1; }}\n",
            sh_quote(&format!("# {line}"))
        ));
    }
    script.push_str("exit $rc\n");
    if is_root() {
        return run("sh", &["-c", &script]);
    }
    if !which("pkexec") {
        return CmdOut {
            ok: false,
            code: None,
            stdout: String::new(),
            stderr: "pkexec not found: install polkit (e.g. `policykit-1` / `polkit`) or run the app as root".into(),
        };
    }
    let mut out = run("pkexec", &["/bin/sh", "-c", &script]);
    match out.code {
        Some(126) => out.stderr = "Authentication was cancelled.".into(),
        Some(127) => {
            out.stderr = "Not authorized (or no polkit authentication agent is running).".into()
        }
        _ => {}
    }
    out
}

/// Parse sizes like "1.2G", "512.0M", "24K", "3 MiB", "1.5 GB".
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let idx = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let num: f64 = s[..idx].trim().parse().ok()?;
    let unit = s[idx..].trim().to_ascii_uppercase();
    let mult: f64 = match unit.chars().next() {
        None | Some('B') => 1.0,
        Some('K') => 1024.0,
        Some('M') => 1024f64.powi(2),
        Some('G') => 1024f64.powi(3),
        Some('T') => 1024f64.powi(4),
        _ => return None,
    };
    Some((num * mult) as u64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_stamp_formats() {
        assert_eq!(super::utc_stamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(super::utc_stamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1.5 MiB"), Some(1_572_864));
        assert_eq!(parse_size("24.0M"), Some(25_165_824));
        assert_eq!(parse_size("100 B"), Some(100));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("junk"), None);
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(12), "12 B");
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("libfoo:amd64"), "libfoo:amd64");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("("), "'('");
    }

    #[test]
    fn clear_dir() {
        let d = std::env::temp_dir().join(format!("linuxward-test-{}", std::process::id()));
        std::fs::create_dir_all(d.join("sub/deep")).unwrap();
        std::fs::write(d.join("a.bin"), vec![1u8; 100_000]).unwrap();
        std::fs::write(d.join("sub/deep/b.bin"), vec![1u8; 50_000]).unwrap();
        assert!(dir_usage(&d) >= 150_000);
        let (freed, errs) = clear_dir_contents(&d);
        assert!(errs.is_empty(), "{errs:?}");
        assert!(freed >= 150_000);
        assert!(d.exists());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        std::fs::remove_dir(&d).unwrap();
    }
}

#[cfg(test)]
mod priv_tests {
    use super::*;

    #[test]
    fn privileged_script_reports_failure() {
        if !is_root() {
            return; // would prompt via pkexec
        }
        let ok = run_privileged(&[vec!["true".into()], vec!["echo".into(), "it's fine".into()]]);
        assert!(ok.ok);
        assert!(ok.stdout.contains("it's fine"));
        let bad = run_privileged(&[vec!["false".into()], vec!["true".into()]]);
        assert!(!bad.ok);
        assert!(bad.stdout.contains("!! command failed"));
    }
}

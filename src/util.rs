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
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let res = if is_dir {
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
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
        let d = std::env::temp_dir().join(format!("diskclean-test-{}", std::process::id()));
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

//! ClamAV integration: scan files, folders or the programs that are running right now.
//! Uses the daemon (`clamdscan`) when this user can reach it, otherwise `clamscan`.

use crate::util::{run, which};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    /// `clamdscan`: fast, the signature database is already loaded.
    Daemon,
    /// `clamscan`: loads the database itself (about 15 s before it starts scanning).
    Standalone,
}

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// What was scanned, for the heading ("your home folder", "142 running programs"...).
    pub target: String,
    pub tool: Option<Tool>,
    /// (path, signature name)
    pub infected: Vec<(String, String)>,
    /// Lines worth showing from ClamAV's own summary.
    pub summary: Vec<String>,
    /// Set when the scan could not run or finished with an error.
    pub error: Option<String>,
}

/// The best tool this user can actually use, or None if ClamAV isn't installed.
pub fn tool() -> Option<Tool> {
    if which("clamdscan") && run("clamdscan", &["--ping", "1:1"]).ok {
        return Some(Tool::Daemon);
    }
    which("clamscan").then_some(Tool::Standalone)
}

pub fn install_hint(pm: Option<crate::pkg::Pm>) -> &'static str {
    use crate::pkg::Pm;
    match pm {
        Some(Pm::Dnf) => "sudo dnf install clamav clamav-update, then sudo freshclam",
        Some(Pm::Apt) => "sudo apt install clamav, then sudo freshclam",
        Some(Pm::Pacman) => "sudo pacman -S clamav, then sudo freshclam",
        Some(Pm::Zypper) => "sudo zypper install clamav, then sudo freshclam",
        None => "install the clamav package, then run sudo freshclam",
    }
}

/// `path: Signature.Name FOUND` lines.
fn parse_infected(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let body = l.trim().strip_suffix(" FOUND")?;
            let (path, sig) = body.rsplit_once(": ")?;
            Some((path.to_string(), sig.to_string()))
        })
        .collect()
}

fn summary_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            [
                "Scanned files:",
                "Infected files:",
                "Scanned directories:",
                "Time:",
            ]
            .iter()
            .any(|k| l.starts_with(k))
        })
        .map(str::to_string)
        .collect()
}

fn execute(tool: Tool, target: &str, input: &[&str]) -> Outcome {
    let mut args: Vec<&str> = match tool {
        Tool::Daemon => vec!["--fdpass", "-m", "--infected"],
        Tool::Standalone => vec!["-r", "--infected", "--cross-fs=no"],
    };
    args.extend_from_slice(input);
    let cmd = if tool == Tool::Daemon {
        "clamdscan"
    } else {
        "clamscan"
    };
    let out = run(cmd, &args);
    let infected = parse_infected(&out.stdout);
    let all = format!("{}\n{}", out.stdout, out.stderr);
    // 0 = clean, 1 = threats found, anything else = the scan itself failed.
    let error = match out.code {
        Some(0) | Some(1) => None,
        _ => {
            let lower = all.to_lowercase();
            Some(
                if lower.contains("no supported database")
                    || lower.contains("can't open") && lower.contains("database")
                {
                    "ClamAV has no virus signatures yet. Run `sudo freshclam` once, then scan again.".to_string()
                } else {
                    all.lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("the scan failed")
                        .to_string()
                },
            )
        }
    };
    Outcome {
        target: target.into(),
        tool: Some(tool),
        infected,
        summary: summary_lines(&all),
        error,
    }
}

fn no_tool(target: &str) -> Outcome {
    Outcome {
        target: target.into(),
        error: Some("ClamAV isn't installed.".into()),
        ..Default::default()
    }
}

pub fn scan_folder(dir: &str) -> Outcome {
    let target = format!("folder {dir}");
    match tool() {
        Some(t) => execute(t, &target, &[dir]),
        None => no_tool(&target),
    }
}

/// Write `text` to a new file in the temp folder that only this user can read. `create_new`
/// refuses an existing file or symlink, so another local user can't pre-create the name.
fn write_private_temp(text: &str) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for attempt in 0..20 {
        let path = std::env::temp_dir().join(format!(
            "diskclean-clam-{}-{nanos}-{attempt}.txt",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(text.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free temp file name",
    ))
}

pub fn scan_files(paths: &[String], label: &str) -> Outcome {
    let Some(t) = tool() else {
        return no_tool(label);
    };
    if paths.is_empty() {
        return Outcome {
            target: label.into(),
            tool: Some(t),
            error: Some("There was nothing to scan.".into()),
            ..Default::default()
        };
    }
    let list = match write_private_temp(&paths.join("\n")) {
        Ok(p) => p,
        Err(e) => {
            return Outcome {
                target: label.into(),
                tool: Some(t),
                error: Some(format!("couldn't write the file list: {e}")),
                ..Default::default()
            };
        }
    };
    let arg = format!("--file-list={}", list.display());
    let out = execute(t, label, &[&arg]);
    let _ = std::fs::remove_file(&list);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_file_list_is_private_and_unique() {
        use std::os::unix::fs::PermissionsExt;
        let a = write_private_temp("one").unwrap();
        let b = write_private_temp("two").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            std::fs::metadata(&a).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "one");
        std::fs::remove_file(a).unwrap();
        std::fs::remove_file(b).unwrap();
    }

    #[test]
    fn parses_clamav_output() {
        let text = "/tmp/a: Win.Test.EICAR_HDB-1 FOUND\n/home/u/we: ird/b: Unix.Trojan.X FOUND\n\n----------- SCAN SUMMARY -----------\nScanned files: 10\nInfected files: 2\nTime: 1.5 sec\n";
        let f = parse_infected(text);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0], ("/tmp/a".into(), "Win.Test.EICAR_HDB-1".into()));
        assert_eq!(f[1].0, "/home/u/we: ird/b");
        assert_eq!(
            summary_lines(text),
            vec!["Scanned files: 10", "Infected files: 2", "Time: 1.5 sec"]
        );
    }
}

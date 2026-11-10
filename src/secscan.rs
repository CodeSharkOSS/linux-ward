//! Security hygiene scan: find files that commonly hold secrets (keys, tokens, credentials,
//! history) and permission mistakes, so they can be reviewed. Secret values are never read
//! into the results: a finding says *what* and *where*, not the secret itself.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Info",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub path: PathBuf,
    pub severity: Severity,
    pub kind: String,
    pub detail: String,
    pub mode: u32,
    /// Group/world access that `chmod` can remove.
    pub fixable: bool,
}

#[derive(Clone, Copy)]
pub struct Options {
    pub scan_contents: bool,
    /// Check git repositories for tracked secret files and secrets in recent history.
    pub scan_git: bool,
}

/// Folders that are huge, regenerable, or full of other people's code rather than your secrets.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    ".cache",
    ".rustup",
    "site-packages",
    "Trash",
    ".npm",
    ".gradle",
    ".m2",
    "__pycache__",
    "vendor",
    "build",
    "dist",
    ".venv",
    "venv",
    ".nvm",
    ".pyenv",
    ".sdkman",
    "JetBrains",
    "testdata",
    "tests",
    "test",
    "fixtures",
];

const TEXT_EXT: &[&str] = &[
    "env",
    "conf",
    "cfg",
    "ini",
    "json",
    "yaml",
    "yml",
    "toml",
    "txt",
    "sh",
    "bash",
    "zsh",
    "py",
    "js",
    "ts",
    "properties",
    "xml",
    "rb",
    "php",
    "tf",
    "tfvars",
    "config",
    "log",
    "sql",
    "gradle",
];

const HISTORY: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
    ".node_repl_history",
    ".lesshst",
];

fn is_example(name: &str) -> bool {
    ["example", "sample", "template", "dist", "default"]
        .iter()
        .any(|w| name.to_lowercase().contains(w))
}

fn alnum_run(s: &str, min: usize) -> bool {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count()
        >= min
}

/// Look for well-known secret formats in one line. Returns a description (never the secret).
fn line_secret(line: &str) -> Option<&'static str> {
    if line.len() > 2000 {
        return None;
    }
    if line.contains("\x2d----BEGIN") && line.contains("PRIVATE KEY") {
        return Some("Private key block");
    }
    for (needle, min, what) in [
        ("AKIA", 16, "AWS access key ID"),
        ("ASIA", 16, "AWS temporary access key ID"),
        ("ghp_", 30, "GitHub personal access token"),
        ("gho_", 30, "GitHub OAuth token"),
        ("github_pat_", 40, "GitHub fine-grained token"),
        ("glpat-", 18, "GitLab access token"),
        ("sk_live_", 20, "Stripe live secret key"),
        ("AIza", 35, "Google API key"),
        ("xoxb-", 20, "Slack bot token"),
        ("xoxp-", 20, "Slack user token"),
    ] {
        for (i, _) in line.match_indices(needle) {
            let rest = &line[i + needle.len()..];
            // The key must stand alone, not sit in the middle of a longer word.
            let before_ok = line[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric());
            let all_caps = needle == "AKIA" || needle == "ASIA";
            let body_ok = if all_caps {
                rest.chars()
                    .take(min)
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && rest.len() >= min
            } else {
                alnum_run(rest, min.saturating_sub(needle.len()).max(10))
            };
            if before_ok && body_ok {
                return Some(what);
            }
        }
    }
    // user:password@host in a URL (git remotes, database strings).
    if let Some(i) = line.find("://") {
        let rest = &line[i + 3..];
        let authority: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '/')
            .collect();
        if let Some((cred, _)) = authority.split_once('@')
            && let Some((user, pass)) = cred.split_once(':')
            && !user.is_empty()
            && !pass.is_empty()
            && !pass.contains('{')
            && !pass.starts_with('$')
        {
            return Some("URL with an embedded password");
        }
    }
    None
}

fn path_ext_is(p: &Path, exts: &[&str]) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| exts.contains(&e.to_lowercase().as_str()))
}

fn read_head(path: &Path, max: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; max];
    let n = File::open(path).ok()?.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn describe_mode(mode: u32) -> &'static str {
    match (mode & 0o070 != 0, mode & 0o007 != 0) {
        (_, true) => "readable by everyone",
        (true, false) => "readable by your group",
        _ => "private",
    }
}

/// Classify one file by name and location. Returns (severity, kind, detail).
fn by_name(path: &Path, name: &str, mode: u32) -> Option<(Severity, String, String)> {
    let lname = name.to_lowercase();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let in_dir = |d: &str| path.components().any(|c| c.as_os_str() == d);
    let exposed = mode & 0o077 != 0;
    let sev = |base: Severity| if exposed { Severity::High } else { base };

    if matches!(
        name,
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "id_ecdsa_sk" | "id_ed25519_sk"
    ) {
        return Some((
            sev(Severity::Low),
            "SSH private key".into(),
            format!("Permissions: {}", describe_mode(mode)),
        ));
    }
    if name == "wallet.dat" || ext == "kdbx" || ext == "kdb" {
        return Some((
            Severity::Medium,
            "Wallet / password database".into(),
            "Make sure it is backed up and encrypted".into(),
        ));
    }
    if matches!(
        ext.as_str(),
        "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" | "ppk"
    ) && !is_example(name)
    {
        return Some((
            sev(Severity::Medium),
            "Key or certificate file".into(),
            format!("Permissions: {}", describe_mode(mode)),
        ));
    }
    if (lname == ".env" || lname.starts_with(".env.") || lname.ends_with(".env"))
        && !is_example(name)
    {
        return Some((
            sev(Severity::Medium),
            "Environment file".into(),
            "Often contains API keys and passwords".into(),
        ));
    }
    match name {
        ".netrc" | "_netrc" => Some((
            sev(Severity::Medium),
            "Stored login (netrc)".into(),
            "Plain-text passwords for FTP/HTTP hosts".into(),
        )),
        ".git-credentials" => Some((
            sev(Severity::High),
            "Git credentials".into(),
            "Plain-text git passwords/tokens".into(),
        )),
        ".pgpass" | ".my.cnf" => Some((
            sev(Severity::Medium),
            "Database password file".into(),
            "Plain-text database credentials".into(),
        )),
        ".pypirc" | ".npmrc" | ".dockercfg" => {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let has_secret = text.lines().any(|l| {
                let l = l.trim();
                !l.starts_with(['#', ';'])
                    && [
                        "_authToken=",
                        "_auth=",
                        "_password=",
                        "password =",
                        "password=",
                        "\"auth\"",
                    ]
                    .iter()
                    .any(|k| l.contains(k))
                    && !l.contains("${")
            });
            has_secret.then(|| {
                (
                    sev(Severity::Medium),
                    "Package registry login".into(),
                    "Contains an auth token or password".into(),
                )
            })
        }
        "credentials" if in_dir(".aws") => Some((
            sev(Severity::High),
            "AWS credentials".into(),
            "Access keys for your cloud account".into(),
        )),
        "config" if in_dir(".kube") => Some((
            sev(Severity::Medium),
            "Kubernetes config".into(),
            "Cluster access tokens or certificates".into(),
        )),
        "config.json" if in_dir(".docker") => Some((
            sev(Severity::Medium),
            "Docker login".into(),
            "May contain registry auth".into(),
        )),
        "hosts.yml" if in_dir("gh") => Some((
            sev(Severity::Medium),
            "GitHub CLI login".into(),
            "Contains an OAuth token".into(),
        )),
        n if HISTORY.contains(&n) => Some((
            Severity::Low,
            "Shell / tool history".into(),
            "May contain passwords typed on a command line".into(),
        )),
        _ => None,
    }
}

fn scan_contents_of(path: &Path, size: u64) -> Option<(usize, &'static str)> {
    if size == 0 || size > 1_000_000 {
        return None;
    }
    let head = read_head(path, 8192)?;
    if head.contains(&0) {
        return None; // binary
    }
    let mut data = head;
    if size > 8192 {
        data = std::fs::read(path).ok()?;
    }
    let text = String::from_utf8_lossy(&data);
    text.lines()
        .enumerate()
        .find_map(|(i, l)| line_secret(l).map(|w| (i + 1, w)))
}

/// Judge one file by its name, location, permissions and (optionally) contents.
fn check_file(path: &Path, name: &str, mode: u32, size: u64, opts: Options) -> Option<Finding> {
    let mut hit: Option<(Severity, String, String)> = by_name(path, name, mode);

    // A key file by name or extension: confirm and flag unencrypted ones.
    if let Some((_, kind, _)) = &hit
        && (kind.contains("private key") || kind.contains("Key or certificate"))
        && let Some(head) = read_head(path, 4096)
    {
        let text = String::from_utf8_lossy(&head);
        let textual = !head.contains(&0);
        let pemish = path_ext_is(path, &["pem", "key", "crt", "cer"]);
        if textual && pemish && kind.contains("Key or certificate") && !text.contains("PRIVATE KEY")
        {
            hit = None; // a public certificate or licence text, not a secret
        } else if text.contains("PRIVATE KEY")
            && !text.contains("ENCRYPTED")
            && !text.contains("BEGIN OPENSSH")
        {
            hit = hit.map(|(s, k, d)| {
                (
                    s.min(Severity::Medium),
                    k,
                    format!("{d}. Not protected by a passphrase"),
                )
            });
        }
    }

    if hit.is_none() && opts.scan_contents {
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_lowercase();
        let git_cfg = name == "config" && path.parent().is_some_and(|p| p.ends_with(".git"));
        if (TEXT_EXT.contains(&ext.as_str()) || ext.is_empty() || git_cfg)
            && !is_example(name)
            && let Some((line, what)) = scan_contents_of(path, size)
        {
            let sev = if mode & 0o004 != 0 {
                Severity::High
            } else {
                Severity::Medium
            };
            hit = Some((
                sev,
                what.into(),
                format!("Found at line {line}; contents not shown"),
            ));
        }
    }

    if hit.is_none() && mode & 0o002 != 0 {
        hit = Some((
            Severity::Low,
            "World-writable file".into(),
            "Anyone on this machine can modify it".into(),
        ));
    }
    let (severity, kind, detail) = hit?;
    Some(Finding {
        path: path.to_path_buf(),
        severity,
        kind,
        detail,
        mode,
        fixable: mode & 0o077 != 0 && severity != Severity::Low || mode & 0o002 != 0,
    })
}

/// Split `items` over up to 8 threads and gather what `f` returns for each.
fn par_collect<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> Option<R> + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8);
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|sc| {
        let f = &f;
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|part| sc.spawn(move || part.iter().filter_map(f).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

pub fn scan(root: &Path, opts: Options) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    // Walking is cheap; reading file contents is not. Collect first, then inspect in parallel.
    let mut files: Vec<(PathBuf, String, u32, u64)> = Vec::new();
    for e in walkdir::WalkDir::new(root)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            e.depth() == 0
                || !crate::util::excluded(e.path())
                    && !(e.file_type().is_dir() && SKIP_DIRS.contains(&n.as_ref()))
                    && !(n == "objects" && e.path().parent().is_some_and(|p| p.ends_with(".git")))
        })
        .filter_map(Result::ok)
    {
        let Ok(meta) = e.metadata() else { continue };
        let mode = meta.permissions().mode() & 0o7777;
        let name = e.file_name().to_string_lossy().to_string();

        if e.file_type().is_dir() {
            if (name == ".ssh" || name == ".gnupg") && mode & 0o077 != 0 {
                findings.push(Finding {
                    path: e.path().to_path_buf(),
                    severity: Severity::High,
                    kind: format!("{name} folder is not private"),
                    detail: format!(
                        "Permissions {mode:o}: {}. Should be 700.",
                        describe_mode(mode)
                    ),
                    mode,
                    fixable: true,
                });
            }
        } else if e.file_type().is_file() {
            files.push((e.into_path(), name, mode, meta.len()));
        }
    }
    let scanned = files.len();
    findings.extend(par_collect(&files, |(path, name, mode, size)| {
        check_file(path, name, *mode, *size, opts)
    }));
    if opts.scan_git {
        let repos = crate::devclean::repos_under(root);
        findings.extend(
            par_collect(&repos, |r| Some(scan_git_repo(r)))
                .into_iter()
                .flatten(),
        );
    }
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.path.cmp(&b.path))
    });
    (findings, scanned)
}

/// Secrets committed to a git repository: tracked files that should never be tracked, and
/// secret-looking lines added in the last 300 commits. Removing a secret from the working tree
/// does not remove it from history, which is why history is checked at all.
pub fn scan_git_repo(repo: &Path) -> Vec<Finding> {
    use crate::util::run;
    let r = repo.to_string_lossy().to_string();
    let mut out = Vec::new();
    let tracked = run("git", &["-C", &r, "-c", "core.quotepath=off", "ls-files"]);
    for rel in tracked.stdout.lines() {
        let path = repo.join(rel);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Some((_, kind, _)) = by_name(&path, &name, 0o600)
            && !kind.contains("history")
        {
            out.push(Finding {
                path,
                severity: Severity::High,
                kind: format!("{kind} committed to git"),
                detail: format!("Tracked in {}. Anyone with the repository can read it; rotate it if the repo was ever shared.", repo.display()),
                mode: 0,
                fixable: false,
            });
        }
    }
    let log = run(
        "git",
        &[
            "-C",
            &r,
            "-c",
            "core.quotepath=off",
            "log",
            "--all",
            "-n",
            "300",
            "-p",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--diff-filter=AM",
            "--format=@@commit %h",
        ],
    );
    let (mut commit, mut file) = (String::new(), String::new());
    let mut seen = std::collections::HashSet::new();
    for line in log.stdout.lines().take(2_000_000) {
        if let Some(h) = line.strip_prefix("@@commit ") {
            commit = h.to_string();
        } else if let Some(f) = line.strip_prefix("+++ b/") {
            file = f.to_string();
        } else if let Some(added) = line.strip_prefix('+')
            && !line.starts_with("+++")
            && let Some(what) = line_secret(added)
            && seen.insert((file.clone(), what))
        {
            out.push(Finding {
                path: repo.join(&file),
                severity: Severity::High,
                kind: format!("{what} in git history"),
                detail: format!("Added in commit {commit}. Deleting the line doesn't remove it from history; rotate the secret."),
                mode: 0,
                fixable: false,
            });
        }
    }
    out
}

/// Remove group/world access: 700 for folders, 600 for files.
pub fn restrict(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("is a symlink".into());
    }
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_formats_without_false_positives() {
        assert_eq!(
            line_secret("key = \x41KIAIOSFODNN7EXAMPLE"),
            Some("AWS access key ID")
        );
        assert_eq!(
            line_secret("token: \x67hp_abcdefghijklmnopqrstuvwxyz0123456789"),
            Some("GitHub personal access token")
        );
        assert_eq!(
            line_secret("\x2d----BEGIN RSA PRIVATE KEY-----"),
            Some("Private key block")
        );
        assert_eq!(
            line_secret("url = https://bob:hunter2\x40example.com/repo.git"),
            Some("URL with an embedded password")
        );
        assert_eq!(line_secret("url = https://example.com/repo.git"), None);
        assert_eq!(
            line_secret("url = https://${USER}:${PASS}@example.com"),
            None
        );
        assert_eq!(line_secret("let x = \"B\x41KIAIOSFODNN7EXAMPLE\""), None);
        assert_eq!(line_secret("AKIA short"), None);
    }

    #[test]
    fn scan_finds_exposed_secrets_and_skips_examples() {
        let dir = std::env::temp_dir().join(format!("secscan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ssh")).unwrap();
        std::fs::write(
            dir.join(".ssh/id_rsa"),
            "\x2d----BEGIN RSA PRIVATE KEY-----\nabc\n",
        )
        .unwrap();
        std::fs::set_permissions(
            dir.join(".ssh/id_rsa"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::write(dir.join(".env"), "A=1").unwrap();
        std::fs::write(dir.join(".env.example"), "A=").unwrap();
        std::fs::write(dir.join("notes.txt"), "pw https://u:p\x40host/x").unwrap();
        std::fs::write(dir.join("plain.txt"), "nothing here").unwrap();
        let (f, scanned) = scan(
            &dir,
            Options {
                scan_contents: true,
                scan_git: false,
            },
        );
        assert_eq!(scanned, 5);
        let names: Vec<_> = f
            .iter()
            .map(|x| x.path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(
            names.contains(&"id_rsa") && names.contains(&".env") && names.contains(&"notes.txt")
        );
        assert!(!names.contains(&".env.example") && !names.contains(&"plain.txt"));
        let key = f.iter().find(|x| x.path.ends_with("id_rsa")).unwrap();
        assert_eq!(key.severity, Severity::High);
        assert!(key.fixable);
        restrict(&key.path).unwrap();
        assert_eq!(
            std::fs::metadata(&key.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn git_scan_finds_tracked_secret_files_and_history() {
        if !crate::util::which("git") {
            return;
        }
        let dir = std::env::temp_dir().join(format!("secscan-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let g = |args: &[&str]| {
            let mut a = vec![
                "-C",
                dir.to_str().unwrap(),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ];
            a.extend_from_slice(args);
            assert!(crate::util::run("git", &a).ok, "git {args:?} failed");
        };
        g(&["init", "-q"]);
        std::fs::write(dir.join(".netrc"), "machine x login y password z").unwrap();
        std::fs::write(dir.join("conf.txt"), "key = \x41KIAIOSFODNN7EXAMPLE\n").unwrap();
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "x"]);
        std::fs::write(dir.join("conf.txt"), "clean\n").unwrap();
        g(&["commit", "-q", "-am", "remove key"]);
        let f = scan_git_repo(&dir);
        assert!(
            f.iter()
                .any(|x| x.kind.contains("committed to git") && x.path.ends_with(".netrc")),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|x| x.kind.contains("AWS access key ID in git history")),
            "{f:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

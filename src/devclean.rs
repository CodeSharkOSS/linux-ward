//! Developer clean-up: regenerable build output inside project folders, stale language
//! toolchains, and git repository maintenance.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::util::{dir_usage, home, run};

// ---------------------------------------------------------------------------------------------
// Project build artifacts
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Artifact {
    pub kind: &'static str,
    pub path: PathBuf,
    pub size: u64,
    /// Days since the folder was last modified.
    pub idle_days: u64,
}

/// What is safe to delete in `dir`, as (folder name, label), judged by marker files next to it.
/// Each rule demands evidence that the folder really is generated output.
fn artifact_rules(dir: &Path) -> Vec<(&'static str, &'static str)> {
    let has = |f: &str| dir.join(f).exists();
    let mut v = Vec::new();
    if has("Cargo.toml")
        && (dir.join("target/CACHEDIR.TAG").exists()
            || dir.join("target/.rustc_info.json").exists())
    {
        v.push(("target", "Rust build"));
    }
    if has("package.json") {
        v.push(("node_modules", "Node modules"));
        v.push((".next", "Next.js cache"));
        v.push((".nuxt", "Nuxt cache"));
        v.push((".parcel-cache", "Parcel cache"));
    }
    if has("pom.xml") && dir.join("target/classes").exists() {
        v.push(("target", "Maven build"));
    }
    if has("build.gradle")
        || has("build.gradle.kts")
        || has("settings.gradle")
        || has("settings.gradle.kts")
    {
        v.push(("build", "Gradle build"));
        v.push((".gradle", "Gradle project cache"));
    }
    if has("CMakeLists.txt") {
        for d in ["build", "cmake-build-debug", "cmake-build-release", "out"] {
            if dir.join(d).join("CMakeCache.txt").exists() {
                v.push((d, "CMake build"));
            }
        }
    }
    for d in [".venv", "venv", "env"] {
        if dir.join(d).join("pyvenv.cfg").exists() {
            v.push((d, "Python virtual env"));
        }
    }
    for d in [".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"] {
        if dir.join(d).is_dir() {
            v.push((d, "Python tool cache"));
        }
    }
    if has("composer.json") && dir.join("vendor/autoload.php").exists() {
        v.push(("vendor", "Composer packages"));
    }
    if std::fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".csproj") || n.ends_with(".sln") || n.ends_with(".fsproj")
        })
    }) {
        for d in ["bin", "obj"] {
            if dir.join(d).is_dir() {
                v.push((d, ".NET build"));
            }
        }
    }
    v
}

fn walk(dir: &Path, depth: usize, found: &mut Vec<(PathBuf, &'static str, PathBuf)>) {
    if depth > 9 || crate::util::excluded(dir) {
        return;
    }
    let rules = artifact_rules(dir);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue; // symlinks are never followed or deleted
        }
        let name = e.file_name().to_string_lossy().to_string();
        let path = e.path();
        if name == "__pycache__" {
            found.push((dir.to_path_buf(), "Python bytecode", path));
            continue;
        }
        if let Some((_, kind)) = rules.iter().find(|(n, _)| *n == name)
            && !crate::util::excluded(&path)
        {
            found.push((dir.to_path_buf(), kind, path));
            continue; // don't descend into what we're about to delete
        }
        // Skip hidden folders (.git, .cache, .config...) and other people's code.
        if name.starts_with('.')
            || matches!(
                name.as_str(),
                "node_modules" | "target" | "vendor" | "site-packages"
            )
        {
            continue;
        }
        walk(&path, depth + 1, found);
    }
}

pub fn scan_artifacts(root: &Path) -> Vec<Artifact> {
    let mut found = Vec::new();
    walk(root, 0, &mut found);
    let now = SystemTime::now();
    let sized: Vec<Artifact> = std::thread::scope(|sc| {
        let chunk = found.len().div_ceil(8).max(1);
        let handles: Vec<_> = found
            .chunks(chunk)
            .map(|part| {
                sc.spawn(move || {
                    part.iter()
                        .map(|(_, kind, path)| Artifact {
                            kind,
                            path: path.clone(),
                            size: dir_usage(path),
                            idle_days: std::fs::metadata(path)
                                .and_then(|m| m.modified())
                                .ok()
                                .and_then(|t| now.duration_since(t).ok())
                                .map(|d| d.as_secs() / 86_400)
                                .unwrap_or(0),
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    let mut v: Vec<Artifact> = sized.into_iter().filter(|a| a.size > 0).collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.size));
    v
}

// ---------------------------------------------------------------------------------------------
// Toolchains
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Removal {
    Dir(PathBuf),
    Cmd(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct Toolchain {
    pub kind: &'static str,
    pub name: String,
    pub size: u64,
    /// In use (default / current): can't be selected.
    pub current: bool,
    pub removal: Removal,
}

fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| (e.file_name().to_string_lossy().to_string(), e.path()))
        .collect();
    v.sort();
    v
}

fn version_key(v: &str) -> Vec<u64> {
    v.trim_start_matches('v')
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse().ok())
        .collect()
}

pub fn toolchains() -> Vec<Toolchain> {
    let h = home();
    let mut out = Vec::new();

    // nvm: the default alias wins; otherwise the newest is kept.
    let nvm = h.join(".nvm/versions/node");
    let vers = subdirs(&nvm);
    let alias = std::fs::read_to_string(h.join(".nvm/alias/default")).unwrap_or_default();
    let alias = alias.trim().trim_start_matches('v');
    let newest = vers.iter().map(|(n, _)| version_key(n)).max();
    for (name, path) in &vers {
        let by_alias = !alias.is_empty() && name.trim_start_matches('v').starts_with(alias);
        let current = by_alias
            || (alias.is_empty()
                || !vers
                    .iter()
                    .any(|(n, _)| n.trim_start_matches('v').starts_with(alias)))
                && Some(version_key(name)) == newest;
        out.push(Toolchain {
            kind: "Node (nvm)",
            name: name.clone(),
            size: dir_usage(path),
            current,
            removal: Removal::Dir(path.clone()),
        });
    }

    // sdkman: <candidate>/<version>, with `current` as a symlink to the active one.
    for (cand, cpath) in subdirs(&h.join(".sdkman/candidates")) {
        let current = std::fs::read_link(cpath.join("current"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
        for (ver, vpath) in subdirs(&cpath) {
            if ver == "current"
                || std::fs::symlink_metadata(&vpath).is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            out.push(Toolchain {
                kind: "SDKMAN",
                name: format!("{cand} {ver}"),
                size: dir_usage(&vpath),
                current: current.as_deref() == Some(ver.as_str()),
                removal: Removal::Dir(vpath),
            });
        }
    }

    // pyenv
    let global = std::fs::read_to_string(h.join(".pyenv/version")).unwrap_or_default();
    for (ver, vpath) in subdirs(&h.join(".pyenv/versions")) {
        let current = global.lines().any(|l| l.trim() == ver);
        out.push(Toolchain {
            kind: "Python (pyenv)",
            name: ver,
            size: dir_usage(&vpath),
            current,
            removal: Removal::Dir(vpath),
        });
    }

    // rustup
    if crate::util::which("rustup") {
        let list = run("rustup", &["toolchain", "list"]);
        for line in list.stdout.lines() {
            let Some(name) = line.split_whitespace().next() else {
                continue;
            };
            let current = line.contains("default")
                || line.contains("active")
                || line.contains("override")
                || list.stdout.lines().count() == 1;
            let dir = h.join(".rustup/toolchains").join(name);
            out.push(Toolchain {
                kind: "Rust (rustup)",
                name: name.to_string(),
                size: dir_usage(&dir),
                current,
                removal: Removal::Cmd(vec![
                    "rustup".into(),
                    "toolchain".into(),
                    "uninstall".into(),
                    name.to_string(),
                ]),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Git repositories
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Repo {
    pub path: PathBuf,
    pub git_size: u64,
    /// Local branches already merged into the default branch.
    pub merged: Vec<String>,
    pub default_branch: String,
}

fn find_repos(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 8 || crate::util::excluded(dir) {
        return;
    }
    if dir.join(".git").is_dir() {
        out.push(dir.to_path_buf());
        return; // nested repos are rare and submodules are managed by their parent
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.')
            || matches!(
                name.as_str(),
                "node_modules" | "target" | "vendor" | "site-packages" | "build"
            )
        {
            continue;
        }
        find_repos(&e.path(), depth + 1, out);
    }
}

pub fn repos_under(root: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    find_repos(root, 0, &mut v);
    v
}

fn git(repo: &Path, args: &[&str]) -> crate::util::CmdOut {
    let mut a = vec![
        "-C",
        repo.to_str().unwrap_or("."),
        "-c",
        "core.quotepath=off",
    ];
    a.extend_from_slice(args);
    run("git", &a)
}

pub fn inspect_repo(path: &Path) -> Repo {
    let default_branch = {
        let r = git(
            path,
            &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        );
        let from_remote = r.stdout.trim().strip_prefix("origin/").map(str::to_string);
        from_remote.unwrap_or_else(|| {
            ["main", "master", "develop"]
                .into_iter()
                .find(|b| {
                    git(
                        path,
                        &[
                            "rev-parse",
                            "--verify",
                            "--quiet",
                            &format!("refs/heads/{b}"),
                        ],
                    )
                    .ok
                })
                .unwrap_or("main")
                .to_string()
        })
    };
    let current = git(path, &["rev-parse", "--abbrev-ref", "HEAD"])
        .stdout
        .trim()
        .to_string();
    let merged: Vec<String> = git(
        path,
        &[
            "branch",
            "--merged",
            &default_branch,
            "--format=%(refname:short)",
        ],
    )
    .stdout
    .lines()
    .map(str::trim)
    .filter(|b| {
        !b.is_empty()
            && *b != default_branch
            && *b != current
            && !matches!(*b, "main" | "master" | "develop" | "dev")
            && !b.contains(' ')
    })
    .map(str::to_string)
    .collect();
    Repo {
        path: path.to_path_buf(),
        git_size: dir_usage(&path.join(".git")),
        merged,
        default_branch,
    }
}

pub fn gc_cmd(repo: &Path) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo.display().to_string(),
        "gc".into(),
        "--prune=now".into(),
    ]
}

/// `-d` (not `-D`) only deletes a branch git considers fully merged.
pub fn delete_branch_cmd(repo: &Path, branch: &str) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo.display().to_string(),
        "branch".into(),
        "-d".into(),
        branch.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_artifacts_only_with_evidence() {
        let base = std::env::temp_dir().join(format!("devclean-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let rust = base.join("proj/rust");
        std::fs::create_dir_all(rust.join("target/debug")).unwrap();
        std::fs::write(rust.join("Cargo.toml"), "").unwrap();
        std::fs::write(rust.join("target/CACHEDIR.TAG"), "x").unwrap();
        std::fs::write(rust.join("target/debug/a"), vec![0u8; 100]).unwrap();
        // A folder named `target` with no Cargo project beside it must be left alone.
        let other = base.join("proj/other");
        std::fs::create_dir_all(other.join("target")).unwrap();
        std::fs::write(other.join("target/keep"), "x").unwrap();
        let node = base.join("proj/web");
        std::fs::create_dir_all(node.join("node_modules/x")).unwrap();
        std::fs::write(node.join("package.json"), "{}").unwrap();
        std::fs::write(node.join("node_modules/x/i.js"), "y").unwrap();
        let found = scan_artifacts(&base);
        let kinds: Vec<_> = found.iter().map(|a| a.kind).collect();
        assert!(
            kinds.contains(&"Rust build") && kinds.contains(&"Node modules"),
            "{kinds:?}"
        );
        assert!(found.iter().all(|a| !a.path.starts_with(&other)));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn version_ordering() {
        assert!(version_key("v20.1.0") > version_key("v18.9.9"));
    }
}

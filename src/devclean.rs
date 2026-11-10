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

/// What removing a toolchain involves: folders to delete and/or commands to run.
#[derive(Clone, Debug, Default)]
pub struct Removal {
    pub dirs: Vec<PathBuf>,
    pub cmds: Vec<Vec<String>>,
}

impl Removal {
    fn dir(p: PathBuf) -> Self {
        Removal {
            dirs: vec![p],
            cmds: vec![],
        }
    }
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
            removal: Removal::dir(path.clone()),
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
                removal: Removal::dir(vpath),
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
            removal: Removal::dir(vpath),
        });
    }

    // The IDE and Android scans measure many large folders: do them alongside the rest.
    let (ide, android) = std::thread::scope(|sc| {
        let a = sc.spawn(ide_leftovers);
        let b = sc.spawn(android_sdk);
        (a.join().unwrap_or_default(), b.join().unwrap_or_default())
    });
    out.extend(ide);
    out.extend(android);

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
                removal: Removal {
                    dirs: vec![],
                    cmds: vec![vec![
                        "rustup".into(),
                        "toolchain".into(),
                        "uninstall".into(),
                        name.to_string(),
                    ]],
                },
            });
        }
    }
    out
}

/// "IntelliJIdea2026.2" → ("IntelliJIdea", "2026.2"). Folders without a version are not IDE profiles.
fn split_ide_name(name: &str) -> Option<(&str, &str)> {
    let i = name.find(|c: char| c.is_ascii_digit())?;
    let (product, ver) = name.split_at(i);
    let ok = !product.is_empty()
        && ver.chars().all(|c| c.is_ascii_digit() || c == '.')
        && ver.contains('.');
    ok.then_some((product, ver))
}

/// Settings, plugins and caches that JetBrains IDEs and Android Studio keep per version.
/// Each upgrade leaves the previous version's folders behind; the newest of each product is kept.
fn ide_leftovers() -> Vec<Toolchain> {
    use std::collections::BTreeMap;
    let h = home();
    let xdg = |var: &str, fallback: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .unwrap_or_else(|| h.join(fallback))
    };
    let roots = [
        (xdg("XDG_CONFIG_HOME", ".config"), "settings"),
        (xdg("XDG_CACHE_HOME", ".cache"), "caches"),
        (xdg("XDG_DATA_HOME", ".local/share"), "plugins & data"),
    ];
    // (vendor folder, product) -> version -> folders
    let mut map: BTreeMap<(&str, String), BTreeMap<String, Vec<PathBuf>>> = BTreeMap::new();
    for vendor in ["JetBrains", "Google"] {
        for (root, _) in &roots {
            for (name, path) in subdirs(&root.join(vendor)) {
                let Some((product, ver)) = split_ide_name(&name) else {
                    continue;
                };
                if vendor == "Google" && product != "AndroidStudio" {
                    continue;
                }
                map.entry((vendor, product.to_string()))
                    .or_default()
                    .entry(ver.to_string())
                    .or_default()
                    .push(path);
            }
        }
    }
    let mut out = Vec::new();
    for ((_, product), versions) in map {
        let newest = versions.keys().max_by_key(|v| version_key(v)).cloned();
        for (ver, dirs) in versions {
            if Some(&ver) == newest.as_ref() {
                continue;
            }
            let size = dirs.iter().map(|d| dir_usage(d)).sum();
            out.push(Toolchain {
                kind: "IDE (old version)",
                name: format!("{product} {ver}"),
                size,
                current: false,
                removal: Removal { dirs, cmds: vec![] },
            });
        }
    }
    out
}

fn android_sdk_root() -> Option<PathBuf> {
    ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .chain([home().join("Android/Sdk"), home().join(".android/sdk")])
        .find(|p| p.is_dir())
}

/// The Android SDK's per-version packages (older platforms, build-tools, NDKs, system images)
/// and emulator devices. The newest of each package kind is kept; system images in use by a
/// virtual device are protected.
fn android_sdk() -> Vec<Toolchain> {
    let mut out = Vec::new();
    let avd_home = std::env::var_os("ANDROID_AVD_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".android/avd"));

    // Virtual devices, and the system images they need.
    let mut used_images: Vec<String> = Vec::new();
    let mut avds = Vec::new();
    for e in std::fs::read_dir(&avd_home).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(avd) = name.strip_suffix(".avd") {
            let dir = e.path();
            if let Ok(cfg) = std::fs::read_to_string(dir.join("config.ini")) {
                used_images.extend(
                    cfg.lines()
                        .filter_map(|l| l.strip_prefix("image.sysdir.1="))
                        .map(|v| v.trim().trim_end_matches('/').to_string()),
                );
            }
            avds.push((avd.to_string(), dir));
        }
    }
    avds.sort();
    for (name, dir) in avds {
        let ini = avd_home.join(format!("{name}.ini"));
        let cmds = if ini.exists() {
            vec![vec![
                "rm".to_string(),
                "-f".into(),
                ini.display().to_string(),
            ]]
        } else {
            vec![]
        };
        out.push(Toolchain {
            kind: "Android emulator",
            name: format!("device {name}"),
            size: dir_usage(&dir),
            current: false,
            removal: Removal {
                dirs: vec![dir],
                cmds,
            },
        });
    }

    let Some(sdk) = android_sdk_root() else {
        return out;
    };
    // Newest version of each single-level package kind is kept.
    for (sub, label) in [
        ("platforms", "Android platform"),
        ("build-tools", "Android build-tools"),
        ("ndk", "Android NDK"),
    ] {
        let vers = subdirs(&sdk.join(sub));
        let newest = vers.iter().map(|(n, _)| version_key(n)).max();
        for (name, path) in vers {
            out.push(Toolchain {
                kind: label,
                name: name.clone(),
                size: dir_usage(&path),
                current: Some(version_key(&name)) == newest,
                removal: Removal::dir(path),
            });
        }
    }
    // system-images/<api>/<variant>/<abi>
    for (api, apath) in subdirs(&sdk.join("system-images")) {
        for (variant, vpath) in subdirs(&apath) {
            for (abi, path) in subdirs(&vpath) {
                let rel = format!("system-images/{api}/{variant}/{abi}");
                let current = used_images.iter().any(|u| u == &rel);
                out.push(Toolchain {
                    kind: "Android system image",
                    name: format!("{api} {variant} {abi}"),
                    size: dir_usage(&path),
                    current,
                    removal: Removal::dir(path),
                });
            }
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

/// Inspect many repositories at once: each takes several `git` calls and a size walk.
pub fn inspect_repos(paths: &[PathBuf]) -> Vec<Repo> {
    std::thread::scope(|sc| {
        let chunk = paths.len().div_ceil(8).max(1);
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| sc.spawn(move || part.iter().map(|p| inspect_repo(p)).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
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
    fn ide_names_split_into_product_and_version() {
        assert_eq!(
            split_ide_name("IntelliJIdea2026.2"),
            Some(("IntelliJIdea", "2026.2"))
        );
        assert_eq!(
            split_ide_name("AndroidStudio2024.1.1"),
            Some(("AndroidStudio", "2024.1.1"))
        );
        assert_eq!(split_ide_name("Toolbox"), None);
        assert_eq!(split_ide_name("Idea"), None);
        assert_eq!(split_ide_name("2026.1"), None);
    }

    #[test]
    fn android_sdk_keeps_newest_and_images_used_by_devices() {
        let base = std::env::temp_dir().join(format!("android-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let sdk = base.join("Sdk");
        for d in [
            "platforms/android-33",
            "platforms/android-34",
            "build-tools/33.0.2",
            "build-tools/34.0.0",
            "system-images/android-34/google_apis/x86_64",
            "system-images/android-30/google_apis/x86_64",
        ] {
            std::fs::create_dir_all(sdk.join(d)).unwrap();
            std::fs::write(sdk.join(d).join("f"), "x").unwrap();
        }
        let avd = base.join("avd");
        std::fs::create_dir_all(avd.join("Pixel.avd")).unwrap();
        std::fs::write(
            avd.join("Pixel.avd/config.ini"),
            "image.sysdir.1=system-images/android-34/google_apis/x86_64/\n",
        )
        .unwrap();
        std::fs::write(avd.join("Pixel.ini"), "path=x").unwrap();
        // SAFETY: tests in this module don't read these variables concurrently.
        unsafe {
            std::env::set_var("ANDROID_HOME", &sdk);
            std::env::set_var("ANDROID_AVD_HOME", &avd);
        }
        let t = android_sdk();
        let find = |n: &str| {
            t.iter()
                .find(|x| x.name.contains(n))
                .unwrap_or_else(|| panic!("{n} missing in {t:?}"))
        };
        assert!(find("android-34").current && !find("android-33").current);
        assert!(find("34.0.0").current && !find("33.0.2").current);
        assert!(
            find("android-34 google_apis").current,
            "image used by an AVD is protected"
        );
        assert!(!find("android-30").current);
        let dev = find("device Pixel");
        assert_eq!(dev.removal.dirs.len(), 1);
        assert_eq!(dev.removal.cmds.len(), 1, "the .ini file is removed too");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn version_ordering() {
        assert!(version_key("v20.1.0") > version_key("v18.9.9"));
    }
}

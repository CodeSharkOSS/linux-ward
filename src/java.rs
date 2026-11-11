//! Java runtime diagnostics: installed runtimes, running JVMs (including the ones embedded in
//! IDEs), heap and GC analysis, and concrete fixes.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::perf::{Rec, natural_cmp, parse_stat};
use crate::pkg::Pm;
use crate::targets::Action;
use crate::util::{self, human, run, run_timeout, which};

pub const LATEST_LTS: u32 = 25;
const LTS: [u32; 5] = [8, 11, 17, 21, 25];
const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

#[derive(Clone)]
pub struct Jvm {
    pub home: PathBuf,
    pub version: String,
    pub major: u32,
    pub vendor: String,
    pub is_jdk: bool,
    pub is_default: bool,
    /// Shipped inside another application (an IDE's `JetBrains` Runtime…): never touched.
    pub bundled: bool,
    /// Java 12+ ships a class-data-sharing archive that speeds up start-up; it can go missing after updates.
    pub cds_missing: bool,
    pub size: u64,
    pub packages: Vec<String>,
    pub running: bool,
}

/// (label, true when it deserves a warning)
pub fn support(major: u32) -> (&'static str, bool) {
    match major {
        m if m == LATEST_LTS => ("latest LTS", false),
        17 | 21 => ("LTS", false),
        11 => ("old LTS – free updates ending", true),
        m if m <= 10 => ("very old", true),
        m if m > LATEST_LTS => ("newer than the latest LTS (short-lived)", false),
        _ => ("non-LTS – no more updates", true),
    }
}

#[derive(Clone)]
pub struct Ide {
    pub vmoptions: PathBuf,
    pub xmx: Option<u64>,
}

#[derive(Clone)]
pub struct JProc {
    pub pid: u32,
    pub label: String,
    pub jvm_home: Option<PathBuf>,
    pub major: Option<u32>,
    pub rss: u64,
    pub cpu: f32,
    pub threads: u32,
    pub mine: bool,
    pub max_heap: Option<u64>,
    pub heap_used: Option<u64>,
    pub gc: Option<String>,
    pub ide: Option<Ide>,
    pub advice: Vec<String>,
    pub flags: String,
}

#[derive(Clone, Default)]
pub struct JavaReport {
    pub jvms: Vec<Jvm>,
    pub procs: Vec<JProc>,
    pub recs: Vec<Rec>,
    pub findings: Vec<String>,
    /// (profile, JVM flags) tuned to this machine.
    pub flag_sets: Vec<(String, String)>,
    pub ram: u64,
    pub cpus: usize,
}

// ----- parsing helpers -----------------------------------------------------------------

pub fn major_of(version: &str) -> u32 {
    let mut it = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let first: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if first == 1 {
        it.next().and_then(|s| s.parse().ok()).unwrap_or(1)
    } else {
        first
    }
}

fn parse_props(text: &str) -> (String, String) {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_default()
    };
    (get("java.version"), get("java.vendor"))
}

/// "-Xmx2048m" style size to bytes.
pub fn parse_xmx(arg: &str) -> Option<u64> {
    let v = arg.strip_prefix("-Xmx")?;
    let (num, mul) = match v.chars().last()? {
        'k' | 'K' => (&v[..v.len() - 1], 1024),
        'm' | 'M' => (&v[..v.len() - 1], MIB),
        'g' | 'G' => (&v[..v.len() - 1], GIB),
        _ => (v, 1),
    };
    num.parse::<u64>().ok().and_then(|n| n.checked_mul(mul))
}

fn flag_value(flags: &str, name: &str) -> Option<u64> {
    flags
        .split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("-XX:{name}="))?.parse().ok())
}

fn gc_name(flags: &str) -> Option<String> {
    [
        ("UseG1GC", "G1"),
        ("UseZGC", "ZGC"),
        ("UseSerialGC", "Serial"),
        ("UseParallelGC", "Parallel"),
        ("UseShenandoahGC", "Shenandoah"),
    ]
    .iter()
    .find(|(f, _)| flags.contains(&format!("-XX:+{f}")))
    .map(|(_, n)| n.to_string())
}

/// "garbage-first heap total reserved 2097152K, committed 1133568K, used 777237K" -> used bytes.
fn heap_used(text: &str) -> Option<u64> {
    // "... used 777237K" / "... 1G used" -> bytes.
    fn used_on(line: &str) -> Option<u64> {
        let after = line.split("used ").nth(1)?;
        let tok: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let unit = after[tok.len()..].chars().next()?;
        let n: f64 = tok.parse().ok()?;
        let mul = match unit {
            'K' => 1024.0,
            'M' => MIB as f64,
            'G' => GIB as f64,
            _ => 1.0,
        };
        Some((n * mul) as u64)
    }
    // G1 reports the whole heap on one line; Parallel and Serial report one line per generation,
    // and the first of them is only the young generation, so the generations are added up.
    if let Some(l) = text
        .lines()
        .find(|l| l.trim_start().starts_with("garbage-first heap"))
    {
        return used_on(l);
    }
    let generations = [
        "PSYoungGen",
        "ParOldGen",
        "def new generation",
        "tenured generation",
    ];
    let parts: Vec<u64> = text
        .lines()
        .filter(|l| generations.iter().any(|g| l.contains(g)))
        .filter_map(used_on)
        .collect();
    if !parts.is_empty() {
        return Some(parts.iter().sum());
    }
    text.lines().find(|l| l.contains("used ")).and_then(used_on)
}

/// Best-effort name of the application a JVM process is running.
pub fn label_for(cmd: &[String], comm: &str) -> String {
    let joined = cmd.join(" ");
    if joined.contains("GradleDaemon") {
        return "Gradle daemon".into();
    }
    if joined.contains("KotlinCompileDaemon") {
        return "Kotlin compile daemon".into();
    }
    if joined.contains("plexus.classworlds") {
        return "Maven".into();
    }
    if let Some(i) = cmd.iter().position(|a| a == "-jar")
        && let Some(j) = cmd.get(i + 1)
    {
        return Path::new(j)
            .file_name()
            .map_or_else(|| j.clone(), |n| n.to_string_lossy().into_owned());
    }
    let mut it = cmd.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-cp" | "-classpath" | "--class-path" | "-p" | "--module-path" | "--add-modules"
            | "--add-opens" | "--add-exports" => {
                it.next();
            }
            "-m" | "--module" => return it.next().cloned().unwrap_or_default(),
            s if s.starts_with('-') || s.starts_with('@') => {}
            s => return s.rsplit('.').next().unwrap_or(s).to_string(),
        }
    }
    comm.to_string()
}

const IDES: &[(&str, &str)] = &[
    ("idea", "IntelliJIdea"),
    ("pycharm", "PyCharm"),
    ("clion", "CLion"),
    ("rustrover", "RustRover"),
    ("webstorm", "WebStorm"),
    ("goland", "GoLand"),
    ("datagrip", "DataGrip"),
    ("phpstorm", "PhpStorm"),
    ("rider", "Rider"),
    ("rubymine", "RubyMine"),
    ("dataspell", "DataSpell"),
];

fn find_ide(exe: &Path) -> Option<Ide> {
    let name = exe.file_name()?.to_string_lossy().into_owned();
    let (_, prefix) = IDES.iter().find(|(n, _)| *n == name)?;
    let root = util::home().join(".config/JetBrains");
    let mut dirs: Vec<String> = std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|d| {
            d.strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        .collect();
    dirs.sort_by(|a, b| natural_cmp(a, b));
    let vmoptions = root.join(dirs.last()?).join(format!("{name}64.vmoptions"));
    let xmx = std::fs::read_to_string(&vmoptions)
        .ok()
        .and_then(|t| t.lines().rev().find_map(|l| parse_xmx(l.trim())));
    Some(Ide { vmoptions, xmx })
}

/// New contents for a `.vmoptions` file with `-Xmx` set to `mb` megabytes.
pub fn with_xmx(text: &str, mb: u64) -> String {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("-Xmx"))
        .map(str::to_string)
        .collect();
    lines.push(format!("-Xmx{mb}m"));
    lines.join("\n") + "\n"
}

/// The file's text, "" when it doesn't exist yet, or None when it exists but can't be read as text
/// (so callers never rewrite a file they failed to read).
fn read_existing(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

/// Whether a Java `.properties` text already sets `key` (`key=v`, `key = v` or `key: v`).
fn has_property(text: &str, key: &str) -> bool {
    text.lines().map(str::trim_start).any(|l| {
        !l.starts_with(['#', '!'])
            && l.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(['=', ':']))
    })
}

/// Shell command (as argv) that writes `content` to `path` safely: symlinks are followed so the real
/// file is edited, the very first version is kept once as `.linuxward.bak` (a later edit never
/// overwrites that original), the write is aborted if the backup fails, and the new text replaces the
/// file atomically with the old file's permissions.
pub fn write_file_cmd(path: &Path, content: &str) -> Vec<String> {
    let script = r#"p=$(readlink -f -- "$1" 2>/dev/null || printf '%s' "$1")
mkdir -p -- "$(dirname -- "$p")" || exit 1
if [ -e "$p" ] && [ ! -e "$p.linuxward.bak" ]; then cp -p -- "$p" "$p.linuxward.bak" || { echo "could not back up $p; nothing changed" >&2; exit 1; }; fi
printf '%s' "$2" > "$p.linuxward.new" || exit 1
if [ -e "$p" ]; then chmod --reference="$p" -- "$p.linuxward.new" 2>/dev/null; fi
mv -f -- "$p.linuxward.new" "$p""#;
    vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "sh".into(),
        path.to_string_lossy().into_owned(),
        content.to_string(),
    ]
}

// ----- installed runtimes ---------------------------------------------------------------

fn candidate_homes() -> Vec<(PathBuf, bool)> {
    let home = util::home();
    let mut found: Vec<(PathBuf, bool)> = Vec::new();
    let mut children = |dir: PathBuf, keep: &dyn Fn(&str) -> bool| {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if keep(&e.file_name().to_string_lossy()) {
                    found.push((e.path(), false));
                }
            }
        }
    };
    children(PathBuf::from("/usr/lib/jvm"), &|_| true);
    children(PathBuf::from("/usr/java"), &|_| true);
    children(PathBuf::from("/opt"), &|n| {
        [
            "jdk", "java", "jre", "temurin", "graal", "zulu", "corretto", "openjdk",
        ]
        .iter()
        .any(|k| n.to_lowercase().contains(k))
    });
    children(home.join(".jdks"), &|_| true);
    children(home.join(".sdkman/candidates/java"), &|n| n != "current");
    if let Ok(rd) = std::fs::read_dir(home.join(".local/share/JetBrains/Toolbox/apps")) {
        for e in rd.flatten() {
            found.push((e.path().join("jbr"), true));
        }
    }
    if let Ok(h) = std::env::var("JAVA_HOME") {
        found.push((PathBuf::from(h), false));
    }
    if let Ok(java) =
        which_path("java").and_then(|p| std::fs::canonicalize(p).map_err(|e| e.to_string()))
        && let Some(h) = java.parent().and_then(Path::parent)
    {
        found.push((h.to_path_buf(), false));
    }
    let mut seen = HashSet::new();
    found
        .into_iter()
        .filter_map(|(p, b)| std::fs::canonicalize(&p).ok().map(|c| (c, b)))
        .filter(|(p, _)| p.join("bin/java").exists())
        .filter(|(p, _)| seen.insert(p.clone()))
        .collect()
}

fn which_path(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var("PATH").map_err(|e| e.to_string())?;
    path.split(':')
        .map(|d| Path::new(d).join(name))
        .find(|p| p.exists())
        .ok_or_else(|| format!("{name} not found"))
}

fn probe(home: &Path, bundled: bool, default_home: Option<&Path>, pm: Option<Pm>) -> Option<Jvm> {
    let java = home.join("bin/java");
    let out = run_timeout(
        &java.to_string_lossy(),
        &["-XshowSettings:properties", "-version"],
        15,
    );
    let (version, vendor) = parse_props(&out.combined());
    if version.is_empty() {
        return None;
    }
    let major = major_of(&version);
    let is_jdk = home.join("bin/javac").exists();
    let cds_missing = major >= 12
        && !home.join("lib/server/classes.jsa").exists()
        && !home.join("lib/server/classes_nocoops.jsa").exists();
    let packages = if bundled {
        vec![]
    } else {
        pm.map(|pm| owning_packages(pm, home)).unwrap_or_default()
    };
    Some(Jvm {
        home: home.to_path_buf(),
        version,
        major,
        vendor,
        is_jdk,
        is_default: default_home == Some(home),
        bundled,
        cds_missing,
        size: util::dir_usage(home),
        packages,
        running: false,
    })
}

fn owning_packages(pm: Pm, home: &Path) -> Vec<String> {
    let files: Vec<String> = ["bin/java", "bin/javac", "lib/modules", "lib/rt.jar"]
        .iter()
        .map(|f| home.join(f))
        .filter(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut names: Vec<String> = Vec::new();
    for f in &files {
        let n = match pm {
            Pm::Dnf | Pm::Zypper => {
                let o = run("rpm", &["-qf", "--qf", "%{NAME}\n", f]);
                if o.ok {
                    o.stdout.lines().next().unwrap_or("").to_string()
                } else {
                    String::new()
                }
            }
            Pm::Apt => run("dpkg", &["-S", f])
                .stdout
                .lines()
                .next()
                .and_then(|l| l.split(':').next())
                .unwrap_or("")
                .to_string(),
            Pm::Pacman => run("pacman", &["-Qo", "-q", f]).stdout.trim().to_string(),
        };
        if !n.is_empty() && crate::pkg::valid_name(&n) && !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

fn set_default_cmds(pm: Pm, j: &Jvm) -> Vec<Vec<String>> {
    let s = |v: &[&str]| {
        v.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
    };
    if pm == Pm::Pacman {
        let name = j
            .home
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        return vec![s(&["archlinux-java", "set", &name])];
    }
    let tool = if which("alternatives") {
        "alternatives"
    } else {
        "update-alternatives"
    };
    let mut v = vec![s(&[
        tool,
        "--set",
        "java",
        &j.home.join("bin/java").to_string_lossy(),
    ])];
    if j.is_jdk {
        v.push(s(&[
            tool,
            "--set",
            "javac",
            &j.home.join("bin/javac").to_string_lossy(),
        ]));
    }
    v
}

// ----- running JVMs ----------------------------------------------------------------------

struct Found {
    pid: u32,
    comm: String,
    cmd: Vec<String>,
    home: Option<PathBuf>,
}

fn find_jvm_processes() -> Vec<Found> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let dir = e.path();
            let raw = std::fs::read(dir.join("cmdline")).ok()?;
            if raw.is_empty() {
                return None; // kernel thread
            }
            let cmd: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            let comm = std::fs::read_to_string(dir.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            // A JVM has libjvm mapped, even when started by a native launcher (IDEs) so the process is not called "java".
            let maps = std::fs::read_to_string(dir.join("maps")).ok();
            let lib = maps.as_deref().and_then(|m| {
                m.lines()
                    .find(|l| l.ends_with("/libjvm.so"))
                    .and_then(|l| l.split_whitespace().last().map(str::to_string))
            });
            let home = lib
                .as_deref()
                // libjvm lives in <home>/lib[/<arch>]/server; /usr/lib/jvm/... paths hold an earlier "/lib/".
                .and_then(|p| p.rfind("/lib/").map(|i| PathBuf::from(&p[..i])));
            let is_jvm = lib.is_some() || (maps.is_none() && comm == "java");
            is_jvm.then_some(Found {
                pid,
                comm,
                cmd,
                home,
            })
        })
        .collect()
}

fn ticks(pid: u32) -> Option<u64> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?).map(|s| s.1)
}

fn status_kb(pid: u32, key: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix(key)
                    .and_then(|r| r.strip_prefix(':'))
                    .and_then(|r| {
                        r.split_whitespace()
                            .next()
                            .and_then(|n| n.parse::<u64>().ok())
                    })
            })
        })
        .unwrap_or(0)
}

fn analyse(
    found: Found,
    cpu: f32,
    jvms: &[Jvm],
    jcmd: Option<&str>,
    ram: u64,
    cpus: usize,
) -> JProc {
    let mine = std::fs::metadata(format!("/proc/{}", found.pid))
        // SAFETY: getuid has no preconditions.
        .is_ok_and(|m| m.uid() == unsafe { libc::getuid() });
    let exe = std::fs::read_link(format!("/proc/{}/exe", found.pid)).unwrap_or_default();
    let major = found
        .home
        .as_ref()
        .and_then(|h| jvms.iter().find(|j| &j.home == h))
        .map(|j| j.major);
    // jcmd attaches to a JVM running as the same user.
    let (mut flags, mut heap_used_b) = (String::new(), None);
    if mine && let Some(jcmd) = jcmd {
        let pid = found.pid.to_string();
        flags = run_timeout(jcmd, &[&pid, "VM.flags"], 6)
            .stdout
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        if !flags.is_empty() {
            heap_used_b = heap_used(&run_timeout(jcmd, &[&pid, "GC.heap_info"], 6).stdout);
        }
    }
    let mut p = JProc {
        pid: found.pid,
        label: label_for(&found.cmd, &found.comm),
        jvm_home: found.home,
        major,
        rss: status_kb(found.pid, "VmRSS") * 1024,
        cpu,
        threads: status_kb(found.pid, "Threads") as u32,
        mine,
        max_heap: flag_value(&flags, "MaxHeapSize"),
        heap_used: heap_used_b,
        gc: gc_name(&flags),
        ide: find_ide(&exe),
        advice: vec![],
        flags,
    };
    p.advice = advise(&p, ram, cpus);
    p
}

fn advise(p: &JProc, ram: u64, cpus: usize) -> Vec<String> {
    let mut v = Vec::new();
    if let (Some(used), Some(max)) = (p.heap_used, p.max_heap)
        && max > 0
        && used * 100 / max >= 80
    {
        v.push(format!("Heap is {}% full ({} of {}). The garbage collector will run constantly; give it a larger -Xmx.", used * 100 / max, human(used), human(max)));
    }
    if let Some(max) = p.max_heap {
        if ram > 0 && max * 10 > ram * 6 {
            v.push(format!(
                "Max heap ({}) is over 60% of RAM ({}); under load the system will swap.",
                human(max),
                human(ram)
            ));
        }
        if p.rss > max + max / 2 && p.rss > GIB {
            v.push(format!("Resident memory ({}) is far above the heap cap ({}): the rest is native memory (code cache, metaspace, thread stacks, direct buffers).", human(p.rss), human(max)));
        }
    } else if p.mine && p.flags.is_empty() {
        v.push("Live JVM flags unavailable (jcmd could not attach).".into());
    }
    if p.gc.as_deref() == Some("Serial") && cpus >= 4 && p.max_heap.unwrap_or(0) > GIB {
        v.push("Uses the single-threaded Serial GC on a multi-core machine with a large heap; G1 (`-XX:+UseG1GC`) pauses less.".into());
    }
    if let Some(m) = p.major
        && m < 17
    {
        v.push(format!(
            "Runs on Java {m}. Java 17+ has faster, lower-memory garbage collectors and start-up."
        ));
    }
    if p.cpu > 150.0 {
        v.push(format!(
            "Using {:.0}% CPU right now (more than one core).",
            p.cpu
        ));
    }
    v
}

// ----- the scan ----------------------------------------------------------------------------

fn meminfo_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("MemTotal:").and_then(|r| {
                    r.split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                })
            })
        })
        .unwrap_or(0)
        * 1024
}

fn round_to(v: u64, step: u64) -> u64 {
    (v / step).max(1) * step
}

fn flag_sets(ram: u64, cpus: usize, major: u32) -> Vec<(String, String)> {
    let ram_mb = ram / MIB;
    let low_mem = ram < 2 * GIB || cpus < 2;
    let gc = if low_mem {
        "-XX:+UseSerialGC"
    } else if major >= 21 && ram >= 16 * GIB && cpus >= 8 {
        "-XX:+UseZGC"
    } else {
        "-XX:+UseG1GC"
    };
    let desktop = round_to((ram_mb / 8).clamp(1024, 4096), 256);
    let server = round_to((ram_mb / 4).clamp(512, 16384), 256);
    vec![
        (
            "Desktop app / IDE".into(),
            format!("-Xmx{desktop}m {gc} -XX:+UseStringDeduplication"),
        ),
        (
            "Long-running server".into(),
            format!(
                "-Xms{server}m -Xmx{server}m {gc} -XX:+AlwaysPreTouch -XX:+HeapDumpOnOutOfMemoryError"
            ),
        ),
        (
            "Short-lived CLI tool (faster start)".into(),
            "-XX:TieredStopAtLevel=1 -XX:+UseSerialGC -Xshare:auto".into(),
        ),
    ]
}

pub fn scan(pm: Option<Pm>) -> JavaReport {
    let ram = meminfo_total();
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let default_home = which_path("java")
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .and_then(|p| p.parent().and_then(Path::parent).map(Path::to_path_buf));

    // Probing a JVM takes a moment each, so do them side by side.
    let homes = candidate_homes();
    let mut jvms: Vec<Jvm> = std::thread::scope(|s| {
        let hs: Vec<_> = homes
            .iter()
            .map(|(h, b)| s.spawn(|| probe(h, *b, default_home.as_deref(), pm)))
            .collect();
        hs.into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .collect()
    });

    // Running JVMs: measure CPU over a short window.
    let found = find_jvm_processes();
    let before: Vec<Option<u64>> = found.iter().map(|f| ticks(f.pid)).collect();
    std::thread::sleep(Duration::from_millis(500));
    // SAFETY: sysconf has no preconditions.
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK).max(1) } as f32;
    let cpu: Vec<f32> = found
        .iter()
        .zip(&before)
        .map(|(f, b)| match (ticks(f.pid), b) {
            (Some(a), Some(b)) => a.saturating_sub(*b) as f32 / tck / 0.5 * 100.0,
            _ => 0.0,
        })
        .collect();
    // JVMs found only through a running process (e.g. an IDE's bundled runtime) are listed as bundled.
    for f in &found {
        if let Some(h) = &f.home
            && !jvms.iter().any(|j| &j.home == h)
            && h.join("bin/java").exists()
            && let Some(j) = probe(h, true, default_home.as_deref(), pm)
        {
            jvms.push(j);
        }
    }
    let jcmd_default = jvms
        .iter()
        .find(|j| j.is_default && j.home.join("bin/jcmd").exists())
        .or_else(|| jvms.iter().find(|j| j.home.join("bin/jcmd").exists()))
        .map(|j| j.home.join("bin/jcmd").to_string_lossy().into_owned());
    let procs: Vec<JProc> = std::thread::scope(|s| {
        let hs: Vec<_> = found
            .into_iter()
            .zip(cpu)
            .map(|(f, c)| {
                let (jvms, ram) = (&jvms, ram);
                let own = f
                    .home
                    .as_ref()
                    .map(|h| h.join("bin/jcmd"))
                    .filter(|p| p.exists())
                    .map(|p| p.to_string_lossy().into_owned());
                let jcmd = own.or_else(|| jcmd_default.clone());
                s.spawn(move || analyse(f, c, jvms, jcmd.as_deref(), ram, cpus))
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    for j in &mut jvms {
        j.running = procs.iter().any(|p| p.jvm_home.as_ref() == Some(&j.home));
    }
    jvms.sort_by(|a, b| {
        b.bundled
            .cmp(&a.bundled)
            .reverse()
            .then(b.major.cmp(&a.major))
            .then_with(|| a.home.cmp(&b.home))
    });
    let mut procs = procs;
    procs.sort_by_key(|p| std::cmp::Reverse(p.rss));

    let (recs, findings) = build_recs(pm, &jvms, &procs, ram);
    let flag_major = jvms
        .iter()
        .find(|j| j.is_default)
        .or_else(|| jvms.iter().find(|j| !j.bundled))
        .map_or(LATEST_LTS, |j| j.major);
    JavaReport {
        flag_sets: flag_sets(ram, cpus, flag_major),
        jvms,
        procs,
        recs,
        findings,
        ram,
        cpus,
    }
}

fn build_recs(pm: Option<Pm>, jvms: &[Jvm], procs: &[JProc], ram: u64) -> (Vec<Rec>, Vec<String>) {
    let mut recs: Vec<Rec> = Vec::new();
    let mut findings: Vec<String> = Vec::new();
    let installed: Vec<&Jvm> = jvms.iter().filter(|j| !j.bundled).collect();
    if installed.is_empty() {
        findings.push("No system Java runtime found. Install one (for example `java-latest-openjdk` or `openjdk-21-jdk`) if you need to run Java programs.".into());
    }

    if let Some(pm) = pm {
        // 1. Missing class-data-sharing archive: every start-up pays for loading classes from scratch.
        // Only system runtimes: running a binary from ~/.jdks or ~/.sdkman as root would leave root-owned files there.
        for j in installed
            .iter()
            .filter(|j| j.cds_missing && !j.home.starts_with(util::home()))
        {
            let java = j.home.join("bin/java").to_string_lossy().into_owned();
            recs.push(Rec {
                tag: "Java",
                title: format!("Rebuild the start-up cache for Java {}", j.major),
                detail: format!("{} has no class-data-sharing archive, so every Java program starts slower and uses more memory. `java -Xshare:dump` regenerates it.", j.home.display()),
                safe: true,
                actions: vec![Action::Root(vec![vec![java, "-Xshare:dump".into()]])],
            });
        }
        // 2. Default runtime: prefer the newest LTS that is installed as a full JDK/JRE.
        if let Some(def) = installed.iter().find(|j| j.is_default)
            && let Some(best) = installed
                .iter()
                .filter(|j| {
                    LTS.contains(&j.major) && j.major > def.major && (j.is_jdk || !def.is_jdk)
                })
                .max_by_key(|j| j.major)
        {
            let cmds = set_default_cmds(pm, best);
            if !cmds.is_empty() {
                recs.push(Rec {
                    tag: "Java",
                    title: format!("Make Java {} the default runtime", best.major),
                    detail: format!(
                        "`java` currently runs Java {} ({}). Java {} ({}) is installed and has better garbage collection and start-up. Programs that insist on an older version can still be pointed at it with JAVA_HOME.",
                        def.major, def.vendor, best.major, best.vendor
                    ),
                    safe: false,
                    actions: vec![Action::Root(cmds)],
                });
            }
        }
        // 3. Old runtimes nothing is using.
        let newest_lts = installed
            .iter()
            .filter(|j| LTS.contains(&j.major))
            .map(|j| j.major)
            .max()
            .unwrap_or(0);
        let old: Vec<&&Jvm> = installed
            .iter()
            .filter(|j| {
                !j.is_default
                    && !j.running
                    && !installed.iter().any(|o| {
                        (o.is_default || o.running)
                            && (o.home.starts_with(&j.home) || j.home.starts_with(&o.home))
                    })
                    && !j.packages.is_empty()
                    && (j.major < 17 && newest_lts >= 17)
            })
            .collect();
        let pkgs: Vec<String> = old
            .iter()
            .flat_map(|j| j.packages.iter().cloned())
            .collect();
        if !pkgs.is_empty() {
            let size: u64 = old.iter().map(|j| j.size).sum();
            recs.push(Rec {
                tag: "Java",
                title: format!("Remove {} unused old Java runtime(s)", old.len()),
                detail: format!(
                    "{} · frees about {}. Old runtimes no longer get security updates.",
                    old.iter()
                        .map(|j| format!("Java {}", j.major))
                        .collect::<Vec<_>>()
                        .join(", "),
                    human(size)
                ),
                safe: false,
                actions: vec![Action::Root(pm.remove_cmds(&pkgs))],
            });
        }
    }

    // 4. Idle build daemons hold gigabytes of RAM for nothing.
    let idle: Vec<&JProc> = procs
        .iter()
        .filter(|p| {
            p.mine
                && p.cpu < 2.0
                && matches!(p.label.as_str(), "Gradle daemon" | "Kotlin compile daemon")
        })
        .collect();
    if !idle.is_empty() {
        let mem: u64 = idle.iter().map(|p| p.rss).sum();
        let mut cmd = vec!["kill".to_string(), "-TERM".to_string()];
        cmd.extend(idle.iter().map(|p| p.pid.to_string()));
        recs.push(Rec {
            tag: "Java",
            title: format!("Stop {} idle build daemon(s)", idle.len()),
            detail: format!("{} are using {} of RAM and looked idle in a brief sample. They start again automatically on the next build, but stopping one that is mid-build would abort that build.", idle.iter().map(|p| p.label.as_str()).collect::<Vec<_>>().join(", "), human(mem)),
            safe: false,
            actions: vec![Action::User(vec![cmd])],
        });
    }

    // 5. IDE heap: only when the heap is actually under pressure.
    for p in procs.iter().filter(|p| p.mine) {
        let (Some(ide), Some(used), Some(max)) = (&p.ide, p.heap_used, p.max_heap) else {
            continue;
        };
        if used * 100 / max.max(1) >= 75 {
            let cur_mb = max / MIB;
            let target = round_to((cur_mb * 2).min(ram / MIB / 4).max(cur_mb + 512), 256);
            let Some(text) = read_existing(&ide.vmoptions) else {
                continue;
            };
            recs.push(Rec {
                tag: "Java",
                title: format!("Raise {} heap from {cur_mb} MB to {target} MB", p.label),
                detail: format!("Its heap is {}% full, which makes it freeze while garbage collecting. Edits {} (a backup is kept). Restart the IDE to apply.", used * 100 / max.max(1), ide.vmoptions.display()),
                safe: true,
                actions: vec![Action::User(vec![write_file_cmd(&ide.vmoptions, &with_xmx(&text, target))])],
            });
        }
    }

    // 6. Gradle defaults.
    let gradle = util::home().join(".gradle");
    let props = gradle.join("gradle.properties");
    // A file that exists but can't be read as text is left alone rather than treated as empty.
    if gradle.is_dir()
        && let Some(text) = read_existing(&props)
    {
        let missing: Vec<String> = [
            ("org.gradle.daemon.idletimeout", "600000"),
            ("org.gradle.parallel", "true"),
            ("org.gradle.caching", "true"),
        ]
        .iter()
        .filter(|(k, _)| !has_property(&text, k))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
        if !missing.is_empty() {
            let mut new = text.clone();
            if !new.is_empty() && !new.ends_with('\n') {
                new.push('\n');
            }
            new.push_str(&missing.join("\n"));
            new.push('\n');
            recs.push(Rec {
                tag: "Java",
                title: "Tune Gradle: stop idle daemons after 10 min, enable parallel builds and the build cache".into(),
                detail: format!("Adds {} to {}. Gradle's default keeps each daemon (and its RAM) for 3 hours.", missing.join(", "), props.display()),
                safe: false,
                actions: vec![Action::User(vec![write_file_cmd(&props, &new)])],
            });
        }
    }

    // Machine-level findings.
    let heaps: u64 = procs.iter().filter_map(|p| p.max_heap).sum();
    if ram > 0 && heaps * 10 > ram * 7 {
        findings.push(format!("The running JVMs are allowed to grow their heaps to {} in total, which is over 70% of your {} of RAM. If they all fill up at once the machine will swap and crawl.", human(heaps), human(ram)));
    }
    let rss: u64 = procs.iter().map(|p| p.rss).sum();
    if ram > 0 && rss * 10 > ram * 4 {
        findings.push(format!(
            "Java processes currently use {} ({}% of RAM).",
            human(rss),
            rss * 100 / ram
        ));
    }
    if let Ok(jh) = std::env::var("JAVA_HOME")
        && !jh.is_empty()
        && !Path::new(&jh).join("bin/java").exists()
    {
        findings.push(format!("JAVA_HOME points to {jh}, which has no Java in it. Tools that honour JAVA_HOME (Maven, Gradle, IDEs) will fail or fall back."));
    }
    if let Ok(rd) = std::fs::read_dir("/usr/lib/jvm") {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && !p.is_symlink() && !p.join("bin/java").exists() {
                findings.push(format!(
                    "{} is a leftover folder from a removed JDK (no Java inside). Safe to delete.",
                    p.display()
                ));
            }
        }
    }
    (recs, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(major_of("25.0.4.1"), 25);
        assert_eq!(major_of("21.0.6"), 21);
        assert_eq!(major_of("1.8.0_392"), 8);
        assert_eq!(major_of("11"), 11);
        assert_eq!(
            parse_props("    java.version = 21.0.6\n    java.vendor = Oracle Corporation\n"),
            ("21.0.6".into(), "Oracle Corporation".into())
        );
    }

    #[test]
    fn heap_used_adds_up_generations_for_parallel_and_serial() {
        let g1 = "garbage-first heap   total reserved 2097152K, committed 1133568K, used 777237K [0x1, 0x2)";
        assert_eq!(heap_used(g1), Some(777_237 * 1024));
        let parallel = " PSYoungGen      total 76288K, used 10000K [0x1, 0x2)\n ParOldGen       total 175104K, used 20000K [0x3, 0x4)\n";
        assert_eq!(heap_used(parallel), Some(30000 * 1024));
        let serial = " def new generation   total 9216K, used 1000K [0x1)\n tenured generation   total 20480K, used 2000K [0x2)\n";
        assert_eq!(heap_used(serial), Some(3000 * 1024));
    }

    #[test]
    fn heap_numbers() {
        assert_eq!(parse_xmx("-Xmx2048m"), Some(2048 * MIB));
        assert_eq!(parse_xmx("-Xmx4g"), Some(4 * GIB));
        assert_eq!(parse_xmx("-Xms1g"), None);
        let h = "garbage-first heap   total reserved 2097152K, committed 1133568K, used 777237K [0x1, 0x2)\n region size 1024K";
        assert_eq!(heap_used(h), Some(777_237 * 1024));
        let f = "-XX:InitialHeapSize=134217728 -XX:MaxHeapSize=2147483648 -XX:+UseG1GC";
        assert_eq!(flag_value(f, "MaxHeapSize"), Some(2 * GIB));
        assert_eq!(gc_name(f).as_deref(), Some("G1"));
    }

    #[test]
    fn labels() {
        let c = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            label_for(&c("java -Xmx1g -jar /opt/app/server.jar --port 80"), "java"),
            "server.jar"
        );
        assert_eq!(
            label_for(&c("java -cp a:b com.example.Main arg"), "java"),
            "Main"
        );
        assert_eq!(
            label_for(
                &c("java -XX:+Foo org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.5"),
                "java"
            ),
            "Gradle daemon"
        );
        assert_eq!(label_for(&c("/x/bin/rustrover"), "rustrover"), "rustrover");
    }

    #[test]
    fn vmoptions_edit() {
        let new = with_xmx("-Dfoo=1\n-Xmx2048m\n-Dbar=2", 4096);
        assert_eq!(new, "-Dfoo=1\n-Dbar=2\n-Xmx4096m\n");
    }

    #[test]
    fn write_cmd_roundtrip() {
        let dir = std::env::temp_dir().join(format!("linuxward-java-{}", std::process::id()));
        let file = dir.join("sub/x.vmoptions");
        let cmd = write_file_cmd(&file, "line one\n-Xmx1g with 'quotes'\n");
        let args: Vec<&str> = cmd[1..].iter().map(String::as_str).collect();
        assert!(run(&cmd[0], &args).ok);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "line one\n-Xmx1g with 'quotes'\n"
        );
        // Writing again keeps a backup of the previous version.
        let cmd = write_file_cmd(&file, "new\n");
        let args: Vec<&str> = cmd[1..].iter().map(String::as_str).collect();
        assert!(run(&cmd[0], &args).ok);
        assert_eq!(
            std::fs::read_to_string(dir.join("sub/x.vmoptions.linuxward.bak")).unwrap(),
            "line one\n-Xmx1g with 'quotes'\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flag_advice() {
        let s = flag_sets(16 * GIB, 8, 25);
        assert!(s[1].1.contains("-Xmx4096m") && s[1].1.contains("UseZGC"));
        assert!(flag_sets(GIB, 1, 21)[0].1.contains("UseSerialGC"));
    }
}

#[cfg(test)]
mod live_java_tests {
    use super::*;

    #[test]
    #[ignore = "queries the live system; run with --ignored"]
    fn live_java_print() {
        let r = scan(Pm::detect());
        println!("RAM {} CPUs {}", human(r.ram), r.cpus);
        for j in &r.jvms {
            println!(
                "JVM {} v{} ({}) jdk={} default={} bundled={} running={} cds_missing={} size={} pkgs={:?} support={:?}",
                j.home.display(),
                j.version,
                j.vendor,
                j.is_jdk,
                j.is_default,
                j.bundled,
                j.running,
                j.cds_missing,
                human(j.size),
                j.packages,
                support(j.major)
            );
        }
        for p in &r.procs {
            println!(
                "PROC {} {} rss={} cpu={:.0}% maxheap={:?} used={:?} gc={:?} ide={:?} advice={:?}",
                p.pid,
                p.label,
                human(p.rss),
                p.cpu,
                p.max_heap.map(human),
                p.heap_used.map(human),
                p.gc,
                p.ide.as_ref().map(|i| (&i.vmoptions, i.xmx)),
                p.advice
            );
        }
        for x in &r.recs {
            println!(
                "REC [{}] safe={} {}\n    {}",
                x.tag, x.safe, x.title, x.detail
            );
        }
        for f in &r.findings {
            println!("FINDING {f}");
        }
        for (n, f) in &r.flag_sets {
            println!("FLAGS {n}: {f}");
        }
    }
}

//! Disk and filesystem health: SMART status, filesystem consistency, `/etc/fstab` problems and
//! kernel-log I/O errors. Every finding that has a software remedy carries a `Repair`; findings
//! that only hardware can fix (a failing drive, a bad cable) say so instead of pretending.
//!
//! Scanning is read-only. One administrator prompt covers every privileged query; repairs are
//! only built here, and run later through the confirmation dialog.

use std::collections::HashMap;
use std::path::Path;

use crate::targets::Action;
use crate::util;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Sev {
    Ok,
    Info,
    Warn,
    Bad,
}

#[derive(Clone, Debug)]
pub struct Repair {
    pub label: String,
    /// What will happen, in plain words, shown in the confirmation dialog.
    pub note: String,
    pub actions: Vec<Action>,
    /// Can change or lose data: the dialog says so.
    pub risky: bool,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub sev: Sev,
    pub text: String,
    pub advice: Option<String>,
    pub repairs: Vec<Repair>,
}

impl Finding {
    fn new(sev: Sev, text: impl Into<String>) -> Self {
        Self {
            sev,
            text: text.into(),
            advice: None,
            repairs: vec![],
        }
    }
    fn advice(mut self, a: impl Into<String>) -> Self {
        self.advice = Some(a.into());
        self
    }
    fn repair(mut self, r: Repair) -> Self {
        self.repairs.push(r);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Item {
    pub title: String,
    pub subtitle: String,
    pub findings: Vec<Finding>,
    /// The tool's own output, for people who want the details.
    pub raw: String,
}

impl Item {
    pub fn worst(&self) -> Sev {
        self.findings.iter().map(|f| f.sev).max().unwrap_or(Sev::Ok)
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub drives: Vec<Item>,
    pub filesystems: Vec<Item>,
    pub mounts: Item,
    pub kernel: Item,
    /// Things the user should know, e.g. the password prompt was refused.
    pub notes: Vec<String>,
}

fn v(args: &[&str]) -> Vec<String> {
    args.iter().map(std::string::ToString::to_string).collect()
}

fn root_repair(
    label: &str,
    note: impl Into<String>,
    cmds: Vec<Vec<String>>,
    risky: bool,
) -> Repair {
    Repair {
        label: label.into(),
        note: note.into(),
        actions: vec![Action::Root(cmds)],
        risky,
    }
}

/// Tools in sbin are not on an ordinary user's PATH on every distro, but root finds them.
fn have(name: &str) -> bool {
    util::which(name)
        || ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"]
            .iter()
            .any(|d| Path::new(d).join(name).is_file())
}

// ---------------------------------------------------------------------------------------------
// lsblk, fstab and mount tables
// ---------------------------------------------------------------------------------------------

fn unescape_hex(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && b.get(i + 1) == Some(&b'x')
            && let Some(h) = s.get(i + 2..i + 4)
            && let Ok(n) = u8::from_str_radix(h, 16)
        {
            out.push(n);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `/proc/mounts` and fstab write a space as `\040`.
fn unescape_octal(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

fn parse_pairs(line: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut rest = line.trim();
    while let Some(eq) = rest.find("=\"") {
        let key = rest[..eq].trim().to_string();
        let after = &rest[eq + 2..];
        let Some(end) = after.find('"') else { break };
        m.insert(key, unescape_hex(&after[..end]));
        rest = after[end + 1..].trim_start();
    }
    m
}

fn lsblk() -> Vec<HashMap<String, String>> {
    let out = util::run(
        "lsblk",
        &[
            "-P",
            "-o",
            "PATH,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,SIZE,MODEL,ROTA,TRAN",
        ],
    );
    if !out.ok {
        return vec![];
    }
    out.stdout.lines().map(parse_pairs).collect()
}

#[derive(Clone, Debug)]
struct Drive {
    dev: String,
    model: String,
    size: String,
    kind: &'static str,
    tran: String,
}

fn drives_from(rows: &[HashMap<String, String>]) -> Vec<Drive> {
    let get = |r: &HashMap<String, String>, k: &str| r.get(k).cloned().unwrap_or_default();
    rows.iter()
        .filter(|r| get(r, "TYPE") == "disk")
        .filter(|r| {
            let p = get(r, "PATH");
            !["/dev/zram", "/dev/ram", "/dev/nbd"]
                .iter()
                .any(|x| p.starts_with(x))
        })
        .map(|r| {
            let dev = get(r, "PATH");
            let tran = get(r, "TRAN");
            let kind = if dev.contains("nvme") {
                "NVMe SSD"
            } else if get(r, "ROTA") == "0" {
                "SSD"
            } else {
                "hard disk"
            };
            Drive {
                model: get(r, "MODEL").trim().to_string(),
                size: get(r, "SIZE"),
                dev,
                kind,
                tran,
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
struct Fs {
    dev: String,
    fstype: String,
    label: String,
    size: String,
    mountpoint: Option<String>,
}

const CHECKABLE: [&str; 6] = ["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat"];

fn filesystems_from(rows: &[HashMap<String, String>]) -> Vec<Fs> {
    let get = |r: &HashMap<String, String>, k: &str| r.get(k).cloned().unwrap_or_default();
    let mut out: Vec<Fs> = vec![];
    let mut uuids: Vec<String> = vec![];
    for r in rows {
        let fstype = get(r, "FSTYPE");
        if !CHECKABLE.contains(&fstype.as_str()) {
            continue;
        }
        let mp = get(r, "MOUNTPOINT");
        let mountpoint = (!mp.is_empty() && !mp.starts_with('[')).then_some(mp);
        let fs = Fs {
            dev: get(r, "PATH"),
            fstype,
            label: get(r, "LABEL"),
            size: get(r, "SIZE"),
            mountpoint,
        };
        // One btrfs filesystem can span several devices, all with the same UUID.
        let uuid = get(r, "UUID");
        if !uuid.is_empty()
            && let Some(i) = uuids.iter().position(|u| *u == uuid)
        {
            if out[i].mountpoint.is_none() && fs.mountpoint.is_some() {
                out[i] = fs;
            }
            continue;
        }
        uuids.push(uuid);
        out.push(fs);
    }
    out
}

/// mountpoint -> option list, from a `/proc/mounts` or fstab style table.
fn mount_table(text: &str, opts_col: usize) -> HashMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > opts_col).then(|| (unescape_octal(f[1]), f[opts_col].to_string()))
        })
        .collect()
}

fn has_opt(opts: &str, o: &str) -> bool {
    opts.split(',').any(|x| x == o)
}

/// Mount points the running system depends on: never unmounted for a repair.
fn is_system_mount(mp: &str) -> bool {
    [
        "/", "/usr", "/var", "/etc", "/opt", "/bin", "/sbin", "/lib", "/lib64", "/nix",
    ]
    .contains(&mp)
}

struct Ctx {
    fstab: HashMap<String, String>,
    mounts: HashMap<String, String>,
    drive_bad: bool,
    grubby: bool,
}

// ---------------------------------------------------------------------------------------------
// Running filesystem tools on a device that may be mounted
// ---------------------------------------------------------------------------------------------

fn join_cmd(cmd: &[String]) -> String {
    cmd.iter()
        .map(|a| util::sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wrap `cmd` so it runs against an unmounted device. Unmounted: as is. Mounted: unmount first
/// (aborting if something uses it), run, then mount it again only if the tool succeeded
/// (`remount_codes` is a `case` pattern of acceptable exit codes, or `None` for always).
/// `None` for mount points the system itself needs.
fn on_unmounted(
    fs: &Fs,
    ctx: &Ctx,
    cmd: Vec<String>,
    remount_codes: Option<&str>,
) -> Option<(Vec<Vec<String>>, String)> {
    let Some(mp) = &fs.mountpoint else {
        return Some((
            vec![cmd],
            format!("{} is not mounted, so it is checked directly.", fs.dev),
        ));
    };
    if is_system_mount(mp) {
        return None;
    }
    let q = util::sh_quote(mp);
    let remount = if ctx.fstab.contains_key(mp) {
        format!("mount {q}")
    } else {
        format!(
            "echo {}",
            util::sh_quote(&format!(
                "{mp} is not in /etc/fstab: mount it again from your file manager"
            ))
        )
    };
    let after = match remount_codes {
        Some(p) => format!(
            "case $rc in {p}) {remount};; *) echo {};; esac",
            util::sh_quote(&format!(
                "Not remounting {mp}: the tool did not finish cleanly"
            ))
        ),
        None => remount,
    };
    let script = format!(
        "umount {q} || {{ echo {}; exit 1; }}; {}; rc=$?; {after}; exit $rc",
        util::sh_quote(&format!(
            "Could not unmount {mp}: something is using it. Close those programs and try again."
        )),
        join_cmd(&cmd),
    );
    Some((
        vec![v(&["sh", "-c", &script])],
        format!("{mp} is unmounted for the duration, then mounted again."),
    ))
}

fn drive_warning(ctx: &Ctx) -> &'static str {
    if ctx.drive_bad {
        "\n⚠ A drive in this computer reports SMART problems. Back up your data first: repairing a failing disk can make things worse."
    } else {
        ""
    }
}

// ---------------------------------------------------------------------------------------------
// SMART
// ---------------------------------------------------------------------------------------------

fn kv(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.trim_start()
            .strip_prefix(key)
            .map(|r| r.trim().to_string())
    })
}

fn leading_num(s: &str) -> u64 {
    s.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn self_test_repairs(dev: &str) -> Finding {
    Finding::new(Sev::Info, "Drive self-tests can refresh these results.")
        .advice("The test runs inside the drive in the background; scan again when it has finished (a long test takes from minutes to hours).")
        .repair(root_repair(
            "Run a short self-test",
            "Starts the drive's built-in short test (about 2 minutes). Harmless; the drive stays usable.",
            vec![v(&["smartctl", "-t", "short", dev])],
            false,
        ))
        .repair(root_repair(
            "Run a long self-test",
            "Starts the drive's built-in full-surface read test (minutes to hours). Harmless; the drive stays usable but may be slower.",
            vec![v(&["smartctl", "-t", "long", dev])],
            false,
        ))
}

fn analyze_smart(dev: &str, text: &str) -> Vec<Finding> {
    let low = text.to_lowercase();
    if text.trim().is_empty() || low.contains("command not found") {
        return vec![Finding::new(
            Sev::Info,
            "SMART could not be read (smartctl produced no output).",
        )];
    }
    if low.contains("permission denied") {
        return vec![Finding::new(
            Sev::Info,
            "SMART could not be read: permission denied.",
        )];
    }
    if low.contains("unable to detect device type")
        || low.contains("smart support is: unavailable")
        || low.contains("lacks smart")
        || low.contains("does not support smart")
    {
        return vec![
            Finding::new(Sev::Info, "This device does not report SMART data.")
                .advice("Virtual disks and some USB enclosures don't. Nothing to repair."),
        ];
    }
    if text.contains("NVMe") && low.contains("percentage used") {
        return analyze_nvme(text);
    }

    let mut f: Vec<Finding> = vec![];
    if low.contains("smart support is: disabled") {
        f.push(
            Finding::new(Sev::Warn, "SMART monitoring is switched off on this drive.").repair(
                root_repair(
                    "Switch SMART on",
                    "Runs `smartctl -s on`. Safe; the drive starts recording health data.",
                    vec![v(&["smartctl", "-s", "on", dev])],
                    false,
                ),
            ),
        );
    }

    let mut judged = false;
    if let Some(r) = kv(text, "SMART overall-health self-assessment test result:")
        .or_else(|| kv(text, "SMART Health Status:"))
    {
        judged = true;
        if r.to_uppercase().contains("PASSED") || r.trim() == "OK" {
            f.push(Finding::new(
                Sev::Ok,
                "The drive's own health verdict: passed.",
            ));
        } else {
            f.push(
                Finding::new(Sev::Bad, format!("The drive reports that it is failing ({r})."))
                    .advice("Back up everything now and plan to replace the drive. No software repair exists for a drive that predicts its own failure."),
            );
        }
    }

    for l in text.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.len() < 10 {
            continue;
        }
        let Ok(id) = t[0].parse::<u32>() else {
            continue;
        };
        let name = t[1];
        let value: u32 = t[3].parse().unwrap_or(100);
        let raw = leading_num(t[9]);
        let lname = name.to_lowercase();
        match id {
            5 if raw > 0 => f.push(
                Finding::new(
                    if raw >= 100 { Sev::Bad } else { Sev::Warn },
                    format!("{raw} sector(s) have been reallocated: the surface has started to wear out."),
                )
                .advice("A few are common on old drives; a count that keeps rising means the drive is dying. Back up and watch it."),
            ),
            197 | 198 if raw > 0 => f.push(
                Finding::new(
                    Sev::Bad,
                    format!("{raw} sector(s) can't be read reliably ({name})."),
                )
                .advice("Back up now. The drive only remaps such sectors when they are rewritten; a long self-test shows whether the number grows."),
            ),
            187 if raw > 0 => f.push(Finding::new(Sev::Warn, format!("{raw} read error(s) the drive could not correct."))),
            199 if raw > 0 => f.push(
                Finding::new(Sev::Warn, format!("{raw} data-cable (CRC) error(s) were recorded."))
                    .advice("Usually a loose or damaged SATA cable or port, not the drive. Reseat or replace the cable. The counter never resets, so only worry if it keeps rising."),
            ),
            190 | 194 if raw >= 60 => f.push(
                Finding::new(
                    if raw >= 70 { Sev::Bad } else { Sev::Warn },
                    format!("The drive is hot: {raw} °C."),
                )
                .advice("Check airflow and fans; sustained heat shortens drive life."),
            ),
            _ if (lname.contains("wear") || lname.contains("life_left") || lname.contains("lifetime")) && value <= 10 => {
                f.push(
                    Finding::new(
                        if value <= 3 { Sev::Bad } else { Sev::Warn },
                        format!("The SSD has used almost all of its rated life ({name}: {value} left)."),
                    )
                    .advice("Plan to replace it; keep backups current."),
                );
            }
            _ => {}
        }
        let when_failed = t[8];
        if when_failed != "-"
            && !when_failed.is_empty()
            && when_failed.chars().next().is_some_and(char::is_alphabetic)
        {
            let now = when_failed.to_uppercase().contains("NOW");
            f.push(Finding::new(
                if now { Sev::Bad } else { Sev::Warn },
                format!("Attribute {name} crossed its failure threshold ({when_failed})."),
            ));
        }
    }

    if low.contains("no self-tests have been logged") {
        f.push(Finding::new(
            Sev::Info,
            "No self-test has ever been run on this drive.",
        ));
    } else if let Some(l) = text.lines().find(|l| l.trim_start().starts_with("# 1")) {
        let status = l
            .trim_start()
            .trim_start_matches("# 1")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if status.contains("Completed without error") {
            f.push(Finding::new(Sev::Ok, "The most recent self-test passed."));
        } else if status.contains("in progress") {
            f.push(Finding::new(
                Sev::Info,
                "A self-test is running: scan again when it has finished.",
            ));
        } else if status.contains("Aborted") || status.contains("Interrupted") {
            f.push(Finding::new(
                Sev::Info,
                "The most recent self-test was interrupted.",
            ));
        } else {
            f.push(
                Finding::new(
                    Sev::Bad,
                    format!("The most recent self-test failed: {status}"),
                )
                .advice("The drive could not read part of its surface. Back up and replace it."),
            );
        }
    }

    if let Some(n) = kv(text, "ATA Error Count:") {
        let n = leading_num(&n);
        if n > 0 {
            f.push(
                Finding::new(Sev::Warn, format!("The drive has logged {n} command error(s)."))
                    .advice("Often a bad cable, a power problem or a controller reset rather than the platters. Reseat the cables; it only matters if the count keeps growing."),
            );
        }
    }

    if !judged && f.is_empty() {
        f.push(Finding::new(
            Sev::Info,
            "SMART data was read but gave no health verdict.",
        ));
    }
    if f.iter().all(|x| x.sev <= Sev::Info) && judged {
        f.push(Finding::new(
            Sev::Ok,
            "No warning signs in the SMART attributes.",
        ));
    }
    f.push(self_test_repairs(dev));
    f
}

fn analyze_nvme(text: &str) -> Vec<Finding> {
    let mut f = vec![];
    let num = |k: &str| kv(text, k).map(|s| leading_num(&s));
    match kv(text, "Critical Warning:") {
        Some(w)
            if w.trim_start_matches("0x")
                .trim_start_matches('0')
                .is_empty() =>
        {
            f.push(Finding::new(Sev::Ok, "No critical warnings."));
        }
        Some(w) => f.push(
            Finding::new(
                Sev::Bad,
                format!("The drive raised a critical warning ({w})."),
            )
            .advice("Spare capacity, temperature, reliability or read-only mode: back up now."),
        ),
        None => {}
    }
    if let Some(used) = num("Percentage Used:") {
        if used >= 100 {
            f.push(
                Finding::new(Sev::Bad, "The SSD has passed its rated endurance.")
                    .advice("Replace it soon."),
            );
        } else if used >= 90 {
            f.push(Finding::new(
                Sev::Warn,
                format!("The SSD has used {used}% of its rated endurance."),
            ));
        }
    }
    if let (Some(spare), Some(th)) = (num("Available Spare:"), num("Available Spare Threshold:"))
        && spare < th
    {
        f.push(
            Finding::new(
                Sev::Bad,
                format!("Spare capacity ({spare}%) is below the drive's threshold ({th}%)."),
            )
            .advice("Back up and replace the drive."),
        );
    }
    if let Some(n) = num("Media and Data Integrity Errors:")
        && n > 0
    {
        f.push(
            Finding::new(Sev::Bad, format!("{n} media or data-integrity error(s) were recorded."))
                .advice("The controller found data it could not store or read correctly. Back up and replace the drive."),
        );
    }
    if let Some(t) = num("Temperature:")
        && t >= 70
    {
        f.push(
            Finding::new(Sev::Warn, format!("The drive is hot: {t} °C."))
                .advice("Check airflow, or add a heatsink."),
        );
    }
    if f.iter().all(|x| x.sev <= Sev::Ok) {
        f.push(Finding::new(
            Sev::Ok,
            "No warning signs in the NVMe health log.",
        ));
    }
    f
}

// ---------------------------------------------------------------------------------------------
// Filesystems
// ---------------------------------------------------------------------------------------------

fn boot_check_repairs(ctx: &Ctx) -> Vec<Repair> {
    if !ctx.grubby {
        return vec![];
    }
    vec![
        root_repair(
            "Check at the next boot",
            "Adds `fsck.mode=force fsck.repair=yes` to every kernel's command line, so the next boot checks and repairs this filesystem before mounting it. Reboot to start it. Afterwards, use \"Stop forcing a check\" so later boots are not slowed down.",
            vec![v(&[
                "grubby",
                "--update-kernel=ALL",
                "--args=fsck.mode=force fsck.repair=yes",
            ])],
            false,
        ),
        root_repair(
            "Stop forcing a check",
            "Removes `fsck.mode=force fsck.repair=yes` from every kernel's command line again.",
            vec![v(&[
                "grubby",
                "--update-kernel=ALL",
                "--remove-args=fsck.mode=force fsck.repair=yes",
            ])],
            false,
        ),
    ]
}

const SYSTEM_FS_ADVICE: &str = "This filesystem is in use by the running system and can't be unmounted. To repair it, boot a live USB (or the distro's rescue mode) and run the check from there.";

fn analyze_ext(fs: &Fs, ctx: &Ctx, out: Option<&(String, Option<i32>)>) -> Vec<Finding> {
    let mut f = vec![];
    let text = out.map_or("", |o| o.0.as_str());
    let mounted = fs.mountpoint.is_some();
    let journaled = kv(text, "Filesystem features:").is_some_and(|x| x.contains("has_journal"));
    let state = kv(text, "Filesystem state:").unwrap_or_default();
    let errors = kv(text, "FS Error count:").map_or(0, |s| leading_num(&s));
    let mut dirty = false;
    if text.trim().is_empty() {
        f.push(Finding::new(
            Sev::Info,
            "The superblock could not be read (administrator access or tune2fs is missing).",
        ));
    } else if errors > 0 {
        dirty = true;
        f.push(
            Finding::new(
                Sev::Bad,
                format!("The kernel has recorded {errors} filesystem error(s)."),
            )
            .advice("Run a check. The record is cleared once a repair completes."),
        );
    } else if state.contains("with errors")
        || (state.contains("not clean") && (journaled || !mounted))
    {
        dirty = true;
        f.push(
            Finding::new(Sev::Bad, format!("The filesystem is marked \"{state}\"."))
                .advice("It was not unmounted cleanly or has detected damage. Run a check."),
        );
    } else if state.contains("not clean") {
        // A mounted ext2 (no journal) is always flagged this way while in use.
        f.push(Finding::new(
            Sev::Info,
            "Marked \"not clean\", which is normal while a journal-less filesystem is mounted.",
        ));
    } else if !state.is_empty() {
        let last = kv(text, "Last checked:").unwrap_or_default();
        f.push(Finding::new(
            Sev::Ok,
            format!("Marked clean (last full check: {last})."),
        ));
    }

    let dev = fs.dev.as_str();
    let warn = drive_warning(ctx);
    let mut check = Finding::new(
        Sev::Info,
        if dirty {
            "Repair options"
        } else {
            "Full check"
        },
    );
    let mut any = false;
    if let Some((cmds, steps)) = on_unmounted(fs, ctx, v(&["e2fsck", "-fn", dev]), None) {
        check = check.repair(root_repair("Check only (read-only)", format!("Runs `e2fsck -fn`: reports problems and changes nothing. {steps} The result appears in the Activity log."), cmds, false));
        any = true;
    }
    if let Some((cmds, steps)) = on_unmounted(fs, ctx, v(&["e2fsck", "-fy", dev]), Some("0|1|2")) {
        check = check.repair(root_repair("Repair (e2fsck -fy)", format!("Runs `e2fsck -fy`: fixes every problem it finds, answering yes to each question. Damaged files may end up in lost+found. {steps}{warn}"), cmds, true));
        any = true;
    }
    if !any {
        for r in boot_check_repairs(ctx) {
            check = check.repair(r);
            any = true;
        }
        if any {
            check = check.advice("This filesystem is in use. It can be checked while the system is off: schedule it for the next boot, or use a live USB.");
        } else {
            check = check.advice(SYSTEM_FS_ADVICE);
        }
    }
    f.push(check);
    f
}

fn analyze_xfs(fs: &Fs, ctx: &Ctx) -> Vec<Finding> {
    let dev = fs.dev.as_str();
    let warn = drive_warning(ctx);
    let mut f = Finding::new(
        Sev::Info,
        "XFS keeps no error history to read: run a check to find out.",
    );
    let mut any = false;
    if let Some(mp) = &fs.mountpoint
        && have("xfs_scrub")
    {
        f = f
            .repair(root_repair("Online check (read-only)", format!("Runs `xfs_scrub -n {mp}`: checks the mounted filesystem and changes nothing. Can take a while on a large disk."), vec![v(&["xfs_scrub", "-n", mp])], false))
            .repair(root_repair("Online repair", format!("Runs `xfs_scrub {mp}`: repairs what it can while the filesystem stays mounted. Needs a recent kernel with online repair support.{warn}"), vec![v(&["xfs_scrub", mp])], true));
        any = true;
    }
    if let Some((cmds, steps)) = on_unmounted(fs, ctx, v(&["xfs_repair", "-n", dev]), None) {
        f = f.repair(root_repair(
            "Check only (xfs_repair -n)",
            format!("Reports problems and changes nothing. {steps}"),
            cmds,
            false,
        ));
        any = true;
    }
    if let Some((cmds, steps)) = on_unmounted(fs, ctx, v(&["xfs_repair", dev]), Some("0")) {
        f = f.repair(root_repair("Repair (xfs_repair)", format!("Runs `xfs_repair`. If it refuses because the log is dirty, mount and unmount the filesystem once to replay it, then retry. {steps}{warn}"), cmds, true));
        any = true;
    }
    if !any {
        f = f.advice(SYSTEM_FS_ADVICE);
    }
    vec![f]
}

/// Sum the non-zero error counters from `btrfs device stats`.
fn btrfs_errors(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|l| {
            let (name, n) = l.trim().rsplit_once(char::is_whitespace)?;
            let n: u64 = n.trim().parse().ok()?;
            (n > 0).then(|| (name.trim().to_string(), n))
        })
        .collect()
}

fn analyze_btrfs(fs: &Fs, ctx: &Ctx, out: Option<&(String, Option<i32>)>) -> Vec<Finding> {
    let warn = drive_warning(ctx);
    let dev = fs.dev.as_str();
    let Some(mp) = &fs.mountpoint else {
        return vec![Finding::new(Sev::Info, "Not mounted: only a read-only check is offered.")
            .advice("`btrfs check --repair` can destroy a filesystem that is otherwise recoverable, so it is deliberately not offered. If this one will not mount, ask for help (btrfs mailing list or your distro's forum) before repairing.")
            .repair(root_repair("Check only (read-only)", "Runs `btrfs check --readonly`: changes nothing.", vec![v(&["btrfs", "check", "--readonly", dev])], false))];
    };
    let mut f = vec![];
    let text = out.map_or("", |o| o.0.as_str());
    let errs = btrfs_errors(text);
    if text.trim().is_empty() {
        f.push(Finding::new(
            Sev::Info,
            "Device error counters could not be read.",
        ));
    } else if errs.is_empty() {
        f.push(Finding::new(
            Sev::Ok,
            "No read, write or corruption errors are recorded.",
        ));
    } else {
        let list = errs
            .iter()
            .map(|(k, n)| format!("{k} = {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        f.push(
            Finding::new(Sev::Bad, format!("Error counters are non-zero: {list}"))
                .advice("Scrub to read everything and repair from a good copy where the data is duplicated (RAID1/DUP; with a single copy it can only report). Reset the counters afterwards so new errors stand out.")
                .repair(root_repair(
                    "Reset the error counters",
                    format!("Runs `btrfs device stats -z {mp}`. Only do this after a scrub came back clean; the counters are how you notice new trouble."),
                    vec![v(&["btrfs", "device", "stats", "-z", mp])],
                    false,
                )),
        );
    }
    f.push(
        Finding::new(Sev::Info, "Scrub")
            .advice("A scrub verifies every checksum and repairs bad blocks from a second copy when the filesystem has one. It runs while the filesystem is in use and can take hours.")
            .repair(root_repair(
                "Scrub now (verify and repair)",
                format!("Runs `btrfs scrub start -B {mp}` and waits for the result, which appears in the Activity log. The app stays usable but shows as busy until it ends.{warn}"),
                vec![v(&["btrfs", "scrub", "start", "-B", mp])],
                false,
            )),
    );
    f
}

fn analyze_fat(fs: &Fs, ctx: &Ctx, out: Option<&(String, Option<i32>)>) -> Vec<Finding> {
    let dev = fs.dev.as_str();
    let warn = drive_warning(ctx);
    let text = out.map_or("", |o| o.0.as_str());
    let code = out.and_then(|o| o.1).unwrap_or(0);
    let mut f = Finding::new(Sev::Ok, "No problems found.");
    if out.is_none() || (text.trim().is_empty() && code != 0) {
        f = Finding::new(
            Sev::Info,
            "Not checked (fsck.fat or administrator access is missing).",
        );
    } else if text.contains("Dirty bit is set") && code == 0 {
        f = Finding::new(Sev::Warn, "Marked dirty: it was not unmounted cleanly.");
    } else if code != 0 {
        f = Finding::new(Sev::Bad, "The filesystem has inconsistencies.")
            .advice("Checked while mounted, a FAT filesystem can show harmless differences; repair from an unmounted state.");
    }
    if let Some((cmds, steps)) = on_unmounted(fs, ctx, v(&["fsck.fat", "-a", dev]), Some("0|1")) {
        f = f.repair(root_repair(
            "Repair (fsck.fat -a)",
            format!(
                "Fixes inconsistencies automatically; changes only what it must. {steps}{warn}"
            ),
            cmds,
            true,
        ));
    } else {
        f = f.advice(SYSTEM_FS_ADVICE);
    }
    vec![f]
}

fn analyze_fs(fs: &Fs, ctx: &Ctx, out: Option<&(String, Option<i32>)>) -> Item {
    let mut findings = match fs.fstype.as_str() {
        "ext2" | "ext3" | "ext4" => analyze_ext(fs, ctx, out),
        "xfs" => analyze_xfs(fs, ctx),
        "btrfs" => analyze_btrfs(fs, ctx, out),
        _ => analyze_fat(fs, ctx, out),
    };
    if let Some(mp) = &fs.mountpoint
        && let (Some(now), Some(wanted)) = (ctx.mounts.get(mp), ctx.fstab.get(mp))
        && has_opt(now, "ro")
        && !has_opt(wanted, "ro")
    {
        findings.insert(
            0,
            Finding::new(Sev::Bad, "Mounted read-only, although /etc/fstab asks for read-write.")
                .advice("Linux does this on its own after a disk or filesystem error. Check the filesystem (and the drive's SMART status) before switching it back.")
                .repair(root_repair(
                    "Remount read-write",
                    format!("Runs `mount -o remount,rw {mp}`. If the filesystem is damaged this can fail or make the damage worse: check it first.{}", drive_warning(ctx)),
                    vec![v(&["mount", "-o", "remount,rw", mp])],
                    true,
                )),
        );
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.sev));
    let name = if fs.label.is_empty() {
        fs.size.clone()
    } else {
        format!("{} · {}", fs.label, fs.size)
    };
    Item {
        title: format!("{} ({})", fs.dev, fs.fstype),
        subtitle: format!(
            "{name} · {}",
            fs.mountpoint
                .as_deref()
                .map_or("not mounted".to_string(), |m| format!("mounted at {m}"))
        ),
        findings,
        raw: out.map(|o| o.0.clone()).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------------------------
// /etc/fstab and the kernel log
// ---------------------------------------------------------------------------------------------

/// `findmnt --verify` output as (target, tag, message): tag is 'E', 'W' or another status letter.
fn parse_verify(text: &str) -> Vec<(String, char, String)> {
    let mut out = vec![];
    let mut target = String::new();
    for l in text.lines() {
        if l.trim().is_empty() {
            continue;
        }
        let t = l.trim();
        if !l.starts_with(char::is_whitespace) {
            if !t.contains("parse error") && !t.starts_with("Success") {
                target = t.to_string();
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix('[')
            && let Some((tag, msg)) = rest.split_once(']')
            && let Some(c) = tag.trim().chars().next()
        {
            out.push((target.clone(), c, msg.trim().to_string()));
        }
    }
    out
}

fn fstab_findings(text: &str) -> Vec<Finding> {
    let mut out = vec![];
    for (target, tag, msg) in parse_verify(text) {
        if tag != 'E' && tag != 'W' {
            continue;
        }
        let sev = if tag == 'E' { Sev::Bad } else { Sev::Warn };
        let mut f = Finding::new(sev, format!("{target}: {msg}"));
        let low = msg.to_lowercase();
        if low.contains("target does not exist") {
            f = f
                .advice("The folder this entry mounts onto is missing.")
                .repair(root_repair(
                    "Create the folder",
                    format!("Runs `mkdir -p {target}`."),
                    vec![v(&["mkdir", "-p", &target])],
                    false,
                ));
        } else if low.contains("systemd still uses the old version") {
            f = f.repair(root_repair(
                "Reload systemd",
                "Runs `systemctl daemon-reload` so systemd reads the edited fstab.",
                vec![v(&["systemctl", "daemon-reload"])],
                false,
            ));
        } else if low.contains("unreachable") {
            // awk's -v and fstab's \040 escapes make names with spaces or backslashes unsafe to match.
            if target.contains(|c: char| c.is_whitespace() || c == '\\') {
                f = f.advice(
                    "The device this entry refers to is missing. Edit /etc/fstab by hand and add `nofail` to the line (make a copy first).",
                );
                out.push(f);
                continue;
            }
            // Never write over /etc/fstab directly: build the new file beside it, check it, then rename.
            let script = format!(
                "cp -p /etc/fstab /etc/fstab.linuxward.bak && awk -v t={} '$0 !~ /^[ \\t]*#/ && $2 == t && $4 !~ /nofail/ {{ $4 = $4 \",nofail\" }} {{ print }}' /etc/fstab.linuxward.bak > /etc/fstab.linuxward.new && test -s /etc/fstab.linuxward.new && chmod --reference=/etc/fstab /etc/fstab.linuxward.new && mv /etc/fstab.linuxward.new /etc/fstab",
                util::sh_quote(&target)
            );
            f = f
                .advice("The device this entry refers to is missing (unplugged, replaced or the UUID changed). A missing required device can stop the computer from booting normally.")
                .repair(root_repair(
                    "Add \"nofail\" to this entry",
                    format!("Keeps a copy at /etc/fstab.linuxward.bak, then adds `nofail` to the options of the {target} line, so boot continues if the device is absent. The entry stays: remove it yourself if the device is gone for good."),
                    vec![v(&["sh", "-c", &script])],
                    true,
                ));
        } else {
            f = f.advice("Fix the line in /etc/fstab by hand (make a copy first).");
        }
        out.push(f);
    }
    if out.is_empty() {
        out.push(Finding::new(Sev::Ok, "No problems found in /etc/fstab."));
    }
    out
}

/// Kernel messages that point at the disk or filesystem layer.
fn is_storage_error(line: &str) -> bool {
    let l = line.to_lowercase();
    [
        "ext4-fs error",
        "ext4-fs warning",
        "i/o error",
        "buffer i/o",
        "blk_update_request",
        "remounting filesystem read-only",
        "btrfs: error",
        "btrfs error",
        "fat-fs",
        "xfs (",
        "failed command:",
        "nvme",
        "medium error",
    ]
    .iter()
    .any(|p| l.contains(p))
        && !l.contains("nvme: unknown")
}

fn kernel_findings(text: &str) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().filter(|l| is_storage_error(l)).collect();
    if lines.is_empty() {
        return vec![Finding::new(
            Sev::Ok,
            "No disk or filesystem errors in the kernel log since boot.",
        )];
    }
    let serious = lines.iter().any(|l| {
        let l = l.to_lowercase();
        l.contains("remounting filesystem read-only")
            || l.contains("i/o error")
            || l.contains("blk_update_request")
            || l.contains("medium error")
    });
    let recent = lines
        .iter()
        .rev()
        .take(5)
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    vec![Finding::new(
        if serious { Sev::Bad } else { Sev::Warn },
        format!("{} disk or filesystem message(s) at error level since boot. Most recent:\n{recent}", lines.len()),
    )
    .advice("I/O errors point at a failing drive, cable or controller; filesystem errors mean the matching filesystem above needs a check. A reboot clears this list, not the cause.")]
}

// ---------------------------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------------------------

/// Split the output of `run_privileged` back into one (text, exit code) per command.
fn split_sections(stdout: &str, cmds: &[Vec<String>]) -> Vec<(String, Option<i32>)> {
    let headers: Vec<String> = cmds.iter().map(|c| format!("# {}", join_cmd(c))).collect();
    let mut out: Vec<(String, Option<i32>)> = vec![];
    for line in stdout.lines() {
        if headers.get(out.len()).is_some_and(|h| line == h) {
            out.push((String::new(), None));
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        if let Some(c) = line.strip_prefix("!! command failed with exit code ") {
            cur.1 = c.trim().parse().ok();
        } else {
            cur.0.push_str(line);
            cur.0.push('\n');
        }
    }
    out.resize(cmds.len(), (String::new(), None));
    out
}

pub fn scan() -> Report {
    let rows = lsblk();
    let drives = drives_from(&rows);
    let filesystems = filesystems_from(&rows);

    // Everything that needs root, in one prompt.
    let mut cmds: Vec<(String, Vec<String>)> = vec![];
    if have("smartctl") {
        for d in &drives {
            cmds.push((format!("smart:{}", d.dev), v(&["smartctl", "-a", &d.dev])));
        }
    }
    for fs in &filesystems {
        match fs.fstype.as_str() {
            "ext2" | "ext3" | "ext4" if have("tune2fs") => {
                cmds.push((format!("fs:{}", fs.dev), v(&["tune2fs", "-l", &fs.dev])));
            }
            "btrfs" if have("btrfs") => {
                if let Some(mp) = &fs.mountpoint {
                    cmds.push((
                        format!("fs:{}", fs.dev),
                        v(&["btrfs", "device", "stats", mp]),
                    ));
                }
            }
            "vfat" if have("fsck.fat") => {
                cmds.push((format!("fs:{}", fs.dev), v(&["fsck.fat", "-n", &fs.dev])));
            }
            _ => {}
        }
    }
    let kernel_cmd = v(&["journalctl", "-k", "-b", "-p", "err", "--no-pager", "-q"]);
    cmds.push(("kernel".into(), kernel_cmd.clone()));

    let mut results: HashMap<String, (String, Option<i32>)> = HashMap::new();
    let mut notes = vec![];
    let argv: Vec<Vec<String>> = cmds.iter().map(|c| c.1.clone()).collect();
    let out = util::run_privileged(&argv);
    let elevated = !out.stdout.trim().is_empty();
    if elevated {
        for ((key, _), sec) in cmds.iter().zip(split_sections(&out.stdout, &argv)) {
            results.insert(key.clone(), sec);
        }
    } else {
        let why = out.stderr.trim();
        notes.push(format!(
            "Administrator access was not granted{}. SMART data and filesystem details need it; only the checks that don't are shown.",
            if why.is_empty() { String::new() } else { format!(" ({why})") }
        ));
        let k = util::run(
            &kernel_cmd[0],
            &kernel_cmd[1..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        results.insert("kernel".into(), (k.stdout, None));
    }
    if !have("smartctl") && !drives.is_empty() {
        notes.push("smartmontools is not installed, so drive health can't be read: install the `smartmontools` package.".into());
    }

    let mut ctx = Ctx {
        fstab: mount_table(
            &std::fs::read_to_string("/etc/fstab").unwrap_or_default(),
            3,
        ),
        mounts: mount_table(
            &std::fs::read_to_string("/proc/self/mounts").unwrap_or_default(),
            3,
        ),
        drive_bad: false,
        grubby: have("grubby"),
    };

    let drive_items: Vec<Item> = drives
        .iter()
        .map(|d| {
            let res = results.get(&format!("smart:{}", d.dev));
            let text = res.map_or("", |r| r.0.as_str());
            let mut findings = if !elevated {
                vec![Finding::new(
                    Sev::Info,
                    "Needs administrator access to read SMART data.",
                )]
            } else if !have("smartctl") {
                vec![Finding::new(Sev::Info, "smartmontools is not installed.")]
            } else {
                analyze_smart(&d.dev, text)
            };
            findings.sort_by_key(|f| std::cmp::Reverse(f.sev));
            let mut bits = vec![d.size.clone(), d.kind.to_string()];
            if !d.tran.is_empty() {
                bits.push(d.tran.clone());
            }
            Item {
                title: format!("{} {}", d.dev, d.model).trim().to_string(),
                subtitle: bits.join(" · "),
                findings,
                raw: text.to_string(),
            }
        })
        .collect();
    ctx.drive_bad = drive_items.iter().any(|i| i.worst() == Sev::Bad);

    let fs_items = filesystems
        .iter()
        .map(|fs| {
            analyze_fs(
                fs,
                &ctx,
                results.get(&format!("fs:{}", fs.dev)).filter(|_| elevated),
            )
        })
        .collect();

    let verify = util::run("findmnt", &["--verify"]);
    let mounts = Item {
        title: "/etc/fstab".into(),
        subtitle: "Mount configuration read at boot".into(),
        findings: if (verify.stdout.is_empty() && verify.stderr.contains("not found"))
            || !have("findmnt")
        {
            vec![Finding::new(Sev::Info, "findmnt is not available.")]
        } else {
            fstab_findings(&verify.combined())
        },
        raw: verify.combined(),
    };
    let ktext = results
        .get("kernel")
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let kernel = Item {
        title: "Kernel log".into(),
        subtitle: "Storage errors since this boot".into(),
        findings: kernel_findings(&ktext),
        raw: ktext,
    };

    Report {
        drives: drive_items,
        filesystems: fs_items,
        mounts,
        kernel,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATA: &str = "\
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       8
197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       3
199 UDMA_CRC_Error_Count    0x003e   200   200   000    Old_age   Always       -       0
194 Temperature_Celsius     0x0022   064   050   000    Old_age   Always       -       36 (Min/Max 20/45)

SMART Self-test log structure revision number 1
Num  Test_Description    Status                  Remaining  LifeTime(hours)  LBA_of_first_error
# 1  Short offline       Completed: read failure       90%     12345         987654
";

    fn find<'a>(f: &'a [Finding], needle: &str) -> Option<&'a Finding> {
        f.iter().find(|x| x.text.contains(needle))
    }

    #[test]
    fn ata_attributes_are_judged() {
        let f = analyze_smart("/dev/sda", ATA);
        assert_eq!(
            find(&f, "8 sector(s) have been reallocated").unwrap().sev,
            Sev::Warn
        );
        assert_eq!(find(&f, "3 sector(s) can't be read").unwrap().sev, Sev::Bad);
        assert_eq!(find(&f, "self-test failed").unwrap().sev, Sev::Bad);
        assert!(
            find(&f, "CRC").is_none(),
            "zero CRC errors are not a finding"
        );
        assert!(find(&f, "hot").is_none());
        assert!(
            f.iter().any(|x| x.repairs.len() == 2),
            "self-test repairs offered"
        );
    }

    #[test]
    fn failing_verdict_is_bad_and_has_no_fake_fix() {
        let t = "SMART overall-health self-assessment test result: FAILED!\n";
        let f = analyze_smart("/dev/sda", t);
        let bad = f.iter().find(|x| x.sev == Sev::Bad).unwrap();
        assert!(bad.repairs.is_empty());
        assert!(bad.advice.as_deref().unwrap().contains("Back up"));
    }

    #[test]
    fn virtual_disk_is_info_not_error() {
        let f = analyze_smart(
            "/dev/vda",
            "SMART support is: Unavailable - device lacks SMART capability.\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].sev, Sev::Info);
    }

    #[test]
    fn smart_off_offers_to_switch_on() {
        let f = analyze_smart(
            "/dev/sdb",
            "SMART support is: Disabled\nSMART overall-health self-assessment test result: PASSED\n",
        );
        let w = f.iter().find(|x| x.text.contains("switched off")).unwrap();
        assert_eq!(w.repairs.len(), 1);
    }

    #[test]
    fn nvme_is_judged() {
        let t = "SMART/Health Information (NVMe Log 0x02)\nCritical Warning:                   0x00\nTemperature:                        35 Celsius\nAvailable Spare:                    4%\nAvailable Spare Threshold:          10%\nPercentage Used:                    3%\nMedia and Data Integrity Errors:    2\n";
        let f = analyze_smart("/dev/nvme0n1", &format!("NVMe\n{t}"));
        assert_eq!(find(&f, "Spare capacity").unwrap().sev, Sev::Bad);
        assert_eq!(find(&f, "integrity").unwrap().sev, Sev::Bad);
        let ok = analyze_nvme(
            "Critical Warning: 0x00\nPercentage Used: 3%\nMedia and Data Integrity Errors: 0\nTemperature: 35 Celsius\n",
        );
        assert!(ok.iter().all(|x| x.sev == Sev::Ok));
    }

    #[test]
    fn lsblk_pairs_parse() {
        let m = parse_pairs(
            r#"PATH="/dev/sda1" TYPE="part" FSTYPE="ext4" LABEL="My\x20Disk" MOUNTPOINT="" SIZE="1G""#,
        );
        assert_eq!(m["LABEL"], "My Disk");
        assert_eq!(m["MOUNTPOINT"], "");
        assert_eq!(m["PATH"], "/dev/sda1");
    }

    #[test]
    fn btrfs_multi_device_collapses_and_unsupported_is_skipped() {
        let rows: Vec<_> = [
            r#"PATH="/dev/sda1" TYPE="part" FSTYPE="btrfs" UUID="u1" MOUNTPOINT="" SIZE="1G""#,
            r#"PATH="/dev/sdb1" TYPE="part" FSTYPE="btrfs" UUID="u1" MOUNTPOINT="/data" SIZE="1G""#,
            r#"PATH="/dev/loop0" TYPE="loop" FSTYPE="squashfs" UUID="" MOUNTPOINT="/snap/x" SIZE="1M""#,
        ]
        .iter()
        .map(|l| parse_pairs(l))
        .collect();
        let f = filesystems_from(&rows);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].mountpoint.as_deref(), Some("/data"));
    }

    fn fs(dev: &str, ty: &str, mp: Option<&str>) -> Fs {
        Fs {
            dev: dev.into(),
            fstype: ty.into(),
            label: String::new(),
            size: "1G".into(),
            mountpoint: mp.map(Into::into),
        }
    }
    fn ctx() -> Ctx {
        Ctx {
            fstab: [("/data".to_string(), "defaults".to_string())].into(),
            mounts: HashMap::new(),
            drive_bad: false,
            grubby: false,
        }
    }

    #[test]
    fn unmounted_runs_directly_mounted_wraps_and_system_refuses() {
        let c = ctx();
        let (cmds, _) = on_unmounted(
            &fs("/dev/sdb1", "ext4", None),
            &c,
            v(&["e2fsck", "-fy", "/dev/sdb1"]),
            None,
        )
        .unwrap();
        assert_eq!(cmds, vec![v(&["e2fsck", "-fy", "/dev/sdb1"])]);

        let (cmds, _) = on_unmounted(
            &fs("/dev/sdb1", "ext4", Some("/data")),
            &c,
            v(&["e2fsck", "-fy", "/dev/sdb1"]),
            Some("0|1|2"),
        )
        .unwrap();
        let script = &cmds[0][2];
        assert!(script.starts_with("umount /data || {"), "{script}");
        assert!(script.contains("e2fsck -fy /dev/sdb1; rc=$?"));
        assert!(
            script.contains("0|1|2) mount /data"),
            "remounts only on success"
        );
        assert!(
            on_unmounted(
                &fs("/dev/sda2", "ext4", Some("/")),
                &c,
                v(&["e2fsck"]),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn mount_point_with_spaces_is_quoted() {
        let (cmds, _) = on_unmounted(
            &fs("/dev/sdb1", "vfat", Some("/run/media/me/My Disk")),
            &ctx(),
            v(&["fsck.fat", "-a", "/dev/sdb1"]),
            Some("0|1"),
        )
        .unwrap();
        assert!(cmds[0][2].contains("umount '/run/media/me/My Disk'"));
    }

    #[test]
    fn ext_state_is_read_correctly() {
        let dirty = ("Filesystem features:      has_journal ext_attr\nFilesystem state:         not clean\nFS Error count:           3\n".to_string(), None);
        let f = analyze_ext(&fs("/dev/sdb1", "ext4", None), &ctx(), Some(&dirty));
        assert_eq!(f[0].sev, Sev::Bad);
        let repair = f
            .iter()
            .flat_map(|x| &x.repairs)
            .find(|r| r.label.starts_with("Repair"))
            .unwrap();
        assert!(repair.risky);

        let clean = ("Filesystem features:      has_journal\nFilesystem state:         clean\nLast checked:             Mon Jan  1 00:00:00 2024\n".to_string(), None);
        let f = analyze_ext(
            &fs("/dev/sdb1", "ext4", Some("/data")),
            &ctx(),
            Some(&clean),
        );
        assert_eq!(f[0].sev, Sev::Ok);

        // A mounted journal-less ext2 always shows "not clean": not a finding.
        let ext2 = (
            "Filesystem features:      ext_attr\nFilesystem state:         not clean\n".to_string(),
            None,
        );
        assert_eq!(
            analyze_ext(&fs("/dev/sdb1", "ext2", Some("/data")), &ctx(), Some(&ext2))[0].sev,
            Sev::Info
        );
    }

    #[test]
    fn mounted_root_gets_boot_time_check_only_with_grubby() {
        let mut c = ctx();
        let clean = (
            "Filesystem features:      has_journal\nFilesystem state:         clean with errors\n"
                .to_string(),
            None,
        );
        let root = fs("/dev/sda2", "ext4", Some("/"));
        let none: Vec<_> = analyze_ext(&root, &c, Some(&clean))
            .iter()
            .flat_map(|f| f.repairs.clone())
            .collect();
        assert!(none.is_empty());
        c.grubby = true;
        let some: Vec<_> = analyze_ext(&root, &c, Some(&clean))
            .iter()
            .flat_map(|f| f.repairs.clone())
            .collect();
        assert_eq!(some.len(), 2);
    }

    #[test]
    fn btrfs_counters() {
        let t = "[/dev/sda2].write_io_errs    0\n[/dev/sda2].read_io_errs     0\n[/dev/sda2].corruption_errs  4\n";
        assert_eq!(
            btrfs_errors(t),
            vec![("[/dev/sda2].corruption_errs".to_string(), 4)]
        );
        let f = analyze_btrfs(
            &fs("/dev/sda2", "btrfs", Some("/")),
            &ctx(),
            Some(&(t.to_string(), None)),
        );
        assert_eq!(f[0].sev, Sev::Bad);
        assert!(
            f.iter()
                .any(|x| x.repairs.iter().any(|r| r.label.starts_with("Scrub")))
        );
    }

    #[test]
    fn read_only_remount_is_flagged() {
        let mut c = ctx();
        c.mounts.insert("/data".into(), "ro,relatime".into());
        let item = analyze_fs(&fs("/dev/sdb1", "xfs", Some("/data")), &c, None);
        assert_eq!(item.findings[0].sev, Sev::Bad);
        assert!(item.findings[0].repairs[0].label.contains("read-write"));
    }

    #[test]
    fn fstab_verify_is_parsed_with_fixes() {
        let t = "/mnt/gone\n   [E] unreachable on boot required source: UUID=1234\n/srv/x\n   [W] target does not exist\n   [W] your fstab has been modified, but systemd still uses the old version; use 'systemctl daemon-reload' to reload\n\n0 parse errors, 1 error, 2 warnings\n";
        let f = fstab_findings(t);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].sev, Sev::Bad);
        assert!(f[0].repairs[0].label.contains("nofail"));
        assert!(f[1].repairs[0].label.contains("Create the folder"));
        assert!(f[2].repairs[0].label.contains("Reload"));
        assert_eq!(
            fstab_findings("Success, no errors or warnings detected\n")[0].sev,
            Sev::Ok
        );
    }

    #[test]
    fn kernel_log_is_classified() {
        assert_eq!(kernel_findings("")[0].sev, Sev::Ok);
        let t = "Nov 1 kernel: usb 1-1: new device\nNov 1 kernel: EXT4-fs error (device sda2): ext4_find_entry\nNov 1 kernel: blk_update_request: I/O error, dev sda, sector 5\n";
        let f = kernel_findings(t);
        assert_eq!(f[0].sev, Sev::Bad);
        assert!(f[0].text.starts_with("2 disk"));
    }

    /// The repair scripts run as root: at least make sure the shell can parse every one of them.
    #[test]
    fn generated_scripts_are_valid_shell() {
        let c = ctx();
        let mut scripts = vec![];
        for (mp, codes) in [
            ("/data", None),
            ("/data", Some("0|1|2")),
            ("/run/media/me/My Disk", Some("0")),
        ] {
            let fs = fs("/dev/sdb1", "ext4", Some(mp));
            let (cmds, _) = on_unmounted(&fs, &c, v(&["e2fsck", "-fy", &fs.dev]), codes).unwrap();
            scripts.push(cmds[0][2].clone());
        }
        let t = "/mnt/gone\n   [E] unreachable on boot required source: UUID=1234\n";
        for f in fstab_findings(t) {
            for r in f.repairs {
                if let Action::Root(cmds) = &r.actions[0]
                    && cmds[0][0] == "sh"
                {
                    scripts.push(cmds[0][2].clone());
                }
            }
        }
        assert!(scripts.len() >= 4);
        for s in scripts {
            let out = std::process::Command::new("sh")
                .args(["-n", "-c", &s])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "invalid shell: {s}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn fstab_edit_adds_nofail_without_touching_other_lines() {
        let t = "/mnt/gone\n   [E] unreachable on boot required source: UUID=1234\n";
        let f = fstab_findings(t);
        let Action::Root(cmds) = &f[0].repairs[0].actions[0] else {
            panic!("root action")
        };
        let script = &cmds[0][2];
        assert!(
            script.contains("mv /etc/fstab.linuxward.new /etc/fstab"),
            "{script}"
        );
        assert!(
            !script.contains("> /etc/fstab;") && !script.ends_with("> /etc/fstab"),
            "must not truncate fstab in place"
        );
        // Run just the awk part against a sample file.
        let dir = std::env::temp_dir().join(format!("lw-fstab-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("fstab");
        std::fs::write(&src, "# comment /mnt/gone\nUUID=1 / ext4 defaults 0 1\nUUID=2 /mnt/gone ext4 defaults 0 2\nUUID=3 /mnt/other ext4 defaults 0 2\n").unwrap();
        // The awk program itself contains `&&`, so cut the command out by its markers.
        let start = script.find("awk -v").unwrap();
        let end = script.find(" > /etc/fstab.linuxward.new").unwrap();
        let awk = script[start..end].replace("/etc/fstab.linuxward.bak", src.to_str().unwrap());
        let out = std::process::Command::new("sh")
            .args(["-c", &awk])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("UUID=2 /mnt/gone ext4 defaults,nofail 0 2"),
            "{text}"
        );
        assert!(text.contains("UUID=3 /mnt/other ext4 defaults 0 2"));
        assert!(text.contains("# comment /mnt/gone"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn privileged_output_splits_back_into_sections() {
        let cmds = vec![
            v(&["smartctl", "-a", "/dev/sda"]),
            v(&["tune2fs", "-l", "/dev/sda1"]),
        ];
        let out = "# smartctl -a /dev/sda\nline one\n!! command failed with exit code 4\n# tune2fs -l /dev/sda1\nstate clean\n";
        let s = split_sections(out, &cmds);
        assert_eq!(s[0], ("line one\n".to_string(), Some(4)));
        assert_eq!(s[1], ("state clean\n".to_string(), None));
    }
}

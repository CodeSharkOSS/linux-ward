//! Running systemd services: what each one is, what it uses, and where its configuration lives.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::pkg::Pm;
use crate::util::run;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    System,
    User,
}

impl Scope {
    fn base(self) -> Vec<&'static str> {
        match self {
            Scope::System => vec![],
            Scope::User => vec!["--user"],
        }
    }
}

#[derive(Clone)]
pub struct Svc {
    pub unit: String,
    /// The one-line `Description=` from the unit file.
    pub description: String,
    pub fragment: Option<PathBuf>,
    pub dropins: Vec<PathBuf>,
    pub pid: u32,
    pub mem: Option<u64>,
    pub since: String,
    /// `UnitFileState`: enabled, disabled, static, …
    pub enabled: String,
    pub category: &'static str,
    /// A plain-language explanation for services we recognise.
    pub blurb: Option<&'static str>,
}

/// (name prefix, category, what it does). First match wins, so specific entries come first.
const KNOWN: &[(&str, &str, &str)] = &[
    (
        "user@",
        "System core",
        "Your login session manager. Everything you run (desktop, apps, terminals) lives under it, so the memory shown is the total of all of them, not one program.",
    ),
    (
        "user-runtime-dir@",
        "System core",
        "Creates your per-login runtime folder (/run/user/UID).",
    ),
    (
        "dbus-:",
        "Desktop",
        "A desktop app started through the session bus; this is a temporary unit that disappears when the app closes.",
    ),
    (
        "app-",
        "Desktop",
        "An application you launched from the desktop, tracked as its own service.",
    ),
    ("vte-spawn", "Desktop", "A terminal window's shell session."),
    (
        "org.gnome.Shell",
        "Desktop",
        "The GNOME desktop itself: windows, panels, notifications. Stopping it ends your session.",
    ),
    (
        "gnome-software",
        "Packages",
        "The app store. It keeps checking for updates in the background.",
    ),
    ("gnome-", "Desktop", "A GNOME desktop component."),
    ("org.gnome.", "Desktop", "A GNOME desktop component."),
    (
        "at-spi",
        "Desktop",
        "Accessibility bus used by screen readers and automation.",
    ),
    ("dconf", "Desktop", "Stores desktop and app settings."),
    (
        "gpg-agent",
        "Security",
        "Holds your GPG keys and passphrases so you are not asked repeatedly.",
    ),
    (
        "ssh-agent",
        "Security",
        "Holds your SSH keys so you are not asked repeatedly.",
    ),
    (
        "clamd",
        "Security",
        "ClamAV antivirus scanner daemon. Uses a lot of RAM for its virus database.",
    ),
    (
        "dnf5daemon",
        "Packages",
        "Package-manager service used by graphical software tools.",
    ),
    (
        "NetworkManager-wait-online",
        "Network",
        "Holds up boot until the network is connected. Often unnecessary on a desktop and a common cause of slow boots.",
    ),
    (
        "NetworkManager-dispatcher",
        "Network",
        "Runs scripts when a network connection goes up or down.",
    ),
    (
        "NetworkManager",
        "Network",
        "Manages wired, Wi-Fi and VPN connections and keeps DNS and routes up to date. Stopping it drops your network.",
    ),
    (
        "wpa_supplicant",
        "Network",
        "Handles Wi-Fi authentication (WPA/WPA2/WPA3) for NetworkManager.",
    ),
    (
        "sshd",
        "Network",
        "OpenSSH server: lets other machines log in to this one remotely.",
    ),
    (
        "avahi-daemon",
        "Network",
        "Local network discovery (mDNS/Bonjour), used to find printers, shares and other devices.",
    ),
    (
        "firewalld",
        "Security",
        "Dynamic firewall: decides which network ports and services are reachable.",
    ),
    (
        "chronyd",
        "Time",
        "Keeps the system clock accurate by syncing with internet time servers.",
    ),
    (
        "systemd-timesyncd",
        "Time",
        "Lightweight clock synchronisation over the network.",
    ),
    (
        "systemd-resolved",
        "Network",
        "Local DNS resolver and cache.",
    ),
    (
        "systemd-networkd",
        "Network",
        "systemd's own network configuration service.",
    ),
    (
        "systemd-journald",
        "Logging",
        "Collects and stores system logs (what `journalctl` reads).",
    ),
    (
        "systemd-logind",
        "System core",
        "Tracks logins, sessions, seats and the power/suspend buttons.",
    ),
    (
        "systemd-udevd",
        "System core",
        "Detects hardware as it appears and creates device files for it.",
    ),
    (
        "systemd-oomd",
        "Memory",
        "Kills runaway processes when the system is about to run out of memory.",
    ),
    (
        "systemd-homed",
        "System core",
        "Manages portable, optionally encrypted home directories.",
    ),
    (
        "systemd-machined",
        "System core",
        "Tracks virtual machines and containers registered with systemd.",
    ),
    (
        "systemd-userdbd",
        "System core",
        "Look-up service for user and group records.",
    ),
    (
        "systemd-",
        "System core",
        "Part of systemd, the system and service manager.",
    ),
    (
        "dbus-broker",
        "System core",
        "The message bus programs use to talk to each other. Essential: most of the desktop depends on it.",
    ),
    (
        "dbus",
        "System core",
        "The message bus programs use to talk to each other. Essential: most of the desktop depends on it.",
    ),
    (
        "polkit",
        "Security",
        "Decides whether a program may do a privileged action (the source of 'authentication required' prompts).",
    ),
    (
        "auditd",
        "Security",
        "Records security-relevant events to the audit log.",
    ),
    (
        "sssd",
        "Security",
        "Single sign-on and directory login (LDAP/Active Directory/Kerberos).",
    ),
    (
        "gssproxy",
        "Security",
        "Lets services use Kerberos credentials on behalf of users.",
    ),
    (
        "rtkit-daemon",
        "Desktop",
        "Gives audio programs real-time priority so sound doesn't stutter.",
    ),
    (
        "gdm",
        "Desktop",
        "The graphical login screen; starts and ends your GNOME desktop session. Stopping it logs you out.",
    ),
    (
        "sddm",
        "Desktop",
        "The graphical login screen for KDE Plasma.",
    ),
    (
        "lightdm",
        "Desktop",
        "The graphical login screen used by Xfce, MATE and others.",
    ),
    (
        "accounts-daemon",
        "Desktop",
        "Provides user account details (name, avatar, language) to the login screen and Settings.",
    ),
    (
        "colord",
        "Desktop",
        "Manages colour profiles for screens, scanners and printers.",
    ),
    (
        "geoclue",
        "Desktop",
        "Location service: tells apps where you are (time zone, weather, maps).",
    ),
    (
        "pipewire",
        "Desktop",
        "Audio and video server (replaces PulseAudio/JACK).",
    ),
    (
        "wireplumber",
        "Desktop",
        "Session manager for PipeWire: decides which audio device apps use.",
    ),
    (
        "gnome-remote-desktop",
        "Desktop",
        "Lets you share your screen or log in remotely.",
    ),
    (
        "gvfs",
        "Desktop",
        "Virtual file system: lets the file manager browse network shares, phones and cameras.",
    ),
    (
        "xdg-",
        "Desktop",
        "Desktop integration helper (portals, document handling).",
    ),
    (
        "evolution",
        "Desktop",
        "Contacts, calendar and mail back-end for GNOME apps.",
    ),
    (
        "tracker",
        "Desktop",
        "Indexes your files so desktop search is fast. Can keep the disk busy after upgrades.",
    ),
    (
        "localsearch",
        "Desktop",
        "Indexes your files so desktop search is fast. Can keep the disk busy after upgrades.",
    ),
    (
        "upower",
        "Hardware",
        "Reports battery and power-supply status to the desktop.",
    ),
    (
        "power-profiles-daemon",
        "Hardware",
        "Switches between power-saver, balanced and performance modes.",
    ),
    (
        "tuned-ppd",
        "Hardware",
        "Maps the desktop's power profile switch onto tuned profiles.",
    ),
    (
        "tuned",
        "Tuning",
        "Applies performance profiles (CPU, disk and memory settings), e.g. virtual-guest or throughput-performance.",
    ),
    ("thermald", "Hardware", "Keeps Intel CPUs from overheating."),
    (
        "irqbalance",
        "Hardware",
        "Spreads hardware interrupts across CPU cores.",
    ),
    (
        "udisks2",
        "Storage",
        "Mounts and manages disks and USB drives for the desktop.",
    ),
    (
        "smartd",
        "Storage",
        "Watches disk health (SMART) and warns before a drive fails.",
    ),
    ("lvm2", "Storage", "Monitors LVM logical volumes."),
    (
        "multipathd",
        "Storage",
        "Manages multiple paths to a storage device.",
    ),
    (
        "fwupd",
        "Hardware",
        "Delivers firmware updates for devices (BIOS, SSDs, peripherals).",
    ),
    (
        "bluetooth",
        "Hardware",
        "Bluetooth support: pairing and connecting devices.",
    ),
    (
        "ModemManager",
        "Hardware",
        "Manages mobile-broadband (3G/4G) modems. Not needed without one.",
    ),
    (
        "switcheroo-control",
        "Hardware",
        "Switches between integrated and discrete GPUs. Not needed on a VM.",
    ),
    (
        "iio-sensor-proxy",
        "Hardware",
        "Reads accelerometer, light and compass sensors (auto-rotate, auto-brightness).",
    ),
    (
        "low-memory-monitor",
        "Memory",
        "Warns apps when the system is low on memory.",
    ),
    (
        "cups-browsed",
        "Printing",
        "Finds network printers automatically.",
    ),
    (
        "cups",
        "Printing",
        "Print server: queues and sends jobs to printers.",
    ),
    (
        "docker",
        "Containers",
        "Docker engine: builds and runs containers.",
    ),
    (
        "containerd",
        "Containers",
        "Low-level container runtime used by Docker and Kubernetes.",
    ),
    ("podman", "Containers", "Podman container service."),
    (
        "libvirtd",
        "Virtualisation",
        "Manages KVM/QEMU virtual machines.",
    ),
    (
        "virtqemud",
        "Virtualisation",
        "Manages KVM/QEMU virtual machines.",
    ),
    (
        "vmtoolsd",
        "Virtualisation",
        "VMware guest tools: clipboard sharing, screen resize, time sync and clean shutdown.",
    ),
    (
        "vmware-vmblock",
        "Virtualisation",
        "VMware drag-and-drop between host and guest.",
    ),
    (
        "vboxservice",
        "Virtualisation",
        "VirtualBox guest additions service.",
    ),
    (
        "spice-vdagent",
        "Virtualisation",
        "SPICE guest agent: clipboard and screen resize for QEMU/KVM guests.",
    ),
    (
        "qemu-guest-agent",
        "Virtualisation",
        "Lets the QEMU/KVM host query and shut down this guest.",
    ),
    (
        "hv_",
        "Virtualisation",
        "Hyper-V guest integration service.",
    ),
    ("snapd", "Packages", "Runs Snap packages."),
    (
        "packagekit",
        "Packages",
        "Software-update service used by graphical package managers.",
    ),
    (
        "flatpak",
        "Packages",
        "Helper for installing and updating Flatpak apps.",
    ),
    ("dnf", "Packages", "Package manager background service."),
    (
        "abrt",
        "Debugging",
        "Collects and reports application crashes.",
    ),
    ("mcelog", "Hardware", "Logs CPU and memory hardware errors."),
    ("crond", "Scheduling", "Runs scheduled jobs (cron)."),
    ("cron", "Scheduling", "Runs scheduled jobs (cron)."),
    ("atd", "Scheduling", "Runs one-off scheduled jobs (`at`)."),
    (
        "rsyslog",
        "Logging",
        "Traditional text-file system logging.",
    ),
    ("httpd", "Server", "Apache web server."),
    ("apache2", "Server", "Apache web server."),
    ("nginx", "Server", "Nginx web server and reverse proxy."),
    ("mariadb", "Server", "MariaDB database server."),
    ("mysql", "Server", "MySQL database server."),
    ("postgresql", "Server", "PostgreSQL database server."),
    ("redis", "Server", "Redis in-memory data store."),
    (
        "smb",
        "Server",
        "Samba: shares files with Windows machines.",
    ),
    ("nmb", "Server", "Samba name service."),
    ("nfs", "Server", "NFS file sharing."),
    (
        "rpcbind",
        "Server",
        "Maps RPC services to ports (needed by NFS).",
    ),
];

pub fn lookup_known(unit: &str) -> Option<(&'static str, &'static str)> {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    KNOWN
        .iter()
        .find(|(p, _, _)| base.starts_with(p))
        .map(|(_, c, b)| (*c, *b))
}

fn parse_show(text: &str) -> Vec<HashMap<String, String>> {
    text.split("\n\n")
        .map(|block| {
            block
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.trim().to_string()))
                .collect::<HashMap<_, _>>()
        })
        .filter(|m| m.contains_key("Id"))
        .collect()
}

fn to_svc(m: &HashMap<String, String>) -> Svc {
    let unit = m.get("Id").cloned().unwrap_or_default();
    let known = lookup_known(&unit);
    let paths = |k: &str| -> Vec<PathBuf> {
        m.get(k)
            .map(|v| v.split_whitespace().map(PathBuf::from).collect())
            .unwrap_or_default()
    };
    let mem = m
        .get("MemoryCurrent")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v != u64::MAX);
    Svc {
        description: m.get("Description").cloned().unwrap_or_default(),
        fragment: m
            .get("FragmentPath")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from),
        dropins: paths("DropInPaths"),
        pid: m.get("MainPID").and_then(|v| v.parse().ok()).unwrap_or(0),
        mem,
        since: m.get("ActiveEnterTimestamp").cloned().unwrap_or_default(),
        enabled: m.get("UnitFileState").cloned().unwrap_or_default(),
        category: known.map_or("Other", |k| k.0),
        blurb: known.map(|k| k.1),
        unit,
    }
}

/// Running services with their metadata, biggest memory users first.
pub fn list_running(scope: Scope) -> Vec<Svc> {
    let mut args = scope.base();
    args.extend([
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--plain",
        "--no-pager",
    ]);
    let listed = run("systemctl", &args).stdout;
    let units: Vec<&str> = listed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if units.is_empty() {
        return vec![];
    }
    let mut args = scope.base();
    args.extend(["show", "--no-pager", "-p", "Id,Description,FragmentPath,DropInPaths,MainPID,MemoryCurrent,ActiveEnterTimestamp,UnitFileState"]);
    args.extend(units.iter().copied());
    let mut v: Vec<Svc> = parse_show(&run("systemctl", &args).stdout)
        .iter()
        .map(to_svc)
        .collect();
    v.sort_by(|a, b| {
        b.mem
            .unwrap_or(0)
            .cmp(&a.mem.unwrap_or(0))
            .then_with(|| a.unit.cmp(&b.unit))
    });
    v
}

// ----- details, loaded when a service is selected ---------------------------------------

#[derive(Clone, Default)]
pub struct Detail {
    /// (package, one-line summary) that ships this service.
    pub package: Option<(String, String)>,
    /// Config files and folders that exist on this machine, most relevant first.
    pub config_files: Vec<PathBuf>,
    /// Effective unit file including drop-ins (`systemctl cat`).
    pub unit_text: String,
}

/// Which package owns `path`, with its summary.
fn owner(pm: Pm, path: &Path) -> Option<(String, String)> {
    let p = path.to_string_lossy();
    match pm {
        Pm::Dnf | Pm::Zypper => {
            let out = run("rpm", &["-qf", "--qf", "%{NAME}\t%{SUMMARY}\n", &p]);
            let l = out.stdout.lines().next()?;
            let (n, s) = l.split_once('\t')?;
            (out.ok && !n.is_empty()).then(|| (n.to_string(), s.to_string()))
        }
        Pm::Apt => {
            let out = run("dpkg", &["-S", &p]);
            let name = out.stdout.lines().next()?.split(':').next()?.to_string();
            let sum = run("dpkg-query", &["-W", "-f", "${binary:Summary}", &name]).stdout;
            (out.ok && !name.is_empty()).then_some((name, sum))
        }
        Pm::Pacman => {
            let out = run("pacman", &["-Qo", "-q", &p]);
            let name = out.stdout.lines().next()?.trim().to_string();
            let info = run("pacman", &["-Qi", &name]).stdout;
            let desc = info
                .lines()
                .find_map(|l| {
                    l.strip_prefix("Description")
                        .and_then(|r| r.split_once(':'))
                        .map(|(_, v)| v.trim().to_string())
                })
                .unwrap_or_default();
            (out.ok && !name.is_empty()).then_some((name, desc))
        }
    }
}

/// Config files the package declares (so the ones you are expected to edit).
fn package_config(pm: Pm, pkg: &str) -> Vec<PathBuf> {
    let lines: Vec<String> = match pm {
        Pm::Dnf | Pm::Zypper => run("rpm", &["-qc", pkg])
            .stdout
            .lines()
            .map(str::to_string)
            .collect(),
        Pm::Apt => run("dpkg-query", &["-W", "-f", "${Conffiles}\n", pkg])
            .stdout
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .collect(),
        Pm::Pacman => run("pacman", &["-Ql", pkg])
            .stdout
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
            .filter(|p| p.starts_with("/etc/"))
            .collect(),
    };
    lines
        .into_iter()
        .filter(|l| l.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

pub fn load_detail(scope: Scope, svc: &Svc, pm: Option<Pm>) -> Detail {
    let mut config: Vec<PathBuf> = Vec::new();
    // Admin overrides first: they are what is actually changing behaviour.
    config.extend(
        svc.dropins
            .iter()
            .filter(|p| p.starts_with("/etc") || p.starts_with(crate::util::home()))
            .cloned(),
    );
    if let Some(f) = &svc.fragment {
        config.push(f.clone());
    }
    config.extend(
        svc.dropins
            .iter()
            .filter(|p| !config.contains(p))
            .cloned()
            .collect::<Vec<_>>(),
    );

    let mut package = None;
    if let (Some(pm), Some(frag)) = (pm, &svc.fragment) {
        package = owner(pm, frag);
        if let Some((name, _)) = &package {
            config.extend(package_config(pm, name));
        }
    }
    // Conventional locations: /etc/<name>/ or /etc/<name>.conf
    let base = svc.unit.strip_suffix(".service").unwrap_or(&svc.unit);
    let base = base.split('@').next().unwrap_or(base);
    for cand in [
        format!("/etc/{base}"),
        format!("/etc/{base}.conf"),
        format!("/etc/sysconfig/{base}"),
        format!("/etc/default/{base}"),
    ] {
        config.push(PathBuf::from(cand));
    }
    let mut seen = std::collections::HashSet::new();
    config.retain(|p| p.exists() && seen.insert(p.clone()));
    config.truncate(30);

    let mut args = scope.base();
    args.extend(["cat", "--no-pager", &svc.unit]);
    let unit_text = run("systemctl", &args)
        .combined()
        .lines()
        .take(250)
        .collect::<Vec<_>>()
        .join("\n");
    Detail {
        package,
        config_files: config,
        unit_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_services() {
        assert_eq!(lookup_known("NetworkManager.service").unwrap().0, "Network");
        assert_eq!(
            lookup_known("NetworkManager-wait-online.service")
                .unwrap()
                .0,
            "Network"
        );
        assert!(
            lookup_known("NetworkManager-wait-online.service")
                .unwrap()
                .1
                .contains("slow boots")
        );
        assert_eq!(
            lookup_known("systemd-journald.service").unwrap().0,
            "Logging"
        );
        assert_eq!(
            lookup_known("systemd-random-seed.service").unwrap().0,
            "System core"
        );
        assert!(lookup_known("totally-unknown.service").is_none());
    }

    #[test]
    fn show_parsing() {
        let t = "Id=a.service\nDescription=A thing\nMainPID=12\nMemoryCurrent=2048\nDropInPaths=/x/1.conf /y/2.conf\nFragmentPath=/usr/lib/systemd/system/a.service\n\nId=b.service\nMemoryCurrent=[not set]\nMainPID=0\n";
        let v: Vec<Svc> = parse_show(t).iter().map(to_svc).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mem, Some(2048));
        assert_eq!(v[0].dropins.len(), 2);
        assert_eq!(v[0].pid, 12);
        assert_eq!(v[1].mem, None);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    #[ignore]
    fn live_services_print() {
        let pm = Pm::detect();
        for scope in [Scope::System, Scope::User] {
            let v = list_running(scope);
            println!("{:?}: {} running", scope, v.len());
            for s in v.iter().take(4) {
                println!(
                    "  {} | {} | {} | mem={:?} | {} | {:?}",
                    s.unit,
                    s.category,
                    s.description,
                    s.mem,
                    s.enabled,
                    s.blurb.map(|b| &b[..b.len().min(40)])
                );
            }
            let unknown = v.iter().filter(|s| s.blurb.is_none()).count();
            println!("  without built-in explanation: {unknown}");
        }
        let v = list_running(Scope::System);
        let nm = v
            .iter()
            .find(|s| s.unit == "NetworkManager.service")
            .unwrap();
        let d = load_detail(Scope::System, nm, pm);
        println!(
            "pkg={:?}\ncfg={:?}\nunit lines={}",
            d.package,
            d.config_files,
            d.unit_text.lines().count()
        );
    }
}

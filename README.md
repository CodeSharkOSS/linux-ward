# LinuxWard

A small Linux desktop app, written in Rust with [egui/eframe](https://github.com/emilk/egui), to clean up disk space, manage packages, scan for exposed secrets and suspicious processes, and tune system performance.

## Features

The tabs are grouped into four sections along the top:

| Section | Tabs |
|---|---|
| 💾 Free space | Quick clean · Large files · Duplicates |
| 📦 Software | Packages · Services |
| 🛠 Developer | Dev cleanup · Open ports · Java |
| 🩺 Health & security | Health & speed · Disks & filesystems · Security · Suspect processes |

**Quick clean**
- Disk usage bars for every real mounted filesystem.
- Scans for reclaimable space and shows the size of each item:
  - Application cache (`~/.cache`) and Trash
  - systemd journal (vacuums to 7 days / 200 MiB), rotated logs in `/var/log`, crash dumps
  - Package manager cache (`apt-get clean`, `dnf clean all`, `paccache`, `zypper clean`)
  - Unused dependencies / orphaned packages (with the list and per-package size)
  - Unused Flatpak runtimes and disabled Snap revisions
  - Developer caches: Cargo registry, npm, Go, Gradle, Maven, pnpm, Conda, NuGet, Bundler, Android, unused Docker/Podman images, containers and build cache (volumes are never removed)
- Everything that needs root is batched into **one** password prompt via `pkexec`.

**Packages**
- All installed packages with version, installed size and whether you installed them or they came in as a dependency.
- An **Upgradable** view shows packages with a newer version in your repos (`1.0 → 2.0`); select some and choose **Upgrade selected…** (one password prompt). apt also refreshes its index first. pacman has no partial upgrades, so there the button upgrades the whole system (`-Syu`). Availability comes from already-downloaded metadata, so refresh your package index to see the latest.
- A **Conflicts** view lists installed packages that declare a conflict with another installed package (shown next to the name). Healthy systems normally show none; version-limited conflicts are not checked.
- Filter, sort by name or size, "installed by me only" toggle.
- Before removing, runs a dry run and shows any **other packages that would also be removed**.
- Essential packages (libc, systemd, sudo, the package manager itself, the running kernel, etc.) can't be selected, and a removal that would cascade into one is blocked.

**Duplicates**
- Finds identical files under a folder (matched by size, then hash, then a byte-for-byte check; hard links are ignored). Keep one copy per set and move the rest to Trash. It refuses to select every copy of a file.

**Security**
- Scans a folder (your home by default) for files that commonly hold secrets: SSH and TLS private keys, `.env` files, cloud/registry/Kubernetes/Docker credentials, stored git and database logins, wallets, and shell history. Optionally looks inside small text files for private-key blocks, AWS/GitHub/GitLab/Slack/Stripe/Google tokens and passwords embedded in URLs.
- With **Check git repos** on, also finds secret files committed to git and secrets added in the last 300 commits (deleting a line doesn't remove it from history).
- Ranks findings by risk (keys readable by other users rank highest) and flags unencrypted private keys, `~/.ssh` / `~/.gnupg` that aren't private, and world-writable files.
- Secret values are never displayed or stored. **Restrict** runs `chmod` to 600/700; you can also move files to Trash. Findings are leads to review, not proof of a leak.

**Dev cleanup**
- **Build artifacts:** scans a code folder for regenerable output (Rust/Maven `target/`, `node_modules/`, Gradle/CMake `build/`, Python virtualenvs and caches, Composer `vendor/`, .NET `bin/`/`obj/`) and shows size and days idle. "Select untouched for over N days" picks the stale ones. Each folder is only listed when a marker file proves it is generated, so an unrelated folder called `target` is never touched.
- **Language toolchains:** old versions from rustup, nvm, SDKMAN and pyenv; the one in use is protected.
- **IDE leftovers:** every JetBrains IDE and Android Studio upgrade leaves the previous version's settings, plugins and caches behind (`~/.config`, `~/.cache`, `~/.local/share`). Each product's newest version is kept; older ones are listed together with their size. JetBrains Toolbox's own app folder is left alone because Toolbox manages it.
- **Android SDK:** older platforms, build-tools and NDKs (newest kept), system images (protected while a virtual device uses them) and emulator devices (the `.avd` folder and its `.ini`). Found via `ANDROID_HOME`, `ANDROID_SDK_ROOT` or `~/Android/Sdk`.
- **Git repositories:** compact with `git gc` and delete merged branches (`git branch -d`, which refuses unmerged ones).

**Open ports**
- Lists TCP ports something is listening on, which process owns them, and whether they're reachable from the network or only locally. Stop your own leftover dev servers with one click (SIGTERM, after a confirmation).

**Suspect processes**
- A **Malware scan (ClamAV)** panel at the top scans every running program's file, or any folder, for known malware, and lists what it finds with Open and Move-to-Trash buttons. It uses `clamdscan` when your user can reach the daemon and falls back to `clamscan` otherwise (slower start, ~15 s to load signatures). If ClamAV isn't installed the panel shows the install command for your distro.
- Ranks running programs by how unusual they look and says why. Signals: executable running from `/tmp`, `/dev/shm` or memory only; a deleted program file that is still running; a name imitating `sshd`, `systemd` and similar from the wrong place; binaries no installed package owns; shells whose input/output is a TCP connection; `LD_PRELOAD` injection; crypto-miner names and pool ports; processes hidden from the process list; and startup entries (cron, systemd, autostart) that download-and-run or run from hidden/temp folders.
- These are hints, not verdicts. Known-benign cases (AppImages, packaged updates, tools in `~/.local`, `~/.cargo` and similar) score low. Processes of other users are only partly visible without root: the tab offers "Scan all processes…", which asks for your password once and runs the same read-only scan as administrator. Actions: open the folder, scan the file with ClamAV (if installed), copy details, stop your own processes. Nothing is stopped automatically.

**Health & speed**
- Live CPU, memory and I/O pressure, boot-time analysis, and recommendations with one-click fixes.
- Startup items: system services and autostart apps you can switch off.
- Installed kernels (remove old ones), and config files left over from package upgrades.
- Health checks: package integrity, failed services, firewall status and pending security updates.

**Disks & filesystems**
- One **Scan** (one password prompt, nothing is changed) reads every drive's SMART health with `smartctl` and checks each ext2/3/4, XFS, Btrfs and FAT filesystem, `/etc/fstab` (`findmnt --verify`) and this boot's kernel log for disk and filesystem errors.
- Drives: the health verdict, reallocated/unreadable sectors, cable (CRC) errors, heat, SSD/NVMe wear and spare capacity, and the last self-test. SMART is switched on and short/long self-tests started from the tab. A drive that reports it is failing is flagged with the advice to back up and replace it: no software can repair that, so none is offered.
- Filesystems: ext recorded errors and unclean state, Btrfs device error counters, FAT dirty bit, and filesystems the kernel remounted read-only.
- Repairs, each behind a confirmation that shows the exact commands:
  - ext: read-only check or `e2fsck -fy`; XFS: `xfs_repair` or online `xfs_scrub`; FAT: `fsck.fat -a`; Btrfs: scrub, and resetting error counters.
  - A mounted filesystem is unmounted first (aborting if something is using it), repaired and mounted again only if the repair finished cleanly. The root filesystem and other system mounts are never unmounted: ext gets a check at the next boot (with `grubby`), otherwise the tab says to use a live USB.
  - `/etc/fstab`: create a missing mount folder, reload systemd, or add `nofail` to an entry whose device is missing (a backup is kept at `/etc/fstab.linuxward.bak`).
  - `btrfs check --repair` and `xfs_repair -L` are deliberately not offered: they can destroy filesystems that are otherwise recoverable.
- Needs `smartmontools` for SMART; each filesystem tool is only used if installed.

**Services**
- Every running systemd service (system or your session) with a plain-language description, memory use and boot state.
- Select one for details, its configuration files (click to open) and Restart / Stop / Disable, each behind a confirmation. Essential services are protected.

**Java**
- Installed runtimes, running JVMs (including those embedded in IDEs), heap and GC analysis, and suggested fixes.

**Large files**
- Find files above a size threshold under any folder; move them to Trash or delete permanently. Hidden folders are skipped by default.

Supported package managers: **apt** (Debian/Ubuntu/Mint/Pop!_OS), **dnf** (Fedora/RHEL), **pacman** (Arch/Manjaro/EndeavourOS), **zypper** (openSUSE).

## Command line and configuration

```sh
linuxward --scan             # print what could be reclaimed
linuxward --clean --dry-run  # list the safe, password-free cleanups it would run
linuxward --clean            # run them (e.g. from cron)
```

- `~/.config/linuxward/exclude`: one folder per line (`~/` allowed, `#` comments). Every scan skips them, and nothing inside them (or containing them) is ever deleted by a cleanup.
- `~/.local/state/linuxward/actions.log`: a timestamped record of everything the app did.

## Build

You need Rust 1.95 (2024 edition) — install with [rustup](https://rustup.rs).

```sh
cargo build --release
./target/release/linuxward
```

No system development libraries are needed to compile; at runtime it uses your desktop's X11 or Wayland and OpenGL, which any desktop install has.

For the root actions you need polkit's `pkexec` (installed by default on GNOME, KDE, Xfce, Cinnamon…). Run the app as your normal user, not with `sudo`.

### Install into your menu

```sh
cargo build --release
install -Dm755 target/release/linuxward ~/.local/bin/linuxward
install -Dm644 linuxward.desktop ~/.local/share/applications/linuxward.desktop
```

## Terminal report

`linuxward --scan` prints the disks, largest packages and reclaimable items without changing anything — handy for checking detection on a new distro.

## Tests

```sh
cargo test                       # unit tests (parsers, quoting, dir clearing)
cargo test -- --ignored --nocapture   # also queries your real package manager (read-only)
```

## Code layout

| File | What it does |
|---|---|
| `src/main.rs` | Window setup and the command-line modes (`--scan`, `--clean`) |
| `src/app.rs` | Application state, the message channel from background threads, the activity log |
| `src/app/nav.rs` | The grouped tab bar |
| `src/app/*_ui.rs` | One file per tab (cleanup, packages, large files, duplicates, security, dev, services, perf, disks, java) plus the confirmation dialog |
| `src/targets.rs` | Each cleanup target: how to measure it and how to clean it |
| `src/pkg.rs` | apt / dnf / pacman / zypper: list, orphans, conflicts, dry-run, remove; protected-package list |
| `src/devclean.rs` | Build artifacts, toolchains, IDE and Android leftovers, git housekeeping |
| `src/fshealth.rs` | SMART and filesystem health: scan, parsers and the repair commands for each finding |
| `src/secscan.rs`, `src/dupes.rs`, `src/ports.rs` | Secret scan, duplicate finder, listening-port list |
| `src/perf.rs`, `src/java.rs`, `src/services.rs` | Performance diagnostics, JVM analysis, systemd services |
| `src/util.rs` | Disk usage, size formatting, command running, `pkexec` batching, exclusions, action log |

## Adding a cleanup target

Write a function in `src/targets.rs` that returns `Option<Target>` with a size and an `Action`:

- `Action::ClearDirs(paths)` – delete directory contents as your user
- `Action::User(cmds)` – run commands as your user
- `Action::Root(cmds)` – run commands as root (joined into the single pkexec prompt)

then add it to the list in `scan_all`.

## Safety notes

- The **administrator process scan** runs this same program as root through `pkexec`. Install the app somewhere only root can write (for example `/usr/local/bin`) before relying on it; run from a build folder in your home, anything that can write there could swap the binary.

- Every destructive action goes through a confirmation dialog.
- Package names are validated and every argument is shell-quoted before reaching the root shell.
- `pacman -Rns` refuses to remove packages that something else depends on; apt/dnf/zypper may remove dependents, which is why the dry-run list is shown first.
- "Move to Trash" doesn't free space until you empty the Trash (which the Cleanup tab can do).

## AI assistance

This project was written with the help of AI (Claude, by Anthropic), under human direction. As with any tool that deletes files and changes system settings, preview first: `linuxward --scan` and `linuxward --clean --dry-run` change nothing, and package removals show a preview of everything affected before you confirm.

## License

LinuxWard is licensed under the [Mozilla Public License 2.0](LICENSE).

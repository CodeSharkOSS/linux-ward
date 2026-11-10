# Disk Cleaner

A small Linux desktop app, written in Rust with [egui/eframe](https://github.com/emilk/egui), for freeing disk space and removing packages.

## Features

**Cleanup tab**
- Disk usage bars for every real mounted filesystem.
- Scans for reclaimable space and shows the size of each item:
  - Application cache (`~/.cache`) and Trash
  - systemd journal (vacuums to 7 days / 200 MiB), rotated logs in `/var/log`, crash dumps
  - Package manager cache (`apt-get clean`, `dnf clean all`, `paccache`, `zypper clean`)
  - Unused dependencies / orphaned packages (with the list and per-package size)
  - Unused Flatpak runtimes and disabled Snap revisions
  - Developer caches: Cargo registry, npm, Go, Gradle, Maven, pnpm, Conda, NuGet, Bundler, unused Docker/Podman images, containers and build cache (volumes are never removed)
- Everything that needs root is batched into **one** password prompt via `pkexec`.

**Packages tab**
- All installed packages with version, installed size and whether you installed them or they came in as a dependency.
- An **Upgradable** view shows packages with a newer version in your repos (`1.0 → 2.0`); select some and choose **Upgrade selected…** (one password prompt). apt also refreshes its index first. pacman has no partial upgrades, so there the button upgrades the whole system (`-Syu`). Availability comes from already-downloaded metadata, so refresh your package index to see the latest.
- A **Conflicts** view lists installed packages that declare a conflict with another installed package (shown next to the name). Healthy systems normally show none; version-limited conflicts are not checked.
- Filter, sort by name or size, "installed by me only" toggle.
- Before removing, runs a dry run and shows any **other packages that would also be removed**.
- Essential packages (libc, systemd, sudo, the package manager itself, the running kernel, etc.) can't be selected, and a removal that would cascade into one is blocked.

**Duplicates tab**
- Finds identical files under a folder (matched by size, then hash, then a byte-for-byte check; hard links are ignored). Keep one copy per set and move the rest to Trash. It refuses to select every copy of a file.

**Security tab**
- Scans a folder (your home by default) for files that commonly hold secrets: SSH and TLS private keys, `.env` files, cloud/registry/Kubernetes/Docker credentials, stored git and database logins, wallets, and shell history. Optionally looks inside small text files for private-key blocks, AWS/GitHub/GitLab/Slack/Stripe/Google tokens and passwords embedded in URLs.
- With **Check git repos** on, also finds secret files committed to git and secrets added in the last 300 commits (deleting a line doesn't remove it from history).
- Ranks findings by risk (keys readable by other users rank highest) and flags unencrypted private keys, `~/.ssh` / `~/.gnupg` that aren't private, and world-writable files.
- Secret values are never displayed or stored. **Restrict** runs `chmod` to 600/700; you can also move files to Trash. Findings are leads to review, not proof of a leak.

**Projects tab** (for developers)
- **Build artifacts:** scans a code folder for regenerable output (Rust/Maven `target/`, `node_modules/`, Gradle/CMake `build/`, Python virtualenvs and caches, Composer `vendor/`, .NET `bin/`/`obj/`) and shows size and days idle. "Select untouched for over N days" picks the stale ones. Each folder is only listed when a marker file proves it is generated, so an unrelated folder called `target` is never touched.
- **Language toolchains:** old versions from rustup, nvm, SDKMAN and pyenv; the one in use is protected.
- **Git repositories:** compact with `git gc` and delete merged branches (`git branch -d`, which refuses unmerged ones).

**Ports tab**
- Lists TCP ports something is listening on, which process owns them, and whether they're reachable from the network or only locally. Stop your own leftover dev servers with one click (SIGTERM, after a confirmation).

**Performance tab**
- Live CPU, memory and I/O pressure, boot-time analysis, and recommendations with one-click fixes.
- Startup items: system services and autostart apps you can switch off.
- Installed kernels (remove old ones), and config files left over from package upgrades.
- Health checks: package integrity, failed services, firewall status and pending security updates.

**Services tab**
- Every running systemd service (system or your session) with a plain-language description, memory use and boot state.
- Select one for details, its configuration files (click to open) and Restart / Stop / Disable, each behind a confirmation. Essential services are protected.

**Java tab**
- Installed runtimes, running JVMs (including those embedded in IDEs), heap and GC analysis, and suggested fixes.

**Large files tab**
- Find files above a size threshold under any folder; move them to Trash or delete permanently. Hidden folders are skipped by default.

Supported package managers: **apt** (Debian/Ubuntu/Mint/Pop!_OS), **dnf** (Fedora/RHEL), **pacman** (Arch/Manjaro/EndeavourOS), **zypper** (openSUSE).

## Command line and configuration

```sh
diskclean --scan             # print what could be reclaimed
diskclean --clean --dry-run  # list the safe, password-free cleanups it would run
diskclean --clean            # run them (e.g. from cron)
```

- `~/.config/diskclean/exclude`: one folder per line (`~/` allowed, `#` comments). Every scan skips them.
- `~/.local/state/diskclean/actions.log`: a timestamped record of everything the app did.

## Build

You need Rust 1.85+ (2024 edition) — install with [rustup](https://rustup.rs).

```sh
cargo build --release
./target/release/diskclean
```

No system development libraries are needed to compile; at runtime it uses your desktop's X11 or Wayland and OpenGL, which any desktop install has.

For the root actions you need polkit's `pkexec` (installed by default on GNOME, KDE, Xfce, Cinnamon…). Run the app as your normal user, not with `sudo`.

### Install into your menu

```sh
cargo build --release
install -Dm755 target/release/diskclean ~/.local/bin/diskclean
install -Dm644 diskclean.desktop ~/.local/share/applications/diskclean.desktop
```

## Terminal report

`diskclean --scan` prints the disks, largest packages and reclaimable items without changing anything — handy for checking detection on a new distro.

## Tests

```sh
cargo test                       # unit tests (parsers, quoting, dir clearing)
cargo test -- --ignored --nocapture   # also queries your real package manager (read-only)
```

## Code layout

| File | What it does |
|---|---|
| `src/main.rs` | Window setup and the `--scan` mode |
| `src/app.rs` | The GUI: tabs, tables, confirmation dialogs, activity log. Slow work runs on threads and reports back over a channel so the UI never freezes |
| `src/targets.rs` | Each cleanup target: how to measure it and how to clean it |
| `src/pkg.rs` | apt / dnf / pacman / zypper: list, orphans, dry-run, remove; protected-package list |
| `src/util.rs` | Disk usage, size formatting, command running, `pkexec` batching with shell quoting |

## Adding a cleanup target

Write a function in `src/targets.rs` that returns `Option<Target>` with a size and an `Action`:

- `Action::ClearDirs(paths)` – delete directory contents as your user
- `Action::User(cmds)` – run commands as your user
- `Action::Root(cmds)` – run commands as root (joined into the single pkexec prompt)

then add it to the list in `scan_all`.

## Safety notes

- Every destructive action goes through a confirmation dialog.
- Package names are validated and every argument is shell-quoted before reaching the root shell.
- `pacman -Rns` refuses to remove packages that something else depends on; apt/dnf/zypper may remove dependents, which is why the dry-run list is shown first.
- "Move to Trash" doesn't free space until you empty the Trash (which the Cleanup tab can do).

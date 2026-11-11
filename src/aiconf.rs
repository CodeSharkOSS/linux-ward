//! Find configuration, instruction and memory files of AI coding assistants (Claude Code, Codex,
//! Gemini CLI, Cursor, Copilot, Aider, ...) so they can be reviewed and edited in one place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::util;

/// Largest file the editor will open.
pub const MAX_EDIT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AiFile {
    pub path: PathBuf,
    pub tool: &'static str,
    /// What the file is for: "Settings", "Instructions", "MCP servers", ...
    pub kind: &'static str,
    /// May hold API keys or login tokens: hidden in the editor until the user asks.
    pub sensitive: bool,
    pub size: u64,
}

/// Dot-folders worth entering during the folder walk; every other hidden folder is skipped.
const AI_DIRS: &[&str] = &[
    ".claude",
    ".cursor",
    ".gemini",
    ".codex",
    ".github",
    ".continue",
    ".codeium",
    ".windsurf",
    ".roo",
    ".clinerules",
    ".amazonq",
    ".kiro",
];

/// Folders that are huge, regenerable, or hold other people's code. Inside `.claude` the
/// transcripts, plugin caches and snapshots are skipped too: they are not hand-edited config.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "site-packages",
    "Trash",
    "__pycache__",
    "vendor",
    "build",
    "dist",
    "venv",
    "snap",
    "projects",
    "plugins",
    "file-history",
    "shell-snapshots",
    "todos",
    "statsig",
    "ide",
    "cache",
    "debug",
    "telemetry",
    "history",
    "sessions",
    "log",
    "logs",
];

/// Files outside the home folder walk, relative to `$HOME`.
const HOME_FILES: &[&str] = &[
    ".config/opencode/opencode.json",
    ".config/opencode/AGENTS.md",
    ".config/Claude/claude_desktop_config.json",
    ".config/github-copilot/apps.json",
    ".config/github-copilot/hosts.json",
    ".config/goose/config.yaml",
    ".config/Code/User/mcp.json",
    ".config/Cursor/User/mcp.json",
    ".config/zed/settings.json",
    ".aider.conf.yml",
    ".aider.model.settings.yml",
];

fn name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

fn dir_name(p: &Path, up: usize) -> &str {
    p.ancestors().nth(up).map_or("", name)
}

/// Recognise an AI configuration file by its name and the folders around it.
pub fn classify(path: &Path) -> Option<(&'static str, &'static str, bool)> {
    let file = name(path);
    let parent = dir_name(path, 1);
    let ext = Path::new(file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let md = ext == "md";
    Some(match (parent, file) {
        // Whole-file names that mean the same wherever they sit.
        (_, "CLAUDE.md" | "CLAUDE.local.md") => ("Claude Code", "Instructions", false),
        (_, ".claude.json") => ("Claude Code", "Settings & state", true),
        (_, "AGENTS.md") => ("Agents (Codex, Cursor, others)", "Instructions", false),
        (_, "GEMINI.md") => ("Gemini CLI", "Instructions", false),
        (_, ".mcp.json") => ("MCP", "MCP servers", false),
        (_, ".cursorrules") => ("Cursor", "Instructions", false),
        (_, ".windsurfrules") => ("Windsurf", "Instructions", false),
        (_, ".clinerules" | ".continuerules") => ("Cline / Continue", "Instructions", false),
        (_, ".aider.conf.yml" | ".aider.model.settings.yml") => ("Aider", "Settings", false),
        (_, "opencode.json" | "opencode.jsonc") => ("OpenCode", "Settings", false),
        (_, "mcp_config.json") if parent == "windsurf" => ("Windsurf", "MCP servers", false),
        (_, "claude_desktop_config.json") => ("Claude Desktop", "Settings & MCP", true),
        (_, "copilot-instructions.md") if parent == ".github" => {
            ("GitHub Copilot", "Instructions", false)
        }
        (".github", _) if file.ends_with(".instructions.md") => {
            ("GitHub Copilot", "Instructions", false)
        }
        (".claude", "settings.json" | "settings.local.json") => ("Claude Code", "Settings", false),
        (".claude", "keybindings.json") => ("Claude Code", "Keybindings", false),
        (".claude", ".credentials.json") => ("Claude Code", "Login", true),
        ("commands", _) if md && dir_name(path, 2) == ".claude" => {
            ("Claude Code", "Slash command", false)
        }
        ("agents", _) if md && dir_name(path, 2) == ".claude" => ("Claude Code", "Subagent", false),
        ("output-styles", _) if md && dir_name(path, 2) == ".claude" => {
            ("Claude Code", "Output style", false)
        }
        (_, "SKILL.md") if dir_name(path, 2) == "skills" && dir_name(path, 3) == ".claude" => {
            ("Claude Code", "Skill", false)
        }
        (".gemini", "settings.json") => ("Gemini CLI", "Settings", false),
        (".codex", "config.toml") => ("Codex", "Settings", false),
        (".codex", "auth.json") => ("Codex", "Login", true),
        (".cursor", "mcp.json") => ("Cursor", "MCP servers", false),
        ("rules", _) if dir_name(path, 2) == ".cursor" && matches!(ext, "md" | "mdc") => {
            ("Cursor", "Rules", false)
        }
        (".continue", "config.yaml" | "config.yml" | "config.json") => {
            ("Continue", "Settings", false)
        }
        ("github-copilot", "apps.json" | "hosts.json") => ("GitHub Copilot", "Login", true),
        _ => return None,
    })
}

fn entry(path: PathBuf) -> Option<AiFile> {
    let (tool, kind, sensitive) = classify(&path)?;
    let meta = std::fs::metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)?;
    Some(AiFile {
        tool,
        kind,
        sensitive,
        size: meta.len(),
        path,
    })
}

/// Look for AI config files under `root` (and the usual per-user locations when `root` is the
/// home folder). Returns them sorted by tool, then path. Also reports how many files were visited.
pub fn scan(root: &Path) -> (Vec<AiFile>, usize) {
    let mut found: BTreeMap<PathBuf, AiFile> = BTreeMap::new();
    let mut visited = 0;
    let home = util::home();
    if root == home {
        for rel in HOME_FILES {
            if let Some(f) = entry(home.join(rel)) {
                found.insert(f.path.clone(), f);
            }
        }
    }
    let walk = walkdir::WalkDir::new(root)
        .follow_links(false)
        .same_file_system(true)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let n = e.file_name().to_string_lossy();
            if util::excluded(e.path()) {
                return false;
            }
            if e.file_type().is_dir() {
                if SKIP_DIRS.contains(&n.as_ref()) {
                    return false;
                }
                // .github, .claude, ... are entered; other hidden folders are not.
                if n.starts_with('.') {
                    return AI_DIRS.contains(&n.as_ref());
                }
            }
            true
        });
    for e in walk.filter_map(Result::ok) {
        if !e.file_type().is_file() {
            continue;
        }
        visited += 1;
        if let Some(f) = entry(e.into_path()) {
            found.insert(f.path.clone(), f);
        }
    }
    let mut v: Vec<AiFile> = found.into_values().collect();
    v.sort_by(|a, b| (a.tool, &a.path).cmp(&(b.tool, &b.path)));
    (v, visited)
}

/// Read a file for editing. Refuses large or non-text files rather than corrupting them.
pub fn load(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_EDIT_BYTES {
        return Err(format!(
            "{} is too large to edit here (limit {})",
            path.display(),
            util::human(MAX_EDIT_BYTES)
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|_| "not a UTF-8 text file".to_string())
}

/// Where the copy made before the last save is kept.
pub fn backup_path(path: &Path) -> PathBuf {
    let dir = std::env::var_os("XDG_STATE_HOME")
        .map_or_else(|| util::home().join(".local/state"), PathBuf::from)
        .join("linuxward/backups");
    let flat: String = path
        .to_string_lossy()
        .chars()
        .map(|c| if c == '/' { '%' } else { c })
        .collect();
    dir.join(flat)
}

/// Save `text` over `path`, first copying the current file to [`backup_path`]. Writes in place so
/// permissions (for example 600 on a login file) and symlinks (dotfile managers) are preserved.
pub fn save(path: &Path, text: &str) -> Result<PathBuf, String> {
    let backup = backup_path(path);
    if path.exists() {
        if let Some(dir) = backup.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("backup folder: {e}"))?;
        }
        std::fs::copy(path, &backup).map_err(|e| format!("could not back up first: {e}"))?;
    }
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    Ok(backup)
}

/// Syntax problem in a JSON config, if the file looks like JSON and does not parse.
pub fn json_error(path: &Path, text: &str) -> Option<String> {
    // opencode.jsonc and editors' settings allow comments, so only strict `.json` is checked.
    if path.extension().and_then(|e| e.to_str()) != Some("json") || text.trim().is_empty() {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(text)
        .err()
        .map(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_known_files() {
        let c = |p: &str| classify(Path::new(p)).map(|x| (x.0, x.1));
        assert_eq!(c("/h/p/CLAUDE.md"), Some(("Claude Code", "Instructions")));
        assert_eq!(
            c("/h/.claude/settings.json"),
            Some(("Claude Code", "Settings"))
        );
        assert_eq!(
            c("/h/.claude/commands/x.md"),
            Some(("Claude Code", "Slash command"))
        );
        assert_eq!(
            c("/h/.claude/skills/a/SKILL.md"),
            Some(("Claude Code", "Skill"))
        );
        assert_eq!(c("/h/.cursor/rules/a.mdc"), Some(("Cursor", "Rules")));
        assert_eq!(c("/h/.codex/auth.json").map(|_| ()), Some(()));
        assert!(classify(Path::new("/h/p/settings.json")).is_none());
        assert!(classify(Path::new("/h/p/commands/x.md")).is_none());
    }

    #[test]
    fn json_check() {
        assert!(json_error(Path::new("a.json"), "{").is_some());
        assert!(json_error(Path::new("a.json"), "{}").is_none());
        assert!(json_error(Path::new("a.md"), "{").is_none());
    }
}
